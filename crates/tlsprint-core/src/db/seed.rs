use std::io::{BufRead, BufReader};
use std::path::Path;

use rusqlite::params;
use serde::Deserialize;
use tracing::info;

use super::types::ImportStats;
use super::{DbError, FingerprintDb};

/// ja4db.com JSON array entry.
#[derive(Deserialize)]
struct Ja4DbEntry {
    ja4_fingerprint: Option<String>,
    ja4_fingerprint_string: Option<String>,
    application: Option<String>,
    library: Option<String>,
    device: Option<String>,
    os: Option<String>,
    user_agent_string: Option<String>,
    verified: Option<bool>,
    observation_count: Option<i64>,
}

/// trisulnsm/ja3prints NDJSON entry.
#[derive(Deserialize)]
struct Ja3PrintsEntry {
    desc: String,
    ja3_hash: String,
    ja3_str: Option<String>,
}

impl FingerprintDb {
    /// Import ja4db.com data from a JSON file (array format).
    pub fn import_ja4db(&self, path: &Path) -> Result<ImportStats, DbError> {
        let file = std::fs::File::open(path)
            .map_err(|e| DbError::SeedError(format!("{}: {}", path.display(), e)))?;
        let reader = BufReader::new(file);
        let entries: Vec<Ja4DbEntry> = serde_json::from_reader(reader)
            .map_err(|e| DbError::SeedError(format!("JSON parse error: {}", e)))?;

        let tx = self.conn.unchecked_transaction()?;
        let mut stmt = tx.prepare(
            "INSERT INTO ja4_fingerprints
                (hash, application, library, device, os, user_agent,
                 verified, observation_count, raw_string, source)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, 'ja4db')",
        )?;

        let mut imported = 0u64;
        let mut skipped = 0u64;

        for entry in &entries {
            let Some(hash) = &entry.ja4_fingerprint else {
                skipped += 1;
                continue;
            };
            if hash.is_empty() {
                skipped += 1;
                continue;
            }
            stmt.execute(params![
                hash,
                entry.application,
                entry.library,
                entry.device,
                entry.os,
                entry.user_agent_string,
                entry.verified.unwrap_or(false) as i32,
                entry.observation_count.unwrap_or(0),
                entry.ja4_fingerprint_string,
            ])?;
            imported += 1;
        }
        drop(stmt);
        tx.commit()?;

        info!("ja4db import: {} imported, {} skipped", imported, skipped);
        Ok(ImportStats { imported, skipped })
    }

    /// Import trisulnsm/ja3prints data from an NDJSON file.
    pub fn import_ja3prints(&self, path: &Path) -> Result<ImportStats, DbError> {
        let file = std::fs::File::open(path)
            .map_err(|e| DbError::SeedError(format!("{}: {}", path.display(), e)))?;
        let reader = BufReader::new(file);

        let tx = self.conn.unchecked_transaction()?;
        let mut stmt = tx.prepare(
            "INSERT INTO ja3_fingerprints
                (hash, application, category, raw_string, source)
             VALUES (?1, ?2, ?3, ?4, 'ja3prints')",
        )?;

        let mut imported = 0u64;
        let mut skipped = 0u64;

        for line_result in reader.lines() {
            let line = line_result
                .map_err(|e| DbError::SeedError(format!("read line: {}", e)))?;
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') || line.starts_with("//") {
                continue;
            }
            let entry: Ja3PrintsEntry = match serde_json::from_str(line) {
                Ok(e) => e,
                Err(_) => {
                    skipped += 1;
                    continue;
                }
            };

            let category = categorize_ja3_desc(&entry.desc);

            stmt.execute(params![
                entry.ja3_hash,
                entry.desc,
                category,
                entry.ja3_str,
            ])?;
            imported += 1;
        }
        drop(stmt);
        tx.commit()?;

        info!("ja3prints import: {} imported, {} skipped", imported, skipped);
        Ok(ImportStats { imported, skipped })
    }

    /// Clear all fingerprints from a given source.
    pub fn clear_source(&self, source: &str) -> Result<(), DbError> {
        self.conn
            .execute("DELETE FROM ja3_fingerprints WHERE source = ?1", [source])?;
        self.conn
            .execute("DELETE FROM ja4_fingerprints WHERE source = ?1", [source])?;
        Ok(())
    }

    /// Count fingerprints grouped by source.
    pub fn stats(&self) -> Result<DbStats, DbError> {
        let ja3_total: i64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM ja3_fingerprints", [], |row| {
                row.get(0)
            })?;
        let ja4_total: i64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM ja4_fingerprints", [], |row| {
                row.get(0)
            })?;

        let mut ja3_by_source = Vec::new();
        let mut stmt = self
            .conn
            .prepare("SELECT source, COUNT(*) FROM ja3_fingerprints GROUP BY source")?;
        let rows = stmt.query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?;
        for row in rows {
            ja3_by_source.push(row?);
        }

        let mut ja4_by_source = Vec::new();
        let mut stmt = self
            .conn
            .prepare("SELECT source, COUNT(*) FROM ja4_fingerprints GROUP BY source")?;
        let rows = stmt.query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?;
        for row in rows {
            ja4_by_source.push(row?);
        }

        Ok(DbStats {
            ja3_total,
            ja4_total,
            ja3_by_source,
            ja4_by_source,
        })
    }
}

pub struct DbStats {
    pub ja3_total: i64,
    pub ja4_total: i64,
    pub ja3_by_source: Vec<(String, i64)>,
    pub ja4_by_source: Vec<(String, i64)>,
}

/// Simple heuristic categorization from ja3prints description strings.
fn categorize_ja3_desc(desc: &str) -> Option<String> {
    let lower = desc.to_lowercase();
    if lower.contains("malware")
        || lower.contains("trojan")
        || lower.contains("cobalt")
        || lower.contains("metasploit")
        || lower.contains("empire")
    {
        Some("malware".to_string())
    } else if lower.contains("chrome")
        || lower.contains("firefox")
        || lower.contains("safari")
        || lower.contains("edge")
        || lower.contains("browser")
        || lower.contains("opera")
    {
        Some("browser".to_string())
    } else if lower.contains("curl")
        || lower.contains("wget")
        || lower.contains("python")
        || lower.contains("go http")
        || lower.contains("java")
        || lower.contains("okhttp")
        || lower.contains("openssl")
        || lower.contains("nmap")
    {
        Some("tool".to_string())
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::FingerprintDb;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn categorize_browsers() {
        assert_eq!(categorize_ja3_desc("Chrome 120"), Some("browser".into()));
        assert_eq!(categorize_ja3_desc("Firefox 115"), Some("browser".into()));
    }

    #[test]
    fn categorize_tools() {
        assert_eq!(categorize_ja3_desc("curl/7.88"), Some("tool".into()));
        assert_eq!(
            categorize_ja3_desc("Python requests"),
            Some("tool".into())
        );
    }

    #[test]
    fn categorize_malware() {
        assert_eq!(
            categorize_ja3_desc("CobaltStrike beacon"),
            Some("malware".into())
        );
    }

    #[test]
    fn categorize_unknown() {
        assert_eq!(categorize_ja3_desc("Some random app"), None);
    }

    #[test]
    fn import_ja3prints_ndjson() {
        let db = FingerprintDb::open_in_memory().unwrap();

        let mut file = NamedTempFile::new().unwrap();
        writeln!(
            file,
            r#"{{"desc":"Chrome 120","ja3_hash":"abc123","ja3_str":"771,1301-1302"}}"#
        )
        .unwrap();
        writeln!(
            file,
            r#"{{"desc":"curl/7.88","ja3_hash":"def456","ja3_str":"769,47-53"}}"#
        )
        .unwrap();

        let stats = db.import_ja3prints(file.path()).unwrap();
        assert_eq!(stats.imported, 2);
        assert_eq!(stats.skipped, 0);

        let matches = db.lookup_ja3("abc123").unwrap();
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].application, "Chrome 120");
        assert_eq!(matches[0].category.as_deref(), Some("browser"));
    }

    #[test]
    fn clear_source_removes_entries() {
        let db = FingerprintDb::open_in_memory().unwrap();
        db.conn
            .execute(
                "INSERT INTO ja3_fingerprints (hash, application, source)
                 VALUES ('h1', 'App1', 'ja3prints')",
                [],
            )
            .unwrap();
        db.conn
            .execute(
                "INSERT INTO ja3_fingerprints (hash, application, source)
                 VALUES ('h2', 'App2', 'manual')",
                [],
            )
            .unwrap();

        db.clear_source("ja3prints").unwrap();

        let count: i64 = db
            .conn
            .query_row("SELECT COUNT(*) FROM ja3_fingerprints", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(count, 1); // only 'manual' entry remains
    }
}
