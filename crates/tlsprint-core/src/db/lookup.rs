use rusqlite::params;

use super::types::{Classification, Ja3Match, Ja4Match};
use super::{DbError, FingerprintDb};

impl FingerprintDb {
    /// Look up all JA3 matches for a given hash.
    pub fn lookup_ja3(&self, hash: &str) -> Result<Vec<Ja3Match>, DbError> {
        let mut stmt = self.conn.prepare_cached(
            "SELECT application, category, raw_string, source
             FROM ja3_fingerprints WHERE hash = ?1",
        )?;
        let matches = stmt
            .query_map(params![hash], |row| {
                Ok(Ja3Match {
                    application: row.get(0)?,
                    category: row.get(1)?,
                    description: row.get(2)?,
                    source: row.get(3)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(matches)
    }

    /// Look up all JA4 matches for a given hash.
    pub fn lookup_ja4(&self, hash: &str) -> Result<Vec<Ja4Match>, DbError> {
        let mut stmt = self.conn.prepare_cached(
            "SELECT application, library, device, os, verified,
                    observation_count, source
             FROM ja4_fingerprints WHERE hash = ?1",
        )?;
        let matches = stmt
            .query_map(params![hash], |row| {
                Ok(Ja4Match {
                    application: row.get(0)?,
                    library: row.get(1)?,
                    device: row.get(2)?,
                    os: row.get(3)?,
                    verified: row.get::<_, i32>(4)? != 0,
                    observation_count: row.get(5)?,
                    source: row.get(6)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(matches)
    }

    /// Combined classification: look up both JA3 and JA4, derive best match.
    pub fn classify(&self, ja3_hash: &str, ja4_hash: &str) -> Result<Classification, DbError> {
        let ja3_matches = self.lookup_ja3(ja3_hash)?;
        let ja4_matches = self.lookup_ja4(ja4_hash)?;
        let mut classification = Classification {
            ja3_matches,
            ja4_matches,
            best_match: None,
        };
        classification.derive_best_match();
        Ok(classification)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_db() -> FingerprintDb {
        FingerprintDb::open_in_memory().unwrap()
    }

    #[test]
    fn lookup_ja3_returns_matches() {
        let db = test_db();
        db.conn
            .execute(
                "INSERT INTO ja3_fingerprints (hash, application, category, source)
                 VALUES ('abc123', 'Chrome 120', 'browser', 'ja3prints')",
                [],
            )
            .unwrap();

        let matches = db.lookup_ja3("abc123").unwrap();
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].application, "Chrome 120");
        assert_eq!(matches[0].category.as_deref(), Some("browser"));
    }

    #[test]
    fn lookup_ja3_returns_empty_on_miss() {
        let db = test_db();
        let matches = db.lookup_ja3("nonexistent").unwrap();
        assert!(matches.is_empty());
    }

    #[test]
    fn lookup_ja4_returns_matches() {
        let db = test_db();
        db.conn
            .execute(
                "INSERT INTO ja4_fingerprints
                    (hash, application, library, verified, observation_count, source)
                 VALUES ('t13d1509h2_abc_def', 'Chrome', 'BoringSSL', 1, 1500, 'ja4db')",
                [],
            )
            .unwrap();

        let matches = db.lookup_ja4("t13d1509h2_abc_def").unwrap();
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].application.as_deref(), Some("Chrome"));
        assert!(matches[0].verified);
        assert_eq!(matches[0].observation_count, 1500);
    }

    #[test]
    fn classify_combines_both() {
        let db = test_db();
        db.conn
            .execute(
                "INSERT INTO ja3_fingerprints (hash, application, source)
                 VALUES ('ja3hash', 'TestApp', 'ja3prints')",
                [],
            )
            .unwrap();
        db.conn
            .execute(
                "INSERT INTO ja4_fingerprints
                    (hash, application, library, verified, observation_count, source)
                 VALUES ('ja4hash', 'TestApp', 'TestLib', 1, 100, 'ja4db')",
                [],
            )
            .unwrap();

        let c = db.classify("ja3hash", "ja4hash").unwrap();
        assert_eq!(c.ja3_matches.len(), 1);
        assert_eq!(c.ja4_matches.len(), 1);
        assert!(c.best_match.is_some());
        assert!(c.best_match.unwrap().contains("TestApp"));
    }

    #[test]
    fn classify_empty_db_returns_empty() {
        let db = test_db();
        let c = db.classify("nope", "nope").unwrap();
        assert!(c.is_empty());
        assert!(c.best_match.is_none());
    }
}
