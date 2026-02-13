use serde::Serialize;

/// A single JA3 match from the database.
#[derive(Debug, Clone, Serialize)]
pub struct Ja3Match {
    pub application: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub category: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub source: String,
}

/// A single JA4 match from the database.
#[derive(Debug, Clone, Serialize)]
pub struct Ja4Match {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub application: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub library: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub os: Option<String>,
    pub verified: bool,
    pub observation_count: i64,
    pub source: String,
}

/// Classification result combining JA3 and JA4 lookups.
#[derive(Debug, Clone, Serialize)]
pub struct Classification {
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub ja3_matches: Vec<Ja3Match>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub ja4_matches: Vec<Ja4Match>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub best_match: Option<String>,
}

impl Classification {
    pub fn empty() -> Self {
        Self {
            ja3_matches: vec![],
            ja4_matches: vec![],
            best_match: None,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.ja3_matches.is_empty() && self.ja4_matches.is_empty()
    }

    /// Derive a single best-match summary string.
    /// Priority: verified JA4 > highest observation_count JA4 > JA3 match.
    pub fn derive_best_match(&mut self) {
        // Try verified JA4 matches first
        if let Some(m) = self.ja4_matches.iter().find(|m| m.verified) {
            self.best_match = Some(format_ja4_match(m, true));
            return;
        }

        // Then highest observation count JA4
        if let Some(m) = self
            .ja4_matches
            .iter()
            .filter(|m| m.application.is_some())
            .max_by_key(|m| m.observation_count)
        {
            self.best_match = Some(format_ja4_match(m, false));
            return;
        }

        // Fall back to JA3
        if let Some(m) = self.ja3_matches.first() {
            let mut s = m.application.clone();
            if let Some(cat) = &m.category {
                s.push_str(&format!(" [{}]", cat));
            }
            self.best_match = Some(s);
        }
    }
}

fn format_ja4_match(m: &Ja4Match, verified: bool) -> String {
    let mut parts = Vec::new();
    if let Some(app) = &m.application {
        parts.push(app.clone());
    }
    if let Some(lib) = &m.library {
        parts.push(format!("({})", lib));
    }
    let mut s = parts.join(" ");
    if s.is_empty() {
        s = "(unknown app)".to_string();
    }
    let mut meta = vec![m.source.clone()];
    if verified {
        meta.push("verified".to_string());
    }
    format!("{} [{}]", s, meta.join(", "))
}

/// Statistics returned by import operations.
pub struct ImportStats {
    pub imported: u64,
    pub skipped: u64,
}
