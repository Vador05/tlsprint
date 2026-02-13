pub mod lookup;
pub mod schema;
pub mod seed;
pub mod types;

use std::path::{Path, PathBuf};

use rusqlite::Connection;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum DbError {
    #[error("database error: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("seed data error: {0}")]
    SeedError(String),
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

/// Handle to the fingerprint SQLite database.
pub struct FingerprintDb {
    conn: Connection,
}

impl FingerprintDb {
    /// Open (or create) the database at the given path.
    /// Runs schema initialization if needed.
    pub fn open(path: &Path) -> Result<Self, DbError> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let conn = Connection::open(path)?;
        conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;")?;
        let db = Self { conn };
        schema::initialize(&db.conn)?;
        Ok(db)
    }

    /// Open the database at the default XDG path.
    pub fn open_default() -> Result<Self, DbError> {
        let path = default_db_path();
        Self::open(&path)
    }

    /// Open an in-memory database (for testing).
    pub fn open_in_memory() -> Result<Self, DbError> {
        let conn = Connection::open_in_memory()?;
        let db = Self { conn };
        schema::initialize(&db.conn)?;
        Ok(db)
    }
}

/// Default database path: `~/.local/share/tlsprint/fingerprints.db`
pub fn default_db_path() -> PathBuf {
    let base = std::env::var("XDG_DATA_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            let home = std::env::var("HOME").expect("HOME not set");
            PathBuf::from(home).join(".local/share")
        });
    base.join("tlsprint/fingerprints.db")
}
