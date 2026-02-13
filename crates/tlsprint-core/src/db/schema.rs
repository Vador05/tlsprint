use rusqlite::Connection;

use super::DbError;

const SCHEMA_VERSION: i32 = 1;

pub fn initialize(conn: &Connection) -> Result<(), DbError> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS schema_version (
            version INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS ja3_fingerprints (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            hash        TEXT NOT NULL,
            application TEXT NOT NULL,
            category    TEXT,
            raw_string  TEXT,
            source      TEXT NOT NULL DEFAULT 'unknown',
            created_at  TEXT NOT NULL DEFAULT (datetime('now'))
        );

        CREATE INDEX IF NOT EXISTS idx_ja3_hash
            ON ja3_fingerprints(hash);

        CREATE TABLE IF NOT EXISTS ja4_fingerprints (
            id                INTEGER PRIMARY KEY AUTOINCREMENT,
            hash              TEXT NOT NULL,
            application       TEXT,
            library           TEXT,
            device            TEXT,
            os                TEXT,
            user_agent        TEXT,
            verified          INTEGER DEFAULT 0,
            observation_count INTEGER DEFAULT 0,
            raw_string        TEXT,
            source            TEXT NOT NULL DEFAULT 'unknown',
            created_at        TEXT NOT NULL DEFAULT (datetime('now'))
        );

        CREATE INDEX IF NOT EXISTS idx_ja4_hash
            ON ja4_fingerprints(hash);",
    )?;

    // Set schema version if not already set
    let count: i32 =
        conn.query_row("SELECT COUNT(*) FROM schema_version", [], |row| row.get(0))?;
    if count == 0 {
        conn.execute(
            "INSERT INTO schema_version (version) VALUES (?1)",
            [SCHEMA_VERSION],
        )?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn initialize_creates_tables() {
        let conn = Connection::open_in_memory().unwrap();
        initialize(&conn).unwrap();

        // Verify tables exist by querying them
        let ja3_count: i32 = conn
            .query_row("SELECT COUNT(*) FROM ja3_fingerprints", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(ja3_count, 0);

        let ja4_count: i32 = conn
            .query_row("SELECT COUNT(*) FROM ja4_fingerprints", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(ja4_count, 0);

        let version: i32 = conn
            .query_row("SELECT version FROM schema_version", [], |row| row.get(0))
            .unwrap();
        assert_eq!(version, SCHEMA_VERSION);
    }

    #[test]
    fn initialize_is_idempotent() {
        let conn = Connection::open_in_memory().unwrap();
        initialize(&conn).unwrap();
        initialize(&conn).unwrap(); // second call should not fail
    }
}
