use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};

use tlsprint_core::db::{self, FingerprintDb};

#[derive(Parser)]
#[command(name = "tlsprint-db")]
#[command(about = "Manage the TLSprint fingerprint database")]
struct Cli {
    /// Path to the database file
    /// [default: ~/.local/share/tlsprint/fingerprints.db]
    #[arg(long, global = true)]
    db: Option<PathBuf>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Initialize an empty database (creates file and tables)
    Init,

    /// Import fingerprints from seed data files
    Import {
        #[command(subcommand)]
        source: ImportSource,
    },

    /// Show database statistics
    Stats,

    /// Look up a fingerprint hash (checks both JA3 and JA4 tables)
    Lookup {
        /// The hash to look up
        hash: String,
    },
}

#[derive(Subcommand)]
enum ImportSource {
    /// Import from ja4db.com JSON file
    ///
    /// Download first: curl -o ja4db.json https://ja4db.com/api/read/
    Ja4db {
        /// Path to the downloaded JSON file
        file: PathBuf,
        /// Clear existing ja4db entries before importing
        #[arg(long)]
        replace: bool,
    },
    /// Import from trisulnsm/ja3prints NDJSON file
    ///
    /// Download: wget https://raw.githubusercontent.com/trisulnsm/ja3prints/master/ja3fingerprint.json
    Ja3prints {
        /// Path to the NDJSON file
        file: PathBuf,
        /// Clear existing ja3prints entries before importing
        #[arg(long)]
        replace: bool,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    tracing_subscriber::fmt()
        .with_target(false)
        .with_level(true)
        .init();

    let db_path = cli.db.unwrap_or_else(db::default_db_path);

    match cli.command {
        Commands::Init => {
            let _db = FingerprintDb::open(&db_path)
                .with_context(|| format!("Failed to initialize database at {}", db_path.display()))?;
            println!("Database initialized: {}", db_path.display());
        }

        Commands::Import { source } => {
            let db = FingerprintDb::open(&db_path)
                .with_context(|| format!("Failed to open database at {}", db_path.display()))?;

            match source {
                ImportSource::Ja4db { file, replace } => {
                    if replace {
                        db.clear_source("ja4db")?;
                        println!("Cleared existing ja4db entries.");
                    }
                    let stats = db
                        .import_ja4db(&file)
                        .with_context(|| format!("Failed to import {}", file.display()))?;
                    println!(
                        "ja4db import complete: {} imported, {} skipped",
                        stats.imported, stats.skipped
                    );
                }
                ImportSource::Ja3prints { file, replace } => {
                    if replace {
                        db.clear_source("ja3prints")?;
                        println!("Cleared existing ja3prints entries.");
                    }
                    let stats = db
                        .import_ja3prints(&file)
                        .with_context(|| format!("Failed to import {}", file.display()))?;
                    println!(
                        "ja3prints import complete: {} imported, {} skipped",
                        stats.imported, stats.skipped
                    );
                }
            }
        }

        Commands::Stats => {
            let db = FingerprintDb::open(&db_path)
                .with_context(|| format!("Failed to open database at {}", db_path.display()))?;
            let stats = db.stats()?;

            println!("Database: {}", db_path.display());
            println!("JA3 fingerprints: {}", stats.ja3_total);
            for (source, count) in &stats.ja3_by_source {
                println!("  {}: {}", source, count);
            }
            println!("JA4 fingerprints: {}", stats.ja4_total);
            for (source, count) in &stats.ja4_by_source {
                println!("  {}: {}", source, count);
            }
        }

        Commands::Lookup { hash } => {
            let db = FingerprintDb::open(&db_path)
                .with_context(|| format!("Failed to open database at {}", db_path.display()))?;

            let ja3_matches = db.lookup_ja3(&hash)?;
            let ja4_matches = db.lookup_ja4(&hash)?;

            if ja3_matches.is_empty() && ja4_matches.is_empty() {
                println!("No matches found for: {}", hash);
                return Ok(());
            }

            for m in &ja3_matches {
                let cat = m
                    .category
                    .as_deref()
                    .map(|c| format!(", category: {}", c))
                    .unwrap_or_default();
                println!(
                    "JA3 match: \"{}\" (source: {}{})",
                    m.application, m.source, cat
                );
            }
            for m in &ja4_matches {
                let app = m.application.as_deref().unwrap_or("(unknown)");
                let lib = m
                    .library
                    .as_deref()
                    .map(|l| format!(", library: {}", l))
                    .unwrap_or_default();
                let verified = if m.verified { ", verified" } else { "" };
                println!(
                    "JA4 match: \"{}\" (source: {}{}{}, observations: {})",
                    app, m.source, lib, verified, m.observation_count
                );
            }
        }
    }

    Ok(())
}
