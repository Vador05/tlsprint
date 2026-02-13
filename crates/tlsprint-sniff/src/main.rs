use anyhow::Result;
use clap::Parser;
use tracing::info;

use tlsprint_core::db::{self, FingerprintDb};

mod capture;
mod output;
mod packet;
mod reassembly;

#[derive(Parser)]
#[command(name = "tlsprint-sniff")]
#[command(about = "Passive TLS fingerprint sniffer — captures ClientHellos from network traffic")]
struct Cli {
    /// Network interface to capture on (e.g., eth0, wlan0).
    /// If omitted, lists available interfaces and exits.
    #[arg(short, long)]
    interface: Option<String>,

    /// BPF filter expression
    #[arg(short, long, default_value = "tcp port 443")]
    filter: String,

    /// Enable promiscuous mode (capture all traffic on the segment)
    #[arg(short, long, default_value_t = false)]
    promisc: bool,

    /// Snap length — max bytes captured per packet
    #[arg(short, long, default_value_t = 1600)]
    snaplen: i32,

    /// Print verbose output (raw JA3/JA4 strings)
    #[arg(short, long, default_value_t = false)]
    verbose: bool,

    /// Output format: "text" (human-readable) or "json" (NDJSON, one object per line)
    #[arg(short, long, default_value = "text")]
    output: String,

    /// Disable fingerprint classification (skip database lookups)
    #[arg(long, default_value_t = false)]
    no_classify: bool,

    /// Path to the fingerprint database
    /// [default: ~/.local/share/tlsprint/fingerprints.db]
    #[arg(long)]
    db: Option<std::path::PathBuf>,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    tracing_subscriber::fmt()
        .with_target(false)
        .with_level(true)
        .init();

    let iface = match cli.interface {
        Some(name) => name,
        None => {
            capture::list_interfaces()?;
            return Ok(());
        }
    };

    let format = output::OutputFormat::parse(&cli.output)?;

    let db = if cli.no_classify {
        None
    } else {
        let path = cli.db.unwrap_or_else(db::default_db_path);
        match FingerprintDb::open(&path) {
            Ok(db) => {
                info!("Fingerprint DB loaded: {}", path.display());
                Some(db)
            }
            Err(_) => {
                info!("No fingerprint DB found (classification disabled)");
                None
            }
        }
    };

    info!("Capturing on interface: {}", iface);
    info!("BPF filter: {}", cli.filter);
    info!("Press Ctrl+C to stop\n");

    capture::run_capture(
        &iface,
        &cli.filter,
        cli.promisc,
        cli.snaplen,
        cli.verbose,
        format,
        db.as_ref(),
    )
}
