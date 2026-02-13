use std::env;
use std::net::SocketAddr;

use tokio::io::AsyncReadExt;
use tokio::net::TcpListener;
use tracing::{error, info, warn};

use tlsprint_core::fingerprint::clienthello::parse_client_hello;
use tlsprint_core::fingerprint::ja3::compute_ja3;
use tlsprint_core::fingerprint::ja4::compute_ja4;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_target(false)
        .with_level(true)
        .init();

    let port: u16 = env::args()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(8443);

    let addr: SocketAddr = ([0, 0, 0, 0], port).into();
    let listener = TcpListener::bind(addr).await?;

    info!("TLSprint sniffer listening on {}", addr);
    info!("Test with: curl -k https://localhost:{}", port);
    info!("Press Ctrl+C to stop\n");

    loop {
        let (mut stream, peer) = listener.accept().await?;

        tokio::spawn(async move {
            // Read TLS record header (5 bytes): content_type(1) + version(2) + length(2)
            let mut header = [0u8; 5];
            if let Err(e) = stream.read_exact(&mut header).await {
                warn!("[{}] failed to read TLS header: {}", peer, e);
                return;
            }

            if header[0] != 0x16 {
                warn!("[{}] not a TLS handshake (got 0x{:02x})", peer, header[0]);
                return;
            }

            let record_len = u16::from_be_bytes([header[3], header[4]]) as usize;
            if record_len > 16384 {
                warn!("[{}] record too large: {} bytes", peer, record_len);
                return;
            }

            // Read the full record body
            let mut body = vec![0u8; record_len];
            if let Err(e) = stream.read_exact(&mut body).await {
                warn!("[{}] failed to read record body: {}", peer, e);
                return;
            }

            // Reassemble: header + body for the parser
            let mut full = Vec::with_capacity(5 + record_len);
            full.extend_from_slice(&header);
            full.extend_from_slice(&body);

            // Parse and fingerprint
            match parse_client_hello(&full) {
                Ok(info) => {
                    let ja3 = compute_ja3(&info);
                    let ja4 = compute_ja4(&info, false);

                    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
                    println!("  Client:     {}", peer);
                    println!(
                        "  SNI:        {}",
                        info.server_name.as_deref().unwrap_or("(none)")
                    );
                    println!("  TLS ver:    0x{:04x}", info.tls_version);
                    if !info.supported_versions.is_empty() {
                        let vers: Vec<String> =
                            info.supported_versions.iter().map(|v| format!("0x{:04x}", v)).collect();
                        println!("  Sup. vers:  {}", vers.join(", "));
                    }
                    println!("  Ciphers:    {} suites", info.cipher_suites.len());
                    println!("  Extensions: {} types", info.extensions.len());
                    if !info.alpn_protocols.is_empty() {
                        println!("  ALPN:       {}", info.alpn_protocols.join(", "));
                    }
                    println!("  ──────────────────────────────────────────────────");
                    println!("  JA3:        {}", ja3.hash);
                    println!("  JA3 raw:    {}", ja3.raw_string);
                    println!("  JA4:        {}", ja4.hash);
                    println!("  JA4 raw:    {}", ja4.raw);
                    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
                }
                Err(e) => {
                    error!("[{}] parse error: {}", peer, e);
                }
            }

            // Connection drops here — client will see a TLS error, that's expected
        });
    }
}
