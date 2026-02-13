use anyhow::{bail, Context, Result};
use pcap::{Capture, Device};
use tracing::{debug, error};

use tlsprint_core::db::types::Classification;
use tlsprint_core::db::FingerprintDb;

use crate::output::{self, OutputFormat};
use crate::packet;
use crate::reassembly::{ProcessResult, TcpReassembler};

/// List all available network interfaces.
pub fn list_interfaces() -> Result<()> {
    let devices =
        Device::list().context("Failed to list network devices. Do you have permission?")?;

    if devices.is_empty() {
        println!("No network interfaces found.");
        println!("Hint: run with sudo or set CAP_NET_RAW capability.");
        return Ok(());
    }

    println!("Available interfaces:");
    for dev in &devices {
        let desc = dev.desc.as_deref().unwrap_or("");
        let addrs: Vec<String> = dev.addresses.iter().map(|a| format!("{}", a.addr)).collect();
        let addr_str = if addrs.is_empty() {
            "(no addresses)".to_string()
        } else {
            addrs.join(", ")
        };
        println!("  {:<16} {} [{}]", dev.name, desc, addr_str);
    }

    println!("\nUsage: tlsprint-sniff -i <interface>");
    Ok(())
}

/// Open a capture on the given interface and process packets in a loop.
pub fn run_capture(
    iface: &str,
    bpf_filter: &str,
    promisc: bool,
    snaplen: i32,
    verbose: bool,
    format: OutputFormat,
    db: Option<&FingerprintDb>,
) -> Result<()> {
    let mut cap = Capture::from_device(iface)
        .with_context(|| {
            format!(
                "Failed to open interface '{}'.\n\
                 Hint: run with sudo or: sudo setcap cap_net_raw+ep <binary>",
                iface
            )
        })?
        .promisc(promisc)
        .snaplen(snaplen)
        .timeout(1000) // 1s read timeout so Ctrl+C works
        .open()
        .with_context(|| {
            format!(
                "Failed to activate capture on '{}'. Permission denied?\n\
                 Hint: sudo setcap cap_net_raw+ep <binary>",
                iface
            )
        })?;

    cap.filter(bpf_filter, true)
        .with_context(|| format!("Invalid BPF filter: '{}'", bpf_filter))?;

    debug!("Capture active, BPF filter applied: {}", bpf_filter);

    let mut reassembler = TcpReassembler::new();

    loop {
        match cap.next_packet() {
            Ok(packet) => match packet::parse_packet(packet.data) {
                Ok(Some(pkt)) => {
                    if let ProcessResult::Complete(tls_data) =
                        reassembler.process(pkt.flow, &pkt.tcp_payload)
                    {
                        match packet::fingerprint_tls_record(&pkt.flow, &tls_data) {
                            Ok(Some(result)) => {
                                let classification = db
                                    .map(|db| db.classify(&result.ja3.hash, &result.ja4.hash))
                                    .transpose()
                                    .unwrap_or_else(|e| {
                                        debug!("Classification error: {}", e);
                                        None
                                    })
                                    .unwrap_or_else(Classification::empty);
                                output::print_fingerprint(
                                    &result,
                                    &classification,
                                    format,
                                    verbose,
                                );
                            }
                            Ok(None) => {}
                            Err(e) => {
                                debug!("Fingerprint error: {}", e);
                            }
                        }
                    }
                }
                Ok(None) => {}
                Err(e) => {
                    debug!("Packet parse error: {}", e);
                }
            },
            Err(pcap::Error::TimeoutExpired) => {
                reassembler.evict_stale();
                continue;
            }
            Err(e) => {
                error!("Capture error: {}", e);
                bail!("Capture terminated: {}", e);
            }
        }
    }
}
