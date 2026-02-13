use std::net::IpAddr;

use anyhow::{bail, Result};
use etherparse::{NetSlice, SlicedPacket, TransportSlice};
use tracing::warn;

use tlsprint_core::fingerprint::clienthello::{parse_client_hello, ParseError};
use tlsprint_core::fingerprint::ja3::compute_ja3;
use tlsprint_core::fingerprint::ja4::compute_ja4;
use tlsprint_core::fingerprint::types::{ClientHelloInfo, Ja3Result, Ja4Result};

use crate::reassembly::FlowKey;

/// Extracted packet-level information before TLS parsing.
pub struct PacketInfo {
    pub flow: FlowKey,
    pub tcp_payload: Vec<u8>,
}

/// All extracted information from a successfully fingerprinted ClientHello.
pub struct FingerprintResult {
    pub src_ip: IpAddr,
    pub src_port: u16,
    pub dst_ip: IpAddr,
    pub dst_port: u16,
    pub info: ClientHelloInfo,
    pub ja3: Ja3Result,
    pub ja4: Ja4Result,
}

/// Parse a raw captured packet (from Ethernet header) and extract the flow
/// key and TCP payload. No TLS-level inspection.
///
/// Returns:
/// - `Ok(Some(info))` if the packet contains a TCP segment with payload
/// - `Ok(None)` if the packet has no TCP payload (SYN, ACK, FIN, etc.)
/// - `Err` if packet parsing fails (not TCP, no IP header, etc.)
pub fn parse_packet(raw: &[u8]) -> Result<Option<PacketInfo>> {
    let sliced = SlicedPacket::from_ethernet(raw)?;

    let (src_ip, dst_ip) = match &sliced.net {
        Some(NetSlice::Ipv4(ipv4)) => {
            let hdr = ipv4.header();
            (
                IpAddr::V4(hdr.source_addr()),
                IpAddr::V4(hdr.destination_addr()),
            )
        }
        Some(NetSlice::Ipv6(ipv6)) => {
            let hdr = ipv6.header();
            (
                IpAddr::V6(hdr.source_addr()),
                IpAddr::V6(hdr.destination_addr()),
            )
        }
        _ => bail!("No IP header found"),
    };

    let (src_port, dst_port, tcp_payload) = match &sliced.transport {
        Some(TransportSlice::Tcp(tcp)) => (tcp.source_port(), tcp.destination_port(), tcp.payload()),
        _ => bail!("Not a TCP packet"),
    };

    if tcp_payload.is_empty() {
        return Ok(None);
    }

    Ok(Some(PacketInfo {
        flow: FlowKey {
            src_ip,
            src_port,
            dst_ip,
            dst_port,
        },
        tcp_payload: tcp_payload.to_vec(),
    }))
}

/// Given a complete TLS record (from reassembly or single segment),
/// attempt to parse the ClientHello and compute fingerprints.
pub fn fingerprint_tls_record(
    flow: &FlowKey,
    tls_data: &[u8],
) -> Result<Option<FingerprintResult>> {
    match parse_client_hello(tls_data) {
        Ok(info) => {
            let ja3 = compute_ja3(&info);
            let ja4 = compute_ja4(&info, false);

            Ok(Some(FingerprintResult {
                src_ip: flow.src_ip,
                src_port: flow.src_port,
                dst_ip: flow.dst_ip,
                dst_port: flow.dst_port,
                info,
                ja3,
                ja4,
            }))
        }
        Err(ParseError::NotClientHello | ParseError::NotHandshake) => Ok(None),
        Err(e) => {
            warn!("ClientHello parse error: {} ({})", e, flow);
            Ok(None)
        }
    }
}
