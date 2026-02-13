use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::time::{Duration, Instant};

use tracing::{debug, warn};

/// Identifies a unidirectional TCP flow.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FlowKey {
    pub src_ip: IpAddr,
    pub src_port: u16,
    pub dst_ip: IpAddr,
    pub dst_port: u16,
}

impl std::fmt::Display for FlowKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}:{} -> {}:{}",
            self.src_ip, self.src_port, self.dst_ip, self.dst_port
        )
    }
}

/// A partially-reassembled TLS record.
struct FlowBuffer {
    /// Accumulated TCP payload bytes.
    data: Vec<u8>,
    /// Total bytes needed: 5 (TLS record header) + record_length.
    expected_len: usize,
    /// When the first segment was seen.
    first_seen: Instant,
}

/// Outcome of processing a packet through the reassembler.
pub enum ProcessResult {
    /// A complete TLS record is ready for fingerprinting.
    Complete(Vec<u8>),
    /// Segment was buffered; record is not yet complete.
    Buffering,
    /// Segment was skipped (not relevant for reassembly).
    Skipped,
}

const DEFAULT_TIMEOUT: Duration = Duration::from_secs(5);
const DEFAULT_MAX_BUFFER: usize = 32 * 1024;
const DEFAULT_MAX_FLOWS: usize = 4096;
const MAX_COMPLETED: usize = 65536;

/// Accumulates TCP segments per-flow until a complete TLS ClientHello record
/// is available for parsing.
pub struct TcpReassembler {
    flows: HashMap<FlowKey, FlowBuffer>,
    completed: HashSet<FlowKey>,
    timeout: Duration,
    max_buffer_size: usize,
    max_flows: usize,
}

impl TcpReassembler {
    pub fn new() -> Self {
        Self {
            flows: HashMap::new(),
            completed: HashSet::new(),
            timeout: DEFAULT_TIMEOUT,
            max_buffer_size: DEFAULT_MAX_BUFFER,
            max_flows: DEFAULT_MAX_FLOWS,
        }
    }

    /// Process a TCP segment for a given flow.
    ///
    /// Returns `ProcessResult::Complete(data)` when a full TLS ClientHello
    /// record has been reassembled and is ready for fingerprinting.
    pub fn process(&mut self, flow: FlowKey, tcp_payload: &[u8]) -> ProcessResult {
        // Already fingerprinted this flow — skip all further packets.
        if self.completed.contains(&flow) {
            return ProcessResult::Skipped;
        }

        // Already buffering this flow — append data.
        if self.flows.contains_key(&flow) {
            return self.append_to_buffer(flow, tcp_payload);
        }

        // New segment: determine if it starts a TLS ClientHello record.
        if tcp_payload.is_empty() {
            return ProcessResult::Skipped;
        }

        // Not TLS handshake content type (0x16)
        if tcp_payload[0] != 0x16 {
            return ProcessResult::Skipped;
        }

        // Need at least 6 bytes: 5-byte TLS record header + 1 byte handshake type
        if tcp_payload.len() < 6 {
            return ProcessResult::Skipped;
        }

        // Only buffer ClientHello (handshake type 0x01).
        // Skip ServerHello (0x02), Certificate (0x0B), etc.
        if tcp_payload[5] != 0x01 {
            return ProcessResult::Skipped;
        }

        let record_len = u16::from_be_bytes([tcp_payload[3], tcp_payload[4]]) as usize;
        let total_needed = 5 + record_len;

        // Fast path: entire record fits in this single segment.
        if tcp_payload.len() >= total_needed {
            self.mark_completed(flow);
            return ProcessResult::Complete(tcp_payload[..total_needed].to_vec());
        }

        // Reject records that exceed our buffer limit.
        if total_needed > self.max_buffer_size {
            warn!(
                "TLS record too large to buffer: {} bytes (max {}). Skipping {}",
                total_needed, self.max_buffer_size, flow
            );
            return ProcessResult::Skipped;
        }

        // Evict oldest flow if we're at capacity.
        if self.flows.len() >= self.max_flows {
            debug!("Max concurrent flows ({}) reached, evicting oldest", self.max_flows);
            self.evict_oldest();
        }

        let mut data = Vec::with_capacity(total_needed);
        data.extend_from_slice(tcp_payload);

        self.flows.insert(
            flow,
            FlowBuffer {
                data,
                expected_len: total_needed,
                first_seen: Instant::now(),
            },
        );

        debug!(
            "Buffering ClientHello: {}/{} bytes ({})",
            tcp_payload.len(),
            total_needed,
            flow
        );

        ProcessResult::Buffering
    }

    /// Append data to an existing flow buffer.
    fn append_to_buffer(&mut self, flow: FlowKey, tcp_payload: &[u8]) -> ProcessResult {
        let buf = self.flows.get_mut(&flow).unwrap();

        let remaining = buf.expected_len - buf.data.len();
        let to_copy = tcp_payload.len().min(remaining);
        buf.data.extend_from_slice(&tcp_payload[..to_copy]);

        if buf.data.len() >= buf.expected_len {
            let buf = self.flows.remove(&flow).unwrap();
            self.mark_completed(flow);
            debug!("Reassembled ClientHello: {} bytes ({})", buf.data.len(), flow);
            ProcessResult::Complete(buf.data)
        } else {
            ProcessResult::Buffering
        }
    }

    fn mark_completed(&mut self, flow: FlowKey) {
        if self.completed.len() >= MAX_COMPLETED {
            debug!("Completed set full, clearing {} entries", self.completed.len());
            self.completed.clear();
        }
        self.completed.insert(flow);
    }

    fn evict_oldest(&mut self) {
        if let Some((&oldest_key, _)) = self.flows.iter().min_by_key(|(_, buf)| buf.first_seen) {
            debug!("Evicting stale flow buffer: {}", oldest_key);
            self.flows.remove(&oldest_key);
        }
    }

    /// Evict all flow buffers that have exceeded the timeout.
    /// Returns the number of evicted flows.
    pub fn evict_stale(&mut self) -> usize {
        let now = Instant::now();
        let before = self.flows.len();

        self.flows.retain(|flow, buf| {
            let stale = now.duration_since(buf.first_seen) > self.timeout;
            if stale {
                debug!(
                    "Evicting timed-out flow: {} (buffered {}/{} bytes, age {:?})",
                    flow,
                    buf.data.len(),
                    buf.expected_len,
                    now.duration_since(buf.first_seen)
                );
            }
            !stale
        });

        before - self.flows.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn test_flow() -> FlowKey {
        FlowKey {
            src_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)),
            src_port: 54321,
            dst_ip: IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
            dst_port: 443,
        }
    }

    /// Build a fake TLS ClientHello record header + padding.
    /// Returns bytes: [0x16, 0x03, 0x01, len_hi, len_lo, 0x01, ...padding...]
    fn make_client_hello_record(total_payload_len: usize) -> Vec<u8> {
        let record_len = total_payload_len - 5; // subtract TLS record header
        let mut data = vec![
            0x16,                           // content type: handshake
            0x03, 0x01,                     // TLS version
            (record_len >> 8) as u8,        // length high byte
            (record_len & 0xFF) as u8,      // length low byte
            0x01,                           // handshake type: ClientHello
        ];
        data.resize(total_payload_len, 0xAA); // pad with dummy data
        data
    }

    #[test]
    fn single_segment_completes_immediately() {
        let mut r = TcpReassembler::new();
        let flow = test_flow();
        let record = make_client_hello_record(200);

        match r.process(flow, &record) {
            ProcessResult::Complete(data) => assert_eq!(data.len(), 200),
            _ => panic!("Expected Complete"),
        }
    }

    #[test]
    fn two_segments_reassemble() {
        let mut r = TcpReassembler::new();
        let flow = test_flow();
        let record = make_client_hello_record(3000);

        // First segment: first 1448 bytes
        match r.process(flow, &record[..1448]) {
            ProcessResult::Buffering => {}
            _ => panic!("Expected Buffering"),
        }

        // Second segment: remaining bytes
        match r.process(flow, &record[1448..]) {
            ProcessResult::Complete(data) => assert_eq!(data.len(), 3000),
            _ => panic!("Expected Complete"),
        }
    }

    #[test]
    fn completed_flow_is_skipped() {
        let mut r = TcpReassembler::new();
        let flow = test_flow();
        let record = make_client_hello_record(200);

        // Complete the flow
        r.process(flow, &record);

        // Further packets on same flow are skipped
        match r.process(flow, &[0x16, 0x03, 0x03, 0x00, 0x05, 0x02]) {
            ProcessResult::Skipped => {}
            _ => panic!("Expected Skipped"),
        }
    }

    #[test]
    fn non_client_hello_is_skipped() {
        let mut r = TcpReassembler::new();
        let flow = test_flow();
        // ServerHello: handshake type 0x02
        let payload = vec![0x16, 0x03, 0x03, 0x00, 0x50, 0x02, 0x00];

        match r.process(flow, &payload) {
            ProcessResult::Skipped => {}
            _ => panic!("Expected Skipped for ServerHello"),
        }
    }

    #[test]
    fn non_tls_is_skipped() {
        let mut r = TcpReassembler::new();
        let flow = test_flow();

        match r.process(flow, &[0x17, 0x03, 0x03, 0x00, 0x20, 0x01]) {
            ProcessResult::Skipped => {}
            _ => panic!("Expected Skipped for non-handshake content type"),
        }
    }

    #[test]
    fn empty_payload_is_skipped() {
        let mut r = TcpReassembler::new();
        let flow = test_flow();

        match r.process(flow, &[]) {
            ProcessResult::Skipped => {}
            _ => panic!("Expected Skipped for empty payload"),
        }
    }

    #[test]
    fn oversized_record_is_skipped() {
        let mut r = TcpReassembler::new();
        let flow = test_flow();
        // Claim a record length of 40000 bytes (> 32KB max)
        let payload = vec![0x16, 0x03, 0x01, 0x9C, 0x40, 0x01, 0x00];

        match r.process(flow, &payload) {
            ProcessResult::Skipped => {}
            _ => panic!("Expected Skipped for oversized record"),
        }
    }

    #[test]
    fn stale_flows_are_evicted() {
        let mut r = TcpReassembler::new();
        r.timeout = Duration::from_millis(1);

        let flow = test_flow();
        let record = make_client_hello_record(3000);

        // Start buffering
        r.process(flow, &record[..1448]);
        assert_eq!(r.flows.len(), 1);

        // Wait for timeout
        std::thread::sleep(Duration::from_millis(10));

        let evicted = r.evict_stale();
        assert_eq!(evicted, 1);
        assert_eq!(r.flows.len(), 0);
    }
}
