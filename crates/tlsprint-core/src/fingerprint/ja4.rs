use sha2::{Digest, Sha256};

use crate::fingerprint::grease::{filter_grease_u16, is_grease_u16};
use crate::fingerprint::types::{ClientHelloInfo, Ja4Result};

/// Compute the JA4 fingerprint from a parsed ClientHello.
///
/// JA4 format: `{part_a}_{part_b}_{part_c}`
///
/// Part A: `{proto}{ver}{sni}{cipher_count:02}{ext_count:02}{alpn}`
/// Part B: sorted cipher suites as 4-char hex → SHA256 truncated to 12 chars
/// Part C: sorted extensions (excl. SNI+ALPN) + sig_algs → SHA256 truncated to 12 chars
pub fn compute_ja4(info: &ClientHelloInfo, is_quic: bool) -> Ja4Result {
    let part_a = compute_part_a(info, is_quic);
    let (part_b, part_b_raw) = compute_part_b(info);
    let (part_c, part_c_raw) = compute_part_c(info);

    Ja4Result {
        hash: format!("{}_{}", part_a, format!("{}_{}", part_b, part_c)),
        raw: format!("{}_{}", part_a, format!("{}_{}", part_b_raw, part_c_raw)),
    }
}

/// Part A: protocol + version + SNI + cipher count + extension count + ALPN indicator
fn compute_part_a(info: &ClientHelloInfo, is_quic: bool) -> String {
    let proto = if is_quic { 'q' } else { 't' };
    let version = resolve_tls_version(info);
    let sni = if info.server_name.is_some() { 'd' } else { 'i' };

    let cipher_count = filter_grease_u16(&info.cipher_suites).len().min(99);
    let ext_count = filter_grease_u16(&info.extensions).len().min(99);

    let alpn = compute_alpn_indicator(&info.alpn_protocols);

    format!(
        "{}{}{}{:02}{:02}{}",
        proto, version, sni, cipher_count, ext_count, alpn
    )
}

/// Part B: sorted cipher suites → SHA256 truncated to 12 chars
///
/// Returns (hash, raw_string)
fn compute_part_b(info: &ClientHelloInfo) -> (String, String) {
    let mut ciphers: Vec<u16> = info
        .cipher_suites
        .iter()
        .copied()
        .filter(|c| !is_grease_u16(*c))
        .collect();
    ciphers.sort();

    if ciphers.is_empty() {
        return ("000000000000".to_string(), String::new());
    }

    let raw = ciphers
        .iter()
        .map(|c| format!("{:04x}", c))
        .collect::<Vec<_>>()
        .join(",");

    (truncated_sha256(&raw, 12), raw)
}

/// Part C: sorted extensions (excluding SNI 0x0000 and ALPN 0x0010) + signature algorithms
///
/// Returns (hash, raw_string)
fn compute_part_c(info: &ClientHelloInfo) -> (String, String) {
    let mut exts: Vec<u16> = info
        .extensions
        .iter()
        .copied()
        .filter(|e| !is_grease_u16(*e) && *e != 0x0000 && *e != 0x0010)
        .collect();
    exts.sort();

    if exts.is_empty() && info.signature_algorithms.is_empty() {
        return ("000000000000".to_string(), String::new());
    }

    let ext_str = exts
        .iter()
        .map(|e| format!("{:04x}", e))
        .collect::<Vec<_>>()
        .join(",");

    // Signature algorithms in original wire order (not sorted)
    let sig_str = info
        .signature_algorithms
        .iter()
        .map(|s| format!("{:04x}", s))
        .collect::<Vec<_>>()
        .join(",");

    let combined = if sig_str.is_empty() {
        ext_str.clone()
    } else {
        format!("{}_{}", ext_str, sig_str)
    };

    let raw = if sig_str.is_empty() {
        ext_str
    } else {
        format!("{}_{}", ext_str, sig_str)
    };

    (truncated_sha256(&combined, 12), raw)
}

/// Resolve TLS version for JA4.
///
/// If the `supported_versions` extension is present, use the highest non-GREASE value.
/// Otherwise, use the record-layer version.
fn resolve_tls_version(info: &ClientHelloInfo) -> &'static str {
    let version = if !info.supported_versions.is_empty() {
        filter_grease_u16(&info.supported_versions)
            .into_iter()
            .max()
            .unwrap_or(info.tls_version)
    } else {
        info.tls_version
    };

    match version {
        0x0304 => "13",
        0x0303 => "12",
        0x0302 => "11",
        0x0301 => "10",
        0x0300 => "s3",
        0x0200 => "s2",
        _ => "00",
    }
}

/// Compute first and last alphanumeric chars of the first ALPN value, or "00".
fn compute_alpn_indicator(alpn: &[String]) -> String {
    match alpn.first() {
        None => "00".to_string(),
        Some(val) => {
            let chars: Vec<char> = val.chars().filter(|c| c.is_ascii_alphanumeric()).collect();
            if chars.is_empty() {
                "00".to_string()
            } else {
                format!("{}{}", chars[0], chars[chars.len() - 1])
            }
        }
    }
}

/// SHA256 hash, lowercase hex, truncated to `len` characters.
fn truncated_sha256(input: &str, len: usize) -> String {
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    let full = hex::encode(hasher.finalize());
    full[..len].to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fingerprint::types::ClientHelloInfo;

    fn sample_info() -> ClientHelloInfo {
        ClientHelloInfo {
            tls_version: 0x0303,
            cipher_suites: vec![0x1301, 0x1302, 0x1303, 0xC02B, 0xC02F],
            extensions: vec![
                0x0000, // SNI
                0x0017, // extended_master_secret
                0x000a, // supported_groups
                0x000b, // ec_point_formats
                0x000d, // signature_algorithms
                0x0010, // ALPN
                0x002b, // supported_versions
                0x002d, // psk_key_exchange_modes
                0x0033, // key_share
            ],
            elliptic_curves: vec![0x001d, 0x0017, 0x0018],
            ec_point_formats: vec![0x00],
            signature_algorithms: vec![0x0403, 0x0503, 0x0603],
            server_name: Some("example.com".to_string()),
            alpn_protocols: vec!["h2".to_string(), "http/1.1".to_string()],
            supported_versions: vec![0x0304, 0x0303],
        }
    }

    #[test]
    fn test_ja4_part_a() {
        let info = sample_info();
        let part_a = compute_part_a(&info, false);

        // t=TCP, 13=TLS1.3 (from supported_versions), d=has SNI
        // 05 ciphers, 09 extensions, h2 → "h2"
        assert_eq!(part_a, "t13d0509h2");
    }

    #[test]
    fn test_ja4_part_a_no_sni() {
        let mut info = sample_info();
        info.server_name = None;
        let part_a = compute_part_a(&info, false);
        assert!(part_a.contains('i'));
    }

    #[test]
    fn test_ja4_part_a_no_alpn() {
        let mut info = sample_info();
        info.alpn_protocols = vec![];
        let part_a = compute_part_a(&info, false);
        assert!(part_a.ends_with("00"));
    }

    #[test]
    fn test_ja4_part_a_quic() {
        let info = sample_info();
        let part_a = compute_part_a(&info, true);
        assert!(part_a.starts_with('q'));
    }

    #[test]
    fn test_ja4_part_b_sorted() {
        let info = sample_info();
        let (hash, raw) = compute_part_b(&info);

        // Ciphers should be sorted
        assert!(raw.starts_with("1301,")); // 0x1301 < 0x1302 < ...
        assert_eq!(hash.len(), 12);
        assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_ja4_part_c_excludes_sni_alpn() {
        let info = sample_info();
        let (_hash, raw) = compute_part_c(&info);

        // SNI (0x0000) and ALPN (0x0010) should be excluded
        assert!(!raw.contains("0000,"));
        assert!(!raw.contains("0010"));
        // But other extensions should be present
        assert!(raw.contains("000a")); // supported_groups
        assert!(raw.contains("000d")); // signature_algorithms extension
    }

    #[test]
    fn test_ja4_full() {
        let info = sample_info();
        let result = compute_ja4(&info, false);

        // Format: part_a_part_b_part_c
        let parts: Vec<&str> = result.hash.split('_').collect();
        assert_eq!(parts.len(), 3);
        assert_eq!(parts[0], "t13d0509h2");
        assert_eq!(parts[1].len(), 12);
        assert_eq!(parts[2].len(), 12);
    }

    #[test]
    fn test_alpn_indicator() {
        assert_eq!(compute_alpn_indicator(&[]), "00");
        assert_eq!(
            compute_alpn_indicator(&["h2".to_string()]),
            "h2"
        );
        assert_eq!(
            compute_alpn_indicator(&["http/1.1".to_string()]),
            "h1"
        );
    }

    #[test]
    fn test_resolve_tls_version() {
        let mut info = sample_info();

        // With supported_versions containing 0x0304 (TLS 1.3)
        assert_eq!(resolve_tls_version(&info), "13");

        // Without supported_versions, fall back to record version
        info.supported_versions = vec![];
        assert_eq!(resolve_tls_version(&info), "12"); // 0x0303
    }
}
