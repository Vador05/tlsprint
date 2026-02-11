use md5::{Digest, Md5};

use crate::fingerprint::grease::filter_grease_u16;
use crate::fingerprint::types::{ClientHelloInfo, Ja3Result};

/// Compute the JA3 fingerprint from a parsed ClientHello.
///
/// JA3 format: MD5(SSLVersion,Ciphers,Extensions,EllipticCurves,EcPointFormats)
///
/// - Fields separated by commas
/// - Values within each field separated by dashes
/// - GREASE values filtered from all fields
/// - All values in decimal
pub fn compute_ja3(info: &ClientHelloInfo) -> Ja3Result {
    let version = info.tls_version.to_string();

    let ciphers = filter_grease_u16(&info.cipher_suites)
        .iter()
        .map(|c| c.to_string())
        .collect::<Vec<_>>()
        .join("-");

    let extensions = filter_grease_u16(&info.extensions)
        .iter()
        .map(|e| e.to_string())
        .collect::<Vec<_>>()
        .join("-");

    let curves = filter_grease_u16(&info.elliptic_curves)
        .iter()
        .map(|c| c.to_string())
        .collect::<Vec<_>>()
        .join("-");

    let point_formats = info
        .ec_point_formats
        .iter()
        .map(|f| f.to_string())
        .collect::<Vec<_>>()
        .join("-");

    let raw_string = format!("{},{},{},{},{}", version, ciphers, extensions, curves, point_formats);

    let mut hasher = Md5::new();
    hasher.update(raw_string.as_bytes());
    let hash = format!("{:x}", hasher.finalize());

    Ja3Result { hash, raw_string }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fingerprint::types::ClientHelloInfo;

    #[test]
    fn test_ja3_basic() {
        // Construct a minimal ClientHelloInfo
        let info = ClientHelloInfo {
            tls_version: 0x0303, // TLS 1.2 = 771 decimal
            cipher_suites: vec![0x1301, 0x1302, 0x1303, 0xC02B, 0xC02F],
            extensions: vec![0x0000, 0x0017, 0x000a, 0x000b, 0x000d],
            elliptic_curves: vec![0x001d, 0x0017, 0x0018],
            ec_point_formats: vec![0x00],
            signature_algorithms: vec![],
            server_name: Some("example.com".to_string()),
            alpn_protocols: vec!["h2".to_string(), "http/1.1".to_string()],
            supported_versions: vec![],
        };

        let result = compute_ja3(&info);

        // Verify the raw string format
        assert_eq!(
            result.raw_string,
            "771,4865-4866-4867-49195-49199,0-23-10-11-13,29-23-24,0"
        );
        // Hash should be a 32-char hex string
        assert_eq!(result.hash.len(), 32);
        assert!(result.hash.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_ja3_grease_filtered() {
        let info = ClientHelloInfo {
            tls_version: 0x0303,
            cipher_suites: vec![0x0A0A, 0x1301, 0xFAFA, 0x1302],
            extensions: vec![0x2A2A, 0x0000, 0x000a],
            elliptic_curves: vec![0x4A4A, 0x001d],
            ec_point_formats: vec![0x00],
            signature_algorithms: vec![],
            server_name: None,
            alpn_protocols: vec![],
            supported_versions: vec![],
        };

        let result = compute_ja3(&info);

        // GREASE values should be filtered out
        assert_eq!(result.raw_string, "771,4865-4866,0-10,29,0");
    }

    #[test]
    fn test_ja3_empty_fields() {
        let info = ClientHelloInfo {
            tls_version: 0x0303,
            cipher_suites: vec![],
            extensions: vec![],
            elliptic_curves: vec![],
            ec_point_formats: vec![],
            signature_algorithms: vec![],
            server_name: None,
            alpn_protocols: vec![],
            supported_versions: vec![],
        };

        let result = compute_ja3(&info);
        assert_eq!(result.raw_string, "771,,,,");
    }
}
