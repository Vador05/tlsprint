/// Check if a u16 value is a GREASE value (RFC 8701).
///
/// GREASE values follow the pattern 0x?A?A where both nibble pairs are identical:
/// 0x0A0A, 0x1A1A, 0x2A2A, ..., 0xFAFA
pub fn is_grease_u16(val: u16) -> bool {
    let hi = (val >> 8) as u8;
    let lo = val as u8;
    hi == lo && (hi & 0x0F) == 0x0A
}

/// Filter GREASE values from a slice of u16 values.
pub fn filter_grease_u16(values: &[u16]) -> Vec<u16> {
    values.iter().copied().filter(|v| !is_grease_u16(*v)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_grease_values() {
        // All 16 GREASE values
        let grease_values: Vec<u16> = vec![
            0x0A0A, 0x1A1A, 0x2A2A, 0x3A3A, 0x4A4A, 0x5A5A, 0x6A6A, 0x7A7A,
            0x8A8A, 0x9A9A, 0xAAAA, 0xBABA, 0xCACA, 0xDADA, 0xEAEA, 0xFAFA,
        ];
        for v in &grease_values {
            assert!(is_grease_u16(*v), "0x{:04X} should be GREASE", v);
        }
    }

    #[test]
    fn test_non_grease_values() {
        assert!(!is_grease_u16(0x0301)); // TLS 1.0
        assert!(!is_grease_u16(0x0303)); // TLS 1.2
        assert!(!is_grease_u16(0xC02B)); // TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
        assert!(!is_grease_u16(0x1301)); // TLS_AES_128_GCM_SHA256
        assert!(!is_grease_u16(0x00FF)); // TLS_EMPTY_RENEGOTIATION_INFO_SCSV
    }

    #[test]
    fn test_filter_grease() {
        let input = vec![0x0A0A, 0x1301, 0x1302, 0xFAFA, 0xC02B];
        let filtered = filter_grease_u16(&input);
        assert_eq!(filtered, vec![0x1301, 0x1302, 0xC02B]);
    }
}
