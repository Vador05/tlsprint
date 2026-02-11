/// Parsed ClientHello information needed for JA3/JA4 fingerprinting.
#[derive(Debug, Clone)]
pub struct ClientHelloInfo {
    /// TLS version from the record layer (e.g., 0x0303 for TLS 1.2)
    pub tls_version: u16,
    /// Cipher suite values in wire order
    pub cipher_suites: Vec<u16>,
    /// Extension type codes in wire order
    pub extensions: Vec<u16>,
    /// Supported groups / named curves (from extension 0x000a)
    pub elliptic_curves: Vec<u16>,
    /// EC point format values (from extension 0x000b)
    pub ec_point_formats: Vec<u8>,
    /// Signature algorithms (from extension 0x000d)
    pub signature_algorithms: Vec<u16>,
    /// Server Name Indication
    pub server_name: Option<String>,
    /// ALPN protocol values
    pub alpn_protocols: Vec<String>,
    /// Supported TLS versions (from extension 0x002b)
    pub supported_versions: Vec<u16>,
}

/// Result of a JA3 fingerprint computation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ja3Result {
    /// 32-character MD5 hex hash
    pub hash: String,
    /// The raw string before hashing
    pub raw_string: String,
}

/// Result of a JA4 fingerprint computation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ja4Result {
    /// Full JA4 fingerprint: part_a + "_" + part_b + "_" + part_c
    pub hash: String,
    /// JA4_r: raw sorted values instead of hashes
    pub raw: String,
}
