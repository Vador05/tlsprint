use serde::Serialize;

use tlsprint_core::db::types::Classification;

use crate::packet::FingerprintResult;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputFormat {
    Text,
    Json,
}

impl OutputFormat {
    pub fn parse(s: &str) -> anyhow::Result<Self> {
        match s {
            "text" => Ok(Self::Text),
            "json" => Ok(Self::Json),
            _ => anyhow::bail!("Invalid output format '{}'. Expected 'text' or 'json'.", s),
        }
    }
}

#[derive(Serialize)]
struct JsonRecord<'a> {
    timestamp: String,
    src_ip: String,
    src_port: u16,
    dst_ip: String,
    dst_port: u16,
    sni: Option<&'a str>,
    tls_version: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    supported_versions: Vec<String>,
    cipher_suites: usize,
    extensions: usize,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    alpn: &'a Vec<String>,
    ja3_hash: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    ja3_raw: Option<&'a str>,
    ja4_hash: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    ja4_raw: Option<&'a str>,
    #[serde(skip_serializing_if = "Classification::is_empty")]
    classification: &'a Classification,
}

pub fn print_fingerprint(
    result: &FingerprintResult,
    classification: &Classification,
    format: OutputFormat,
    verbose: bool,
) {
    match format {
        OutputFormat::Text => print_text(result, classification, verbose),
        OutputFormat::Json => print_json(result, classification, verbose),
    }
}

fn print_text(result: &FingerprintResult, classification: &Classification, verbose: bool) {
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("  Source:     {}:{}", result.src_ip, result.src_port);
    println!("  Dest:       {}:{}", result.dst_ip, result.dst_port);
    println!(
        "  SNI:        {}",
        result.info.server_name.as_deref().unwrap_or("(none)")
    );
    println!("  TLS ver:    0x{:04x}", result.info.tls_version);
    if !result.info.supported_versions.is_empty() {
        let vers: Vec<String> = result
            .info
            .supported_versions
            .iter()
            .map(|v| format!("0x{:04x}", v))
            .collect();
        println!("  Sup. vers:  {}", vers.join(", "));
    }
    println!("  Ciphers:    {} suites", result.info.cipher_suites.len());
    println!("  Extensions: {} types", result.info.extensions.len());
    if !result.info.alpn_protocols.is_empty() {
        println!("  ALPN:       {}", result.info.alpn_protocols.join(", "));
    }
    println!("  ──────────────────────────────────────────────────");
    println!("  JA3:        {}", result.ja3.hash);
    if verbose {
        println!("  JA3 raw:    {}", result.ja3.raw_string);
    }
    println!("  JA4:        {}", result.ja4.hash);
    if verbose {
        println!("  JA4 raw:    {}", result.ja4.raw);
    }
    if let Some(best) = &classification.best_match {
        println!("  ──────────────────────────────────────────────────");
        println!("  Match:      {}", best);
    }
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
}

fn print_json(result: &FingerprintResult, classification: &Classification, verbose: bool) {
    let record = JsonRecord {
        timestamp: chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
        src_ip: result.src_ip.to_string(),
        src_port: result.src_port,
        dst_ip: result.dst_ip.to_string(),
        dst_port: result.dst_port,
        sni: result.info.server_name.as_deref(),
        tls_version: format!("0x{:04x}", result.info.tls_version),
        supported_versions: result
            .info
            .supported_versions
            .iter()
            .map(|v| format!("0x{:04x}", v))
            .collect(),
        cipher_suites: result.info.cipher_suites.len(),
        extensions: result.info.extensions.len(),
        alpn: &result.info.alpn_protocols,
        ja3_hash: &result.ja3.hash,
        ja3_raw: if verbose {
            Some(&result.ja3.raw_string)
        } else {
            None
        },
        ja4_hash: &result.ja4.hash,
        ja4_raw: if verbose { Some(&result.ja4.raw) } else { None },
        classification,
    };

    println!("{}", serde_json::to_string(&record).unwrap());
}
