use crate::fingerprint::types::ClientHelloInfo;
use tls_parser::nom::Err as NomErr;
use tls_parser::{
    parse_tls_extensions, parse_tls_plaintext, TlsExtension, TlsMessage, TlsMessageHandshake,
    TlsRecordType,
};

#[derive(Debug, thiserror::Error)]
pub enum ParseError {
    #[error("not enough data: need at least {0} bytes")]
    NotEnoughData(usize),
    #[error("not a TLS handshake record")]
    NotHandshake,
    #[error("not a ClientHello message")]
    NotClientHello,
    #[error("TLS parse error: {0}")]
    TlsParseError(String),
}

/// Parse raw bytes from a TCP stream into a `ClientHelloInfo`.
///
/// The input should be the raw bytes peeked from a TCP connection,
/// starting with the TLS record header.
pub fn parse_client_hello(raw: &[u8]) -> Result<ClientHelloInfo, ParseError> {
    if raw.len() < 5 {
        return Err(ParseError::NotEnoughData(5));
    }

    // Verify this is a Handshake record (content type 0x16)
    if raw[0] != 0x16 {
        return Err(ParseError::NotHandshake);
    }

    // Parse the TLS plaintext record
    let (_, record) = parse_tls_plaintext(raw).map_err(|e| match e {
        NomErr::Incomplete(needed) => {
            let n = match needed {
                tls_parser::nom::Needed::Size(s) => s.get(),
                tls_parser::nom::Needed::Unknown => 0,
            };
            ParseError::NotEnoughData(raw.len() + n)
        }
        _ => ParseError::TlsParseError(format!("{}", e)),
    })?;

    // Check record type
    if record.hdr.record_type != TlsRecordType::Handshake {
        return Err(ParseError::NotHandshake);
    }

    // Find the ClientHello message
    for msg in &record.msg {
        if let TlsMessage::Handshake(TlsMessageHandshake::ClientHello(ch)) = msg {
            let mut info = ClientHelloInfo {
                tls_version: ch.version.0,
                cipher_suites: ch.ciphers.iter().map(|c| c.0).collect(),
                extensions: Vec::new(),
                elliptic_curves: Vec::new(),
                ec_point_formats: Vec::new(),
                signature_algorithms: Vec::new(),
                server_name: None,
                alpn_protocols: Vec::new(),
                supported_versions: Vec::new(),
            };

            // Parse extensions if present
            if let Some(ext_data) = ch.ext {
                if let Ok((_, extensions)) = parse_tls_extensions(ext_data) {
                    for ext in &extensions {
                        // Record the extension type code
                        info.extensions.push(extension_type_code(ext));

                        // Extract specific extension data
                        match ext {
                            TlsExtension::SNI(sni_list) => {
                                for (_, name_bytes) in sni_list {
                                    if let Ok(name) = std::str::from_utf8(name_bytes) {
                                        info.server_name = Some(name.to_string());
                                    }
                                }
                            }
                            TlsExtension::EllipticCurves(curves) => {
                                info.elliptic_curves =
                                    curves.iter().map(|c| c.0).collect();
                            }
                            TlsExtension::EcPointFormats(formats) => {
                                info.ec_point_formats = formats.to_vec();
                            }
                            TlsExtension::SignatureAlgorithms(algs) => {
                                info.signature_algorithms = algs.to_vec();
                            }
                            TlsExtension::ALPN(protocols) => {
                                info.alpn_protocols = protocols
                                    .iter()
                                    .filter_map(|p| std::str::from_utf8(p).ok())
                                    .map(|s| s.to_string())
                                    .collect();
                            }
                            TlsExtension::SupportedVersions(versions) => {
                                info.supported_versions =
                                    versions.iter().map(|v| v.0).collect();
                            }
                            _ => {}
                        }
                    }
                }
            }

            return Ok(info);
        }
    }

    Err(ParseError::NotClientHello)
}

/// Get the extension type code (u16) for a TlsExtension variant.
fn extension_type_code(ext: &TlsExtension) -> u16 {
    match ext {
        TlsExtension::SNI(_) => 0x0000,
        TlsExtension::MaxFragmentLength(_) => 0x0001,
        TlsExtension::StatusRequest(_) => 0x0005,
        TlsExtension::EllipticCurves(_) => 0x000a,
        TlsExtension::EcPointFormats(_) => 0x000b,
        TlsExtension::SignatureAlgorithms(_) => 0x000d,
        TlsExtension::SessionTicket(_) => 0x0023,
        TlsExtension::KeyShare(_) => 0x0033,
        TlsExtension::PreSharedKey(_) => 0x0029,
        TlsExtension::EarlyData(_) => 0x002a,
        TlsExtension::SupportedVersions(_) => 0x002b,
        TlsExtension::Cookie(_) => 0x002c,
        TlsExtension::PskExchangeModes(_) => 0x002d,
        TlsExtension::PostHandshakeAuth => 0x0031,
        TlsExtension::Heartbeat(_) => 0x000f,
        TlsExtension::ALPN(_) => 0x0010,
        TlsExtension::EncryptThenMac => 0x0016,
        TlsExtension::ExtendedMasterSecret => 0x0017,
        TlsExtension::NextProtocolNegotiation => 0xff01,
        TlsExtension::RenegotiationInfo(_) => 0xff01,
        TlsExtension::Padding(_) => 0x0015,
        TlsExtension::RecordSizeLimit(_) => 0x001c,
        // For unknown or other extensions, extract the type from the raw data
        TlsExtension::Unknown(code, _) => (*code).into(),
        _ => 0xffff,
    }
}
