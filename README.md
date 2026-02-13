# TLSprint

A TLS fingerprint detection and classification platform. Extracts JA3/JA4 fingerprints from TLS ClientHello messages for client identification, security monitoring, and threat detection.

## Features

- **Passive sniffing** — capture ClientHellos from live network traffic without disrupting connections (libpcap)
- **Active proxy** — TCP listener that fingerprints incoming TLS connections
- **JA3 + JA4 fingerprinting** — dual-hash computation with GREASE filtering (RFC 8701)
- **TCP reassembly** — handles ClientHellos spanning multiple TCP segments
- **Fingerprint classification** — SQLite database with 62K+ known fingerprints from ja4db.com and ja3prints
- **JSON output** — NDJSON streaming for log pipelines, SIEMs, and scripting

## Quick Start

### Prerequisites

```bash
sudo apt install libpcap-dev    # Debian/Ubuntu
cargo build                     # Build all binaries
```

### Passive Sniffer

```bash
# List network interfaces
sudo ./target/debug/tlsprint-sniff

# Capture on an interface
sudo ./target/debug/tlsprint-sniff -i eth0

# JSON output
sudo ./target/debug/tlsprint-sniff -i eth0 -o json

# Verbose (include raw fingerprint strings)
sudo ./target/debug/tlsprint-sniff -i eth0 -v

# Skip without sudo (grant capability once)
sudo setcap cap_net_raw+ep target/debug/tlsprint-sniff
./target/debug/tlsprint-sniff -i eth0
```

#### Sniffer Options

| Flag | Description | Default |
|------|-------------|---------|
| `-i <interface>` | Network interface (omit to list all) | -- |
| `-f <filter>` | BPF filter expression | `tcp port 443` |
| `-o <format>` | Output format: `text` or `json` | `text` |
| `-v` | Verbose (show raw JA3/JA4 strings) | off |
| `-p` | Promiscuous mode | off |
| `-s <snaplen>` | Max bytes per packet | 1600 |
| `--db <path>` | Fingerprint database path | `~/.local/share/tlsprint/fingerprints.db` |
| `--no-classify` | Disable fingerprint classification | off |

#### Example Output

```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Source:     192.168.1.100:54321
  Dest:       93.184.216.34:443
  SNI:        example.com
  TLS ver:    0x0303
  Sup. vers:  0x0304, 0x0303
  Ciphers:    17 suites
  Extensions: 15 types
  ALPN:       h2, http/1.1
  ──────────────────────────────────────────────────
  JA3:        e7d705a3286e19ea42f587b344ee6865
  JA4:        t13d1715h2_8daaf6152771_e5627efa2ab1
  ──────────────────────────────────────────────────
  Match:      Chrome 120 (BoringSSL) [ja4db, verified]
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

### Database Management

```bash
# Initialize the fingerprint database
./target/debug/tlsprint-db init

# Download and import seed data
curl -o /tmp/ja4db.json https://ja4db.com/api/read/
wget -O /tmp/ja3prints.json https://raw.githubusercontent.com/trisulnsm/ja3prints/master/ja3fingerprint.json

./target/debug/tlsprint-db import ja4db /tmp/ja4db.json
./target/debug/tlsprint-db import ja3prints /tmp/ja3prints.json

# Re-import (clear old entries first)
./target/debug/tlsprint-db import ja4db /tmp/ja4db.json --replace

# Show statistics
./target/debug/tlsprint-db stats

# Manual hash lookup
./target/debug/tlsprint-db lookup <hash>
```

### Active Proxy

```bash
# Listen on default port 8443
./target/debug/tlsprint-proxy

# Custom port
./target/debug/tlsprint-proxy 9443

# Test with curl
curl -k https://localhost:8443
```

## Architecture

```
tlsprint-core (library)
  ├── fingerprint/     JA3/JA4 computation, ClientHello parsing, GREASE filtering
  └── db/              SQLite fingerprint database, seed importers, classification
        │
        ├── tlsprint-sniff (binary)    Passive libpcap sniffer with TCP reassembly
        ├── tlsprint-proxy (binary)    Active TCP listener
        ├── tlsprint-db    (binary)    Database management CLI
        └── tlsprint-api   (binary)    REST API (planned)
```

### Fingerprinting Pipeline

```
Raw bytes → parse_client_hello() → ClientHelloInfo
  → compute_ja3(&info) → Ja3Result { hash, raw_string }
  → compute_ja4(&info) → Ja4Result { hash, raw }
  → db.classify(ja3, ja4) → Classification { best_match, ja3_matches, ja4_matches }
```

### Sniffer Packet Flow

```
Network interface (libpcap, BPF "tcp port 443")
  → etherparse: Ethernet → IP → TCP → payload
  → TcpReassembler: accumulate segments per flow
  → parse_client_hello() → compute JA3/JA4
  → classify against SQLite DB → output (text/JSON)
```

## Seed Data Sources

| Source | Type | Entries | Format |
|--------|------|---------|--------|
| [ja4db.com](https://ja4db.com) | JA4 | ~62K | JSON array |
| [trisulnsm/ja3prints](https://github.com/trisulnsm/ja3prints) | JA3 | ~611 | NDJSON |

## Fingerprinting Methods

- **JA3**: MD5 hash of `SSLVersion,Ciphers,Extensions,EllipticCurves,ECPointFormats`. Widely adopted, 32-char hex.
- **JA4**: Modern successor with human-readable prefix + truncated SHA-256 of sorted cipher/extension lists. More robust against randomization.

Both methods filter GREASE values per RFC 8701.

## Implementation Phases

1. ~~Core fingerprinting (ClientHello parser, GREASE, JA3, JA4) + tests~~
2. ~~Active proxy (TCP listener, fingerprint on connect)~~
3. ~~Passive sniffer (libpcap, etherparse, BPF filter, TCP reassembly)~~
4. ~~Database and classification (SQLite, seed data loader, ja4db + ja3prints)~~
5. TLS-terminating reverse proxy (peek + rustls + hyper, filter engine)
6. REST API (axum, CRUD, statistics)
7. Production hardening (PostgreSQL, metrics, HTTP/2, Docker)

## Licensing

- TLSprint: MIT
- JA4 (basic TLS fingerprint): BSD 3-Clause
- JA4+ extensions (JA4S, JA4H, JA4X): FoxIO License 1.1 -- not implemented
