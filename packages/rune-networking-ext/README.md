# rune-networking-ext

Network-layer governance, protocol enforcement, traffic classification,
network segmentation, certificate management, DNS governance, rate limiting,
firewall rules, and connection auditing for the RUNE governance ecosystem.

## Overview

`rune-networking-ext` governs the transport and network layers. Where
`rune-web` governs the HTTP application layer and `rune-shield` governs the
AI inference layer, this crate enforces governance at the network boundary.
It is the library that air-gapped deployments (HEIMDALL, P25/ASTRO 25
infrastructure) and zero-trust network architectures need.

## Modules

| Module | Purpose |
|---|---|
| `protocol` | TLS version enforcement, cipher suite governance, mTLS requirements, 4 built-in policies (modern/intermediate/legacy/air_gapped) |
| `connection` | Connection lifecycle tracking (open→authenticate→establish→close), byte counters, idle detection |
| `traffic` | Traffic classification by trust level (Untrusted→Privileged), rule-based with CIDR matching |
| `segmentation` | Network zone definitions, zone-to-zone flow policies, port/protocol restrictions |
| `certificate` | Certificate validation (expiry/revocation/key size), pinning, lifecycle management |
| `dns` | DNS resolution governance, domain blocking/allowing, pattern matching, query auditing |
| `rate_limit` | Network-level rate limiting per source, global, and per-connection bandwidth |
| `firewall` | Software-defined firewall rules with priority ordering, hit counting, default-deny |
| `audit` | 15 network event types covering all governance decisions |
| `error` | `NetworkError` with 15 domain-specific variants |

## Key Concepts

### Protocol Enforcement

Four built-in TLS policies:
- **Modern**: TLS 1.3 only, AEAD ciphers, PFS required, strict certificate validation
- **Intermediate**: TLS 1.2+, strong ciphers, PFS required
- **Legacy**: TLS 1.2+, allows CBC ciphers, no PFS requirement
- **Air-Gapped**: TLS 1.3, mTLS required, certificate pinning, OCSP stapling

### Trust Levels

Five ordered levels classify network traffic:

`Untrusted` < `Restricted` < `Conditional` < `Trusted` < `Privileged`

Traffic rules assign trust levels based on source CIDR, destination port,
protocol, identity presence, and mTLS status.

### Network Segmentation

Zones (Public, DMZ, Internal, Restricted, AirGapped, Management) with
CIDR-based address membership. Flow policies control which zones can
communicate, with optional port and protocol restrictions. Denied flows
take precedence over allowed flows. Default action is Deny.

### Firewall

Priority-ordered rules evaluated against inbound/outbound traffic. Each rule
has a condition (source/dest addr/CIDR, port, protocol, And/Or/Not combinators)
and an action (Allow/Deny/Log/RateLimit/Redirect). Hit counts track rule
effectiveness. Default-deny when no rule matches.

### CIDR Matching

IPv4 CIDR matching (`is_in_cidr`) is shared between traffic classification,
segmentation, and firewall modules. Handles address:port stripping, /0-/32
prefix lengths, and gracefully rejects unparseable input.

## Dependencies

- `rune-lang` — Core language types (no default features)
- `rune-security` — `SecuritySeverity` for audit events
- `serde` / `serde_json` — Serialization

Cross-crate integration uses string-based context maps.

## Tests

116 unit tests covering all modules. Run with:

```sh
cargo test -p rune-networking-ext
```
