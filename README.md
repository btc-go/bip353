# bip353-go

[![Go Reference](https://pkg.go.dev/badge/github.com/bip353/bip353-go.svg)](https://pkg.go.dev/github.com/bip353/bip353-go)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

A Go implementation of [BIP-353: DNS Payment Instructions](https://github.com/bitcoin/bips/blob/master/bip-0353.mediawiki).

BIP-353 maps human-readable addresses like **₿alice@example.com** to Bitcoin payment instructions stored in DNSSEC-secured DNS TXT records. This library resolves them — with full BOLT-12 TLV decoding, BIP-352 Silent Payment address parsing, DNS-over-HTTPS, and optional Tor routing.

---

## Features

| Feature | Status |
|---------|--------|
| BIP-353 resolution (DNSSEC required by default) | Done |
| BOLT-12 offer decoding (full TLV stream parser) | Done |
| BIP-352 Silent Payment address decoding | Done |
| BOLT-11 invoice support | Done |
| On-chain addresses (P2PKH, P2SH, P2WPKH, P2TR) | Done |
| BIP-321 `bc=` native segwit param (multiple values) | Done |
| BIP-321 `req-` required parameter rejection | Done |
| BIP-321 case-insensitive query parameter keys | Done |
| DNS-over-HTTPS (RFC 8484, binary wire + JSON) | Done |
| Tor-routed DNS (SOCKS5 + DoH) | Done |
| Standard UDP/TCP with DNSSEC-validating resolvers | Done |
| Typed error sentinels (`errors.Is` compatible) | Done |
| BIP-21 URI builder for publishing records | Done |
| CLI tool (`bip353`) | Done |

---

## Installation

```bash
go get github.com/bip353/bip353-go
```

**CLI tool:**
```bash
go install github.com/bip353/bip353-go/examples/cli@latest
```

---

## Quick Start

```go
package main

import (
    "context"
    "fmt"
    "log"

    bip353 "github.com/bip353/bip353-go"
)

func main() {
    ctx := context.Background()

    // Secure by default: DNSSEC required, public DNSSEC-validating resolvers.
    r, err := bip353.NewSecure()
    if err != nil {
        log.Fatal(err)
    }

    inst, err := r.Resolve(ctx, "₿alice@example.com")
    if err != nil {
        log.Fatal(err)
    }

    switch inst.PaymentType {
    case bip353.PaymentTypeLightningBOLT12:
        fmt.Println("Pay via BOLT-12 offer:", inst.BOLT12Offer)
        if d := inst.BOLT12Details; d != nil {
            fmt.Println("Description:", d.Description)
            fmt.Println("Node ID:", d.NodeID)
        }
    case bip353.PaymentTypeSilentPayment:
        fmt.Println("Pay via silent payment:", inst.SilentPaymentAddress)
        if d := inst.SilentPaymentDetails; d != nil {
            fmt.Printf("Scan key: %x\n", d.ScanPubkey)
            fmt.Printf("Spend key: %x\n", d.SpendPubkey)
        }
    case bip353.PaymentTypeLightningBOLT11:
        fmt.Println("Pay via BOLT-11 invoice:", inst.BOLT11Invoice)
    case bip353.PaymentTypeOnChain:
        fmt.Println("Pay on-chain:", inst.OnChainAddress)
        // Multiple segwit addresses may be present (e.g. P2WPKH + P2TR)
        for _, addr := range inst.OnChainAddresses {
            fmt.Println("  segwit address:", addr)
        }
    }
}
```

---

## Transport Options

### Classic DNS (default)

Uses UDP/TCP to well-known DNSSEC-validating public resolvers (Cloudflare 1.1.1.1, Google 8.8.8.8, Quad9 9.9.9.9). Fastest option. Your ISP may observe DNS query names (but cannot forge responses without breaking DNSSEC).

```go
r, _ := bip353.NewSecure()
// or equivalently:
r, _ := bip353.New(bip353.DefaultOptions())
```

Custom nameservers:
```go
t := bip353.NewClassicTransportWithNameservers([]string{"192.0.2.1:53"})
opts := bip353.DefaultOptions()
opts.Transport = t
r, _ := bip353.New(opts)
```

### DNS-over-HTTPS (DoH)

Hides DNS query names from your ISP and any on-path network observer. The DoH server operator can see your queries but not your IP if combined with Tor.

```go
// Using a named provider:
r, _ := bip353.NewWithDoH("cloudflare") // or "google", "quad9", "nextdns"

// Custom DoH endpoint:
t, _ := bip353.NewDoHTransportWithURL("https://my-resolver.example.com/dns-query")
opts := bip353.DefaultOptions()
opts.Transport = t
r, _ := bip353.New(opts)
```

Supported named providers:

| Name | URL |
|------|-----|
| `cloudflare` | https://cloudflare-dns.com/dns-query |
| `google` | https://dns.google/dns-query |
| `quad9` | https://dns.quad9.net/dns-query |
| `nextdns` | https://dns.nextdns.io/dns-query |

### Tor + DoH (maximum privacy)

Routes DoH queries through a Tor SOCKS5 proxy. The DoH server sees only the Tor exit node's IP. Requires a running Tor daemon.

```go
// Tor daemon (default port):
r, _ := bip353.NewWithTor("127.0.0.1:9050", "cloudflare")

// Tor Browser:
r, _ := bip353.NewWithTor("127.0.0.1:9150", "cloudflare")
```

**Privacy comparison:**

| Transport | ISP sees query? | DoH server sees IP? | Notes |
|-----------|----------------|---------------------|-------|
| Classic | Yes | — | Fastest |
| DoH | No | Yes | Good privacy |
| Tor + DoH | No | No | Strongest privacy, ~1s latency |

---

## BOLT-12 TLV Decoding

The library decodes BOLT-12 offer TLV streams from the bech32m-encoded offer string. This covers all standardized fields in the [BOLT-12 spec](https://github.com/lightning/bolts/blob/master/12-offer-encoding.md):

```go
inst, _ := r.Resolve(ctx, "₿merchant@shop.example.com")
if inst.BOLT12Details != nil {
    d := inst.BOLT12Details
    fmt.Println("Type:", d.Type)               // "offer", "invoice_request", "invoice"
    fmt.Println("Description:", d.Description) // Human-readable offer description
    fmt.Println("Issuer:", d.Issuer)            // Merchant name
    fmt.Printf("Node ID: %s\n", d.NodeID)      // Hex-encoded x-only pubkey
    if d.AmountMsat > 0 {
        fmt.Printf("Amount: %d msat\n", d.AmountMsat)
    }
    fmt.Printf("Blinded paths: %d\n", len(d.Paths))
}
```

Decoded TLV fields:

| Field | TLV Type | Description |
|-------|----------|-------------|
| `Description` | 10 | Human-readable offer description |
| `NodeID` | 22 | Offer-signing node x-only pubkey (hex) |
| `AmountMsat` | 8/34 | Amount in millisatoshis (0 = sender sets) |
| `Currency` | 6 | ISO 4217 currency code (empty = BTC) |
| `Issuer` | 18 | Human-readable issuer name |
| `QuantityMax` | 20 | Maximum quantity (0 = unlimited) |
| `Features` | 12 | Raw feature bits |
| `Paths` | 16/38 | Blinded payment paths |

Unknown odd TLV types are silently skipped per the BOLT spec. Unknown even types (must-understand) cause a decode error but the raw offer string is always available.

---

## BIP-352 Silent Payment Decoding

```go
inst, _ := r.Resolve(ctx, "₿alice@example.com")
if inst.SilentPaymentDetails != nil {
    d := inst.SilentPaymentDetails
    fmt.Println("Network:", d.Network)            // "mainnet", "testnet", "signet"
    fmt.Println("Version:", d.Version)            // 0 (BIP-352 v0)
    fmt.Printf("Scan key:  %x\n", d.ScanPubkey)  // 33-byte compressed pubkey
    fmt.Printf("Spend key: %x\n", d.SpendPubkey) // 33-byte compressed pubkey
}
```

The decoder validates:
- Bech32m checksum (constant `0x2bc830a3`)
- HRP: `sp` (mainnet), `tsp` (testnet), `sprt` (signet)
- Version byte (0–16; v0 requires exactly 66 key bytes)
- Compressed public key format (0x02/0x03 prefix + 32-byte x-coordinate)

---

## Multi-Payment Records

A single BIP-353 record may contain multiple payment methods. The library always
populates all recognized fields — not just the highest-priority one — so callers
can fall back gracefully:

```go
inst, _ := r.Resolve(ctx, "₿tips@bip353.com")

// Primary: BOLT-12 (highest priority)
fmt.Println("BOLT-12:", inst.BOLT12Offer)

// Also available on the same record:
fmt.Println("Silent payment:", inst.SilentPaymentAddress)
fmt.Println("On-chain:", inst.OnChainAddress)

// BIP-321: multiple segwit addresses (e.g. P2WPKH + P2TR) via bc= param
for _, addr := range inst.OnChainAddresses {
    fmt.Println("  segwit:", addr)
}
```

Payment type priority (highest wins for `inst.PaymentType`):

```
BOLT-12 > Silent Payment > BOLT-11 > on-chain
```

---

## Building DNS TXT Records

To publish your payment information, add a TXT record to your DNS zone:

```go
uri, err := bip353.NewURIBuilder("bc1qyouraddress").
    WithBOLT12Offer("lno1yourBOLT12Offer").
    WithBOLT11Invoice("lnbc1yourBOLT11Invoice").
    WithSilentPayment("sp1yourSilentPaymentAddress").
    Build()
// → "bitcoin:bc1qyouraddress?lno=lno1...&lightning=lnbc1...&sp=sp1..."
```

Publish as a DNS TXT record (zone must be DNSSEC-signed):

```bind
alice.user._bitcoin-payment.example.com. 300 IN TXT "bitcoin:bc1q...?lno=lno1..."
```

> **Note:** The DNS name format is `<user>.user._bitcoin-payment.<domain>.` — note
> `_bitcoin-payment`, not `_bitcoin._dns`. This is the format specified in BIP-353.

---

## Error Handling

Use `errors.Is` to detect specific failure conditions:

```go
inst, err := r.Resolve(ctx, "₿alice@example.com")
switch {
case errors.Is(err, bip353.ErrNXDOMAIN):
    // The user is not registered; no DNS record exists.
case errors.Is(err, bip353.ErrDNSSECRequired):
    // The domain's DNS zone is not DNSSEC-signed, or the resolver
    // returned an unauthenticated response.
case errors.Is(err, bip353.ErrAmbiguousRecord):
    // Multiple BIP-353 TXT records found; DNS misconfiguration.
case errors.Is(err, bip353.ErrNoRecord):
    // A DNS name exists but has no "bitcoin:" TXT record.
case errors.Is(err, bip353.ErrRequiredParam):
    // URI contains a req- prefixed parameter this library does not understand.
    // Per BIP-321 the entire URI must be rejected.
case err != nil:
    // Other DNS or network error.
}
```

**Do not silently fall back to an insecure resolver if `ErrDNSSECRequired` is returned.** This error may indicate an active DNS spoofing attack. Surface it to the user.

---

## CLI

```
USAGE:
  bip353 <command> [flags] [arguments]

COMMANDS:
  resolve <address>    Resolve ₿user@domain to Bitcoin payment info
  dnsname <address>    Print the BIP-353 DNS TXT record name
  build [flags]        Build a BIP-21 URI for a DNS TXT record
  decode <value>       Decode a BOLT-12 offer or silent payment address
```

Examples:

```bash
# Resolve with default transport:
bip353 resolve ₿alice@example.com

# Resolve with DoH:
bip353 resolve --transport doh:cloudflare ₿alice@example.com

# Resolve through Tor + DoH:
bip353 resolve --transport tor:cloudflare ₿alice@example.com

# Show full decoded fields (BOLT-12 details, silent payment keys, etc.):
bip353 resolve --verbose ₿alice@example.com

# Print the DNS name (for manual dig verification):
bip353 dnsname ₿alice@example.com
# → alice.user._bitcoin-payment.example.com.

# Build a TXT record value:
bip353 build --address bc1q... --bolt12 lno1... --bolt11 lnbc1...

# Decode a BOLT-12 offer:
bip353 decode lno1qcpjkuepqyz5z...

# Decode a silent payment address:
bip353 decode sp1qqgmrp7a...
```

### Live test addresses / Working Examples

These are real BIP-353 records you can use to verify the library is working:
```bash
# BOLT-12 offer with DNSSEC:
$ bip353 resolve ₿matt@mattcorallo.com
Resolved: ₿matt@mattcorallo.com
Type:     lightning_bolt12
Reusable: true
DNSSEC:   true
Offer:    lno1zr5qyugqgskrk70kqmuq7v3dnr2fnmhukps9n8hut48vkqpqnskt...

# On-chain via bc= param — record has an intentional junk TXT entry that must be ignored:
$ bip353 resolve ₿simple@dnssec_proof_tests.bitcoin.ninja
Resolved: ₿simple@dnssec_proof_tests.bitcoin.ninja
Type:     onchain
Reusable: false
DNSSEC:   true
Address:  bc1qztwy6xen3zdtt7z0vrgapmjtfz8acjkfp5fp7l

# BOLT-12 + silent payment + on-chain in a single record:
$ bip353 resolve ₿tips@bip353.com
Resolved: ₿tips@bip353.com
Type:     lightning_bolt12
Reusable: true
DNSSEC:   true
Offer:    lno1zrxq8pjw7qjlm68mtp7e3yvxee4y5xrgjhhyf2fxhlphpckrvevh...

# Two conflicting bitcoin: TXT records — must error:
$ bip353 resolve ₿invalid@dnssec_proof_tests.bitcoin.ninja
error: bip353: multiple BIP-353 TXT records found at invalid.user._bitcoin-payment.dnssec_proof_tests.bitcoin.ninja. (2 records)

# Domain without DNSSEC — must error:
$ bip353 resolve ₿bitnomad@blink.sv
error: bip353: DNSSEC validation required: AD bit not set (name: bitnomad.user._bitcoin-payment.blink.sv., transport: classic)
```

---

## Security

### DNSSEC

BIP-353 requires DNSSEC to prevent DNS spoofing. This library checks the **AD (Authenticated Data) bit** in DNS responses, which a DNSSEC-validating recursive resolver sets after verifying the full DNSSEC chain from root → TLD → zone.

- Default public resolvers (Cloudflare, Google, Quad9) all perform DNSSEC validation.
- If you use your own resolver, ensure it validates DNSSEC and sets the AD bit.
- `NewInsecure()` is provided for test environments only. **Never use in production.**

### What DNSSEC does NOT protect against

- A compromised DNSSEC-validating resolver lying about the AD bit.
- Side-channel timing attacks.
- Cryptographic signature verification of BOLT-12 offers (requires a full Lightning node).

### Reporting vulnerabilities

Please do not file public GitHub issues for security vulnerabilities. Contact the maintainers privately.

---

## Architecture

```
github.com/bip353/bip353-go/
├── bip353.go              # Public API (re-exports, convenience constructors)
├── bip353_test.go         # Tests (mock transport for unit tests)
│
├── pkg/
│   ├── types/             # Core types, error sentinels, BIP-21 URI parser
│   ├── bolt12/            # BOLT-12 TLV decoder (bech32m → TLV stream → fields)
│   ├── silentpayment/     # BIP-352 address decoder (bech32m → scan/spend keys)
│   ├── resolver/          # BIP-353 resolution logic
│   └── bip21/             # BIP-21 URI builder
│
├── transport/
│   ├── transport.go       # Transport interface + ClassicTransport (UDP/TCP)
│   ├── doh.go             # DoHTransport (RFC 8484, wire + JSON)
│   └── tor.go             # TorTransport (SOCKS5 + DoH)
│
└── examples/
    └── cli/               # bip353 CLI tool
```

**Design principles:**
- `Transport` is an interface: swap DNS backends without changing resolver logic.
- All errors are typed and wrap `errors.Is`-compatible sentinel values.
- No global state; all configuration is per-`Resolver`.
- BOLT-12 and Silent Payment decoding are non-fatal: the raw string is always available.
- BIP-321 compliance: case-insensitive query keys, `req-` param rejection, multiple `bc=` values.
- `min()` built-in requires Go 1.21+ (specified in `go.mod`).

---

## Dependencies

| Package | Purpose |
|---------|---------|
| `github.com/miekg/dns` | DNS wire-format encoding/decoding (ClassicTransport, DoH wire format) |
| `golang.org/x/net` | `proxy.SOCKS5` for Tor routing |
| `golang.org/x/crypto` | (transitive) |

The BOLT-12 bech32m decoder and BigSize integer parser are implemented from scratch with zero external dependencies.

---

## License

MIT. See [LICENSE](LICENSE).

---

## References

- [BIP-353](https://github.com/bitcoin/bips/blob/master/bip-0353.mediawiki): DNS Payment Instructions
- [BIP-352](https://github.com/bitcoin/bips/blob/master/bip-0352.mediawiki): Silent Payments
- [BIP-321](https://github.com/bitcoin/bips/blob/master/bip-0321.mediawiki): URI Scheme (replaces BIP-21)
- [BOLT-12](https://github.com/lightning/bolts/blob/master/12-offer-encoding.md): Offer Protocol
- [RFC 8484](https://www.rfc-editor.org/rfc/rfc8484): DNS Queries over HTTPS (DoH)
- [BOLT-01 TLV](https://github.com/lightning/bolts/blob/master/01-messaging.md#type-length-value-format): BigSize and TLV format