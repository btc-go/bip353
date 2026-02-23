[![Go Reference](https://pkg.go.dev/badge/github.com/btc-go/bip353.svg)](https://pkg.go.dev/github.com/btc-go/bip353)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

A Go implementation of [BIP-353: DNS Payment Instructions](https://github.com/bitcoin/bips/blob/master/bip-0353.mediawiki).

BIP-353 maps human-readable addresses like **₿alice@example.com** to Bitcoin payment instructions stored in DNSSEC-secured DNS TXT records. This library resolves them — with full BOLT-12 TLV decoding, BIP-352 Silent Payment address parsing, DNS-over-HTTPS, and optional Tor routing.

---

## Features

| Feature | Status |
|---------|--------|
| BIP-353 resolution (DNSSEC required by default) | ✅ |
| DNS TTL enforcement per BIP-353 spec | ✅ |
| BOLT-12 offer decoding (full TLV stream parser) | ✅ |
| BIP-352 Silent Payment address decoding | ✅ |
| BOLT-11 invoice support | ✅ |
| On-chain addresses (P2PKH, P2SH, P2WPKH, P2TR) | ✅ |
| BIP-321 `bc=` native segwit param (multiple values) | ✅ |
| BIP-321 `req-` required parameter rejection | ✅ |
| BIP-321 case-insensitive query parameter keys | ✅ |
| DNS-over-HTTPS (RFC 8484, binary wire + JSON) | ✅ |
| Tor-routed DNS (SOCKS5 + DoH) | ✅ |
| Standard UDP/TCP with DNSSEC-validating resolvers | ✅ |
| Typed error sentinels (`errors.Is` compatible) | ✅ |
| BIP-21 URI builder for publishing records | ✅ |
| CLI tool (`bip353`) | ✅ |

---

## Installation

```bash
go get github.com/btc-go/bip353
```

**CLI tool:**
```bash
go install github.com/btc-go/bip353/cmd/bip353@latest
```

---

## Quick Start

```go
package main

import (
    "context"
    "fmt"
    "log"
    "time"

    bip353 "github.com/btc-go/bip353"
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

    // Respect the DNS TTL when caching
    cacheFor := time.Duration(inst.TTL) * time.Second
    fmt.Printf("Cache this result for: %s\n", cacheFor)

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
        for _, addr := range inst.OnChainAddresses {
            fmt.Println("  segwit address:", addr)
        }
    }
}
```

---

## Transport Options

### Classic DNS (default)

Uses UDP/TCP to well-known DNSSEC-validating public resolvers (Cloudflare 1.1.1.1, Google 8.8.8.8, Quad9 9.9.9.9). Fastest option. Your ISP may observe DNS query names but cannot forge responses without breaking DNSSEC.

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
// Named provider:
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

The library decodes BOLT-12 offer TLV streams from the bech32m-encoded offer string, covering all standardized fields in the [BOLT-12 spec](https://github.com/lightning/bolts/blob/master/12-offer-encoding.md):

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

A single BIP-353 record may contain multiple payment methods. The library populates all recognized fields so callers can fall back gracefully:

```go
inst, _ := r.Resolve(ctx, "₿tips@example.com")

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

> **Note:** The DNS label is `_bitcoin-payment`, not `_bitcoin._dns`. This is the exact format specified in BIP-353.

---

## Error Handling

Use `errors.Is` to detect specific failure conditions:

```go
inst, err := r.Resolve(ctx, "₿alice@example.com")
switch {
case errors.Is(err, bip353.ErrNXDOMAIN):
    // No DNS record exists for this user.
case errors.Is(err, bip353.ErrDNSSECRequired):
    // DNS zone is not DNSSEC-signed, or resolver returned unauthenticated response.
    // Do NOT fall back silently — this may indicate an active spoofing attack.
case errors.Is(err, bip353.ErrAmbiguousRecord):
    // Multiple BIP-353 TXT records found — DNS misconfiguration.
case errors.Is(err, bip353.ErrNoRecord):
    // DNS name exists but has no "bitcoin:" TXT record.
case errors.Is(err, bip353.ErrRequiredParam):
    // URI contains a req- prefixed parameter this library does not understand.
    // Per BIP-321 the entire URI must be rejected.
case err != nil:
    // Other DNS or network error.
}
```

**Do not silently fall back to an insecure resolver if `ErrDNSSECRequired` is returned.** This may indicate an active DNS spoofing attack. Surface it to the user.

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
  help                 Show this help

RESOLVE FLAGS:
  --transport <spec>       classic | doh:<provider> | tor:<provider>
  --tor-proxy <host:port>  Tor SOCKS5 proxy (default: 127.0.0.1:9050)
  --insecure               Disable DNSSEC (NOT safe for production)
  --timeout <duration>     Query timeout (default: 10s)
  --verbose                Show full decoded fields including DNS TTL
```

Examples:

```bash
bip353 resolve ₿alice@example.com
bip353 resolve --transport doh:cloudflare ₿alice@example.com
bip353 resolve --transport tor:cloudflare ₿alice@example.com
bip353 resolve --verbose ₿alice@example.com
bip353 dnsname ₿alice@example.com
bip353 build --address bc1q... --bolt12 lno1...
bip353 decode lno1qcpjkuepqyz5z...
bip353 decode sp1qqgmrp7a...
```

### Live test addresses

These are real published BIP-353 records verified against this library:

```bash
# The BIP author's own address — BOLT-12 + on-chain, DNSSEC validated:
$ bip353 resolve ₿matt@mattcorallo.com
Address:  ₿matt@mattcorallo.com
Type:     lightning_bolt12
Reusable: true
DNSSEC:   true
Offer:    lno1zr5qyugqgskrk70kqmuq7v3dnr2fnmhukps9n8hut48vkqpqnskt...

# Verbose output showing full fields including DNS TTL:
$ bip353 resolve --verbose ₿matt@mattcorallo.com
Address:          ₿matt@mattcorallo.com
Payment type:     lightning_bolt12
Reusable:         true
DNSSEC validated: true
DNS TTL:          3600s
BOLT-12 offer:    lno1zr5qyugqgskrk70kqmuq7v3dnr2fnmhukps9n8hut48vkqpqnskt...
On-chain address: bc1qztwy6xen3zdtt7z0vrgapmjtfz8acjkfp5fp7l

# Domain without DNSSEC — correctly rejected:
$ bip353 resolve ₿bitnomad@blink.sv
error: bip353: DNSSEC validation required: AD bit not set (name: bitnomad.user._bitcoin-payment.blink.sv., transport: classic)

# --insecure bypasses DNSSEC but record must still exist:
$ bip353 resolve --insecure ₿bitnomad@blink.sv
error: bip353: no BIP-353 TXT record found at bitnomad.user._bitcoin-payment.blink.sv.

# Verify a DNS name manually with dig:
$ bip353 dnsname ₿matt@mattcorallo.com
matt.user._bitcoin-payment.mattcorallo.com.
$ dig TXT matt.user._bitcoin-payment.mattcorallo.com.
```

---

## Security

### DNSSEC

BIP-353 requires DNSSEC to prevent DNS spoofing. This library checks the **AD (Authenticated Data) bit** in DNS responses, which a DNSSEC-validating recursive resolver sets after verifying the full DNSSEC chain from root → TLD → zone.

- Default public resolvers (Cloudflare, Google, Quad9) all perform full DNSSEC validation.
- If you use your own resolver, ensure it validates DNSSEC and sets the AD bit.
- `AllowInsecure: true` is for test environments only. **Never use in production.**

### TTL enforcement

Per BIP-353, clients must not cache payment instructions longer than the DNS TTL. This library exposes `inst.TTL` (in seconds) on every resolved `PaymentInstruction`. Callers are responsible for respecting it when caching results.

### What DNSSEC does NOT protect against

- A compromised DNSSEC-validating resolver lying about the AD bit.
- Cryptographic signature verification of BOLT-12 offers (requires a full Lightning node).

### Reporting vulnerabilities

Please do not file public GitHub issues for security vulnerabilities. Contact the maintainers privately.

---

## Architecture

```
github.com/btc-go/bip353/
├── bip353.go              # Public API (re-exports, convenience constructors)
├── bip353_test.go         # Tests (mock transport for unit tests)
│
├── pkg/
│   ├── types/             # Core types, error sentinels, BIP-21 URI parser
│   ├── bolt12/            # BOLT-12 TLV decoder (bech32m → TLV stream → fields)
│   ├── silentpayment/     # BIP-352 address decoder (bech32m → scan/spend keys)
│   ├── resolver/          # BIP-353 resolution logic
│   └── builder/             # BIP-21 URI builder
│
├── transport/
│   ├── transport.go       # Transport interface + ClassicTransport (UDP/TCP)
│   ├── doh.go             # DoHTransport (RFC 8484, wire + JSON)
│   └── tor.go             # TorTransport (SOCKS5 + DoH)
│
└── cmd/
    └── bip353/               # bip353 CLI tool
```

**Design principles:**
- `Transport` is an interface: swap DNS backends without changing resolver logic.
- All errors are typed and wrap `errors.Is`-compatible sentinel values.
- No global state; all configuration is per-`Resolver`.
- BOLT-12 and Silent Payment decoding are non-fatal: the raw string is always available.
- DNS TTL is propagated to callers — never silently discarded.
- Requires Go 1.21+.

---

## Dependencies

| Package | Purpose |
|---------|---------|
| `github.com/miekg/dns` | DNS wire-format encoding/decoding |
| `golang.org/x/net` | `proxy.SOCKS5` for Tor routing |

The BOLT-12 bech32m decoder and BigSize integer parser are implemented from scratch with no external dependencies.

---

## License

MIT. See [LICENSE](LICENSE).

---

## References

- [BIP-353](https://github.com/bitcoin/bips/blob/master/bip-0353.mediawiki): DNS Payment Instructions
- [BIP-352](https://github.com/bitcoin/bips/blob/master/bip-0352.mediawiki): Silent Payments
- [BIP-321](https://github.com/bitcoin/bips/blob/master/bip-0321.mediawiki): URI Scheme
- [BOLT-12](https://github.com/lightning/bolts/blob/master/12-offer-encoding.md): Offer Protocol
- [RFC 8484](https://www.rfc-editor.org/rfc/rfc8484): DNS Queries over HTTPS (DoH)
- [BOLT-01 TLV](https://github.com/lightning/bolts/blob/master/01-messaging.md#type-length-value-format): BigSize and TLV format