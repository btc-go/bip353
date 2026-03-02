[![Go Reference](https://pkg.go.dev/badge/github.com/btc-go/bip353.svg)](https://pkg.go.dev/github.com/btc-go/bip353)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![CI](https://github.com/btc-go/bip353/actions/workflows/test.yml/badge.svg)](https://github.com/btc-go/bip353/actions/workflows/test.yml)
[![CodeQL](https://github.com/btc-go/bip353/actions/workflows/codeql.yml/badge.svg)](https://github.com/btc-go/bip353/actions/workflows/codeql.yml)
[![codecov](https://codecov.io/gh/btc-go/bip353/branch/main/graph/badge.svg)](https://codecov.io/gh/btc-go/bip353)
[![Go Report Card](https://goreportcard.com/badge/github.com/btc-go/bip353)](https://goreportcard.com/report/github.com/btc-go/bip353)

A Go implementation of [BIP-353: DNS Payment Instructions](https://github.com/bitcoin/bips/blob/master/bip-0353.mediawiki).

BIP-353 maps human-readable addresses like **₿alice@example.com** to Bitcoin payment instructions stored in DNSSEC-signed DNS TXT records. This library resolves them with full local DNSSEC chain validation, BOLT-12 TLV decoding, BIP-352 Silent Payment address parsing, DNS-over-HTTPS, and optional Tor routing.

---

## Features

| Feature | Status |
|---------|--------|
| Full local DNSSEC chain validation (dnssec-prover, never trusts resolver) | Done |
| DNS TTL enforcement per BIP-353 spec | Done |
| BOLT-12 offer decoding (full TLV stream parser) | Done |
| BOLT-12 invoice request and invoice decoding | Done |
| BIP-352 Silent Payment address decoding | Done |
| BOLT-11 invoice support | Done |
| On-chain addresses (P2PKH, P2SH, P2WPKH, P2TR) | Done |
| BIP-321 `bc=` native segwit param (multiple values) | Done |
| BIP-321 `req-` required parameter rejection | Done |
| BIP-321 case-insensitive query parameter keys | Done |
| DNS-over-HTTPS (RFC 8484, wire format) | Done |
| Tor-routed DNS (SOCKS5 + DoH) | Done |
| Typed error sentinels (`errors.Is` compatible) | Done |
| BIP-21 URI builder for publishing records | Done |
| Standalone BOLT-12 / Silent Payment decoder | Done |
| CLI tool (`bip353`) | Done |

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
r, err := bip353.New()
if err != nil {
    log.Fatal(err)
}

inst, err := r.Resolve(ctx, "₿alice@example.com")
if err != nil {
    log.Fatal(err)
}

// Respect the DNS TTL when caching (BIP-353 requirement).
cacheFor := time.Duration(inst.TTL) * time.Second

switch inst.PaymentType {
case bip353.PaymentTypeLightningBOLT12:
    pay(inst.BOLT12Offer)
case bip353.PaymentTypeSilentPayment:
    pay(inst.SilentPaymentAddress)
case bip353.PaymentTypeLightningBOLT11:
    pay(inst.BOLT11Invoice)
case bip353.PaymentTypeOnChain:
    pay(inst.OnChainAddress)
}
```

---

## Transport Options

All transports perform full local DNSSEC chain validation via [dnssec-prover](https://github.com/TheBlueMatt/dnssec-prover) — the reference implementation written by the BIP-353 author. The remote resolver is used only to relay raw DNS queries. Its responses are fed into dnssec-prover for local verification. This satisfies the BIP-353 requirement:

> Clients MUST fully validate DNSSEC signatures leading to the DNS root and MUST NOT trust a remote resolver to validate DNSSEC records on their behalf.

### Direct (default)

Sends DNS queries over TCP to public resolvers. Fastest option. Your ISP may observe query names but cannot forge responses without breaking the DNSSEC chain.
```go
r, err := bip353.New()

// Custom nameservers:
t := transport.NewFullValidationTransportWithNameservers([]string{"192.0.2.1:53"})
opts := bip353.DefaultOptions()
opts.Transport = t
r, err = bip353.NewWithOptions(opts)
```

### DNS-over-HTTPS (DoH)

Hides query names from your ISP. The DoH server is used as a relay only — DNSSEC validation still happens locally.
```go
r, err := bip353.NewWithDoH("cloudflare") // or "google", "quad9", "nextdns"

// Custom endpoint:
r, err = bip353.NewWithDoHURL("https://my-resolver.example.com/dns-query")
```

| Provider | URL |
|----------|-----|
| `cloudflare` | https://cloudflare-dns.com/dns-query |
| `google` | https://dns.google/dns-query |
| `quad9` | https://dns.quad9.net/dns-query |
| `nextdns` | https://dns.nextdns.io/dns-query |

### Tor + DoH

Routes DoH queries through a Tor SOCKS5 proxy. The DoH server sees only the Tor exit node's IP. Requires a running Tor daemon.
```go
r, err := bip353.NewWithTor("127.0.0.1:9050", "cloudflare")
// Tor Browser:
r, err = bip353.NewWithTor("127.0.0.1:9150", "cloudflare")
```

| Transport | ISP sees query? | DoH server sees IP? |
|-----------|----------------|---------------------|
| Direct | Yes | — |
| DoH | No | Yes |
| Tor + DoH | No | No |

---

## BOLT-12 Decoding

### Via resolution
```go
inst, _ := r.Resolve(ctx, "₿merchant@shop.example.com")
if inst.BOLT12Details != nil {
    d := inst.BOLT12Details
    fmt.Println("Type:", d.Type)           // offer | invoice_request | invoice
    fmt.Println("Description:", d.Description)
    fmt.Println("Issuer:", d.Issuer)
    fmt.Printf("Node ID: %s\n", d.NodeID)
    if d.AmountMsat > 0 {
        fmt.Printf("Amount: %d msat\n", d.AmountMsat)
    }
    fmt.Printf("Blinded paths: %d\n", len(d.Paths))
}
```

### Standalone decode
```go
import "github.com/btc-go/bip353/pkg/bolt12"

details, err := bolt12.DecodeOffer("lno1...")
if err != nil {
    log.Fatal(err)
}
fmt.Println(details.NodeID)
fmt.Println(details.Description)
```

| Field | TLV Type | Description |
|-------|----------|-------------|
| `Description` | 10 | Human-readable offer description |
| `NodeID` | 22 | Offer-signing node pubkey (hex) |
| `AmountMsat` | 8 | Amount in millisatoshis (0 = sender sets) |
| `Currency` | 6 | ISO 4217 currency code (empty = BTC) |
| `Issuer` | 18 | Human-readable issuer name |
| `QuantityMax` | 20 | Maximum quantity (0 = unlimited) |
| `AbsoluteExpiry` | 14 | Unix timestamp after which offer is invalid |
| `Features` | 12 | Raw feature bits |
| `Paths` | 16 | Blinded payment paths |

Unknown odd TLV types are silently skipped per the BOLT spec. The raw offer string is always available at `inst.BOLT12Offer`.

---

## BIP-352 Silent Payment Decoding

### Via resolution
```go
inst, _ := r.Resolve(ctx, "₿alice@example.com")
if inst.SilentPaymentDetails != nil {
    d := inst.SilentPaymentDetails
    fmt.Println("Network:", d.Network)            // "mainnet", "testnet", "signet"
    fmt.Println("Version:", d.Version)            // 0
    fmt.Printf("Scan key:  %x\n", d.ScanPubkey)  // 33-byte compressed pubkey
    fmt.Printf("Spend key: %x\n", d.SpendPubkey) // 33-byte compressed pubkey
}
```

### Standalone decode
```go
import "github.com/btc-go/bip353/pkg/silentpayment"

details, err := silentpayment.Decode("sp1...")
if err != nil {
    log.Fatal(err)
}
fmt.Println(details.Network)
fmt.Printf("Scan:  %x\n", details.ScanPubkey)
fmt.Printf("Spend: %x\n", details.SpendPubkey)
```

---

## Multi-Payment Records

A single BIP-353 record may carry multiple payment methods. The library populates all recognised fields:
```go
inst, _ := r.Resolve(ctx, "₿tips@example.com")

fmt.Println("BOLT-12:", inst.BOLT12Offer)
fmt.Println("Silent payment:", inst.SilentPaymentAddress)
fmt.Println("On-chain:", inst.OnChainAddress)
for _, addr := range inst.OnChainAddresses {
    fmt.Println("  segwit:", addr)
}
```

Payment type priority (highest wins for `inst.PaymentType`): `BOLT-12 > Silent Payment > BOLT-11 > on-chain`

---

## Building DNS TXT Records
```go
uri, err := bip353.NewURIBuilder("bc1qyouraddress").
    WithBOLT12Offer("lno1...").
    WithSilentPayment("sp1...").
    Build()
```

Publish as a DNS TXT record on a DNSSEC-signed zone:
```
alice.user._bitcoin-payment.example.com. 300 IN TXT "bitcoin:bc1q...?lno=lno1..."
```

---

## Error Handling
```go
inst, err := r.Resolve(ctx, "₿alice@example.com")
switch {
case errors.Is(err, bip353.ErrNXDOMAIN):
    // No DNS record exists for this user.
case errors.Is(err, bip353.ErrAmbiguousRecord):
    // Multiple bitcoin: TXT records found — DNS misconfiguration.
case errors.Is(err, bip353.ErrNoRecord):
    // DNS name exists but has no bitcoin: TXT record.
case errors.Is(err, bip353.ErrRequiredParam):
    // URI contains a req- prefixed parameter this library does not understand.
case err != nil:
    // DNSSEC validation failure or network error.
}
```

DNSSEC validation failures return errors directly from dnssec-prover. They should be surfaced to the user and never silently retried with a less secure transport.

---

## Offline Proof Verification

Wallets accepting payment information from hardware wallets can verify a
DNSSEC proof offline without making any network requests:
```go
proof := // RFC 9102 / dnssec-prover byte-stream proof from hardware wallet
inst, err := bip353.VerifyProof(proof, "₿alice@example.com")
if err != nil {
    log.Fatal(err)
}
```

The proof is verified against the DNS name derived from the address.
A proof for a different name will not validate.

---

## CLI
```
USAGE:
  bip353 <command> [flags] [arguments]

COMMANDS:
  resolve <address>    Resolve ₿user@domain to payment info
  dnsname <address>    Print the BIP-353 DNS TXT record name
  build [flags]        Build a BIP-21 URI for a DNS TXT record
  decode <value>       Decode a BOLT-12 offer or silent payment address
  help                 Show this help

RESOLVE FLAGS:
  --transport <spec>       direct | doh:<provider> | tor:<provider>
                           Providers: cloudflare | google | quad9 | nextdns
                           Custom DoH: doh:https://your.doh.server/dns-query
  --tor-proxy <host:port>  Tor SOCKS5 proxy (default: 127.0.0.1:9050)
  --nameservers <list>     Comma-separated resolvers for direct transport
  --timeout <duration>     Query timeout (default: 10s)
  --verbose                Show full decoded fields including DNS TTL

BUILD FLAGS:
  --address <addr>     On-chain Bitcoin address
  --bolt12 <offer>     BOLT-12 offer (lno1...)
  --bolt11 <invoice>   BOLT-11 invoice (lnbc1...)
  --sp <addr>          Silent payment address (sp1...)
  --payjoin <url>      PayJoin BIP-78 endpoint URL
```

### Live examples
```bash
# Resolve with full local DNSSEC chain validation:
$ bip353 resolve ₿matt@mattcorallo.com
Resolved: ₿matt@mattcorallo.com
Type:     lightning_bolt12
Reusable: true
DNSSEC:   true
Offer:    lno1zr5qyugqgskrk70kqmuq7v3dnr2fnmhukps9n8hut48vkqpqnskt2svs...

# Verbose — DNS TTL, all decoded TLV fields:
$ bip353 resolve --verbose ₿matt@mattcorallo.com
Address:          ₿matt@mattcorallo.com
Payment type:     lightning_bolt12
Reusable:         true
DNSSEC validated: true
DNS TTL:          3600s
BOLT-12 offer:    lno1zr5qyugqgskrk70kqmuq7v3dnr2fnmhukps9n8hut48vkqpqnskt2svs…
  Node ID:        0386fe4a3bf04aea…
On-chain address: bc1qztwy6xen3zdtt7z0vrgapmjtfz8acjkfp5fp7l

# Multi-method record — BOLT-12 + silent payment + on-chain:
$ bip353 resolve --verbose ₿tips@bip353.com
Address:          ₿tips@bip353.com
Payment type:     lightning_bolt12
Reusable:         true
DNSSEC validated: true
DNS TTL:          10800s
BOLT-12 offer:    lno1zrxq8pjw7qjlm68mtp7e3yvxee4y5xrgjhhyf2fxhlphpckrvevh50u0…
On-chain address: bc1q4t2wxedqh6dn9kdxsmg9nllz9jnhykwwcy3r2z
Silent payment:   sp1qqvtg6a26w7ddww5t4t87sm729xzpqndcfnve0fu4tthp35gllm62kqcq…
  Network:        mainnet
  Version:        0

# Decode a BOLT-12 offer directly — no DNS involved:
$ bip353 decode lno1zr5qyugqgskrk70kqmuq7v3dnr2fnmhukps9n8hut...
Type:          offer
Node ID:       0386fe4a3bf04aea4124e1910f12559dd57c833998dd7d360dea61997651b11f84
Amount:        (payer sets amount)
Blinded paths: 1

# Decode a silent payment address:
$ bip353 decode sp1qqvtg6a26w7ddww5t4t87sm729xzpqndcfnve0fu4tthp35gllm62kqcq...
Network:   mainnet
Version:   0
Scan key:  02...
Spend key: 03...

# DoH — query names hidden from ISP, DNSSEC validation still local:
$ bip353 resolve --transport doh:cloudflare ₿matt@mattcorallo.com
Resolved: ₿matt@mattcorallo.com
Type:     lightning_bolt12
Reusable: true
DNSSEC:   true
Offer:    lno1zr5qyugqgskrk70kqmuq7v3dnr2fnmhukps9n8hut48vkqpqnskt2svsqwjakp7k6pyhtkuxw7y2kqmsxlwruhzqv0zsnhh9q3t9xhx39suc6qsr07ekm5esdyum0w66mnx8vdquwvp7dp5jp7j3v5cp6aj0w329fnkqqv60q96sz5nkrc5r95qffx002q53tqdk8x9m2tmt85jtpmcycvfnrpx3lr45h2g7na3sec7xguctfzzcm8jjqtj5ya27te60j03vpt0vq9tm2n9yxl2hngfnmygesa25s4u4zlxewqpvp94xt7rur4rhxunwkthk9vly3lm5hh0pqv4aymcqejlgssnlpzwlggykkajp7yjs5jvr2agkyypcdlj280cy46jpynsezrcj2kwa2lyr8xvd6lfkph4xrxtk2xc3lpq

# Tor — maximum privacy, requires Tor daemon at 127.0.0.1:9050, else error:
$ bip353 resolve --transport tor:cloudflare ₿matt@mattcorallo.com
error: bip353: DNS lookup for matt.user._bitcoin-payment.mattcorallo.com.: tor(127.0.0.1:9050): bip353/tor+doh: query failed: doh: all endpoints failed: request to https://cloudflare-dns.com/dns-query: Post "https://cloudflare-dns.com/dns-query": socks connect tcp 127.0.0.1:9050->cloudflare-dns.com:443: dial tcp 127.0.0.1:9050: connect: connection refused

# Print DNS name for manual verification:
$ bip353 dnsname ₿matt@mattcorallo.com
matt.user._bitcoin-payment.mattcorallo.com.

$ dig TXT matt.user._bitcoin-payment.mattcorallo.com.
...
;; ANSWER SECTION:
matt.user._bitcoin-payment.mattcorallo.com. 3594 IN TXT "as long as it doesn't start with bitcoin:, other records should be ignored"
matt.user._bitcoin-payment.mattcorallo.com. 3594 IN TXT "bitcoin:bc1qztwy6xen3zdtt7z0vrgapmjtfz8acjkfp5fp7l?lno=lno1zr5qyugqgskrk70kqmuq7v3dnr2fnmhukps9n8hut48vkqpqnskt2svsqwjakp7k6pyhtkuxw7y2kqmsxlwruhzqv0zsnhh9q3t9xhx39suc6..."

# Multiple bitcoin: records — rejected as ambiguous (DNS misconfiguration):
$ bip353 resolve ₿invalid@dnssec_proof_tests.bitcoin.ninja
error: bip353: multiple BIP-353 TXT records found at invalid.user._bitcoin-payment.dnssec_proof_tests.bitcoin.ninja. (2 records)

# Domain without DNSSEC — rejected:
$ bip353 resolve ₿bitnomad@blink.sv
error: bip353/direct: invalid DNS response: ProofBuildingError: Unauthenticated: \
  The server indicated the records we needed were not DNSSEC-authenticated
```

---

## Architecture
```
github.com/btc-go/bip353/
├── bip353.go              # Public API
├── bip353_test.go         # Unit tests (mock transport)
├── integration_test.go    # Integration tests (live DNS)
│
├── internal/
│   └── dnssec/            # dnssec-prover UniFFI bindings + precompiled static library
│
├── pkg/
│   ├── types/             # Core types, error sentinels, BIP-21 URI parser
│   ├── bolt12/            # BOLT-12 bech32 decoder + TLV stream parser
│   ├── silentpayment/     # BIP-352 bech32m decoder
│   ├── resolver/          # BIP-353 resolution logic
│   └── builder/           # BIP-21 URI builder
│
├── transport/
│   ├── transport.go       # Transport interface, FullValidationTransport
│   ├── doh.go             # DoHTransport (RFC 8484)
│   └── tor.go             # TorTransport (SOCKS5 + DoH)
│
└── cmd/
    └── bip353/            # CLI tool
```

- `Transport` is an interface — swap DNS backends without changing resolver logic.
- All errors are typed and `errors.Is`-compatible.
- No global state — all configuration is per-`Resolver`.
- BOLT-12 and Silent Payment decoding are non-fatal — the raw string is always available even if TLV parsing fails.
- Requires Go 1.22+.

---

## go vet

`go vet ./...` reports one `unsafe.Pointer` warning in `internal/dnssec/dnssec_prover.go`. This file is auto-generated UniFFI scaffolding for the Rust `dnssec-prover` library and is not subject to modification. The warning is a known limitation of UniFFI's Go bindings generator and does not affect correctness. The CI workflow excludes this package from `go vet`.

---

## Dependencies

| Package | Purpose |
|---------|---------|
| [`dnssec-prover`](https://github.com/TheBlueMatt/dnssec-prover) | Full local DNSSEC chain validation (UniFFI + static library) |
| [`github.com/miekg/dns`](https://github.com/miekg/dns) | DNS wire-format encoding/decoding |
| [`golang.org/x/net`](https://pkg.go.dev/golang.org/x/net) | SOCKS5 proxy for Tor routing; IDNA/punycode for international domain names |

The BOLT-12 decoder and BigSize/tu64 integer parsers are implemented from scratch with no external dependencies.

---

## License

MIT. See [LICENSE](LICENSE).

---

## References

- [BIP-353](https://github.com/bitcoin/bips/blob/master/bip-0353.mediawiki): DNS Payment Instructions
- [BIP-352](https://github.com/bitcoin/bips/blob/master/bip-0352.mediawiki): Silent Payments
- [BIP-321](https://github.com/bitcoin/bips/blob/master/bip-0321.mediawiki): URI Scheme
- [BOLT-12](https://github.com/lightning/bolts/blob/master/12-offer-encoding.md): Offer Protocol
- [RFC 8484](https://www.rfc-editor.org/rfc/rfc8484): DNS Queries over HTTPS
- [dnssec-prover](https://github.com/TheBlueMatt/dnssec-prover): Reference DNSSEC implementation