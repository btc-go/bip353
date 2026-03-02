// Package bip353 implements BIP-353: Human-Readable Bitcoin Payment Instructions.
//
// BIP-353 maps human-readable addresses like ₿alice@example.com to Bitcoin
// payment instructions stored in DNSSEC-signed DNS TXT records. This library
// resolves them with full local DNSSEC chain validation, BOLT-12 TLV decoding,
// BIP-352 Silent Payment address parsing, DNS-over-HTTPS, and optional Tor routing.
//
// # Quick Start
//
//	r, err := bip353.New()
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	inst, err := r.Resolve(ctx, "₿alice@example.com")
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	// Respect the DNS TTL when caching (BIP-353 requirement).
//	cacheFor := time.Duration(inst.TTL) * time.Second
//
//	switch inst.PaymentType {
//	case bip353.PaymentTypeLightningBOLT12:
//	    pay(inst.BOLT12Offer)
//	case bip353.PaymentTypeSilentPayment:
//	    pay(inst.SilentPaymentAddress)
//	case bip353.PaymentTypeLightningBOLT11:
//	    pay(inst.BOLT11Invoice)
//	case bip353.PaymentTypeOnChain:
//	    pay(inst.OnChainAddress)
//	}
//
// # Transports
//
// All transports perform full local DNSSEC chain validation via dnssec-prover —
// the reference implementation written by the BIP-353 author. The remote resolver
// is used only to relay raw DNS queries; its responses are fed into dnssec-prover
// for local verification. Clients MUST fully validate DNSSEC signatures leading
// to the DNS root and MUST NOT trust a remote resolver to validate on their behalf.
//
// Direct (default) — fastest, ISP may observe query names but cannot forge responses:
//
//	r, err := bip353.New()
//
// DNS-over-HTTPS — hides query names from your ISP:
//
//	r, err := bip353.NewWithDoH("cloudflare") // or "google", "quad9", "nextdns"
//	r, err = bip353.NewWithDoHURL("https://my-resolver.example.com/dns-query")
//
// Tor + DoH — maximum privacy, routes through SOCKS5 proxy, requires Tor daemon:
//
//	r, err := bip353.NewWithTor("127.0.0.1:9050", "cloudflare")
//
// Custom transport or nameservers:
//
//	opts := bip353.DefaultOptions()
//	opts.Transport = myTransport
//	r, err = bip353.NewWithOptions(opts)
//
// # Payment Types
//
// A resolved [PaymentInstruction] carries all recognised payment methods. The
// PaymentType field reflects the highest-priority method present:
// BOLT-12 > Silent Payment > BOLT-11 > on-chain.
//
//   - [PaymentTypeOnChain]         — P2PKH, P2SH, P2WPKH, or P2TR address
//   - [PaymentTypeLightningBOLT11] — BOLT-11 invoice
//   - [PaymentTypeLightningBOLT12] — BOLT-12 offer (see [BOLT12OfferDetails])
//   - [PaymentTypeSilentPayment]   — BIP-352 silent payment (see [SilentPaymentDetails])
//
// Multi-method records populate all fields simultaneously:
//
//	inst, _ := r.Resolve(ctx, "₿tips@example.com")
//	fmt.Println("BOLT-12:", inst.BOLT12Offer)
//	fmt.Println("Silent payment:", inst.SilentPaymentAddress)
//	fmt.Println("On-chain:", inst.OnChainAddress)
//	for _, addr := range inst.OnChainAddresses {
//	    fmt.Println("  segwit:", addr)
//	}
//
// # BOLT-12 Decoding
//
// BOLT-12 details are decoded from the full TLV stream and available on the
// [BOLT12OfferDetails] struct after resolution:
//
//	inst, _ := r.Resolve(ctx, "₿merchant@shop.example.com")
//	if inst.BOLT12Details != nil {
//	    d := inst.BOLT12Details
//	    fmt.Println("Type:", d.Type)        // offer | invoice_request | invoice
//	    fmt.Println("Description:", d.Description)
//	    fmt.Printf("Node ID: %s\n", d.NodeID)
//	    if d.AmountMsat > 0 {
//	        fmt.Printf("Amount: %d msat\n", d.AmountMsat)
//	    }
//	    fmt.Printf("Blinded paths: %d\n", len(d.Paths))
//	}
//
// For standalone decoding without DNS resolution, use [github.com/btc-go/bip353/pkg/bolt12]:
//
//	details, err := bolt12.DecodeOffer("lno1...")
//
// Unknown odd TLV types are silently skipped per the BOLT spec. The raw offer
// string is always available at inst.BOLT12Offer even if TLV parsing fails.
//
// # BIP-352 Silent Payment Decoding
//
// Silent payment details are decoded from the bech32m address:
//
//	inst, _ := r.Resolve(ctx, "₿alice@example.com")
//	if inst.SilentPaymentDetails != nil {
//	    d := inst.SilentPaymentDetails
//	    fmt.Println("Network:", d.Network)            // "mainnet", "testnet", "signet"
//	    fmt.Println("Version:", d.Version)            // 0
//	    fmt.Printf("Scan key:  %x\n", d.ScanPubkey)  // 33-byte compressed pubkey
//	    fmt.Printf("Spend key: %x\n", d.SpendPubkey) // 33-byte compressed pubkey
//	}
//
// For standalone decoding, use [github.com/btc-go/bip353/pkg/silentpayment]:
//
//	details, err := silentpayment.Decode("sp1...")
//
// # Error Handling
//
// All errors are typed sentinels compatible with errors.Is:
//
//	inst, err := r.Resolve(ctx, "₿alice@example.com")
//	switch {
//	case errors.Is(err, bip353.ErrNXDOMAIN):
//	    // No DNS record exists for this user.
//	case errors.Is(err, bip353.ErrAmbiguousRecord):
//	    // Multiple bitcoin: TXT records found — DNS misconfiguration.
//	case errors.Is(err, bip353.ErrNoRecord):
//	    // DNS name exists but has no bitcoin: TXT record.
//	case errors.Is(err, bip353.ErrRequiredParam):
//	    // URI contains a req- parameter this library does not understand.
//	case err != nil:
//	    // DNSSEC validation failure or network error.
//	}
//
// DNSSEC validation failures are returned directly from dnssec-prover and should
// be surfaced to the user. Never silently retry with a less secure transport.
//
// # Offline / Hardware Wallet Proof Verification
//
// [VerifyProof] validates an RFC 9102 DNSSEC proof offline without any network
// requests, intended for hardware wallet integration:
//
//	proof := // byte-stream proof produced by hardware wallet
//	inst, err := bip353.VerifyProof(proof, "₿alice@example.com")
//
// A proof for a different DNS name will not validate.
//
// # Building DNS TXT Records
//
// Use [NewURIBuilder] to construct BIP-21 URIs for publishing DNSSEC records:
//
//	uri, err := bip353.NewURIBuilder("bc1qyouraddress").
//	    WithBOLT12Offer("lno1...").
//	    WithSilentPayment("sp1...").
//	    Build()
//
// Publish the result as a TXT record on a DNSSEC-signed zone:
//
//	alice.user._bitcoin-payment.example.com. 300 IN TXT "bitcoin:bc1q...?lno=lno1..."
//
// # Sub-packages
//
// The root package re-exports everything needed for typical use cases.
// Internal implementation is split across focused sub-packages:
//
//   - [github.com/btc-go/bip353/pkg/resolver]      — BIP-353 DNS resolution logic
//   - [github.com/btc-go/bip353/pkg/types]          — Core types and error sentinels
//   - [github.com/btc-go/bip353/pkg/bolt12]         — BOLT-12 bech32 + TLV decoding
//   - [github.com/btc-go/bip353/pkg/silentpayment]  — BIP-352 bech32m decoding
//   - [github.com/btc-go/bip353/pkg/builder]        — BIP-21 URI builder
//   - [github.com/btc-go/bip353/transport]          — Pluggable transport interface (DoH, Tor)
package bip353
