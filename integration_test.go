package bip353_test

// Integration tests hit real DNS and require network access.
// They are excluded from normal `go test ./...` runs to keep CI fast.
//
// Run with:
//
//	go test -tags integration -v -timeout 30s ./...
//
// These tests depend on third-party DNS records staying stable.
// If a test fails, check the record still exists before assuming a bug:
//
//	dig TXT <user>.user._bitcoin-payment.<domain>. @8.8.8.8 +dnssec +short

import (
	"context"
	"errors"
	"testing"
	"time"

	bip353 "github.com/btc-go/bip353"
)

func integrationResolver(t *testing.T) *bip353.Resolver {
	t.Helper()
	r, err := bip353.NewSecure()
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func ctx(t *testing.T) context.Context {
	t.Helper()
	c, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	t.Cleanup(cancel)
	return c
}

// TestIntegration_MattCorallo is the canonical BIP-353 test case.
// matt@mattcorallo.com is maintained by the BIP author and should
// always resolve to a valid BOLT-12 offer with DNSSEC.
func TestIntegration_MattCorallo(t *testing.T) {
	inst, err := integrationResolver(t).Resolve(ctx(t), "matt@mattcorallo.com")
	if err != nil {
		t.Fatalf("matt@mattcorallo.com failed: %v", err)
	}
	if inst.PaymentType != bip353.PaymentTypeLightningBOLT12 {
		t.Errorf("type: got %s, want lightning_bolt12", inst.PaymentType)
	}
	if !inst.IsReusable {
		t.Error("BOLT-12 must be reusable")
	}
	if !inst.DNSSECValidated {
		t.Error("mattcorallo.com must have DNSSEC")
	}
	if inst.BOLT12Offer == "" {
		t.Error("BOLT12Offer must not be empty")
	}
	// Offer must start with lno1 (mainnet BOLT-12 bech32m prefix)
	if len(inst.BOLT12Offer) < 4 || inst.BOLT12Offer[:4] != "lno1" {
		t.Errorf("offer prefix: got %q, want lno1...", inst.BOLT12Offer[:min(4, len(inst.BOLT12Offer))])
	}
}

// TestIntegration_SimpleRecord tests the bc= param case from the BIP-353
// spec test domain. The record intentionally has a second TXT entry
// ("bitcoin is cool!") that must be ignored by the resolver.
func TestIntegration_SimpleRecord(t *testing.T) {
	const wantAddr = "bc1qztwy6xen3zdtt7z0vrgapmjtfz8acjkfp5fp7l"
	inst, err := integrationResolver(t).Resolve(ctx(t), "simple@dnssec_proof_tests.bitcoin.ninja")
	if err != nil {
		t.Fatalf("simple@dnssec_proof_tests.bitcoin.ninja failed: %v", err)
	}
	if inst.PaymentType != bip353.PaymentTypeOnChain {
		t.Errorf("type: got %s, want onchain", inst.PaymentType)
	}
	if inst.OnChainAddress != wantAddr {
		t.Errorf("address: got %q, want %q", inst.OnChainAddress, wantAddr)
	}
	if !inst.DNSSECValidated {
		t.Error("bitcoin.ninja must have DNSSEC")
	}
}

// TestIntegration_MultiMethod tests a record with BOLT-12, silent payment,
// and on-chain all present. tips@bip353.com is a well-known test address.
// All fields must be populated, not just the highest-priority one.
func TestIntegration_MultiMethod(t *testing.T) {
	inst, err := integrationResolver(t).Resolve(ctx(t), "tips@bip353.com")
	if err != nil {
		t.Fatalf("tips@bip353.com failed: %v", err)
	}
	if inst.PaymentType != bip353.PaymentTypeLightningBOLT12 {
		t.Errorf("type: got %s, want lightning_bolt12", inst.PaymentType)
	}
	if !inst.DNSSECValidated {
		t.Error("bip353.com must have DNSSEC")
	}
	// All three methods must be populated
	if inst.BOLT12Offer == "" {
		t.Error("BOLT12Offer must not be empty")
	}
	if inst.SilentPaymentAddress == "" {
		t.Error("SilentPaymentAddress must not be empty — record has sp= param")
	}
	if inst.OnChainAddress == "" {
		t.Error("OnChainAddress must not be empty — record has on-chain fallback")
	}
	// Silent payment must decode correctly
	if inst.SilentPaymentDetails == nil {
		t.Error("SilentPaymentDetails must be populated for a valid sp1 address")
	} else {
		if inst.SilentPaymentDetails.Network != "mainnet" {
			t.Errorf("network: got %q, want mainnet", inst.SilentPaymentDetails.Network)
		}
		if inst.SilentPaymentDetails.Version != 0 {
			t.Errorf("version: got %d, want 0", inst.SilentPaymentDetails.Version)
		}
	}
}

// TestIntegration_DNSSECRequired verifies that a domain without DNSSEC is
// rejected. blink.sv does not have DNSSEC configured on their zone.
func TestIntegration_DNSSECRequired(t *testing.T) {
	_, err := integrationResolver(t).Resolve(ctx(t), "bitnomad@blink.sv")
	if err == nil {
		t.Fatal("blink.sv has no DNSSEC — must be rejected")
	}
	if !errors.Is(err, bip353.ErrDNSSECRequired) {
		t.Errorf("expected ErrDNSSECRequired, got: %v", err)
	}
}

// TestIntegration_NXDOMAIN verifies a completely nonexistent user returns
// ErrNXDOMAIN and not a generic network error.
func TestIntegration_NXDOMAIN(t *testing.T) {
	_, err := integrationResolver(t).Resolve(ctx(t), "thisusercannotpossiblyexist99999@mattcorallo.com")
	if err == nil {
		t.Fatal("expected NXDOMAIN for nonexistent user")
	}
	if !errors.Is(err, bip353.ErrNXDOMAIN) {
		t.Errorf("expected ErrNXDOMAIN, got: %v", err)
	}
}

// TestIntegration_DoH verifies the DoH transport produces the same result
// as the classic transport for a known-good address.
func TestIntegration_DoH(t *testing.T) {
	r, err := bip353.NewWithDoH("cloudflare")
	if err != nil {
		t.Fatal(err)
	}
	inst, err := r.Resolve(ctx(t), "matt@mattcorallo.com")
	if err != nil {
		t.Fatalf("DoH resolve failed: %v", err)
	}
	if inst.PaymentType != bip353.PaymentTypeLightningBOLT12 {
		t.Errorf("DoH: type: got %s, want lightning_bolt12", inst.PaymentType)
	}
	if !inst.DNSSECValidated {
		t.Error("DoH: Cloudflare must return AD bit for mattcorallo.com")
	}
}

// TestIntegration_PrefixForms verifies all ₿ prefix variants resolve
// identically against a real DNS record.
func TestIntegration_PrefixForms(t *testing.T) {
	r := integrationResolver(t)
	forms := []string{
		"matt@mattcorallo.com",
		"₿matt@mattcorallo.com",
		"<20bf>matt@mattcorallo.com",
		"\u20bfmatt@mattcorallo.com",
	}
	var wantOffer string
	for i, form := range forms {
		inst, err := r.Resolve(ctx(t), form)
		if err != nil {
			t.Errorf("form %q failed: %v", form, err)
			continue
		}
		if i == 0 {
			wantOffer = inst.BOLT12Offer
		} else if inst.BOLT12Offer != wantOffer {
			t.Errorf("form %q: offer differs from baseline", form)
		}
	}
}

func TestIntegration_InvalidAmbiguous(t *testing.T) {
    _, err := integrationResolver(t).Resolve(ctx(t), "invalid@dnssec_proof_tests.bitcoin.ninja")
    if !errors.Is(err, bip353.ErrAmbiguousRecord) {
        t.Errorf("expected ErrAmbiguousRecord (two bitcoin: records, one mixed case), got: %v", err)
    }
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}