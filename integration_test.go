package bip353_test

// Run with:
//
//	go test -tags integration -v -timeout 60s ./...
//
// If a test fails, verify the record still exists before assuming a bug:
//
//	dig TXT <user>.user._bitcoin-payment.<domain>. @8.8.8.8 +dnssec +short

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	bip353 "github.com/btc-go/bip353"
)

func integrationResolver(t *testing.T) *bip353.Resolver {
	t.Helper()
	r, err := bip353.New()
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func ctx(t *testing.T) context.Context {
	t.Helper()
	c, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	return c
}

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
		t.Error("DNSSECValidated must always be true")
	}
	if inst.BOLT12Offer == "" {
		t.Error("BOLT12Offer must not be empty")
	}
	if len(inst.BOLT12Offer) < 4 || inst.BOLT12Offer[:4] != "lno1" {
		t.Errorf("offer must start with lno1, got: %q", inst.BOLT12Offer[:min(4, len(inst.BOLT12Offer))])
	}
}

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
		t.Error("DNSSECValidated must always be true")
	}
}

func TestIntegration_MultiMethod(t *testing.T) {
	inst, err := integrationResolver(t).Resolve(ctx(t), "tips@bip353.com")
	if err != nil {
		t.Fatalf("tips@bip353.com failed: %v", err)
	}
	if inst.PaymentType != bip353.PaymentTypeLightningBOLT12 {
		t.Errorf("type: got %s, want lightning_bolt12", inst.PaymentType)
	}
	if inst.BOLT12Offer == "" {
		t.Error("BOLT12Offer must not be empty")
	}
	if inst.SilentPaymentAddress == "" {
		t.Error("SilentPaymentAddress must not be empty")
	}
	if inst.OnChainAddress == "" {
		t.Error("OnChainAddress must not be empty")
	}
	if inst.SilentPaymentDetails == nil {
		t.Error("SilentPaymentDetails must be populated")
	} else {
		if inst.SilentPaymentDetails.Network != "mainnet" {
			t.Errorf("network: got %q, want mainnet", inst.SilentPaymentDetails.Network)
		}
		if inst.SilentPaymentDetails.Version != 0 {
			t.Errorf("version: got %d, want 0", inst.SilentPaymentDetails.Version)
		}
	}
}

func TestIntegration_NoDNSSEC(t *testing.T) {
	_, err := integrationResolver(t).Resolve(ctx(t), "bitnomad@blink.sv")
	if err == nil {
		t.Fatal("blink.sv has no DNSSEC — must be rejected")
	}
	t.Logf("correctly rejected: %v", err)
}

func TestIntegration_NXDOMAIN(t *testing.T) {
	_, err := integrationResolver(t).Resolve(ctx(t), "thisusercannotpossiblyexist99999@mattcorallo.com")
	if err == nil {
		t.Fatal("expected NXDOMAIN for nonexistent user")
	}
	if !errors.Is(err, bip353.ErrNXDOMAIN) {
		t.Errorf("expected ErrNXDOMAIN, got: %v", err)
	}
}

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
		t.Errorf("DoH type: got %s, want lightning_bolt12", inst.PaymentType)
	}
	if !inst.DNSSECValidated {
		t.Error("DNSSECValidated must always be true")
	}
}

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


func TestIntegration_AmbiguousRecord(t *testing.T) {
	_, err := integrationResolver(t).Resolve(ctx(t), "invalid@dnssec_proof_tests.bitcoin.ninja")
	if !errors.Is(err, bip353.ErrAmbiguousRecord) {
		t.Errorf("expected ErrAmbiguousRecord, got: %v", err)
	}
}


func TestIntegration_Punycode(t *testing.T) {
	dnsName, err := bip353.DNSNameFor("alice@bücher.example")
	if err != nil {
		t.Fatalf("DNSNameFor failed: %v", err)
	}
	if strings.Contains(dnsName, "ü") {
		t.Errorf("DNS name contains raw non-ASCII: %q", dnsName)
	}
	if !strings.Contains(dnsName, "xn--") {
		t.Errorf("DNS name missing punycode xn-- prefix: %q", dnsName)
	}
	t.Logf("punycode DNS name: %s", dnsName)
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}