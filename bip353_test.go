package bip353_test

import (
	"context"
	"errors"
	"testing"

	bip353 "github.com/btc-go/bip353"
	"github.com/btc-go/bip353/transport"
)

// mockTransport lets us test resolver logic without hitting real DNS.
// In production, the transport guarantees DNSSEC chain validation.
// In tests, the mock returns whatever records we specify — testing
// resolver logic, not DNS or DNSSEC behaviour.
type mockTransport struct {
	records []string
	err     error
}

func (m *mockTransport) LookupTXT(_ context.Context, _ string) (*transport.QueryResult, error) {
	if m.err != nil {
		return nil, m.err
	}
	return &transport.QueryResult{
		Records:   m.records,
		Transport: "mock",
	}, nil
}

func newResolver(t *testing.T, mock *mockTransport) *bip353.Resolver {
	t.Helper()
	opts := bip353.DefaultOptions()
	opts.Transport = mock
	r, err := bip353.NewWithOptions(opts)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestResolve_BOLT12(t *testing.T) {
	r := newResolver(t, &mockTransport{
		records: []string{"bitcoin:?lno=lno1qcpjkuepqyz5ztest"},
	})
	inst, err := r.Resolve(context.Background(), "₿matt@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if inst.PaymentType != bip353.PaymentTypeLightningBOLT12 {
		t.Errorf("got %s, want lightning_bolt12", inst.PaymentType)
	}
	if inst.BOLT12Offer != "lno1qcpjkuepqyz5ztest" {
		t.Errorf("offer: got %q", inst.BOLT12Offer)
	}
	if !inst.IsReusable {
		t.Error("BOLT-12 offers are reusable")
	}
	if !inst.DNSSECValidated {
		t.Error("DNSSECValidated must always be true")
	}
}

func TestResolve_SilentPayment(t *testing.T) {
	r := newResolver(t, &mockTransport{
		records: []string{"bitcoin:?sp=sp1qqvtg6a26w7test"},
	})
	inst, err := r.Resolve(context.Background(), "₿alice@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if inst.PaymentType != bip353.PaymentTypeSilentPayment {
		t.Errorf("got %s, want silent_payment", inst.PaymentType)
	}
	if !inst.IsReusable {
		t.Error("silent payments are reusable")
	}
	if inst.SilentPaymentAddress != "sp1qqvtg6a26w7test" {
		t.Errorf("sp address: got %q", inst.SilentPaymentAddress)
	}
}

func TestResolve_BOLT11(t *testing.T) {
	r := newResolver(t, &mockTransport{
		records: []string{"bitcoin:bc1qlegacy?lightning=lnbc100n1test"},
	})
	inst, err := r.Resolve(context.Background(), "₿carol@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if inst.PaymentType != bip353.PaymentTypeLightningBOLT11 {
		t.Errorf("got %s, want lightning_bolt11", inst.PaymentType)
	}
	if inst.IsReusable {
		t.Error("BOLT-11 invoices are single-use")
	}
	if inst.BOLT11Invoice != "lnbc100n1test" {
		t.Errorf("invoice: got %q", inst.BOLT11Invoice)
	}
}

func TestResolve_OnChain(t *testing.T) {
	r := newResolver(t, &mockTransport{
		records: []string{"bitcoin:bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq"},
	})
	inst, err := r.Resolve(context.Background(), "₿dave@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if inst.PaymentType != bip353.PaymentTypeOnChain {
		t.Errorf("got %s, want onchain", inst.PaymentType)
	}
	if inst.OnChainAddress != "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq" {
		t.Errorf("address: got %q", inst.OnChainAddress)
	}
}

func TestResolve_BCParam(t *testing.T) {
	const addr = "bc1qztwy6xen3zdtt7z0vrgapmjtfz8acjkfp5fp7l"
	r := newResolver(t, &mockTransport{
		records: []string{"bitcoin:?bc=" + addr},
	})
	inst, err := r.Resolve(context.Background(), "₿simple@dnssec_proof_tests.bitcoin.ninja")
	if err != nil {
		t.Fatal(err)
	}
	if inst.OnChainAddress != addr {
		t.Errorf("OnChainAddress: got %q, want %q", inst.OnChainAddress, addr)
	}
}

func TestResolve_MultipleBCParams(t *testing.T) {
	const (
		addrV0 = "bc1qufgy354j3kmvuch987xe4s40836x3h0lg8f5n2"
		addrV1 = "bc1p5swkugezn97763tl0yty6556856uug0q6jflljvep9m4p7339x5qzyrh4g"
	)
	r := newResolver(t, &mockTransport{
		records: []string{"bitcoin:?bc=" + addrV0 + "&bc=" + addrV1},
	})
	inst, err := r.Resolve(context.Background(), "₿alice@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if len(inst.OnChainAddresses) != 2 {
		t.Fatalf("expected 2 bc= addresses, got %d", len(inst.OnChainAddresses))
	}
	if inst.OnChainAddresses[0] != addrV0 {
		t.Errorf("first: got %q, want %q", inst.OnChainAddresses[0], addrV0)
	}
	if inst.OnChainAddresses[1] != addrV1 {
		t.Errorf("second: got %q, want %q", inst.OnChainAddresses[1], addrV1)
	}
}

func TestResolve_Priority(t *testing.T) {
	r := newResolver(t, &mockTransport{
		records: []string{"bitcoin:bc1qfallback?lno=lno1offer&sp=sp1addr&lightning=lnbc1inv"},
	})
	inst, err := r.Resolve(context.Background(), "₿alice@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if inst.PaymentType != bip353.PaymentTypeLightningBOLT12 {
		t.Errorf("BOLT-12 must win priority: got %s", inst.PaymentType)
	}
	if inst.BOLT12Offer != "lno1offer" {
		t.Errorf("BOLT12Offer: got %q", inst.BOLT12Offer)
	}
	if inst.SilentPaymentAddress != "sp1addr" {
		t.Errorf("SilentPaymentAddress: got %q", inst.SilentPaymentAddress)
	}
	if inst.BOLT11Invoice != "lnbc1inv" {
		t.Errorf("BOLT11Invoice: got %q", inst.BOLT11Invoice)
	}
	if inst.OnChainAddress != "bc1qfallback" {
		t.Errorf("OnChainAddress: got %q", inst.OnChainAddress)
	}
}

func TestResolve_IgnoresNonBitcoinTXT(t *testing.T) {
	const addr = "bc1qztwy6xen3zdtt7z0vrgapmjtfz8acjkfp5fp7l"
	r := newResolver(t, &mockTransport{
		records: []string{
			"bitcoin:?bc=" + addr,
			"bitcoin is cool!",
		},
	})
	inst, err := r.Resolve(context.Background(), "₿simple@dnssec_proof_tests.bitcoin.ninja")
	if err != nil {
		t.Fatalf("junk TXT record caused failure (should be ignored): %v", err)
	}
	if inst.OnChainAddress != addr {
		t.Errorf("OnChainAddress: got %q, want %q", inst.OnChainAddress, addr)
	}
}

func TestResolve_AmbiguousRecords(t *testing.T) {
	r := newResolver(t, &mockTransport{
		records: []string{"bitcoin:bc1qaddr1", "bitcoin:bc1qaddr2"},
	})
	_, err := r.Resolve(context.Background(), "₿alice@example.com")
	if !errors.Is(err, bip353.ErrAmbiguousRecord) {
		t.Errorf("expected ErrAmbiguousRecord, got: %v", err)
	}
}

func TestResolve_NoRecord(t *testing.T) {
	r := newResolver(t, &mockTransport{
		records: []string{"v=spf1 include:example.com ~all"},
	})
	_, err := r.Resolve(context.Background(), "₿alice@example.com")
	if !errors.Is(err, bip353.ErrNoRecord) {
		t.Errorf("expected ErrNoRecord, got: %v", err)
	}
}

func TestResolve_RequiredParamRejected(t *testing.T) {
	r := newResolver(t, &mockTransport{
		records: []string{"bitcoin:bc1qaddr?req-futureparam=value"},
	})
	_, err := r.Resolve(context.Background(), "₿alice@example.com")
	if !errors.Is(err, bip353.ErrRequiredParam) {
		t.Errorf("expected ErrRequiredParam, got: %v", err)
	}
}

func TestResolve_NXDOMAIN(t *testing.T) {
	r := newResolver(t, &mockTransport{
		err: errors.New("NXDOMAIN: alice.user._bitcoin-payment.example.com."),
	})
	_, err := r.Resolve(context.Background(), "₿alice@example.com")
	if !errors.Is(err, bip353.ErrNXDOMAIN) {
		t.Errorf("expected ErrNXDOMAIN, got: %v", err)
	}
}

func TestResolve_PrefixStripping(t *testing.T) {
	mock := &mockTransport{
		records: []string{"bitcoin:bc1qaddr"},
	}
	forms := []string{
		"₿alice@example.com",
		"\u20bfalice@example.com",
		"<20bf>alice@example.com",
		"alice@example.com",
	}
	for _, input := range forms {
		t.Run(input, func(t *testing.T) {
			r := newResolver(t, mock)
			inst, err := r.Resolve(context.Background(), input)
			if err != nil {
				t.Fatalf("prefix form %q failed: %v", input, err)
			}
			if inst.OriginalAddress.User != "alice" {
				t.Errorf("user: got %q, want alice", inst.OriginalAddress.User)
			}
		})
	}
}

func TestDNSNameFor(t *testing.T) {
	tests := []struct {
		input   string
		want    string
		wantErr bool
	}{
		{"₿alice@example.com", "alice.user._bitcoin-payment.example.com.", false},
		{"₿ALICE@example.com", "alice.user._bitcoin-payment.example.com.", false},
		{"₿bob@pay.example.com", "bob.user._bitcoin-payment.pay.example.com.", false},
		{"₿simple@dnssec_proof_tests.bitcoin.ninja", "simple.user._bitcoin-payment.dnssec_proof_tests.bitcoin.ninja.", false},
		{"aliceexample.com", "", true},
		{"alice@bob@example.com", "", true},
	}
	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			got, err := bip353.DNSNameFor(tc.input)
			if tc.wantErr {
				if err == nil {
					t.Errorf("expected error for %q", tc.input)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Errorf("got  %q\nwant %q", got, tc.want)
			}
		})
	}
}

func TestResolve_RawTXTRecord(t *testing.T) {
	const raw = "bitcoin:bc1qaddr?lno=lno1offer"
	r := newResolver(t, &mockTransport{
		records: []string{raw},
	})
	inst, err := r.Resolve(context.Background(), "₿alice@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if inst.RawTXTRecord != raw {
		t.Errorf("RawTXTRecord: got %q, want %q", inst.RawTXTRecord, raw)
	}
}
