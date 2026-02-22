package bip353_test

import (
	"context"
	"errors"
	"testing"

	bip353 "github.com/btc-go/bip353"
	"github.com/btc-go/bip353/transport"
)

// mockTransport lets us test resolver logic without hitting real DNS.
type mockTransport struct {
	records       []string
	authenticated bool
	err           error
}

func (m *mockTransport) LookupTXT(_ context.Context, _ string) (*transport.QueryResult, error) {
	if m.err != nil {
		return nil, m.err
	}
	return &transport.QueryResult{
		Records:       m.records,
		Authenticated: m.authenticated,
		Transport:     "mock",
	}, nil
}

func newResolver(t *testing.T, mock *mockTransport, allowInsecure bool) *bip353.Resolver {
	t.Helper()
	opts := bip353.DefaultOptions()
	opts.Transport = mock
	opts.AllowInsecure = allowInsecure
	r, err := bip353.New(opts)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestResolve_BOLT12(t *testing.T) {
	r := newResolver(t, &mockTransport{
		records:       []string{"bitcoin:?lno=lno1qcpjkuepqyz5ztest"},
		authenticated: true,
	}, false)
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
		t.Error("BOLT-12 offers are reusable by definition")
	}
	if !inst.DNSSECValidated {
		t.Error("AD bit was set, DNSSECValidated must be true")
	}
}

func TestResolve_SilentPayment(t *testing.T) {
	// sp1 is mainnet BIP-352. No on-chain fallback intentional.
	r := newResolver(t, &mockTransport{
		records:       []string{"bitcoin:?sp=sp1qqvtg6a26w7test"},
		authenticated: true,
	}, false)
	inst, err := r.Resolve(context.Background(), "₿alice@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if inst.PaymentType != bip353.PaymentTypeSilentPayment {
		t.Errorf("got %s, want silent_payment", inst.PaymentType)
	}
	if !inst.IsReusable {
		t.Error("silent payments are reusable (new address per sender, same recipient code)")
	}
	if inst.SilentPaymentAddress != "sp1qqvtg6a26w7test" {
		t.Errorf("sp address: got %q", inst.SilentPaymentAddress)
	}
}

func TestResolve_BOLT11(t *testing.T) {
	r := newResolver(t, &mockTransport{
		records:       []string{"bitcoin:bc1qlegacy?lightning=lnbc100n1test"},
		authenticated: true,
	}, false)
	inst, err := r.Resolve(context.Background(), "₿carol@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if inst.PaymentType != bip353.PaymentTypeLightningBOLT11 {
		t.Errorf("got %s, want lightning_bolt11", inst.PaymentType)
	}
	if inst.IsReusable {
		t.Error("BOLT-11 invoices are single-use, IsReusable must be false")
	}
	if inst.BOLT11Invoice != "lnbc100n1test" {
		t.Errorf("invoice: got %q", inst.BOLT11Invoice)
	}
}

func TestResolve_OnChain_AddressField(t *testing.T) {
	r := newResolver(t, &mockTransport{
		records:       []string{"bitcoin:bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq"},
		authenticated: true,
	}, false)
	inst, err := r.Resolve(context.Background(), "₿dave@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if inst.PaymentType != bip353.PaymentTypeOnChain {
		t.Errorf("got %s, want onchain", inst.PaymentType)
	}
	if inst.IsReusable {
		t.Error("plain on-chain address reuse is bad practice, IsReusable must be false")
	}
	if inst.OnChainAddress != "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq" {
		t.Errorf("address: got %q", inst.OnChainAddress)
	}
}


func TestResolve_BCParam(t *testing.T) {
	const addr = "bc1qztwy6xen3zdtt7z0vrgapmjtfz8acjkfp5fp7l"
	r := newResolver(t, &mockTransport{
		records:       []string{"bitcoin:?bc=" + addr},
		authenticated: true,
	}, false)
	inst, err := r.Resolve(context.Background(), "₿simple@dnssec_proof_tests.bitcoin.ninja")
	if err != nil {
		t.Fatal(err)
	}
	if inst.OnChainAddress != addr {
		t.Errorf("OnChainAddress: got %q, want %q", inst.OnChainAddress, addr)
	}
	if len(inst.OnChainAddresses) != 1 || inst.OnChainAddresses[0] != addr {
		t.Errorf("OnChainAddresses: got %v", inst.OnChainAddresses)
	}
}

// TestResolve_MultipleBCParams: BIP-321 allows multiple bc= values so a wallet
// can pick its preferred segwit version (e.g. offer both P2WPKH and P2TR).
func TestResolve_MultipleBCParams(t *testing.T) {
	const (
		addrV0 = "bc1qufgy354j3kmvuch987xe4s40836x3h0lg8f5n2"
		addrV1 = "bc1p5swkugezn97763tl0yty6556856uug0q6jflljvep9m4p7339x5qzyrh4g"
	)
	r := newResolver(t, &mockTransport{
		records:       []string{"bitcoin:?bc=" + addrV0 + "&bc=" + addrV1},
		authenticated: true,
	}, false)
	inst, err := r.Resolve(context.Background(), "₿alice@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if len(inst.OnChainAddresses) != 2 {
		t.Fatalf("expected 2 bc= addresses, got %d: %v", len(inst.OnChainAddresses), inst.OnChainAddresses)
	}
	if inst.OnChainAddresses[0] != addrV0 {
		t.Errorf("first address: got %q, want %q", inst.OnChainAddresses[0], addrV0)
	}
	if inst.OnChainAddresses[1] != addrV1 {
		t.Errorf("second address: got %q, want %q", inst.OnChainAddresses[1], addrV1)
	}
	if inst.OnChainAddress != addrV0 {
		t.Errorf("OnChainAddress (compat field): got %q, want %q", inst.OnChainAddress, addrV0)
	}
}


// TestResolve_Priority verifies the order mandated by BIP-353 / BIP-321:
// BOLT-12 > Silent Payment > BOLT-11 > on-chain.
func TestResolve_Priority(t *testing.T) {
	r := newResolver(t, &mockTransport{
		records: []string{
			"bitcoin:bc1qfallback?lno=lno1offer&sp=sp1addr&lightning=lnbc1inv",
		},
		authenticated: true,
	}, false)
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


// TestResolve_IgnoresNonBitcoinTXT is the exact case hit against
// simple@dnssec_proof_tests.bitcoin.ninja, which has two TXT records: one valid bitcoin: record and one junk record. The resolver must ignore the junk
func TestResolve_IgnoresNonBitcoinTXT(t *testing.T) {
	const addr = "bc1qztwy6xen3zdtt7z0vrgapmjtfz8acjkfp5fp7l"
	r := newResolver(t, &mockTransport{
		records: []string{
			"bitcoin:?bc=" + addr,
			"bitcoin is cool!",
		},
		authenticated: true,
	}, false)
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
		records: []string{
			"bitcoin:bc1qaddr1",
			"bitcoin:bc1qaddr2",
		},
		authenticated: true,
	}, false)
	_, err := r.Resolve(context.Background(), "₿alice@example.com")
	if !errors.Is(err, bip353.ErrAmbiguousRecord) {
		t.Errorf("expected ErrAmbiguousRecord, got: %v", err)
	}
}

func TestResolve_NoRecord(t *testing.T) {
	// Domain exists (no NXDOMAIN) but has no bitcoin: TXT record.
	r := newResolver(t, &mockTransport{
		records:       []string{"v=spf1 include:example.com ~all"},
		authenticated: true,
	}, false)
	_, err := r.Resolve(context.Background(), "₿alice@example.com")
	if !errors.Is(err, bip353.ErrNoRecord) {
		t.Errorf("expected ErrNoRecord, got: %v", err)
	}
}


// TestResolve_RequiredParamRejected: BIP-321 says if a URI contains a req-
// prefixed parameter the client doesn't understand, the entire URI must be
// rejected. This is to allow future extensions without risking silent downgrades. In this test, the mock transport returns a record with a made-up required parameter. The resolver must reject it with ErrRequiredParam.
func TestResolve_RequiredParamRejected(t *testing.T) {
	r := newResolver(t, &mockTransport{
		records:       []string{"bitcoin:bc1qaddr?req-futureparam=value"},
		authenticated: true,
	}, false)
	_, err := r.Resolve(context.Background(), "₿alice@example.com")
	if err == nil {
		t.Fatal("req- param must cause URI rejection per BIP-321")
	}
	if !errors.Is(err, bip353.ErrRequiredParam) {
		t.Errorf("expected ErrRequiredParam, got: %v", err)
	}
}


func TestResolve_DNSSECRequired(t *testing.T) {
	// AD bit not set — resolver must reject, not silently downgrade.
	// Returning ErrDNSSECRequired lets callers surface this to the user
	// rather than silently paying to a potentially spoofed address.
	r := newResolver(t, &mockTransport{
		records:       []string{"bitcoin:bc1qaddr"},
		authenticated: false,
	}, false)
	_, err := r.Resolve(context.Background(), "₿alice@example.com")
	if err == nil {
		t.Fatal("must reject when AD bit is not set")
	}
	if !errors.Is(err, bip353.ErrDNSSECRequired) {
		t.Errorf("expected ErrDNSSECRequired, got: %v", err)
	}
}

func TestResolve_AllowInsecure(t *testing.T) {
	// AllowInsecure is for testing only — DNSSECValidated must reflect
	// reality (false) even when the resolver proceeds anyway.
	r := newResolver(t, &mockTransport{
		records:       []string{"bitcoin:bc1qaddr"},
		authenticated: false,
	}, true)
	inst, err := r.Resolve(context.Background(), "₿alice@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if inst.DNSSECValidated {
		t.Error("DNSSECValidated must be false when AD bit is not set")
	}
}

func TestResolve_NXDOMAIN(t *testing.T) {
	r := newResolver(t, &mockTransport{
		err: errors.New("NXDOMAIN: alice.user._bitcoin-payment.example.com."),
	}, false)
	_, err := r.Resolve(context.Background(), "₿alice@example.com")
	if !errors.Is(err, bip353.ErrNXDOMAIN) {
		t.Errorf("expected ErrNXDOMAIN, got: %v", err)
	}
}


// TestResolve_PrefixStripping: the ₿ prefix appears in three forms in the wild.
// All must be stripped before DNS lookup.
func TestResolve_PrefixStripping(t *testing.T) {
	mock := &mockTransport{
		records:       []string{"bitcoin:bc1qaddr"},
		authenticated: true,
	}
	forms := []string{
		"₿alice@example.com",      
		"\u20bfalice@example.com", 
		"<20bf>alice@example.com", 
		"alice@example.com",      
	}
	for _, input := range forms {
		t.Run(input, func(t *testing.T) {
			r := newResolver(t, mock, false)
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
		records:       []string{raw},
		authenticated: true,
	}, false)
	inst, err := r.Resolve(context.Background(), "₿alice@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if inst.RawTXTRecord != raw {
		t.Errorf("RawTXTRecord: got %q, want %q", inst.RawTXTRecord, raw)
	}
}