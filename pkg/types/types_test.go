package types_test

import (
	"errors"
	"testing"

	"github.com/btc-go/bip353/pkg/types"
)

func TestParseHumanReadableAddress(t *testing.T) {
	tests := []struct {
		input      string
		wantUser   string
		wantDomain string
		wantErr    bool
	}{
		{"₿alice@example.com", "alice", "example.com", false},
		{"alice@example.com", "alice", "example.com", false},
		{"₿bob@pay.example.com", "bob", "pay.example.com", false},
		{"₿alice-smith@example.com", "alice-smith", "example.com", false},
		{"₿user123@example.com", "user123", "example.com", false},
		{"<20bf>alice@example.com", "alice", "example.com", false},
		{"\u20bfalice@example.com", "alice", "example.com", false},
		{"₿alice@xn--nxasmq6b.com", "alice", "xn--nxasmq6b.com", false},
		{"₿ALICE@example.com", "ALICE", "example.com", false},
		{"₿simple@dnssec_proof_tests.bitcoin.ninja", "simple", "dnssec_proof_tests.bitcoin.ninja", false},

		// Error cases
		{"₿aliceexample.com", "", "", true},
		{"₿a@b@example.com", "", "", true},
		{"₿@example.com", "", "", true},
		{"₿alice@", "", "", true},
		{"₿alice@localhost", "", "", true},
		{"", "", "", true},
		{"₿ali ce@example.com", "", "", true},
		// Homograph attack — Cyrillic 'а' (U+0430) looks identical to Latin 'a'.
		{"₿аlice@example.com", "", "", true},
		// Mixed-script domain homograph.
		{"₿alice@еxample.com", "", "", true},
	}
	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			hra, err := types.ParseHumanReadableAddress(tc.input)
			if tc.wantErr {
				if err == nil {
					t.Errorf("expected error for %q", tc.input)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error for %q: %v", tc.input, err)
			}
			if hra.User != tc.wantUser {
				t.Errorf("user: got %q, want %q", hra.User, tc.wantUser)
			}
			if hra.Domain != tc.wantDomain {
				t.Errorf("domain: got %q, want %q", hra.Domain, tc.wantDomain)
			}
		})
	}
}

func TestHRADNSName(t *testing.T) {
	tests := []struct {
		user   string
		domain string
		want   string
	}{
		{"alice", "example.com", "alice.user._bitcoin-payment.example.com."},
		{"ALICE", "example.com", "alice.user._bitcoin-payment.example.com."},
		{"bob", "pay.example.com", "bob.user._bitcoin-payment.pay.example.com."},
		{"alice", "example.com.", "alice.user._bitcoin-payment.example.com."},
		{"simple", "dnssec_proof_tests.bitcoin.ninja", "simple.user._bitcoin-payment.dnssec_proof_tests.bitcoin.ninja."},
	}
	for _, tc := range tests {
		hra := types.HumanReadableAddress{User: tc.user, Domain: tc.domain}
		if got := hra.DNSName(); got != tc.want {
			t.Errorf("DNSName(%q, %q)\ngot  %q\nwant %q", tc.user, tc.domain, got, tc.want)
		}
	}
}

func TestHRAString(t *testing.T) {
	hra := types.HumanReadableAddress{User: "alice", Domain: "example.com"}
	if got := hra.String(); got != "₿alice@example.com" {
		t.Errorf("String() = %q, want ₿alice@example.com", got)
	}
}

func TestParseBIP21URI(t *testing.T) {
	tests := []struct {
		input      string
		wantAddr   string
		wantParams map[string]string
		wantErr    bool
	}{
		{"bitcoin:bc1qexample", "bc1qexample", nil, false},
		{"bitcoin:?lno=lno1example", "", map[string]string{"lno": "lno1example"}, false},
		{"bitcoin:bc1qaddr?lno=lno1offer&lightning=lnbc1inv", "bc1qaddr", map[string]string{"lno": "lno1offer", "lightning": "lnbc1inv"}, false},
		{"bitcoin:?sp=sp1addr", "", map[string]string{"sp": "sp1addr"}, false},
		{"bitcoin:?bc=bc1qnative", "", map[string]string{"bc": "bc1qnative"}, false},
		{"BITCOIN:BC1QADDR", "BC1QADDR", nil, false},
		{"", "", nil, true},
		{"http://example.com", "", nil, true},
	}
	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			parsed, err := types.ParseBIP21URI(tc.input)
			if tc.wantErr {
				if err == nil {
					t.Errorf("expected error for %q", tc.input)
				}
				if err != nil && !errors.Is(err, types.ErrInvalidURI) {
					t.Errorf("expected ErrInvalidURI, got: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error for %q: %v", tc.input, err)
			}
			if parsed.Address != tc.wantAddr {
				t.Errorf("address: got %q, want %q", parsed.Address, tc.wantAddr)
			}
			for k, want := range tc.wantParams {
				if got := parsed.Params.Get(k); got != want {
					t.Errorf("param[%q]: got %q, want %q", k, got, want)
				}
			}
		})
	}
}

func TestParseBIP21URI_CaseInsensitiveKeys(t *testing.T) {
	uri := "BITCOIN:?BC=BC1QUFGY354J3KMVUCH987XE4S40836X3H0LG8F5N2"
	parsed, err := types.ParseBIP21URI(uri)
	if err != nil {
		t.Fatalf("uppercase URI failed: %v", err)
	}
	if got := parsed.Params.Get("bc"); got == "" {
		t.Error("BC= param not accessible as bc= after key normalization")
	}
}

func TestParseBIP21URI_RequiredParam(t *testing.T) {
	cases := []struct {
		uri     string
		wantErr bool
	}{
		{"bitcoin:bc1q?req-futurepaymentmethod=value", true},
		{"bitcoin:bc1q?req-pop=callbackapp%3a", false},
	}
	for _, tc := range cases {
		t.Run(tc.uri, func(t *testing.T) {
			_, err := types.ParseBIP21URI(tc.uri)
			if tc.wantErr && err == nil {
				t.Errorf("expected error for %q", tc.uri)
			}
			if !tc.wantErr && err != nil {
				t.Errorf("unexpected error for %q: %v", tc.uri, err)
			}
			if tc.wantErr && err != nil && !errors.Is(err, types.ErrRequiredParam) {
				t.Errorf("expected ErrRequiredParam, got: %v", err)
			}
		})
	}
}

func TestDetectPaymentType(t *testing.T) {
	tests := []struct {
		name         string
		uri          string
		wantType     types.PaymentType
		wantReusable bool
		wantErr      bool
	}{
		{"bolt12 only", "bitcoin:?lno=lno1x", types.PaymentTypeLightningBOLT12, true, false},
		{"silent payment", "bitcoin:?sp=sp1x", types.PaymentTypeSilentPayment, true, false},
		{"bolt11 with fallback", "bitcoin:bc1q?lightning=lnbc1x", types.PaymentTypeLightningBOLT11, false, false},
		{"onchain address field", "bitcoin:bc1qaddr", types.PaymentTypeOnChain, false, false},
		{"onchain bc= param", "bitcoin:?bc=bc1qnative", types.PaymentTypeOnChain, false, false},
		{"all methods bolt12 wins", "bitcoin:?lno=x&sp=y&lightning=z", types.PaymentTypeLightningBOLT12, true, false},
		{"empty", "bitcoin:", types.PaymentTypeUnknown, false, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			parsed, err := types.ParseBIP21URI(tc.uri)
			if err != nil {
				t.Fatalf("parse error: %v", err)
			}
			pt, reusable, err := types.DetectPaymentType(parsed)
			if tc.wantErr {
				if err == nil {
					t.Errorf("expected error")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if pt != tc.wantType {
				t.Errorf("type: got %s, want %s", pt, tc.wantType)
			}
			if reusable != tc.wantReusable {
				t.Errorf("reusable: got %v, want %v", reusable, tc.wantReusable)
			}
		})
	}
}
