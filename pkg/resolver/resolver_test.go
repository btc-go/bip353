package resolver

import (
	"context"
	"testing"

	"github.com/btc-go/bip353/pkg/types"
	"github.com/btc-go/bip353/transport"
)

type countingTransport struct{ calls int }

func (c *countingTransport) LookupTXT(context.Context, string) (*transport.QueryResult, error) {
	c.calls++
	return nil, nil
}

func TestResolveHRAValidatesInput(t *testing.T) {
	ct := &countingTransport{}
	r := New(Options{Transport: ct})
	for _, hra := range []types.HumanReadableAddress{
		{User: "a.b\x00", Domain: "example.com"},
		{User: "alice", Domain: "exa mple.com"},
		{User: "", Domain: "example.com"},
	} {
		if _, err := r.ResolveHRA(context.Background(), hra); err == nil {
			t.Errorf("accepted %+v", hra)
		}
	}
	if ct.calls != 0 {
		t.Errorf("transport called %d times for invalid input", ct.calls)
	}
}

func TestParseVerifiedProofSizeLimits(t *testing.T) {
	hra := types.HumanReadableAddress{User: "alice", Domain: "example.com"}
	if _, err := ParseVerifiedProof(nil, hra); err == nil {
		t.Error("empty proof accepted")
	}
	if _, err := ParseVerifiedProof(make([]byte, maxProofBytes+1), hra); err == nil {
		t.Error("oversized proof accepted")
	}
}
