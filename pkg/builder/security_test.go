package builder_test

import (
	"strings"
	"testing"

	"github.com/btc-go/bip353/pkg/builder"
	"github.com/btc-go/bip353/pkg/types"
)

func TestBuildCannotSmuggleParams(t *testing.T) {
	uri, err := builder.NewURIBuilder("bc1qxyz").WithParam("label", "a&amount=5&lno=evil").Build()
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := types.ParseBIP21URI(uri)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Params.Get("amount") != "" || parsed.Params.Get("lno") != "" {
		t.Errorf("injected params in %q", uri)
	}
	if parsed.Params.Get("label") != "a&amount=5&lno=evil" {
		t.Errorf("label not preserved: %q", parsed.Params.Get("label"))
	}
}

func TestBuildRejectsBadKeysAndAddresses(t *testing.T) {
	if _, err := builder.NewURIBuilder("bc1q").WithParam("a=b&c", "x").Build(); err == nil {
		t.Error("bad key accepted")
	}
	for _, addr := range []string{"bc1q?amount=1", "bc1q&x", "bc1q x", "bc1q#f"} {
		if _, err := builder.NewURIBuilder(addr).Build(); err == nil {
			t.Errorf("address %q accepted", addr)
		}
	}
	uri := builder.NewURIBuilder("bc1qxyz").MustBuild()
	if !strings.HasPrefix(uri, "bitcoin:bc1qxyz") {
		t.Errorf("unexpected %q", uri)
	}
}
