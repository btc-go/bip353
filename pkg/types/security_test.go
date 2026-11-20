package types_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/btc-go/bip353/pkg/types"
)

func TestSanitizeText(t *testing.T) {
	got := types.SanitizeText("ok\x1b[2J\r\nnext‮evil")
	if strings.ContainsAny(got, "\x1b\r\n‮") {
		t.Errorf("control characters survived: %q", got)
	}
	if !strings.HasPrefix(got, "ok") {
		t.Errorf("normal text altered: %q", got)
	}
}

func TestParseHRARejectsUnsafeCharacters(t *testing.T) {
	for _, in := range []string{
		`a\.b@example.com`, `a"b@example.com`, "a b@example.com",
		"a.b@exa mple.com", `al@ice@example.com`, "alice͏@example.com", "ㅤ@example.com",
		"alice@exa\\mple.com", "alice@exa_mple..com",
	} {
		if _, err := types.ParseHumanReadableAddress(in); err == nil {
			t.Errorf("accepted %q", in)
		}
	}
}

func TestParseBIP21DuplicateParams(t *testing.T) {
	for _, uri := range []string{
		"bitcoin:?lno=a&lno=b", "bitcoin:?lno=a&LNO=b", "bitcoin:?sp=a&Sp=b",
	} {
		if _, err := types.ParseBIP21URI(uri); !errors.Is(err, types.ErrInvalidURI) {
			t.Errorf("%q: want ErrInvalidURI, got %v", uri, err)
		}
	}
	p, err := types.ParseBIP21URI("bitcoin:?bc=bc1qa&bc=bc1qb")
	if err != nil || len(p.Params["bc"]) != 2 {
		t.Errorf("repeated bc should be allowed: %v %v", p, err)
	}
}
