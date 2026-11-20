package bolt12

import "testing"

func TestDecodeNoPanicOnNonASCII(t *testing.T) {
	for _, s := range []string{"lno1Āabc", "lno1qq\xff", "lno1é"} {
		if _, err := DecodeOffer(s); err == nil {
			t.Errorf("expected error for %q", s)
		}
	}
}
