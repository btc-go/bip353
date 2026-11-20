package transport

import (
	"testing"
	"time"
)

func TestParseVerifiedJSON(t *testing.T) {
	now := time.Unix(1000000, 0)
	mk := func(vf, ex int64, name string) string {
		return `{"valid_from": ` + itoa(vf) + `, "expires": ` + itoa(ex) + `, "max_cache_ttl": 3600, "verified_rrs": [{"type":"txt","name":"` + name + `","contents":"x"}]}`
	}
	if r, ttl, err := ParseVerifiedJSON(mk(999000, 1001000, "a.b."), "a.b.", now); err != nil || len(r) != 1 || ttl != 1000 {
		t.Fatalf("valid: %v %v %v", r, ttl, err)
	}
	if _, _, err := ParseVerifiedJSON(mk(1, 2, "a.b."), "a.b.", now); err == nil {
		t.Error("expired proof accepted")
	}
	if _, _, err := ParseVerifiedJSON(mk(2000000, 3000000, "a.b."), "a.b.", now); err == nil {
		t.Error("not-yet-valid proof accepted")
	}
	if r, _, _ := ParseVerifiedJSON(mk(999000, 1001000, "other.b."), "a.b.", now); len(r) != 0 {
		t.Error("foreign-name record accepted")
	}
}

func TestDoHRequiresHTTPS(t *testing.T) {
	if _, err := NewDoHTransportWithURL("http://x/dns-query"); err == nil {
		t.Error("http endpoint accepted")
	}
}

func itoa(i int64) string { return fmtInt(i) }
func fmtInt(i int64) string {
	if i == 0 {
		return "0"
	}
	s := ""
	for ; i > 0; i /= 10 {
		s = string(rune('0'+i%10)) + s
	}
	return s
}
