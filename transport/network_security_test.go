package transport

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestTorRefusesRemoteProxy(t *testing.T) {
	t.Setenv("BIP353_ALLOW_REMOTE_TOR_PROXY", "")
	if _, err := NewTorTransport("203.0.113.5:9050", "cloudflare"); err == nil {
		t.Error("remote proxy accepted")
	}
	if _, err := NewTorTransport("127.0.0.1:9050", "cloudflare"); err != nil {
		t.Errorf("loopback proxy rejected: %v", err)
	}
	t.Setenv("BIP353_ALLOW_REMOTE_TOR_PROXY", "1")
	if _, err := NewTorTransport("203.0.113.5:9050", "cloudflare"); err != nil {
		t.Errorf("override ignored: %v", err)
	}
}

func TestDoHDoesNotFollowRedirects(t *testing.T) {
	hit := false
	target := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hit = true }))
	defer target.Close()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusTemporaryRedirect)
	}))
	defer srv.Close()
	client := srv.Client()
	client.CheckRedirect = noRedirect
	if _, err := sendDoHQuery(context.Background(), client, srv.URL, make([]byte, 12)); err == nil {
		t.Error("redirect treated as success")
	}
	if hit {
		t.Error("redirect target was contacted")
	}
}

func TestDoHRejectsMismatchedResponse(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte{9, 9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0})
	}))
	defer srv.Close()
	if _, err := sendDoHQuery(context.Background(), srv.Client(), srv.URL, []byte{1, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}); err == nil {
		t.Error("response with wrong transaction ID accepted")
	}
}
