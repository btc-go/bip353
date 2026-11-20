package transport

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// WellKnownDoHProviders maps short provider names to their RFC 8484 endpoints.
var WellKnownDoHProviders = map[string]string{
	"cloudflare": "https://cloudflare-dns.com/dns-query",
	"google":     "https://dns.google/dns-query",
	"quad9":      "https://dns.quad9.net/dns-query",
	"nextdns":    "https://dns.nextdns.io/dns-query",
}

// DoHTransport sends DNS queries over HTTPS (RFC 8484). Hides query names
// from your ISP. The DoH server is used only as a query relay — it is not
// trusted for DNSSEC validation. Chain validation always happens locally
// via dnssec-prover.
type DoHTransport struct {
	Endpoints []string
	Client    *http.Client
}

func NewDoHTransport(provider string) (*DoHTransport, error) {
	endpoint, ok := WellKnownDoHProviders[strings.ToLower(provider)]
	if !ok {
		return nil, fmt.Errorf("doh: unknown provider %q (known: cloudflare, google, quad9, nextdns)", provider)
	}
	return &DoHTransport{
		Endpoints: []string{endpoint},
		Client:    newHTTPClient(),
	}, nil
}

// noRedirect makes redirects fail (surfacing as a non-200 status) so a relay
// cannot bounce queries to another host or downgrade to plaintext.
func noRedirect(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

func newHTTPClient() *http.Client {
	return &http.Client{Timeout: DefaultTimeout, CheckRedirect: noRedirect}
}

func NewDoHTransportWithURL(endpoint string) (*DoHTransport, error) {
	u, err := url.ParseRequestURI(endpoint)
	if err != nil {
		return nil, fmt.Errorf("doh: invalid endpoint URL %q: %w", endpoint, err)
	}
	if u.Scheme != "https" || u.Host == "" {
		return nil, fmt.Errorf("doh: endpoint must be an https:// URL with a host: %q", endpoint)
	}
	return &DoHTransport{
		Endpoints: []string{endpoint},
		Client:    newHTTPClient(),
	}, nil
}

func (t *DoHTransport) LookupTXT(ctx context.Context, name string) (*QueryResult, error) {
	return resolveWithProver(ctx, name, "doh", t.sendQuery)
}

func (t *DoHTransport) sendQuery(ctx context.Context, query []byte) ([]byte, error) {
	client := t.Client
	if client == nil {
		client = newHTTPClient()
	}
	var lastErr error
	for _, endpoint := range t.Endpoints {
		resp, err := sendDoHQuery(ctx, client, endpoint, query)
		if err != nil {
			lastErr = err
			continue
		}
		return resp, nil
	}
	return nil, fmt.Errorf("doh: all endpoints failed: %w", lastErr)
}

// sendDoHQuery sends a raw DNS wire-format query via HTTP POST (RFC 8484)
// and returns the raw DNS wire-format response for dnssec-prover to process.
func sendDoHQuery(ctx context.Context, client *http.Client, endpoint string, query []byte) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(query))
	if err != nil {
		return nil, fmt.Errorf("building request: %w", err)
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request to %s: %w", endpoint, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d from %s", resp.StatusCode, endpoint)
	}

	const maxBody = 64 * 1024
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody+1))
	if err != nil {
		return nil, fmt.Errorf("reading response: %w", err)
	}
	if len(body) > maxBody {
		return nil, fmt.Errorf("response from %s too large", endpoint)
	}
	if len(body) < 12 || len(query) < 2 || body[0] != query[0] || body[1] != query[1] {
		return nil, fmt.Errorf("malformed or mismatched DNS response from %s", endpoint)
	}
	return body, nil
}
