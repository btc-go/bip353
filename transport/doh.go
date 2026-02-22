package transport

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/miekg/dns"
)

var WellKnownDoHProviders = map[string]string{
	"cloudflare": "https://cloudflare-dns.com/dns-query",
	"google":     "https://dns.google/dns-query",
	"quad9":      "https://dns.quad9.net/dns-query",
	"nextdns":    "https://dns.nextdns.io/dns-query",
}

type DoHFormat uint8

const (
	DoHFormatWire DoHFormat = iota
	DoHFormatJSON
)

type DoHTransport struct {
	Endpoints []string
	Format    DoHFormat
	Client    *http.Client
}

func NewDoHTransport(provider string) (*DoHTransport, error) {
	endpoint, ok := WellKnownDoHProviders[strings.ToLower(provider)]
	if !ok {
		return nil, fmt.Errorf("doh: unknown provider %q", provider)
	}
	return &DoHTransport{
		Endpoints: []string{endpoint},
		Format:    DoHFormatWire,
		Client:    &http.Client{Timeout: DefaultTimeout},
	}, nil
}

func NewDoHTransportWithURL(endpoint string) (*DoHTransport, error) {
	if _, err := url.ParseRequestURI(endpoint); err != nil {
		return nil, fmt.Errorf("doh: invalid endpoint URL %q: %w", endpoint, err)
	}
	return &DoHTransport{
		Endpoints: []string{endpoint},
		Format:    DoHFormatWire,
		Client:    &http.Client{Timeout: DefaultTimeout},
	}, nil
}

func (t *DoHTransport) LookupTXT(ctx context.Context, name string) (*QueryResult, error) {
	client := t.Client
	if client == nil {
		client = &http.Client{Timeout: DefaultTimeout}
	}
	var lastErr error
	for _, endpoint := range t.Endpoints {
		var result *QueryResult
		var err error
		if t.Format == DoHFormatJSON {
			result, err = t.queryJSON(ctx, client, endpoint, name)
		} else {
			result, err = t.queryWire(ctx, client, endpoint, name)
		}
		if err != nil {
			lastErr = err
			continue
		}
		return result, nil
	}
	return nil, fmt.Errorf("doh: all endpoints failed: %w", lastErr)
}

func (t *DoHTransport) queryWire(ctx context.Context, client *http.Client, endpoint, name string) (*QueryResult, error) {
	msg := newDNSSECQuery(name, dns.TypeTXT)
	wire, err := msg.Pack()
	if err != nil {
		return nil, fmt.Errorf("doh: packing query: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(wire))
	if err != nil {
		return nil, fmt.Errorf("doh: building request: %w", err)
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("doh: request to %s: %w", endpoint, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("doh: HTTP %d from %s", resp.StatusCode, endpoint)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return nil, fmt.Errorf("doh: reading response: %w", err)
	}
	var dnsResp dns.Msg
	if err := dnsResp.Unpack(body); err != nil {
		return nil, fmt.Errorf("doh: unpacking response: %w", err)
	}
	return parseResponse(&dnsResp, "doh-wire")
}

func (t *DoHTransport) queryJSON(ctx context.Context, client *http.Client, endpoint, name string) (*QueryResult, error) {
	reqURL := fmt.Sprintf("%s?name=%s&type=TXT&do=1&cd=0",
		endpoint, url.QueryEscape(strings.TrimSuffix(name, ".")))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, fmt.Errorf("doh-json: building request: %w", err)
	}
	req.Header.Set("Accept", "application/dns-json")
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("doh-json: request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("doh-json: HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return nil, fmt.Errorf("doh-json: reading response: %w", err)
	}
	return parseJSONResponse(body)
}

type dohJSONResponse struct {
	Status int             `json:"Status"`
	AD     bool            `json:"AD"`
	Answer []dohJSONRecord `json:"Answer"`
}

type dohJSONRecord struct {
	Type uint16 `json:"type"`
	Data string `json:"data"`
}

func parseJSONResponse(body []byte) (*QueryResult, error) {
	var resp dohJSONResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("doh-json: parsing response: %w", err)
	}
	if resp.Status == dns.RcodeNameError {
		return nil, fmt.Errorf("NXDOMAIN")
	}
	if resp.Status != dns.RcodeSuccess {
		return nil, fmt.Errorf("DNS error: rcode %d", resp.Status)
	}
	result := &QueryResult{Authenticated: resp.AD, Transport: "doh-json"}
	for _, rec := range resp.Answer {
		if rec.Type != dns.TypeTXT {
			continue
		}
		data := rec.Data
		if strings.Contains(data, `" "`) {
			parts := strings.Split(data, `" "`)
			cleaned := make([]string, len(parts))
			for i, p := range parts {
				cleaned[i] = strings.Trim(p, `"`)
			}
			data = strings.Join(cleaned, "")
		} else {
			data = strings.Trim(data, `"`)
		}
		result.Records = append(result.Records, data)
	}
	return result, nil
}