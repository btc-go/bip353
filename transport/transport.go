package transport

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/miekg/dns"
)

const DefaultTimeout = 10 * time.Second

type QueryResult struct {
	Records       []string
	Authenticated bool
	Transport     string
	TTL           uint32
}

type Transport interface {
	LookupTXT(ctx context.Context, name string) (*QueryResult, error)
}

type ClassicTransport struct {
	Nameservers []string
	Timeout     time.Duration
}

var DefaultNameservers = []string{
	"1.1.1.1:53",
	"1.0.0.1:53",
	"8.8.8.8:53",
	"9.9.9.9:53",
}

func NewClassicTransport() *ClassicTransport {
	return &ClassicTransport{Nameservers: DefaultNameservers, Timeout: DefaultTimeout}
}

func NewClassicTransportWithNameservers(nameservers []string) *ClassicTransport {
	return &ClassicTransport{Nameservers: nameservers, Timeout: DefaultTimeout}
}

func (t *ClassicTransport) LookupTXT(ctx context.Context, name string) (*QueryResult, error) {
	msg := newDNSSECQuery(name, dns.TypeTXT)
	timeout := t.Timeout
	if timeout == 0 {
		timeout = DefaultTimeout
	}
	client := &dns.Client{Net: "tcp", Timeout: timeout}
	resp, err := t.tryAll(ctx, client, msg)
	if err != nil {
		client.Net = "udp"
		resp, err = t.tryAll(ctx, client, msg)
		if err != nil {
			return nil, fmt.Errorf("classic DNS: all resolvers failed: %w", err)
		}
	}
	return parseResponse(resp, "classic")
}

func (t *ClassicTransport) tryAll(ctx context.Context, client *dns.Client, msg *dns.Msg) (*dns.Msg, error) {
	var lastErr error
	for _, ns := range t.Nameservers {
		resp, _, err := client.ExchangeContext(ctx, msg, ns)
		if err != nil {
			lastErr = fmt.Errorf("%s: %w", ns, err)
			continue
		}
		if resp != nil {
			return resp, nil
		}
	}
	return nil, lastErr
}

func newDNSSECQuery(name string, qtype uint16) *dns.Msg {
	msg := new(dns.Msg)
	msg.SetQuestion(name, qtype)
	msg.SetEdns0(4096, true)
	msg.RecursionDesired = true
	msg.CheckingDisabled = false
	return msg
}

func parseResponse(resp *dns.Msg, transportName string) (*QueryResult, error) {
	if resp.Rcode == dns.RcodeNameError {
		if len(resp.Question) > 0 {
			return nil, fmt.Errorf("NXDOMAIN: %s", resp.Question[0].Name)
		}
		return nil, fmt.Errorf("NXDOMAIN")
	}
	if resp.Rcode != dns.RcodeSuccess {
		return nil, fmt.Errorf("DNS error: %s", dns.RcodeToString[resp.Rcode])
	}
	result := &QueryResult{
		Authenticated: resp.AuthenticatedData,
		Transport:     transportName,
		TTL:           ^uint32(0),
	}
	for _, rr := range resp.Answer {
		txt, ok := rr.(*dns.TXT)
		if !ok {
			continue
		}
		if rr.Header().Ttl < result.TTL {
			result.TTL = rr.Header().Ttl
		}
		result.Records = append(result.Records, joinTXT(txt.Txt))
	}
	if result.TTL == ^uint32(0) {
		result.TTL = 0
	}
	return result, nil
}


func joinTXT(parts []string) string {
	switch len(parts) {
	case 0:
		return ""
	case 1:
		return parts[0]
	default:
		n := 0
		for _, p := range parts {
			n += len(p)
		}
		b := make([]byte, 0, n)
		for _, p := range parts {
			b = append(b, p...)
		}
		return string(b)
	}
}

// SystemNameservers reads /etc/resolv.conf and returns nameservers in host:port format.
// Falls back to DefaultNameservers if reading fails.
func SystemNameservers() []string {
	cfg, err := dns.ClientConfigFromFile("/etc/resolv.conf")
	if err != nil || len(cfg.Servers) == 0 {
		return DefaultNameservers
	}
	out := make([]string, 0, len(cfg.Servers))
	for _, s := range cfg.Servers {
		if net.ParseIP(s) != nil {
			out = append(out, s+":53")
		} else {
			out = append(out, s)
		}
	}
	return out
}