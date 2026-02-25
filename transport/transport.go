package transport

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/btc-go/bip353/internal/dnssec"
	"github.com/miekg/dns"
)

const DefaultTimeout = 10 * time.Second

// QueryResult is the result of a fully DNSSEC-validated DNS TXT lookup.
// Every result returned by any transport in this package has been verified
// against the full chain from the DNS root via dnssec-prover.
type QueryResult struct {
	Records   []string
	Transport string
	TTL       uint32
}

// Transport resolves DNS TXT records with full DNSSEC chain validation.
type Transport interface {
	LookupTXT(ctx context.Context, name string) (*QueryResult, error)
}

// queryFunc sends a single raw DNS wire-format query and returns a raw response.
// dnssec-prover drives the query loop; the transport only handles the wire protocol.
type queryFunc func(ctx context.Context, query []byte) ([]byte, error)

// DefaultNameservers are public resolvers used when no custom ones are provided.
var DefaultNameservers = []string{
	"1.1.1.1:53",
	"1.0.0.1:53",
	"8.8.8.8:53",
	"9.9.9.9:53",
}

// resolveWithProver runs the dnssec-prover proof-building loop using sendQuery
// to exchange raw DNS messages. All transports go through this — chain
// validation always happens locally, never delegated to the remote resolver.
func resolveWithProver(ctx context.Context, name, transportName string, sendQuery queryFunc) (*QueryResult, error) {
	builder := dnssec.InitProofBuilder(name, dns.TypeTXT)
	if builder == nil || *builder == nil {
		return nil, fmt.Errorf("bip353/%s: failed to init proof builder for %s", transportName, name)
	}
	pb := *builder

	for {
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("bip353/%s: %w", transportName, ctx.Err())
		default:
		}

		query := pb.GetNextQuery()
		if query == nil {
			break
		}

		resp, err := sendQuery(ctx, *query)
		if err != nil {
			return nil, fmt.Errorf("bip353/%s: query failed: %w", transportName, err)
		}

		if err := pb.ProcessQueryResponse(resp); err != nil {
			return nil, fmt.Errorf("bip353/%s: invalid DNS response: %w", transportName, err)
		}
	}

	proof := pb.GetUnverifiedProof()
	if proof == nil {
		return nil, fmt.Errorf("NXDOMAIN: %s", name)
	}

	return parseProofResult(dnssec.VerifyByteStream(*proof, name), transportName)
}

func parseProofResult(resultJSON, transportName string) (*QueryResult, error) {
	var vr struct {
		Error       string `json:"error"`
		MaxCacheTTL uint32 `json:"max_cache_ttl"`
		VerifiedRRs []struct {
			Type     string `json:"type"`
			Contents string `json:"contents"`
		} `json:"verified_rrs"`
	}
	if err := json.Unmarshal([]byte(resultJSON), &vr); err != nil {
		return nil, fmt.Errorf("bip353/%s: failed to parse proof result: %w", transportName, err)
	}
	if vr.Error != "" {
		return nil, fmt.Errorf("bip353/%s: DNSSEC validation failed: %s", transportName, vr.Error)
	}
	result := &QueryResult{
		Transport: transportName,
		TTL:       vr.MaxCacheTTL,
	}
	for _, rr := range vr.VerifiedRRs {
		if rr.Type == "txt" {
			result.Records = append(result.Records, rr.Contents)
		}
	}
	return result, nil
}

// FullValidationTransport is the default transport. Sends DNS queries directly
// over TCP to public resolvers. Full DNSSEC chain validation via dnssec-prover.
type FullValidationTransport struct {
	Nameservers []string
	Timeout     time.Duration
}

func NewFullValidationTransport() *FullValidationTransport {
	return &FullValidationTransport{
		Nameservers: DefaultNameservers,
		Timeout:     DefaultTimeout,
	}
}

func NewFullValidationTransportWithNameservers(nameservers []string) *FullValidationTransport {
	return &FullValidationTransport{
		Nameservers: nameservers,
		Timeout:     DefaultTimeout,
	}
}

func (t *FullValidationTransport) LookupTXT(ctx context.Context, name string) (*QueryResult, error) {
	return resolveWithProver(ctx, name, "direct", t.sendQuery)
}

func (t *FullValidationTransport) sendQuery(ctx context.Context, query []byte) ([]byte, error) {
	timeout := t.Timeout
	if timeout == 0 {
		timeout = DefaultTimeout
	}
	var lastErr error
	for _, ns := range t.Nameservers {
		resp, err := sendTCPQuery(ctx, query, ns, timeout)
		if err != nil {
			lastErr = err
			continue
		}
		return resp, nil
	}
	return nil, fmt.Errorf("all nameservers failed: %w", lastErr)
}

// sendTCPQuery sends a raw DNS wire-format query over TCP using the standard
// 2-byte big-endian length prefix and returns the raw response bytes.
func sendTCPQuery(ctx context.Context, query []byte, server string, timeout time.Duration) ([]byte, error) {
	d := net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, "tcp", server)
	if err != nil {
		return nil, fmt.Errorf("%s: connect: %w", server, err)
	}
	defer conn.Close()

	if timeout > 0 {
		if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
			return nil, fmt.Errorf("%s: set deadline: %w", server, err)
		}
	}

	msgLen := len(query)
	if msgLen > 65535 {
		return nil, fmt.Errorf("query too large: %d bytes", msgLen)
	}
	buf := make([]byte, 2+msgLen)
	buf[0] = byte(msgLen >> 8)
	buf[1] = byte(msgLen)
	copy(buf[2:], query)

	if _, err := conn.Write(buf); err != nil {
		return nil, fmt.Errorf("%s: write: %w", server, err)
	}

	lenBuf := make([]byte, 2)
	if _, err := io.ReadFull(conn, lenBuf); err != nil {
		return nil, fmt.Errorf("%s: read length prefix: %w", server, err)
	}
	respLen := int(lenBuf[0])<<8 | int(lenBuf[1])
	if respLen == 0 {
		return nil, fmt.Errorf("%s: empty response", server)
	}
	if respLen > 65535 {
		return nil, fmt.Errorf("%s: response too large: %d bytes", server, respLen)
	}

	resp := make([]byte, respLen)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return nil, fmt.Errorf("%s: read response: %w", server, err)
	}
	return resp, nil
}

// SystemNameservers reads /etc/resolv.conf and returns nameservers in host:port
// format. Falls back to DefaultNameservers if reading fails.
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