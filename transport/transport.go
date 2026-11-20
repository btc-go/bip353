package transport

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"strings"
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
const (
	maxProofQueries = 30
	maxLookupTime   = 45 * time.Second
)

func resolveWithProver(ctx context.Context, name, transportName string, sendQuery queryFunc) (res *QueryResult, err error) {
	defer func() {
		if r := recover(); r != nil {
			res, err = nil, fmt.Errorf("bip353/%s: dnssec prover panic: %v", transportName, r)
		}
	}()
	builder := dnssec.InitProofBuilder(name, dns.TypeTXT)
	if builder == nil || *builder == nil {
		return nil, fmt.Errorf("bip353/%s: failed to init proof builder for %s", transportName, name)
	}
	pb := *builder

	// Overall deadline so a black-holing resolver can't stall callers for minutes.
	ctx, cancel := context.WithTimeout(ctx, maxLookupTime)
	defer cancel()

	for i := 0; ; i++ {
		if i >= maxProofQueries {
			return nil, fmt.Errorf("bip353/%s: proof building exceeded %d queries for %s", transportName, maxProofQueries, name)
		}
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

	return parseProofResult(dnssec.VerifyByteStream(*proof, name), name, transportName)
}

func parseProofResult(resultJSON, name, transportName string) (*QueryResult, error) {
	records, ttl, err := ParseVerifiedJSON(resultJSON, name, time.Now())
	if err != nil {
		return nil, fmt.Errorf("bip353/%s: %w", transportName, err)
	}
	return &QueryResult{Transport: transportName, TTL: ttl, Records: records}, nil
}

// clockSkew tolerates small clock differences when checking RRSIG validity.
const clockSkew = 5 * time.Minute

// ParseVerifiedJSON parses dnssec-prover's verification output and returns the
// TXT records owned by name. Unlike the prover itself, it enforces the RRSIG
// validity window (valid_from/expires) so replayed stale proofs are rejected,
// and only accepts records whose owner name matches the requested name.
func ParseVerifiedJSON(resultJSON, name string, now time.Time) (records []string, ttl uint32, err error) {
	var vr struct {
		Error       string `json:"error"`
		ValidFrom   int64  `json:"valid_from"`
		Expires     int64  `json:"expires"`
		MaxCacheTTL uint32 `json:"max_cache_ttl"`
		VerifiedRRs []struct {
			Type     string `json:"type"`
			Name     string `json:"name"`
			Contents string `json:"contents"`
		} `json:"verified_rrs"`
	}
	if err := json.Unmarshal([]byte(resultJSON), &vr); err != nil {
		return nil, 0, fmt.Errorf("failed to parse proof result: %w", err)
	}
	if vr.Error != "" {
		return nil, 0, fmt.Errorf("DNSSEC validation failed: %s", vr.Error)
	}
	if vr.Expires == 0 {
		return nil, 0, fmt.Errorf("DNSSEC proof carries no validity window")
	}
	if now.Add(clockSkew).Unix() < vr.ValidFrom {
		return nil, 0, fmt.Errorf("DNSSEC proof is not yet valid")
	}
	if now.Add(-clockSkew).Unix() > vr.Expires {
		return nil, 0, fmt.Errorf("DNSSEC proof has expired")
	}
	ttl = vr.MaxCacheTTL
	if remaining := vr.Expires - now.Unix(); remaining < int64(ttl) {
		if remaining < 0 {
			remaining = 0
		}
		ttl = uint32(remaining)
	}
	want := strings.ToLower(strings.TrimSuffix(name, "."))
	for _, rr := range vr.VerifiedRRs {
		if rr.Type == "txt" && strings.ToLower(strings.TrimSuffix(rr.Name, ".")) == want {
			records = append(records, rr.Contents)
		}
	}
	return records, ttl, nil
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
	defer func() { _ = conn.Close() }()

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
			out = append(out, net.JoinHostPort(s, "53"))
		} else {
			out = append(out, s)
		}
	}
	return out
}
