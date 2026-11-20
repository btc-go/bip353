package builder

import (
	"fmt"
	"net/url"
	"strings"
)

// URIBuilder constructs BIP-21 URIs for BIP-353 DNS TXT records.
// Use method chaining to set fields, then call Build().
type URIBuilder struct {
	address    string
	params     []param
	paramIndex map[string]int
}

type param struct {
	key, value string
}

func NewURIBuilder(onChainAddress string) *URIBuilder {
	return &URIBuilder{
		address:    onChainAddress,
		paramIndex: make(map[string]int),
	}
}

func (b *URIBuilder) WithBOLT12Offer(offer string) *URIBuilder {
	return b.set("lno", offer)
}

func (b *URIBuilder) WithBOLT11Invoice(invoice string) *URIBuilder {
	return b.set("lightning", invoice)
}

func (b *URIBuilder) WithSilentPayment(spAddress string) *URIBuilder {
	return b.set("sp", spAddress)
}

func (b *URIBuilder) WithPayJoin(pjURL string) *URIBuilder {
	return b.set("pj", pjURL)
}

func (b *URIBuilder) WithParam(key, value string) *URIBuilder {
	return b.set(key, value)
}

// Build returns the BIP-21 URI string.
// BIP-21 does not percent-encode parameter values; they are transmitted as-is
// after the '?' separator. This preserves BOLT-12 offer strings verbatim.
func (b *URIBuilder) Build() (string, error) {
	if b.address == "" && len(b.params) == 0 {
		return "", fmt.Errorf("bip21: URI must have an address or at least one parameter")
	}
	if strings.ContainsAny(b.address, "?&#%= \t\r\n\x00") {
		return "", fmt.Errorf("bip21: address contains invalid characters")
	}
	for _, p := range b.params {
		if p.key == "" || strings.IndexFunc(p.key, func(r rune) bool {
			return !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '.' || r == '_' || r == '-')
		}) >= 0 {
			return "", fmt.Errorf("bip21: invalid parameter key %q", p.key)
		}
	}
	var sb strings.Builder
	sb.WriteString("bitcoin:")
	sb.WriteString(b.address)
	for i, p := range b.params {
		if i == 0 {
			sb.WriteByte('?')
		} else {
			sb.WriteByte('&')
		}
		sb.WriteString(p.key)
		sb.WriteByte('=')
		sb.WriteString(escapeValue(p.value))
	}
	return sb.String(), nil
}

func (b *URIBuilder) MustBuild() string {
	uri, err := b.Build()
	if err != nil {
		panic("bip21: " + err.Error())
	}
	return uri
}

func (b *URIBuilder) set(key, value string) *URIBuilder {
	if idx, exists := b.paramIndex[key]; exists {
		b.params[idx].value = value
	} else {
		b.paramIndex[key] = len(b.params)
		b.params = append(b.params, param{key, value})
	}
	return b
}

// escapeValue percent-encodes a parameter value so it cannot terminate or
// inject other parameters. Bech32 strings (lno, sp) are unaffected.
func escapeValue(v string) string {
	r := strings.NewReplacer("&", "%26", "=", "%3D")
	return r.Replace(url.PathEscape(v))
}
