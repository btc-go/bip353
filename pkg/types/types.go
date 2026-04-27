package types

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
	"unicode"

	"golang.org/x/net/idna"
)

var (
	ErrNXDOMAIN        = errors.New("DNS name not found (NXDOMAIN)")
	ErrAmbiguousRecord = errors.New("multiple BIP-353 TXT records found")
	ErrNoRecord        = errors.New("no BIP-353 TXT record found")
	ErrInvalidURI      = errors.New("invalid BIP-21 URI")
	ErrNoPaymentMethod = errors.New("no recognized payment method in URI")
	ErrRequiredParam   = errors.New("unsupported required parameter (req- prefix)")
)

type PaymentType uint8

const (
	PaymentTypeUnknown         PaymentType = 0
	PaymentTypeOnChain         PaymentType = 1
	PaymentTypeLightningBOLT11 PaymentType = 2
	PaymentTypeLightningBOLT12 PaymentType = 3
	PaymentTypeSilentPayment   PaymentType = 4
)

func (p PaymentType) String() string {
	switch p {
	case PaymentTypeOnChain:
		return "onchain"
	case PaymentTypeLightningBOLT11:
		return "lightning_bolt11"
	case PaymentTypeLightningBOLT12:
		return "lightning_bolt12"
	case PaymentTypeSilentPayment:
		return "silent_payment"
	default:
		return "unknown"
	}
}

type BOLT12Type uint8

const (
	BOLT12TypeOffer          BOLT12Type = 0
	BOLT12TypeInvoiceRequest BOLT12Type = 1
	BOLT12TypeInvoice        BOLT12Type = 2
)

func (t BOLT12Type) String() string {
	switch t {
	case BOLT12TypeOffer:
		return "offer"
	case BOLT12TypeInvoiceRequest:
		return "invoice_request"
	case BOLT12TypeInvoice:
		return "invoice"
	default:
		return "unknown"
	}
}

type HumanReadableAddress struct {
	User   string
	Domain string
}

func (h HumanReadableAddress) String() string {
	return fmt.Sprintf("₿%s@%s", h.User, h.Domain)
}

// DNSName returns the fully-qualified DNS name for this address per BIP-353.
// Non-ASCII components are encoded as punycode using the UTS#46 lookup profile.
func (h HumanReadableAddress) DNSName() string {
	user := strings.ToLower(h.User)
	domain := h.Domain

	if !isASCII(user) {
		if encoded, err := idna.Lookup.ToASCII(user); err == nil {
			user = encoded
		}
	}

	if !isASCII(domain) {
		d := strings.TrimSuffix(domain, ".")
		if encoded, err := idna.Lookup.ToASCII(d); err == nil {
			domain = encoded
		}
	}

	if !strings.HasSuffix(domain, ".") {
		domain += "."
	}
	return fmt.Sprintf("%s.user._bitcoin-payment.%s", user, domain)
}

type PaymentInstruction struct {
	OriginalAddress      HumanReadableAddress
	RawTXTRecord         string
	URI                  string
	PaymentType          PaymentType
	IsReusable           bool
	DNSSECValidated      bool
	TTL                  uint32
	OnChainAddress       string
	OnChainAddresses     []string
	BOLT11Invoice        string
	BOLT12Offer          string
	BOLT12Details        *BOLT12OfferDetails
	SilentPaymentAddress string
	SilentPaymentDetails *SilentPaymentDetails
	ExtraParams          map[string]string
}

type BOLT12OfferDetails struct {
	Type           BOLT12Type
	Description    string
	NodeID         string
	Currency       string
	AmountMsat     uint64
	Issuer         string
	QuantityMax    uint64
	AbsoluteExpiry uint64
	Features       []byte
	Paths          []BlindedPath
	RawChains      []byte
	RawMetadata    []byte
	RawSignature   []byte
}

type BlindedPath struct {
	IntroductionNodeID []byte
	BlindingPoint      []byte
	Hops               []BlindedHop
}

type BlindedHop struct {
	BlindedNodeID          []byte
	EncryptedRecipientData []byte
}

type SilentPaymentDetails struct {
	Network     string
	ScanPubkey  []byte
	SpendPubkey []byte
	Version     byte
}

type ParsedBIP21 struct {
	Address string
	Params  url.Values
}

func ParseHumanReadableAddress(addr string) (HumanReadableAddress, error) {
	if addr == "" {
		return HumanReadableAddress{}, fmt.Errorf("address cannot be empty")
	}
	cleaned := strings.TrimPrefix(addr, "₿")
	cleaned = strings.TrimPrefix(cleaned, "\u20bf")
	cleaned = strings.TrimPrefix(cleaned, "<20bf>")
	if strings.Count(cleaned, "@") != 1 {
		return HumanReadableAddress{}, fmt.Errorf("address must contain exactly one '@': %q", addr)
	}
	at := strings.Index(cleaned, "@")
	user, domain := cleaned[:at], cleaned[at+1:]
	if err := validateUser(user); err != nil {
		return HumanReadableAddress{}, fmt.Errorf("invalid user %q: %w", user, err)
	}
	if err := validateDomain(domain); err != nil {
		return HumanReadableAddress{}, fmt.Errorf("invalid domain %q: %w", domain, err)
	}
	return HumanReadableAddress{User: user, Domain: domain}, nil
}

func validateUser(user string) error {
	if user == "" {
		return fmt.Errorf("user part cannot be empty")
	}
	if len(user) > 63 {
		return fmt.Errorf("user part exceeds 63 bytes (%d)", len(user))
	}
	if !isASCII(user) {
		if err := rejectMixedScript(user); err != nil {
			return err
		}
	}
	for _, r := range user {
		if unicode.IsSpace(r) || r == '@' || r == '\x00' || unicode.Is(unicode.Cf, r) || unicode.Is(unicode.Cc, r) {
			return fmt.Errorf("user part contains invalid character: %q", r)
		}
	}
	return nil
}

func validateDomain(domain string) error {
	if domain == "" {
		return fmt.Errorf("domain cannot be empty")
	}
	d := strings.TrimSuffix(domain, ".")
	if !isASCII(d) {
		for _, label := range strings.Split(d, ".") {
			if !isASCII(label) {
				if err := rejectMixedScript(label); err != nil {
					return fmt.Errorf("domain label %q: %w", label, err)
				}
			}
		}
		if _, err := idna.Lookup.ToASCII(d); err != nil {
			return fmt.Errorf("invalid international domain name: %w", err)
		}
	}
	if len(d) > 253 {
		return fmt.Errorf("domain exceeds 253 bytes")
	}
	labels := strings.Split(d, ".")
	if len(labels) < 2 {
		return fmt.Errorf("domain must have at least two labels")
	}
	for _, label := range labels {
		if label == "" || len(label) > 63 {
			return fmt.Errorf("domain label %q is invalid", label)
		}
		if isASCII(label) {
			if !isAlphaNum(rune(label[0])) || !isAlphaNum(rune(label[len(label)-1])) {
				return fmt.Errorf("domain label %q must start and end with an alphanumeric character", label)
			}
		}
	}
	return nil
}

// rejectMixedScript returns an error if s mixes characters from more than one
// Unicode script. A purely Cyrillic or purely Latin string is fine; mixing the
// two is a classic homograph attack vector (e.g. Cyrillic 'а' vs Latin 'a').
// Common and Inherited are neutral scripts (digits, punctuation) and are ignored.
func rejectMixedScript(s string) error {
	scripts := make(map[string]bool)
	for _, r := range s {
		for name, table := range unicode.Scripts {
			if unicode.Is(table, r) {
				scripts[name] = true
				break
			}
		}
	}
	delete(scripts, "Common")
	delete(scripts, "Inherited")
	if len(scripts) > 1 {
		return fmt.Errorf("mixes multiple Unicode scripts (possible homograph attack)")
	}
	return nil
}

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] > 127 {
			return false
		}
	}
	return true
}

func isAlphaNum(r rune) bool {
	return (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9')
}

func normalizeParams(params url.Values) url.Values {
	normalized := make(url.Values, len(params))
	for k, v := range params {
		normalized[strings.ToLower(k)] = v
	}
	return normalized
}

func ParseBIP21URI(uri string) (*ParsedBIP21, error) {
	if uri == "" {
		return nil, fmt.Errorf("%w: empty string", ErrInvalidURI)
	}
	if !strings.HasPrefix(strings.ToLower(uri), "bitcoin:") {
		return nil, fmt.Errorf("%w: must start with 'bitcoin:'", ErrInvalidURI)
	}
	rest := uri[len("bitcoin:"):]
	result := &ParsedBIP21{Params: make(url.Values)}
	parts := strings.SplitN(rest, "?", 2)
	result.Address = parts[0]
	if len(parts) == 2 && parts[1] != "" {
		params, err := url.ParseQuery(parts[1])
		if err != nil {
			return nil, fmt.Errorf("%w: bad query string: %v", ErrInvalidURI, err)
		}
		result.Params = normalizeParams(params)
		for k := range result.Params {
			if strings.HasPrefix(k, "req-") {
				known := map[string]bool{"req-pop": true}
				if !known[k] {
					return nil, fmt.Errorf("%w: %q", ErrRequiredParam, k)
				}
			}
		}
	}
	return result, nil
}

// DetectPaymentType returns the highest-priority payment type present in a
// BIP-21 URI. Priority: BOLT-12 > Silent Payment > BOLT-11 > on-chain.
func DetectPaymentType(parsed *ParsedBIP21) (PaymentType, bool, error) {
	if parsed.Params.Get("lno") != "" {
		return PaymentTypeLightningBOLT12, true, nil
	}
	if parsed.Params.Get("sp") != "" {
		return PaymentTypeSilentPayment, true, nil
	}
	if parsed.Params.Get("lightning") != "" {
		return PaymentTypeLightningBOLT11, false, nil
	}
	if parsed.Address != "" {
		return PaymentTypeOnChain, false, nil
	}
	if len(parsed.Params["bc"]) > 0 || len(parsed.Params["tb"]) > 0 {
		return PaymentTypeOnChain, false, nil
	}
	return PaymentTypeUnknown, false, ErrNoPaymentMethod
}
