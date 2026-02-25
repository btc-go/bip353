package bip353

import (
	"context"
	"errors"
	"fmt"

	"github.com/btc-go/bip353/pkg/builder"
	"github.com/btc-go/bip353/pkg/resolver"
	"github.com/btc-go/bip353/pkg/types"
	tr "github.com/btc-go/bip353/transport"
)

type (
	PaymentInstruction   = types.PaymentInstruction
	HumanReadableAddress = types.HumanReadableAddress
	PaymentType          = types.PaymentType
	BOLT12OfferDetails   = types.BOLT12OfferDetails
	SilentPaymentDetails = types.SilentPaymentDetails
	Options              = resolver.Options
	Transport            = tr.Transport
)

const (
	PaymentTypeUnknown         = types.PaymentTypeUnknown
	PaymentTypeOnChain         = types.PaymentTypeOnChain
	PaymentTypeLightningBOLT11 = types.PaymentTypeLightningBOLT11
	PaymentTypeLightningBOLT12 = types.PaymentTypeLightningBOLT12
	PaymentTypeSilentPayment   = types.PaymentTypeSilentPayment
)

var (
	ErrNXDOMAIN        = types.ErrNXDOMAIN
	ErrAmbiguousRecord = types.ErrAmbiguousRecord
	ErrNoRecord        = types.ErrNoRecord
	ErrInvalidURI      = types.ErrInvalidURI
	ErrNoPaymentMethod = types.ErrNoPaymentMethod
	ErrRequiredParam   = types.ErrRequiredParam
)

func DefaultOptions() Options                                          { return resolver.DefaultOptions() }
func NewDoHTransport(provider string) (*tr.DoHTransport, error)        { return tr.NewDoHTransport(provider) }
func NewDoHTransportWithURL(u string) (*tr.DoHTransport, error)        { return tr.NewDoHTransportWithURL(u) }
func NewTorTransport(proxy, provider string) (*tr.TorTransport, error) { return tr.NewTorTransport(proxy, provider) }
func ParseAddress(address string) (HumanReadableAddress, error) {
	return types.ParseHumanReadableAddress(address)
}
func DNSNameFor(address string) (string, error)     { return resolver.DNSNameFor(address) }
func FormatSummary(inst *PaymentInstruction) string { return resolver.FormatSummary(inst) }
func NewURIBuilder(onChainAddress string) *builder.URIBuilder {
	return builder.NewURIBuilder(onChainAddress)
}
func IsNXDOMAIN(err error) bool { return errors.Is(err, ErrNXDOMAIN) }

type Resolver struct{ inner *resolver.Resolver }

func New() (*Resolver, error)                        { return NewWithOptions(DefaultOptions()) }
func NewWithOptions(opts Options) (*Resolver, error) { return &Resolver{resolver.New(opts)}, nil }

func NewWithDoH(provider string) (*Resolver, error) {
	t, err := NewDoHTransport(provider)
	if err != nil {
		return nil, err
	}
	opts := DefaultOptions()
	opts.Transport = t
	return NewWithOptions(opts)
}

func NewWithDoHURL(endpoint string) (*Resolver, error) {
	t, err := NewDoHTransportWithURL(endpoint)
	if err != nil {
		return nil, err
	}
	opts := DefaultOptions()
	opts.Transport = t
	return NewWithOptions(opts)
}

func NewWithTor(proxyAddr, dohProvider string) (*Resolver, error) {
	t, err := NewTorTransport(proxyAddr, dohProvider)
	if err != nil {
		return nil, err
	}
	opts := DefaultOptions()
	opts.Transport = t
	return NewWithOptions(opts)
}

func (r *Resolver) Resolve(ctx context.Context, address string) (*PaymentInstruction, error) {
	return r.inner.Resolve(ctx, address)
}
func (r *Resolver) ResolveUser(ctx context.Context, user, domain string) (*PaymentInstruction, error) {
	return r.inner.ResolveUser(ctx, user, domain)
}
func (r *Resolver) ResolveHRA(ctx context.Context, hra HumanReadableAddress) (*PaymentInstruction, error) {
	return r.inner.ResolveHRA(ctx, hra)
}

// VerifyProof verifies an RFC 9102 DNSSEC proof and resolves the payment
// instruction from it. This is intended for hardware wallet integration:
// the hardware wallet produces a proof offline, and the caller verifies it
// without making any network requests.
func VerifyProof(proof []byte, address string) (*PaymentInstruction, error) {
	hra, err := types.ParseHumanReadableAddress(address)
	if err != nil {
		return nil, fmt.Errorf("bip353: %w", err)
	}
	return resolver.ParseVerifiedProof(proof, hra)
}