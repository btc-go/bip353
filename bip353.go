// Package bip353 implements BIP-353: DNS Payment Instructions.
//
// BIP-353 maps human-readable Bitcoin addresses (₿alice@example.com) to payment
// instructions stored in DNSSEC-signed DNS TXT records.
//
// Quick start:
//
//	r, err := bip353.NewSecure()
//	inst, err := r.Resolve(ctx, "₿alice@example.com")
//	switch inst.PaymentType {
//	case bip353.PaymentTypeLightningBOLT12:
//	    pay(inst.BOLT12Offer)
//	case bip353.PaymentTypeSilentPayment:
//	    pay(inst.SilentPaymentAddress)
//	case bip353.PaymentTypeLightningBOLT11:
//	    pay(inst.BOLT11Invoice)
//	case bip353.PaymentTypeOnChain:
//	    pay(inst.OnChainAddress)
//	}
package bip353

import (
	"context"
	"errors"

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
	ErrDNSSECRequired  = types.ErrDNSSECRequired
	ErrNXDOMAIN        = types.ErrNXDOMAIN
	ErrAmbiguousRecord = types.ErrAmbiguousRecord
	ErrNoRecord        = types.ErrNoRecord
	ErrInvalidURI      = types.ErrInvalidURI
	ErrNoPaymentMethod = types.ErrNoPaymentMethod
	ErrRequiredParam   = types.ErrRequiredParam
)

func DefaultOptions() Options                                          { return resolver.DefaultOptions() }
func NewClassicTransport() *tr.ClassicTransport                        { return tr.NewClassicTransport() }
func NewClassicTransportWithNameservers(ns []string) *tr.ClassicTransport {
	return tr.NewClassicTransportWithNameservers(ns)
}
func NewDoHTransport(provider string) (*tr.DoHTransport, error) { return tr.NewDoHTransport(provider) }
func NewDoHTransportWithURL(u string) (*tr.DoHTransport, error) { return tr.NewDoHTransportWithURL(u) }
func NewTorTransport(proxy, provider string) (*tr.TorTransport, error) {
	return tr.NewTorTransport(proxy, provider)
}
func ParseAddress(address string) (HumanReadableAddress, error) {
	return types.ParseHumanReadableAddress(address)
}
func DNSNameFor(address string) (string, error) { return resolver.DNSNameFor(address) }
func FormatSummary(inst *PaymentInstruction) string { return resolver.FormatSummary(inst) }
func NewURIBuilder(onChainAddress string) *builder.URIBuilder {
	return builder.NewURIBuilder(onChainAddress)
}
func IsNXDOMAIN(err error) bool     { return errors.Is(err, ErrNXDOMAIN) }
func IsDNSSECError(err error) bool  { return errors.Is(err, ErrDNSSECRequired) }

type Resolver struct{ inner *resolver.Resolver }

func New(opts Options) (*Resolver, error)   { return &Resolver{resolver.New(opts)}, nil }
func NewSecure() (*Resolver, error)         { return New(DefaultOptions()) }
func NewInsecure() (*Resolver, error) {
	opts := DefaultOptions()
	opts.AllowInsecure = true
	return New(opts)
}
func NewWithDoH(provider string) (*Resolver, error) {
	t, err := NewDoHTransport(provider)
	if err != nil {
		return nil, err
	}
	opts := DefaultOptions()
	opts.Transport = t
	return New(opts)
}
func NewWithTor(proxyAddr, dohProvider string) (*Resolver, error) {
	t, err := NewTorTransport(proxyAddr, dohProvider)
	if err != nil {
		return nil, err
	}
	opts := DefaultOptions()
	opts.Transport = t
	return New(opts)
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