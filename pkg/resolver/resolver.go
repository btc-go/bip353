// Resolver logic is tested via the public API in the root package.
// See bip353_test.go and integration_test.go

package resolver

import (
	"context"
	"fmt"
	"strings"

	"github.com/btc-go/bip353/pkg/bolt12"
	"github.com/btc-go/bip353/pkg/silentpayment"
	"github.com/btc-go/bip353/pkg/types"
	"github.com/btc-go/bip353/transport"
)

const maxTXTLength = 8192

type Options struct {
	Transport           transport.Transport
	RequireDNSSEC       bool
	AllowInsecure       bool
	DecodeBOLT12        bool
	DecodeSilentPayment bool
}

func DefaultOptions() Options {
	return Options{
		RequireDNSSEC:       true,
		DecodeBOLT12:        true,
		DecodeSilentPayment: true,
	}
}

type Resolver struct {
	transport transport.Transport
	opts      Options
}

func New(opts Options) *Resolver {
	t := opts.Transport
	if t == nil {
		t = transport.NewClassicTransport()
	}
	if opts.AllowInsecure {
		opts.RequireDNSSEC = false
	}
	return &Resolver{transport: t, opts: opts}
}

func (r *Resolver) Resolve(ctx context.Context, address string) (*types.PaymentInstruction, error) {
	hra, err := types.ParseHumanReadableAddress(address)
	if err != nil {
		return nil, fmt.Errorf("bip353: %w", err)
	}
	return r.ResolveHRA(ctx, hra)
}

func (r *Resolver) ResolveUser(ctx context.Context, user, domain string) (*types.PaymentInstruction, error) {
	return r.ResolveHRA(ctx, types.HumanReadableAddress{User: user, Domain: domain})
}

func (r *Resolver) ResolveHRA(ctx context.Context, hra types.HumanReadableAddress) (*types.PaymentInstruction, error) {
	dnsName := hra.DNSName()
	qResult, err := r.transport.LookupTXT(ctx, dnsName)
	if err != nil {
		if strings.Contains(err.Error(), "NXDOMAIN") {
			return nil, fmt.Errorf("bip353: %w", types.ErrNXDOMAIN)
		}
		return nil, fmt.Errorf("bip353: DNS lookup for %s: %w", dnsName, err)
	}
	if r.opts.RequireDNSSEC && !qResult.Authenticated {
		return nil, fmt.Errorf("bip353: %w (name: %s, transport: %s)",
			types.ErrDNSSECRequired, dnsName, qResult.Transport)
	}
	var bip353Records []string
	for _, rec := range qResult.Records {
		if strings.HasPrefix(strings.ToLower(rec), "bitcoin:") {
			if len(rec) > maxTXTLength {
				return nil, fmt.Errorf("bip353: TXT record at %s exceeds %d bytes", dnsName, maxTXTLength)
			}
			bip353Records = append(bip353Records, rec)
		}
	}
	if len(bip353Records) == 0 {
		return nil, fmt.Errorf("bip353: %w at %s", types.ErrNoRecord, dnsName)
	}
	if len(bip353Records) > 1 {
		return nil, fmt.Errorf("bip353: %w at %s (%d records)", types.ErrAmbiguousRecord, dnsName, len(bip353Records))
	}
	rawRecord := bip353Records[0]
	inst, err := r.buildInstruction(rawRecord)
	if err != nil {
		return nil, fmt.Errorf("bip353: parsing record at %s: %w", dnsName, err)
	}
	inst.OriginalAddress = hra
	inst.DNSSECValidated = qResult.Authenticated
	inst.RawTXTRecord = rawRecord
	inst.TTL = qResult.TTL  

	return inst, nil
}

// knownParams are BIP-321 defined keys that should not appear in ExtraParams.
var knownParams = map[string]bool{
	"lno":       true,
	"lightning": true,
	"sp":        true,
	"bc":        true,
	"tb":        true, // testnet segwit
	"pay":       true, // BIP-351 private payments
	"pj":        true, // payjoin
	"pjos":      true, // payjoin output substitution
	"amount":    true,
	"label":     true,
	"message":   true,
	"pop":       true,
	"req-pop":   true,
}

func (r *Resolver) buildInstruction(raw string) (*types.PaymentInstruction, error) {
	parsed, err := types.ParseBIP21URI(raw)
	if err != nil {
		return nil, err
	}
	payType, isReusable, err := types.DetectPaymentType(parsed)
	if err != nil {
		return nil, err
	}
	inst := &types.PaymentInstruction{
		URI:            raw,
		PaymentType:    payType,
		IsReusable:     isReusable,
		ExtraParams:    make(map[string]string),
		OnChainAddress: parsed.Address,
	}

	// bc= carries native segwit addresses per BIP-321.
	// Multiple values are valid (e.g. one segwit v0 + one segwit v1).
	// OnChainAddress holds the first for convenience; OnChainAddresses holds all.
	if bcVals := parsed.Params["bc"]; len(bcVals) > 0 {
		inst.OnChainAddresses = bcVals
		if inst.OnChainAddress == "" {
			inst.OnChainAddress = bcVals[0]
		}
	}

	if lno := parsed.Params.Get("lno"); lno != "" {
		inst.BOLT12Offer = lno
		if r.opts.DecodeBOLT12 {
			if details, err := bolt12.DecodeOffer(lno); err == nil {
				inst.BOLT12Details = details
			}
		}
	}
	if inv := parsed.Params.Get("lightning"); inv != "" {
		inst.BOLT11Invoice = inv
	}
	if sp := parsed.Params.Get("sp"); sp != "" {
		inst.SilentPaymentAddress = sp
		if r.opts.DecodeSilentPayment {
			if details, err := silentpayment.Decode(sp); err == nil {
				inst.SilentPaymentDetails = details
			}
		}
	}
	for k, v := range parsed.Params {
		if !knownParams[k] && len(v) > 0 {
			inst.ExtraParams[k] = v[0]
		}
	}
	return inst, nil
}

func DNSNameFor(address string) (string, error) {
	hra, err := types.ParseHumanReadableAddress(address)
	if err != nil {
		return "", err
	}
	return hra.DNSName(), nil
}

func FormatSummary(inst *types.PaymentInstruction) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Address:          %s\n", inst.OriginalAddress)
	fmt.Fprintf(&b, "Payment type:     %s\n", inst.PaymentType)
	fmt.Fprintf(&b, "Reusable:         %v\n", inst.IsReusable)
	fmt.Fprintf(&b, "DNSSEC validated: %v\n", inst.DNSSECValidated)
	if inst.TTL > 0 {
		fmt.Fprintf(&b, "DNS TTL:          %ds\n", inst.TTL)
	}
	if inst.BOLT12Offer != "" {
		fmt.Fprintf(&b, "BOLT-12 offer:    %s\n", trunc(inst.BOLT12Offer, 60))
		if d := inst.BOLT12Details; d != nil {
			if d.Description != "" {
				fmt.Fprintf(&b, "  Description:    %s\n", d.Description)
			}
			if d.Issuer != "" {
				fmt.Fprintf(&b, "  Issuer:         %s\n", d.Issuer)
			}
			if d.NodeID != "" {
				fmt.Fprintf(&b, "  Node ID:        %s\n", trunc(d.NodeID, 20)+"…")
			}
			if d.AmountMsat > 0 {
				fmt.Fprintf(&b, "  Amount:         %d msat\n", d.AmountMsat)
			}
			if d.AbsoluteExpiry > 0 {
				fmt.Fprintf(&b, "  Expires:        %d\n", d.AbsoluteExpiry)
			}
		}
	}
	if inst.BOLT11Invoice != "" {
		fmt.Fprintf(&b, "BOLT-11 invoice:  %s\n", trunc(inst.BOLT11Invoice, 60))
	}
	if inst.OnChainAddress != "" {
		fmt.Fprintf(&b, "On-chain address: %s\n", inst.OnChainAddress)
		if len(inst.OnChainAddresses) > 1 {
			for _, a := range inst.OnChainAddresses[1:] {
				fmt.Fprintf(&b, "                  %s\n", a)
			}
		}
	}
	if inst.SilentPaymentAddress != "" {
		fmt.Fprintf(&b, "Silent payment:   %s\n", trunc(inst.SilentPaymentAddress, 60))
		if d := inst.SilentPaymentDetails; d != nil {
			fmt.Fprintf(&b, "  Network:        %s\n", d.Network)
			fmt.Fprintf(&b, "  Version:        %d\n", d.Version)
		}
	}
	return b.String()
}

func trunc(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}