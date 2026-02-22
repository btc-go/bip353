// Command bip353 resolves and manages BIP-353 DNS payment instructions.
//
//	bip353 resolve [flags] <₿user@domain>
//	bip353 dnsname <₿user@domain>
//	bip353 build [flags]
//	bip353 decode <lno1.../sp1...>
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	bip353 "github.com/btc-go/bip353"
	"github.com/btc-go/bip353/pkg/bolt12"
	"github.com/btc-go/bip353/pkg/silentpayment"
	"github.com/btc-go/bip353/transport"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		printUsage()
		return nil
	}
	switch args[0] {
	case "resolve":
		return cmdResolve(args[1:])
	case "dnsname":
		return cmdDNSName(args[1:])
	case "build":
		return cmdBuild(args[1:])
	case "decode":
		return cmdDecode(args[1:])
	case "help", "-h", "--help":
		printUsage()
		return nil
	default:
		return fmt.Errorf("unknown command %q; run 'bip353 help' for usage", args[0])
	}
}

func cmdResolve(args []string) error {
	fs := flag.NewFlagSet("resolve", flag.ContinueOnError)
	transportSpec := fs.String("transport", "classic", "classic | doh:<provider> | tor:<provider>")
	torProxy := fs.String("tor-proxy", transport.TorDaemonProxy, "Tor SOCKS5 proxy address")
	nameservers := fs.String("nameservers", "", "Comma-separated resolvers for classic transport (host:port)")
	insecure := fs.Bool("insecure", false, "Disable DNSSEC (NOT safe for production)")
	timeout := fs.Duration("timeout", 10*time.Second, "Query timeout")
	verbose := fs.Bool("verbose", false, "Show full decoded fields")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() < 1 {
		return fmt.Errorf("resolve: address required — usage: bip353 resolve [flags] <₿user@domain>")
	}

	t, err := buildTransport(*transportSpec, *torProxy, *nameservers)
	if err != nil {
		return fmt.Errorf("resolve: %w", err)
	}

	opts := bip353.DefaultOptions()
	opts.Transport = t
	opts.AllowInsecure = *insecure

	r, err := bip353.New(opts)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	inst, err := r.Resolve(ctx, fs.Arg(0))
	if err != nil {
		return err
	}

	if *verbose {
		fmt.Print(bip353.FormatSummary(inst))
	} else {
		printInstruction(inst)
	}
	return nil
}

func printInstruction(inst *bip353.PaymentInstruction) {
	fmt.Printf("Resolved: %s\n", inst.OriginalAddress)
	fmt.Printf("Type:     %s\n", inst.PaymentType)
	fmt.Printf("Reusable: %v\n", inst.IsReusable)
	fmt.Printf("DNSSEC:   %v\n", inst.DNSSECValidated)
	switch inst.PaymentType {
	case bip353.PaymentTypeLightningBOLT12:
		fmt.Printf("Offer:    %s\n", inst.BOLT12Offer)
	case bip353.PaymentTypeSilentPayment:
		fmt.Printf("Address:  %s\n", inst.SilentPaymentAddress)
	case bip353.PaymentTypeLightningBOLT11:
		fmt.Printf("Invoice:  %s\n", inst.BOLT11Invoice)
	case bip353.PaymentTypeOnChain:
		fmt.Printf("Address:  %s\n", inst.OnChainAddress)
	}
}

func cmdDNSName(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("dnsname: address required")
	}
	name, err := bip353.DNSNameFor(args[0])
	if err != nil {
		return err
	}
	fmt.Println(name)
	return nil
}

func cmdBuild(args []string) error {
	fs := flag.NewFlagSet("build", flag.ContinueOnError)
	address := fs.String("address", "", "On-chain Bitcoin address")
	bolt12Offer := fs.String("bolt12", "", "BOLT-12 offer (lno1...)")
	bolt11 := fs.String("bolt11", "", "BOLT-11 invoice (lnbc1...)")
	sp := fs.String("sp", "", "Silent payment address (sp1...)")
	payjoin := fs.String("payjoin", "", "PayJoin BIP-78 endpoint URL")
	if err := fs.Parse(args); err != nil {
		return err
	}

	b := bip353.NewURIBuilder(*address)
	if *bolt12Offer != "" {
		b.WithBOLT12Offer(*bolt12Offer)
	}
	if *bolt11 != "" {
		b.WithBOLT11Invoice(*bolt11)
	}
	if *sp != "" {
		b.WithSilentPayment(*sp)
	}
	if *payjoin != "" {
		b.WithPayJoin(*payjoin)
	}

	uri, err := b.Build()
	if err != nil {
		return fmt.Errorf("build: %w", err)
	}
	fmt.Println(uri)
	return nil
}

func cmdDecode(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("decode: argument required (BOLT-12 offer or silent payment address)")
	}
	input := args[0]
	lower := strings.ToLower(input)
	switch {
	case strings.HasPrefix(lower, "lno1") ||
		strings.HasPrefix(lower, "lnr1") ||
		strings.HasPrefix(lower, "lni1"):
		return decodeBOLT12(input)
	case strings.HasPrefix(lower, "sp1") ||
		strings.HasPrefix(lower, "tsp1") ||
		strings.HasPrefix(lower, "sprt1"):
		return decodeSilentPayment(input)
	default:
		return fmt.Errorf("decode: unrecognized format (expected lno1/lnr1/lni1 or sp1/tsp1/sprt1)")
	}
}

func decodeBOLT12(offer string) error {
	details, err := bolt12.DecodeOffer(offer)
	if err != nil && details == nil {
		return fmt.Errorf("decode: %w", err)
	}
	fmt.Printf("Type:    %s\n", details.Type)
	if details.Description != "" {
		fmt.Printf("Description:   %s\n", details.Description)
	}
	if details.Issuer != "" {
		fmt.Printf("Issuer:        %s\n", details.Issuer)
	}
	if details.NodeID != "" {
		fmt.Printf("Node ID:       %s\n", details.NodeID)
	}
	if details.AmountMsat > 0 {
		fmt.Printf("Amount:        %d msat (%.8f BTC)\n", details.AmountMsat, float64(details.AmountMsat)/1e11)
	} else {
		fmt.Println("Amount:        (payer sets amount)")
	}
	if details.Currency != "" {
		fmt.Printf("Currency:      %s\n", details.Currency)
	}
	if details.AbsoluteExpiry > 0 {
		fmt.Printf("Expires:       %d (unix)\n", details.AbsoluteExpiry)
	}
	if details.QuantityMax > 0 {
		fmt.Printf("Quantity max:  %d\n", details.QuantityMax)
	}
	if len(details.Features) > 0 {
		fmt.Printf("Features:      %x\n", details.Features)
	}
	if len(details.Paths) > 0 {
		fmt.Printf("Blinded paths: %d\n", len(details.Paths))
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "warning: partial decode: %v\n", err)
	}
	return nil
}

func decodeSilentPayment(addr string) error {
	details, err := silentpayment.Decode(addr)
	if err != nil {
		return fmt.Errorf("decode: %w", err)
	}
	fmt.Printf("Network:   %s\n", details.Network)
	fmt.Printf("Version:   %d\n", details.Version)
	if len(details.ScanPubkey) > 0 {
		fmt.Printf("Scan key:  %x\n", details.ScanPubkey)
	}
	if len(details.SpendPubkey) > 0 {
		fmt.Printf("Spend key: %x\n", details.SpendPubkey)
	}
	return nil
}

func buildTransport(spec, torProxy, nameservers string) (bip353.Transport, error) {
	switch {
	case spec == "classic":
		if nameservers != "" {
			return bip353.NewClassicTransportWithNameservers(strings.Split(nameservers, ",")), nil
		}
		return bip353.NewClassicTransport(), nil
	case strings.HasPrefix(spec, "doh:"):
		provider := strings.TrimPrefix(spec, "doh:")
		if strings.HasPrefix(provider, "https://") {
			return bip353.NewDoHTransportWithURL(provider)
		}
		return bip353.NewDoHTransport(provider)
	case strings.HasPrefix(spec, "tor:"):
		return bip353.NewTorTransport(torProxy, strings.TrimPrefix(spec, "tor:"))
	default:
		return nil, fmt.Errorf("unknown transport %q; use classic, doh:<provider>, or tor:<provider>", spec)
	}
}

func printUsage() {
	fmt.Print(`bip353 — BIP-353 DNS Payment Instructions

USAGE:
  bip353 <command> [flags] [arguments]

COMMANDS:
  resolve <address>    Resolve ₿user@domain to payment info
  dnsname <address>    Print the BIP-353 DNS TXT record name
  build [flags]        Build a BIP-21 URI for a DNS TXT record
  decode <value>       Decode a BOLT-12 offer or silent payment address
  help                 Show this help

RESOLVE FLAGS:
  --transport <spec>       classic | doh:<provider> | tor:<provider>
                           Providers: cloudflare | google | quad9 | nextdns
                           Custom DoH: doh:https://your.doh.server/dns-query
  --tor-proxy <host:port>  Tor SOCKS5 proxy (default: 127.0.0.1:9050)
  --nameservers <list>     Comma-separated resolvers for classic transport
  --insecure               Disable DNSSEC (NOT safe for production)
  --timeout <duration>     Query timeout (default: 10s)
  --verbose                Show full decoded BOLT-12/Silent Payment fields

BUILD FLAGS:
  --address <addr>     On-chain Bitcoin address
  --bolt12 <offer>     BOLT-12 offer (lno1...)
  --bolt11 <invoice>   BOLT-11 invoice (lnbc1...)
  --sp <addr>          Silent payment address (sp1...)
  --payjoin <url>      PayJoin BIP-78 endpoint URL

EXAMPLES:
  bip353 resolve ₿alice@example.com
  bip353 resolve --transport doh:cloudflare ₿alice@example.com
  bip353 resolve --transport tor:cloudflare ₿alice@example.com
  bip353 dnsname ₿alice@example.com
  bip353 build --address bc1q... --bolt12 lno1...
  bip353 decode lno1qcpjkuepqyz5z...
  bip353 decode sp1qqgmrp7a...
`)
}