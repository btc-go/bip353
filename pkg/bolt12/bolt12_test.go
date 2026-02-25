package bolt12_test

import (
	"strings"
	"testing"

	"github.com/btc-go/bip353/pkg/bolt12"
	"github.com/btc-go/bip353/pkg/types"
)

// Real offers sourced from live BIP-353 records and the BOLT-12 spec.
var (
	// ₿matt@mattcorallo.com — node ID offer with one blinded path.
	offerMatt = "lno1zr5qyugqgskrk70kqmuq7v3dnr2fnmhukps9n8hut48vkqpqnskt2svsqwjakp7k6pyhtkuxw7y2kqmsxlwruhzqv0zsnhh9q3t9xhx39suc6qsr07ekm5esdyum0w66mnx8vdquwvp7dp5jp7j3v5cp6aj0w329fnkqqv60q96sz5nkrc5r95qffx002q53tqdk8x9m2tmt85jtpmcycvfnrpx3lr45h2g7na3sec7xguctfzzcm8jjqtj5ya27te60j03vpt0vq9tm2n9yxl2hngfnmygesa25s4u4zlxewqpvp94xt7rur4rhxunwkthk9vly3lm5hh0pqv4aymcqejlgssnlpzwlggykkajp7yjs5jvr2agkyypcdlj280cy46jpynsezrcj2kwa2lyr8xvd6lfkph4xrxtk2xc3lpq"

	// ₿tips@bip353.com — blinded-paths-only offer (no node ID).
	offerTips = "lno1zrxq8pjw7qjlm68mtp7e3yvxee4y5xrgjhhyf2fxhlphpckrvevh50u0qgve8erq859ugpp8lzpk2pf8atxrq7s9ljwxvc0lt53yhsdzj592wqszzcmftue8eeeflhks0wkppyug4pl6c5g0uh6pqczez76ekk2t8ewqqvedkpuu3ya8wt0mzeapn0pcjzu6v9aw786fj63htcn03wmghx6pt20ulk3j2wqs2w9245tk8ymt77kezvsqq05t64hk988ah4rgqmf0z4stecyl9acjz865txge7gszqxkka6765qqsyc50jeduhux0qrghey0vsl7ndy"

	// From the BIP-353 spec example.
	offerBIP353 = "lno1qsgqmqvgm96frzdg8m0gc6nzeqffvzsqzrxqy32afmr3jn9ggkwg3egfwch2hy0l6jut6vfd8vpsc3h89l6u3dm4q2d6nuamav3w27xvdmv3lpgklhg7l5teypqz9l53hj7zvuaenh34xqsz2sa967yzqkylfu9xtcd5ymcmfp32h083e805y7jfd236w9afhavqqvl8uyma7x77yun4ehe9pnhu2gekjguexmxpqjcr2j822xr7q34p078gzslf9wpwz5y57alxu99s0z2ql0kfqvwhzycqq45ehh58xnfpuek80hw6spvwrvttjrrq9pphh0dpydh06qqspp5uq4gpyt6n9mwexde44qv7lstzzq60nr40ff38u27un6y53aypmx0p4qruk2tf9mjwqlhxak4znvna5y"
)

func TestDecodeOffer_Matt(t *testing.T) {
	d, err := bolt12.DecodeOffer(offerMatt)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if d.Type != types.BOLT12TypeOffer {
		t.Errorf("type: got %v, want offer", d.Type)
	}
	const wantNodeID = "0386fe4a3bf04aea4124e1910f12559dd57c833998dd7d360dea61997651b11f84"
	if d.NodeID != wantNodeID {
		t.Errorf("node ID: got %q, want %q", d.NodeID, wantNodeID)
	}
	if d.AmountMsat != 0 {
		t.Errorf("amount: got %d, want 0 (payer-set)", d.AmountMsat)
	}
	if len(d.Paths) != 1 {
		t.Errorf("blinded paths: got %d, want 1", len(d.Paths))
	}
}

func TestDecodeOffer_Tips(t *testing.T) {
	d, err := bolt12.DecodeOffer(offerTips)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if d.Type != types.BOLT12TypeOffer {
		t.Errorf("type: got %v, want offer", d.Type)
	}
	if d.NodeID != "" {
		t.Errorf("node ID: got %q, want empty (blinded paths only)", d.NodeID)
	}
	if len(d.Paths) == 0 {
		t.Error("expected at least one blinded path")
	}
}

func TestDecodeOffer_BIP353Spec(t *testing.T) {
	d, err := bolt12.DecodeOffer(offerBIP353)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if d.Type != types.BOLT12TypeOffer {
		t.Errorf("type: got %v, want offer", d.Type)
	}
}

func TestDecodeOffer_CaseInsensitive(t *testing.T) {
	upper := strings.ToUpper(offerMatt)
	d, err := bolt12.DecodeOffer(upper)
	if err != nil {
		t.Fatalf("uppercase offer failed: %v", err)
	}
	if d.NodeID == "" {
		t.Error("expected node ID from uppercase offer")
	}
}

func TestValidate(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{"empty", "", true},
		{"hrp only lno", "lno1", true},
		{"hrp only lnr", "lnr1", true},
		{"hrp only lni", "lni1", true},
		{"wrong prefix", "lnbc1payinvoice", true},
		// 'o' is excluded from bech32 to avoid visual confusion with '0'.
		{"invalid chars", "lno1oooooooooooooooooooooooo", true},
		{"valid offer matt", offerMatt, false},
		{"valid offer tips", offerTips, false},
		{"valid offer bip353", offerBIP353, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := bolt12.Validate(tc.input)
			if tc.wantErr && err == nil {
				t.Errorf("expected error for %q", tc.input)
			}
			if !tc.wantErr && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

func TestDecodeOffer_InvalidPrefix(t *testing.T) {
	cases := []string{
		"",
		"lnbc1something",
		"lno1...",
		"lnr1...",
		"lni1...",
	}
	for _, s := range cases {
		t.Run(s, func(t *testing.T) {
			if _, err := bolt12.DecodeOffer(s); err == nil {
				t.Errorf("expected error for %q", s)
			}
		})
	}
}

// TestBigSizeCanonicalRejection confirms non-canonical bech32 characters are
// caught before TLV parsing. readBigSize is unexported so we go through Validate.
func TestBigSizeCanonicalRejection(t *testing.T) {
	invalids := []string{
		"lno1bioquxxx",
		"lno1OILQQ",
	}
	for _, s := range invalids {
		t.Run(s, func(t *testing.T) {
			if err := bolt12.Validate(s); err == nil {
				t.Errorf("expected error for %q", s)
			}
		})
	}
}

func TestDecodeOffer_BlindedPathStructure(t *testing.T) {
	d, err := bolt12.DecodeOffer(offerMatt)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for i, path := range d.Paths {
		if len(path.IntroductionNodeID) != 33 {
			t.Errorf("path %d: introduction node ID: got %d bytes, want 33", i, len(path.IntroductionNodeID))
		}
		if len(path.BlindingPoint) != 33 {
			t.Errorf("path %d: blinding point: got %d bytes, want 33", i, len(path.BlindingPoint))
		}
		for j, hop := range path.Hops {
			if len(hop.BlindedNodeID) != 33 {
				t.Errorf("path %d hop %d: blinded node ID: got %d bytes, want 33", i, j, len(hop.BlindedNodeID))
			}
			if len(hop.EncryptedRecipientData) == 0 {
				t.Errorf("path %d hop %d: empty encrypted recipient data", i, j)
			}
		}
	}
}

func TestDecodeOffer_Idempotent(t *testing.T) {
	d1, err := bolt12.DecodeOffer(offerMatt)
	if err != nil {
		t.Fatalf("first decode: %v", err)
	}
	d2, err := bolt12.DecodeOffer(offerMatt)
	if err != nil {
		t.Fatalf("second decode: %v", err)
	}
	if d1.NodeID != d2.NodeID {
		t.Error("decode is not idempotent: node IDs differ")
	}
	if len(d1.Paths) != len(d2.Paths) {
		t.Error("decode is not idempotent: path counts differ")
	}
}