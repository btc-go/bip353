package silentpayment_test

import (
	"testing"

	"github.com/btc-go/bip353/pkg/silentpayment"
)

func TestDecodeInvalid(t *testing.T) {
	tests := []struct {
		input string
	}{
		{""},
		{"bc1qexample"},
		{"lno1qoffer"},
		{"sp1"},
		{"sp1q"},
		{"tsp1invalid"},
		{"sprt1invalid"},
		{"sp1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq"},
	}
	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			_, err := silentpayment.Decode(tc.input)
			if err == nil {
				t.Errorf("expected error for %q", tc.input)
			}
		})
	}
}

func TestValidateMatchesDecode(t *testing.T) {
	inputs := []string{"", "bc1qtest", "sp1invalid", "tsp1alsoInvalid", "sprt1bad"}
	for _, input := range inputs {
		_, errDecode := silentpayment.Decode(input)
		errValidate := silentpayment.Validate(input)
		if (errDecode == nil) != (errValidate == nil) {
			t.Errorf("Decode and Validate disagree for %q: decode=%v validate=%v",
				input, errDecode, errValidate)
		}
	}
}

func TestPrefixRecognition(t *testing.T) {
	// These fail checksum but must not fail with "unrecognized prefix".
	prefixes := []string{"sp1q", "tsp1q", "sprt1q"}
	for _, p := range prefixes {
		t.Run(p, func(t *testing.T) {
			err := silentpayment.Validate(p + "xxxxxxxx")
			if err == nil {
				t.Errorf("expected error (bad checksum) for %q", p)
			}
			if err != nil && err.Error() == "silentpayment: unrecognized prefix (expected sp1/tsp1/sprt1)" {
				t.Errorf("prefix %q was not recognized", p)
			}
		})
	}
}
