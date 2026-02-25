package silentpayment

import (
	"bytes"
	"fmt"
	"strings"

	"github.com/btc-go/bip353/pkg/types"
)

const bech32Charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

var charValues [256]byte

func init() {
	for i := range charValues {
		charValues[i] = 255
	}
	for i, c := range bech32Charset {
		charValues[byte(c)] = byte(i)
		if c >= 'a' && c <= 'z' {
			charValues[byte(c)-32] = byte(i)
		}
	}
}

// hrpCandidates lists HRPs longest-first to avoid "sp" matching "sprt1...".
var hrpCandidates = []struct{ hrp, network string }{
	{"sprt", "signet"},
	{"tsp", "testnet"},
	{"sp", "mainnet"},
}

func hrpForAddress(lower string) (hrp, network string) {
	for _, c := range hrpCandidates {
		if strings.HasPrefix(lower, c.hrp+"1") {
			return c.hrp, c.network
		}
	}
	return "", ""
}

// Decode parses a BIP-352 silent payment address.
func Decode(addr string) (*types.SilentPaymentDetails, error) {
	if addr == "" {
		return nil, fmt.Errorf("silentpayment: empty address")
	}
	lower := strings.ToLower(addr)
	hrp, network := hrpForAddress(lower)
	if hrp == "" {
		return nil, fmt.Errorf("silentpayment: unrecognized prefix (expected sp1/tsp1/sprt1)")
	}
	dataPart := lower[len(hrp)+1:]
	if len(dataPart) < 6 {
		return nil, fmt.Errorf("silentpayment: data part too short")
	}
	decoded := make([]byte, len(dataPart))
	for i := 0; i < len(dataPart); i++ {
		v := charValues[dataPart[i]]
		if v == 255 {
			return nil, fmt.Errorf("silentpayment: invalid character %q at position %d", dataPart[i], i)
		}
		decoded[i] = v
	}
	if err := verifyChecksum(hrp, decoded); err != nil {
		return nil, fmt.Errorf("silentpayment: %w", err)
	}
	payload := decoded[:len(decoded)-6]
	if len(payload) < 1 {
		return nil, fmt.Errorf("silentpayment: payload empty")
	}
	version := payload[0]
	if version > 16 {
		return nil, fmt.Errorf("silentpayment: invalid version %d (max 16)", version)
	}
	keyData, err := convertBits(payload[1:], 5, 8, false)
	if err != nil {
		return nil, fmt.Errorf("silentpayment: bit conversion: %w", err)
	}
	if version == 0 {
		if len(keyData) != 66 {
			return nil, fmt.Errorf("silentpayment: v0 must have 66 key bytes, got %d", len(keyData))
		}
		scan, spend := keyData[:33], keyData[33:66]
		if err := validateCompressedPubkey(scan); err != nil {
			return nil, fmt.Errorf("silentpayment: scan key: %w", err)
		}
		if err := validateCompressedPubkey(spend); err != nil {
			return nil, fmt.Errorf("silentpayment: spend key: %w", err)
		}
		return &types.SilentPaymentDetails{
			Network:     network,
			ScanPubkey:  bytes.Clone(scan),
			SpendPubkey: bytes.Clone(spend),
			Version:     version,
		}, nil
	}
	return &types.SilentPaymentDetails{Network: network, Version: version}, nil
}

// Validate returns nil if addr is a syntactically valid BIP-352 silent payment address.
func Validate(addr string) error {
	_, err := Decode(addr)
	return err
}

func validateCompressedPubkey(b []byte) error {
	if len(b) != 33 {
		return fmt.Errorf("expected 33 bytes, got %d", len(b))
	}
	if b[0] != 0x02 && b[0] != 0x03 {
		return fmt.Errorf("invalid prefix byte 0x%02x (expected 0x02 or 0x03)", b[0])
	}
	return nil
}

func verifyChecksum(hrp string, data []byte) error {
	const bech32mConst = 0x2bc830a3
	if polymod(hrpExpand(hrp), data) != bech32mConst {
		return fmt.Errorf("invalid bech32m checksum")
	}
	return nil
}

func hrpExpand(hrp string) []byte {
	res := make([]byte, len(hrp)*2+1)
	for i := 0; i < len(hrp); i++ {
		res[i] = hrp[i] >> 5
		res[i+len(hrp)+1] = hrp[i] & 31
	}
	res[len(hrp)] = 0
	return res
}

func polymod(values ...[]byte) uint32 {
	gen := [5]uint32{0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3}
	chk := uint32(1)
	for _, v := range values {
		for _, p := range v {
			top := chk >> 25
			chk = (chk&0x1ffffff)<<5 ^ uint32(p)
			for i := 0; i < 5; i++ {
				if top>>uint(i)&1 != 0 {
					chk ^= gen[i]
				}
			}
		}
	}
	return chk
}

func convertBits(data []byte, fromBits, toBits uint, pad bool) ([]byte, error) {
	var acc, bits int
	var out []byte
	maxv := int((1 << toBits) - 1)
	for _, b := range data {
		acc = (acc << fromBits) | int(b)
		bits += int(fromBits)
		for bits >= int(toBits) {
			bits -= int(toBits)
			out = append(out, byte((acc>>bits)&maxv))
		}
	}
	if pad {
		if bits > 0 {
			out = append(out, byte((acc<<(int(toBits)-bits))&maxv))
		}
	} else if bits >= int(fromBits) || (acc<<(int(toBits)-bits))&maxv != 0 {
		return nil, fmt.Errorf("non-zero padding in bit conversion")
	}
	return out, nil
}