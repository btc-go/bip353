package bolt12

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/btc-go/bip353/pkg/types"
)

const bech32Charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

const maxBlindedHops = 500

var bech32Values [256]byte

func init() {
	for i := range bech32Values {
		bech32Values[i] = 255
	}
	for i, c := range bech32Charset {
		bech32Values[byte(c)] = byte(i)
		if c >= 'a' && c <= 'z' {
			bech32Values[byte(c)-32] = byte(i)
		}
	}
}

const (
	tlvOfferChains         uint64 = 2
	tlvOfferMetadata       uint64 = 4
	tlvOfferCurrency       uint64 = 6
	tlvOfferAmount         uint64 = 8
	tlvOfferDescription    uint64 = 10
	tlvOfferFeatures       uint64 = 12
	tlvOfferAbsoluteExpiry uint64 = 14
	tlvOfferPaths          uint64 = 16
	tlvOfferIssuer         uint64 = 18
	tlvOfferQuantityMax    uint64 = 20
	tlvOfferNodeID         uint64 = 22
	tlvOfferSignature      uint64 = 240
)

func DecodeOffer(raw string) (*types.BOLT12OfferDetails, error) {
	if raw == "" {
		return nil, fmt.Errorf("bolt12: empty string")
	}
	lower := strings.ToLower(raw)
	msgType, hrp, err := classifyPrefix(lower)
	if err != nil {
		return nil, err
	}
	data, err := bech32Decode(lower, hrp)
	if err != nil {
		return nil, fmt.Errorf("bolt12: %w", err)
	}
	details := &types.BOLT12OfferDetails{Type: msgType}
	if err := parseTLVStream(data, details); err != nil {
		return details, fmt.Errorf("bolt12: %w", err)
	}
	return details, nil
}

func Validate(raw string) error {
	if raw == "" {
		return fmt.Errorf("bolt12: empty string")
	}
	_, hrp, err := classifyPrefix(strings.ToLower(raw))
	if err != nil {
		return err
	}
	_, err = bech32Decode(strings.ToLower(raw), hrp)
	return err
}

func classifyPrefix(lower string) (types.BOLT12Type, string, error) {
	switch {
	case strings.HasPrefix(lower, "lno1"):
		return types.BOLT12TypeOffer, "lno", nil
	case strings.HasPrefix(lower, "lnr1"):
		return types.BOLT12TypeInvoiceRequest, "lnr", nil
	case strings.HasPrefix(lower, "lni1"):
		return types.BOLT12TypeInvoice, "lni", nil
	}
	return types.BOLT12TypeOffer, "", fmt.Errorf("bolt12: unrecognized prefix (expected lno1/lnr1/lni1)")
}

// bech32Decode decodes a BOLT-12 offer string. BOLT-12 uses bech32 purely as a
// human-readable container.
func bech32Decode(s, hrp string) ([]byte, error) {
	dataPart := s[len(hrp)+1:]
	if len(dataPart) == 0 {
		return nil, fmt.Errorf("bolt12: data part empty")
	}
	b32 := make([]byte, len(dataPart))
	for i, c := range dataPart {
		v := bech32Values[c]
		if v == 255 {
			return nil, fmt.Errorf("bolt12: invalid character %q at position %d", c, i)
		}
		b32[i] = v
	}
	return convertBits(b32, 5, 8)
}

func convertBits(data []byte, from, to uint) ([]byte, error) {
	var acc, bits int
	out := make([]byte, 0, len(data)*int(from)/int(to)+1)
	mask := int((1 << to) - 1)
	for _, b := range data {
		acc = acc<<from | int(b)
		bits += int(from)
		for bits >= int(to) {
			bits -= int(to)
			out = append(out, byte(acc>>bits&mask))
		}
	}
	if acc<<(int(to)-bits)&mask != 0 {
		return nil, fmt.Errorf("bolt12: non-zero padding bits in encoded offer")
	}
	return out, nil
}

func parseTLVStream(data []byte, d *types.BOLT12OfferDetails) error {
	var lastType uint64
	first := true
	for pos := 0; pos < len(data); {
		tlvType, n, err := readBigSize(data[pos:])
		if err != nil {
			return fmt.Errorf("type at offset %d: %w", pos, err)
		}
		pos += n

		if !first && tlvType <= lastType {
			return fmt.Errorf("TLV stream not canonical: type %d follows %d", tlvType, lastType)
		}
		first, lastType = false, tlvType

		length, n, err := readBigSize(data[pos:])
		if err != nil {
			return fmt.Errorf("length for type %d: %w", tlvType, err)
		}
		pos += n

		if uint64(len(data)-pos) < length {
			return fmt.Errorf("type %d claims %d bytes but only %d remain", tlvType, length, len(data)-pos)
		}
		val := data[pos : pos+int(length)]
		pos += int(length)

		if err := decodeTLVField(tlvType, val, d); err != nil && tlvType%2 == 0 {
			return fmt.Errorf("type %d: %w", tlvType, err)
		}
	}
	return nil
}

// decodeTLVField dispatches scalar and string TLV fields, delegating raw-byte
// fields to decodeTLVFieldBytes to keep cyclomatic complexity manageable.
func decodeTLVField(t uint64, v []byte, d *types.BOLT12OfferDetails) error {
	switch t {
	case tlvOfferDescription:
		return decodeUTF8(v, &d.Description)
	case tlvOfferIssuer:
		return decodeUTF8(v, &d.Issuer)
	case tlvOfferNodeID:
		return decodeNodeID(v, &d.NodeID)
	case tlvOfferAmount:
		return decodeTU64(v, &d.AmountMsat)
	case tlvOfferQuantityMax:
		return decodeTU64(v, &d.QuantityMax)
	case tlvOfferAbsoluteExpiry:
		return decodeTU64(v, &d.AbsoluteExpiry)
	}
	return decodeTLVFieldBytes(t, v, d)
}

// decodeTLVFieldBytes handles TLV fields whose values are stored as raw byte
// slices, including size-validated fixed-width fields.
func decodeTLVFieldBytes(t uint64, v []byte, d *types.BOLT12OfferDetails) error {
	switch t {
	case tlvOfferCurrency:
		if len(v) != 3 {
			return fmt.Errorf("expected 3 bytes, got %d", len(v))
		}
		d.Currency = string(v)
	case tlvOfferFeatures:
		d.Features = bytes.Clone(v)
	case tlvOfferPaths:
		paths, err := decodeBlindedPaths(v)
		if err != nil {
			return err
		}
		d.Paths = paths
	case tlvOfferChains:
		if len(v) == 0 || len(v)%32 != 0 {
			return fmt.Errorf("must be non-zero multiple of 32 bytes, got %d", len(v))
		}
		d.RawChains = bytes.Clone(v)
	case tlvOfferMetadata:
		d.RawMetadata = bytes.Clone(v)
	case tlvOfferSignature:
		if len(v) != 64 {
			return fmt.Errorf("expected 64 bytes, got %d", len(v))
		}
		d.RawSignature = bytes.Clone(v)
	}
	return nil
}

func decodeUTF8(v []byte, dst *string) error {
	if !utf8.Valid(v) {
		return fmt.Errorf("invalid UTF-8")
	}
	*dst = string(v)
	return nil
}

func decodeNodeID(v []byte, dst *string) error {
	if len(v) != 33 {
		return fmt.Errorf("expected 33 bytes, got %d", len(v))
	}
	if v[0] != 0x02 && v[0] != 0x03 {
		return fmt.Errorf("invalid parity byte 0x%02x", v[0])
	}
	*dst = hex.EncodeToString(v)
	return nil
}

func decodeTU64(v []byte, dst *uint64) error {
	n, err := readTU64(v)
	if err != nil {
		return err
	}
	*dst = n
	return nil
}

func decodeBlindedPaths(data []byte) ([]types.BlindedPath, error) {
	const pointLen = 33
	var paths []types.BlindedPath
	for pos := 0; pos < len(data); {
		if len(data)-pos < pointLen*2+1 {
			return nil, fmt.Errorf("blinded_path at %d: truncated header", pos)
		}
		path := types.BlindedPath{
			IntroductionNodeID: bytes.Clone(data[pos : pos+pointLen]),
			BlindingPoint:      bytes.Clone(data[pos+pointLen : pos+pointLen*2]),
		}
		pos += pointLen * 2

		numHops, n, err := readBigSize(data[pos:])
		if err != nil {
			return nil, fmt.Errorf("blinded_path at %d: num_hops: %w", pos, err)
		}
		pos += n

		if numHops > maxBlindedHops {
			return nil, fmt.Errorf("blinded_path: num_hops %d exceeds limit", numHops)
		}

		path.Hops = make([]types.BlindedHop, numHops)
		for i := range path.Hops {
			hop, n, err := decodeBlindedHop(data[pos:], i)
			if err != nil {
				return nil, err
			}
			path.Hops[i] = hop
			pos += n
		}
		paths = append(paths, path)
	}
	return paths, nil
}

func decodeBlindedHop(data []byte, idx int) (types.BlindedHop, int, error) {
	const pointLen = 33
	pos := 0
	if len(data) < pointLen {
		return types.BlindedHop{}, 0, fmt.Errorf("hop %d: truncated node id", idx)
	}
	hop := types.BlindedHop{BlindedNodeID: bytes.Clone(data[pos : pos+pointLen])}
	pos += pointLen

	if len(data)-pos < 2 {
		return types.BlindedHop{}, 0, fmt.Errorf("hop %d: missing payload length", idx)
	}
	encLen := int(binary.BigEndian.Uint16(data[pos : pos+2]))
	pos += 2

	if len(data)-pos < encLen {
		return types.BlindedHop{}, 0, fmt.Errorf("hop %d: payload truncated (want %d, have %d)", idx, encLen, len(data)-pos)
	}
	hop.EncryptedRecipientData = bytes.Clone(data[pos : pos+encLen])
	pos += encLen

	return hop, pos, nil
}

func readBigSize(b []byte) (uint64, int, error) {
	if len(b) == 0 {
		return 0, 0, fmt.Errorf("BigSize: empty buffer")
	}
	switch {
	case b[0] <= 0xfc:
		return uint64(b[0]), 1, nil
	case b[0] == 0xfd:
		if len(b) < 3 {
			return 0, 0, fmt.Errorf("BigSize 0xfd: need 3 bytes, have %d", len(b))
		}
		v := binary.BigEndian.Uint16(b[1:3])
		if v < 0xfd {
			return 0, 0, fmt.Errorf("BigSize 0xfd: non-canonical (%d)", v)
		}
		return uint64(v), 3, nil
	case b[0] == 0xfe:
		if len(b) < 5 {
			return 0, 0, fmt.Errorf("BigSize 0xfe: need 5 bytes, have %d", len(b))
		}
		v := binary.BigEndian.Uint32(b[1:5])
		if v < 0x10000 {
			return 0, 0, fmt.Errorf("BigSize 0xfe: non-canonical (%d)", v)
		}
		return uint64(v), 5, nil
	default:
		if len(b) < 9 {
			return 0, 0, fmt.Errorf("BigSize 0xff: need 9 bytes, have %d", len(b))
		}
		v := binary.BigEndian.Uint64(b[1:9])
		if v < 0x100000000 {
			return 0, 0, fmt.Errorf("BigSize 0xff: non-canonical (%d)", v)
		}
		return v, 9, nil
	}
}

func readTU64(b []byte) (uint64, error) {
	switch {
	case len(b) > 8:
		return 0, fmt.Errorf("tu64: too many bytes (%d)", len(b))
	case len(b) == 0:
		return 0, nil
	case b[0] == 0x00 && len(b) > 1:
		return 0, fmt.Errorf("tu64: non-canonical (leading zero)")
	}
	var buf [8]byte
	copy(buf[8-len(b):], b)
	return binary.BigEndian.Uint64(buf[:]), nil
}