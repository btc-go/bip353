package bolt12

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/btc-go/bip353/pkg/types"
)

const bech32Charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

var bech32Values [256]byte

func init() {
	for i := range bech32Values {
		bech32Values[i] = 255
	}
	for i, c := range bech32Charset {
		bech32Values[byte(c)] = byte(i)
		bech32Values[byte(c)-32] = byte(i)
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

// DecodeOffer decodes a BOLT-12 offer (lno1), invoice_request (lnr1), or invoice (lni1).
// It does not verify cryptographic signatures.
// On unknown future even TLV types, returns partial results and a non-nil error.
func DecodeOffer(raw string) (*types.BOLT12OfferDetails, error) {
	if raw == "" {
		return nil, fmt.Errorf("bolt12: empty string")
	}
	lower := strings.ToLower(raw)
	var msgType types.BOLT12Type
	var hrp string
	switch {
	case strings.HasPrefix(lower, "lno1"):
		msgType, hrp = types.BOLT12TypeOffer, "lno"
	case strings.HasPrefix(lower, "lnr1"):
		msgType, hrp = types.BOLT12TypeInvoiceRequest, "lnr"
	case strings.HasPrefix(lower, "lni1"):
		msgType, hrp = types.BOLT12TypeInvoice, "lni"
	default:
		return nil, fmt.Errorf("bolt12: unrecognized prefix (expected lno1/lnr1/lni1)")
	}
	data, err := bech32mDecode(lower, hrp)
	if err != nil {
		return nil, fmt.Errorf("bolt12: %w", err)
	}
	details := &types.BOLT12OfferDetails{Type: msgType}
	if err := parseTLVStream(data, details); err != nil {
		return details, fmt.Errorf("bolt12: %w", err)
	}
	return details, nil
}

// Validate returns nil if raw is a syntactically valid BOLT-12 bech32m string.
func Validate(raw string) error {
	if raw == "" {
		return fmt.Errorf("bolt12: empty string")
	}
	lower := strings.ToLower(raw)
	var hrp string
	switch {
	case strings.HasPrefix(lower, "lno1"):
		hrp = "lno"
	case strings.HasPrefix(lower, "lnr1"):
		hrp = "lnr"
	case strings.HasPrefix(lower, "lni1"):
		hrp = "lni"
	default:
		return fmt.Errorf("bolt12: unrecognized prefix (expected lno1/lnr1/lni1)")
	}
	_, err := bech32mDecode(lower, hrp)
	return err
}

func bech32mDecode(s, expectedHRP string) ([]byte, error) {
	sep := strings.LastIndexByte(s, '1')
	if sep < 1 {
		return nil, fmt.Errorf("no bech32 separator '1'")
	}
	hrp := s[:sep]
	if hrp != expectedHRP {
		return nil, fmt.Errorf("unexpected HRP: got %q, want %q", hrp, expectedHRP)
	}
	dataPart := s[sep+1:]
	if len(dataPart) < 6 {
		return nil, fmt.Errorf("data part too short (%d chars)", len(dataPart))
	}
	decoded := make([]byte, len(dataPart))
	for i := 0; i < len(dataPart); i++ {
		v := bech32Values[dataPart[i]]
		if v == 255 {
			return nil, fmt.Errorf("invalid bech32 character %q at position %d", dataPart[i], i)
		}
		decoded[i] = v
	}
	const bech32mConst = 0x2bc830a3
	if polymod(hrpExpand(hrp), decoded) != bech32mConst {
		return nil, fmt.Errorf("invalid bech32m checksum")
	}
	out, err := convertBits(decoded[:len(decoded)-6], 5, 8, false)
	if err != nil {
		return nil, fmt.Errorf("bit conversion: %w", err)
	}
	return out, nil
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

func parseTLVStream(data []byte, d *types.BOLT12OfferDetails) error {
	pos := 0
	seenAny := false
	var lastType uint64
	for pos < len(data) {
		tlvType, n, err := readBigSize(data[pos:])
		if err != nil {
			return fmt.Errorf("reading type at offset %d: %w", pos, err)
		}
		pos += n
		if seenAny && tlvType <= lastType {
			return fmt.Errorf("TLV types not strictly increasing: %d after %d", tlvType, lastType)
		}
		seenAny = true
		lastType = tlvType
		tlvLen, n, err := readBigSize(data[pos:])
		if err != nil {
			return fmt.Errorf("reading length for type %d: %w", tlvType, err)
		}
		pos += n
		if uint64(len(data)-pos) < tlvLen {
			return fmt.Errorf("type %d: value exceeds remaining data", tlvType)
		}
		value := data[pos : pos+int(tlvLen)]
		pos += int(tlvLen)
		if err := decodeTLVField(tlvType, value, d); err != nil {
			if tlvType%2 == 0 {
				return fmt.Errorf("unknown even TLV type %d: %w", tlvType, err)
			}
		}
	}
	return nil
}

func decodeTLVField(t uint64, v []byte, d *types.BOLT12OfferDetails) error {
	switch t {
	case tlvOfferDescription:
		if !utf8.Valid(v) {
			return fmt.Errorf("offer_description is not valid UTF-8")
		}
		d.Description = string(v)
	case tlvOfferIssuer:
		if !utf8.Valid(v) {
			return fmt.Errorf("offer_issuer is not valid UTF-8")
		}
		d.Issuer = string(v)
	case tlvOfferNodeID:
		if len(v) != 33 {
			return fmt.Errorf("offer_node_id must be 33 bytes, got %d", len(v))
		}
		if v[0] != 0x02 && v[0] != 0x03 {
			return fmt.Errorf("offer_node_id invalid prefix 0x%02x", v[0])
		}
		d.NodeID = hex.EncodeToString(v)
	case tlvOfferAmount:
		amt, err := readTU64(v)
		if err != nil {
			return fmt.Errorf("offer_amount: %w", err)
		}
		d.AmountMsat = amt
	case tlvOfferCurrency:
		if len(v) != 3 {
			return fmt.Errorf("offer_currency must be 3 bytes, got %d", len(v))
		}
		d.Currency = string(v)
	case tlvOfferFeatures:
		d.Features = clone(v)
	case tlvOfferQuantityMax:
		q, err := readTU64(v)
		if err != nil {
			return fmt.Errorf("offer_quantity_max: %w", err)
		}
		d.QuantityMax = q
	case tlvOfferAbsoluteExpiry:
		exp, err := readTU64(v)
		if err != nil {
			return fmt.Errorf("offer_absolute_expiry: %w", err)
		}
		d.AbsoluteExpiry = exp
	case tlvOfferPaths:
		paths, err := decodeBlindedPaths(v)
		if err != nil {
			return fmt.Errorf("offer_paths: %w", err)
		}
		d.Paths = paths
	case tlvOfferChains:
		if len(v) == 0 || len(v)%32 != 0 {
			return fmt.Errorf("offer_chains must be a non-zero multiple of 32 bytes, got %d", len(v))
		}
		d.RawChains = clone(v)
	case tlvOfferMetadata:
		d.RawMetadata = clone(v)
	case tlvOfferSignature:
		if len(v) != 64 {
			return fmt.Errorf("offer_signature must be 64 bytes, got %d", len(v))
		}
		d.RawSignature = clone(v)
	default:
		return fmt.Errorf("type %d not handled", t)
	}
	return nil
}

// readBigSize reads a BOLT BigSize integer from b.
// Encoding: 0x00-0xfc = 1 byte; 0xfd = 3 bytes (uint16); 0xfe = 5 bytes (uint32); 0xff = 9 bytes (uint64).
// Non-canonical encodings are rejected.
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

// readTU64 decodes a BOLT truncated uint64 (tu64): big-endian, minimum bytes, no prefix.
// Distinct from BigSize: tu64(1000) = [0x03, 0xE8]; BigSize(1000) = [0xfd, 0x03, 0xE8].
func readTU64(b []byte) (uint64, error) {
	if len(b) > 8 {
		return 0, fmt.Errorf("tu64: too many bytes (%d)", len(b))
	}
	if len(b) == 0 {
		return 0, nil
	}
	if b[0] == 0x00 && len(b) > 1 {
		return 0, fmt.Errorf("tu64: non-canonical (leading zero byte)")
	}
	var buf [8]byte
	copy(buf[8-len(b):], b)
	return binary.BigEndian.Uint64(buf[:]), nil
}

func decodeBlindedPaths(data []byte) ([]types.BlindedPath, error) {
	const pointLen = 33
	var paths []types.BlindedPath
	pos := 0
	for pos < len(data) {
		if len(data)-pos < pointLen*2+1 {
			return paths, fmt.Errorf("blinded_path at offset %d: insufficient header data", pos)
		}
		path := types.BlindedPath{
			IntroductionNodeID: clone(data[pos : pos+pointLen]),
			BlindingPoint:      clone(data[pos+pointLen : pos+pointLen*2]),
		}
		pos += pointLen * 2
		numHops, n, err := readBigSize(data[pos:])
		if err != nil {
			return paths, fmt.Errorf("blinded_path: num_hops: %w", err)
		}
		pos += n
		for i := uint64(0); i < numHops; i++ {
			if len(data)-pos < pointLen {
				return paths, fmt.Errorf("blinded_path hop %d: truncated blinded_node_id", i)
			}
			hop := types.BlindedHop{BlindedNodeID: clone(data[pos : pos+pointLen])}
			pos += pointLen
			if len(data)-pos < 2 {
				return paths, fmt.Errorf("blinded_path hop %d: missing encrypted_data length", i)
			}
			encLen := int(binary.BigEndian.Uint16(data[pos : pos+2]))
			pos += 2
			if len(data)-pos < encLen {
				return paths, fmt.Errorf("blinded_path hop %d: encrypted_data truncated", i)
			}
			hop.EncryptedRecipientData = clone(data[pos : pos+encLen])
			pos += encLen
			path.Hops = append(path.Hops, hop)
		}
		paths = append(paths, path)
	}
	return paths, nil
}

func clone(b []byte) []byte {
	if b == nil {
		return nil
	}
	c := make([]byte, len(b))
	copy(c, b)
	return c
}