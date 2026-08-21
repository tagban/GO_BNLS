package crypto

import (
	"encoding/binary"
	"strconv"
	"strings"
)

// DecodedCdKey is the product/public/private triple Blizzard's CD-key
// cipher embeds in a key, used to build the CD-key hash block a
// BNLS_CDKEY/BNLS_CDKEY_EX reply carries.
type DecodedCdKey struct {
	Product uint32
	Public  uint32
	Private uint32
}

// Hash returns the 20-byte X-SHA1 digest for this key, given this
// handshake's client/server tokens.
func (k DecodedCdKey) Hash(clientToken, serverToken uint32) []byte {
	buf := make([]byte, 24)
	binary.LittleEndian.PutUint32(buf[0:4], clientToken)
	binary.LittleEndian.PutUint32(buf[4:8], serverToken)
	binary.LittleEndian.PutUint32(buf[8:12], k.Product)
	binary.LittleEndian.PutUint32(buf[12:16], k.Public)
	binary.LittleEndian.PutUint32(buf[16:20], 0) // reserved, always zero on the wire
	binary.LittleEndian.PutUint32(buf[20:24], k.Private)
	return XSha1(buf)
}

// AuthCheckBlock returns the full 36-byte CD-key block a CDKEY/CDKEY_EX
// reply carries per key: Key Length(4) + Product(4) + Public(4) +
// reserved(4) + the 20-byte hash from Hash. keyLength is the length of the
// original CD-key string as typed (13 or 16).
func (k DecodedCdKey) AuthCheckBlock(keyLength int, clientToken, serverToken uint32) []byte {
	block := make([]byte, 36)
	binary.LittleEndian.PutUint32(block[0:4], uint32(keyLength))
	binary.LittleEndian.PutUint32(block[4:8], k.Product)
	binary.LittleEndian.PutUint32(block[8:12], k.Public)
	binary.LittleEndian.PutUint32(block[12:16], 0) // reserved
	copy(block[16:36], k.Hash(clientToken, serverToken))
	return block
}

const cdKeySalt uint32 = 0x13AC9741

var classicAlpha = [12]int{6, 0, 2, 9, 3, 11, 1, 7, 5, 4, 10, 8}
var modernAlpha = [16]int{5, 6, 0, 1, 2, 3, 4, 9, 10, 11, 12, 13, 14, 15, 7, 8}

const modernChars = "246789BCDEFGHJKMNPRTVWXZ"

// DecodeCdKey decodes a classic 13-digit numeric (StarCraft/Diablo/
// Warcraft II) or modern 16-character alphanumeric (Diablo II/Warcraft
// II:BNE) Battle.net CD-key into its embedded product/public/private
// values, dispatching on length. Returns ok=false if the key is malformed,
// an unsupported length, or fails its checksum. Ported from the salt-
// substitution cipher in Davnit/bncs.py's SCKeyDecoder/D2KeyDecoder
// (bncs/hashing/cdkeys.py) via the companion Invigoration C# project.
//
// Warcraft III/TFT's 26-character format uses a different, more involved
// cipher and is not implemented here yet (see README).
func DecodeCdKey(rawKey string) (DecodedCdKey, bool) {
	key := strings.ToUpper(strings.TrimSpace(rawKey))
	switch len(key) {
	case 13:
		return decodeClassicCdKey(key)
	case 16:
		return decodeModernCdKey(key)
	default:
		return DecodedCdKey{}, false
	}
}

func decodeClassicCdKey(key string) (DecodedCdKey, bool) {
	for i := 0; i < len(key); i++ {
		if key[i] < '0' || key[i] > '9' {
			return DecodedCdKey{}, false
		}
	}

	var decoded [12]byte
	salt := cdKeySalt

	for i := 11; i >= 0; i-- {
		c := key[classicAlpha[i]]
		if c <= 55 { // '0'-'7'
			decoded[i] = c ^ byte(salt&7)
			salt >>= 3
		} else { // '8'-'9'
			decoded[i] = c ^ byte(i&1)
		}
	}

	if classicCheckDigit(key) != key[12] {
		return DecodedCdKey{}, false
	}

	value := string(decoded[:])
	product, err1 := strconv.ParseUint(value[0:2], 10, 32)
	pub, err2 := strconv.ParseUint(value[2:9], 10, 32)
	priv, err3 := strconv.ParseUint(value[9:12], 10, 32)
	if err1 != nil || err2 != nil || err3 != nil {
		return DecodedCdKey{}, false
	}

	return DecodedCdKey{Product: uint32(product), Public: uint32(pub), Private: uint32(priv)}, true
}

func classicCheckDigit(key string) byte {
	check := 3
	for i := 0; i < 12; i++ {
		check += int(key[i]-'0') ^ (check * 2)
	}
	return byte('0' + (((check % 10) + 10) % 10))
}

func decodeModernCdKey(key string) (DecodedCdKey, bool) {
	chars := []byte(key)
	for i := 0; i < 15; i += 2 {
		hi := strings.IndexByte(modernChars, chars[i])
		lo := strings.IndexByte(modernChars, chars[i+1])
		if hi < 0 || lo < 0 {
			return DecodedCdKey{}, false
		}

		n := (lo + hi*24) & 0xFF
		chars[i] = hexChar((n >> 4) & 0xF)
		chars[i+1] = hexChar(n & 0xF)
	}

	var decoded [16]byte
	salt := cdKeySalt

	for i := 15; i >= 0; i-- {
		c := chars[modernAlpha[i]]
		switch {
		case c <= 55: // '0'-'7'
			decoded[i] = c ^ byte(salt&7)
			salt >>= 3
		case c < 65: // '8'-'9' (and the unused ':'-'@' range)
			decoded[i] = c ^ byte(i&1)
		default: // 'A'-'F' (already-decoded hex digit from the pass above)
			decoded[i] = c
		}
	}

	hex := string(decoded[:])
	product, err1 := strconv.ParseUint(hex[0:2], 16, 32)
	pub, err2 := strconv.ParseUint(hex[2:8], 16, 32)
	priv, err3 := strconv.ParseUint(hex[8:16], 16, 32)
	if err1 != nil || err2 != nil || err3 != nil {
		return DecodedCdKey{}, false
	}

	return DecodedCdKey{Product: uint32(product), Public: uint32(pub), Private: uint32(priv)}, true
}

func hexChar(v int) byte {
	v &= 0xF
	if v < 10 {
		return byte(v) + '0'
	}
	return byte(v-10) + 'A'
}
