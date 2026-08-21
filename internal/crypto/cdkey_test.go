package crypto

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"strconv"
	"strings"
	"testing"
)

// Standalone re-implementation of the encode side (classic key format) and
// an independently-typed reference decoder (modern key format), mirroring
// CdKeyDecoderTests.cs in the companion C# project — this catches
// indexing/logic bugs in DecodeCdKey, though it can't rule out the same
// misunderstanding of the source algorithm being made twice. Treat CD-key
// hashing as needing a live-login check before fully trusting it.

func encodeClassicCdKey(product, publicValue, privateValue int) string {
	plain := fmt.Sprintf("%02d%07d%03d", product, publicValue, privateValue)
	encoded := make([]byte, 12)
	salt := cdKeySalt

	for i := 11; i >= 0; i-- {
		c := plain[i]
		target := classicAlpha[i]
		if c <= 55 {
			encoded[target] = c ^ byte(salt&7)
			salt >>= 3
		} else {
			encoded[target] = c ^ byte(i&1)
		}
	}

	check := 3
	for i := 0; i < 12; i++ {
		check += int(encoded[i]-'0') ^ (check * 2)
	}

	return string(encoded) + string(rune('0'+(((check%10)+10)%10)))
}

func referenceDecodeModernCdKey(rawKey string) (DecodedCdKey, bool) {
	key := strings.ToUpper(strings.TrimSpace(rawKey))
	if len(key) != 16 {
		return DecodedCdKey{}, false
	}

	chars := []byte(key)
	for i := 0; i < 16; i += 2 {
		hi := strings.IndexByte(modernChars, chars[i])
		lo := strings.IndexByte(modernChars, chars[i+1])
		if hi < 0 || lo < 0 {
			return DecodedCdKey{}, false
		}

		n := (lo + hi*24) & 0xFF
		chars[i] = referenceHexChar((n >> 4) & 0xF)
		chars[i+1] = referenceHexChar(n & 0xF)
	}

	plain := make([]byte, 16)
	salt := cdKeySalt
	for i := 15; i >= 0; i-- {
		c := chars[modernAlpha[i]]
		switch {
		case c <= 55:
			plain[i] = c ^ byte(salt&7)
			salt >>= 3
		case c < 65:
			plain[i] = c ^ byte(i&1)
		default:
			plain[i] = c
		}
	}

	hex := string(plain)
	product, err1 := strconv.ParseUint(hex[0:2], 16, 32)
	pub, err2 := strconv.ParseUint(hex[2:8], 16, 32)
	priv, err3 := strconv.ParseUint(hex[8:16], 16, 32)
	if err1 != nil || err2 != nil || err3 != nil {
		return DecodedCdKey{}, false
	}

	return DecodedCdKey{Product: uint32(product), Public: uint32(pub), Private: uint32(priv)}, true
}

func referenceHexChar(v int) byte {
	v &= 0xF
	if v < 10 {
		return byte(v) + '0'
	}
	return byte(v-10) + 'A'
}

func TestDecodeCdKey_ClassicKey_RoundTripsThroughEncode(t *testing.T) {
	key := encodeClassicCdKey(6, 1234567, 890)

	decoded, ok := DecodeCdKey(key)

	if !ok {
		t.Fatalf("DecodeCdKey(%q) ok = false, want true", key)
	}
	if decoded.Product != 6 || decoded.Public != 1234567 || decoded.Private != 890 {
		t.Errorf("DecodeCdKey(%q) = %+v, want {Product:6 Public:1234567 Private:890}", key, decoded)
	}
}

func TestDecodeCdKey_ClassicKey_WrongCheckDigit_ReturnsFalse(t *testing.T) {
	key := encodeClassicCdKey(1, 654321, 42)
	lastDigit := key[len(key)-1]
	tampered := key[:len(key)-1] + string(rune('0'+(int(lastDigit-'0')+1)%10))

	_, ok := DecodeCdKey(tampered)

	if ok {
		t.Errorf("DecodeCdKey(%q) ok = true, want false", tampered)
	}
}

func TestDecodeCdKey_ModernKey_MatchesIndependentlyWrittenReferenceDecoder(t *testing.T) {
	keys := []string{
		"2222222222222222",
		"XZWVTRPNMKJHGFED",
		"246897BCDEFGHJKM",
		"D2XPD2XPD2XPD2XP",
	}

	for _, key := range keys {
		t.Run(key, func(t *testing.T) {
			wantKey, wantOk := referenceDecodeModernCdKey(key)
			gotKey, gotOk := DecodeCdKey(key)

			if gotOk != wantOk || gotKey != wantKey {
				t.Errorf("DecodeCdKey(%q) = %+v, %v, want %+v, %v", key, gotKey, gotOk, wantKey, wantOk)
			}
		})
	}
}

func TestDecodeCdKey_UnsupportedLength_ReturnsFalse(t *testing.T) {
	if _, ok := DecodeCdKey("TOOSHORT"); ok {
		t.Error("DecodeCdKey(\"TOOSHORT\") ok = true, want false")
	}
}

func TestHash_ProducesTwentyByteDigest(t *testing.T) {
	decoded := DecodedCdKey{Product: 6, Public: 1234567, Private: 890}

	hash := decoded.Hash(0x11223344, 0x55667788)

	if len(hash) != 20 {
		t.Errorf("len(Hash()) = %d, want 20", len(hash))
	}
}

func TestAuthCheckBlock_ProducesThirtySixByteBlockWithHeaderAndHash(t *testing.T) {
	decoded := DecodedCdKey{Product: 6, Public: 1234567, Private: 890}

	block := decoded.AuthCheckBlock(13, 0x11223344, 0x55667788)

	if len(block) != 36 {
		t.Fatalf("len(AuthCheckBlock()) = %d, want 36", len(block))
	}
	if got := binary.LittleEndian.Uint32(block[0:4]); got != 13 {
		t.Errorf("key length field = %d, want 13", got)
	}
	if got := binary.LittleEndian.Uint32(block[4:8]); got != 6 {
		t.Errorf("product field = %d, want 6", got)
	}
	if got := binary.LittleEndian.Uint32(block[8:12]); got != 1234567 {
		t.Errorf("public field = %d, want 1234567", got)
	}
	if got := binary.LittleEndian.Uint32(block[12:16]); got != 0 {
		t.Errorf("reserved field = %d, want 0", got)
	}
	if !bytes.Equal(block[16:36], decoded.Hash(0x11223344, 0x55667788)) {
		t.Error("hash portion of block does not match Hash()")
	}
}
