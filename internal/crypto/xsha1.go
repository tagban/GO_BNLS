package crypto

import (
	"encoding/binary"
	"math/bits"
)

const xsha1BlockSize = 64

var xsha1RoundConstants = [4]uint32{0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xCA62C1D6}

// XSha1 computes Battle.net's "Broken SHA-1" (a.k.a. X-SHA1) hashing
// algorithm, used by the old login system to hash passwords and CD-keys.
// Structurally identical to standard SHA-1 (same round functions, round
// constants, and finalization) except for two quirks that earned it the
// "broken" name: no length-suffix/0x80-bit padding at all (a final partial
// block is simply zero-filled), and the message-schedule expansion sets
// each extended word to a single bit — 1 << (xor-combo & 31) — instead of
// rotating the xor-combo itself. Segments are hashed as if concatenated.
func XSha1(segments ...[]byte) []byte {
	state := [5]uint32{0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0}
	block := make([]byte, xsha1BlockSize)
	position := 0

	for _, segment := range segments {
		offset := 0
		for offset < len(segment) {
			take := len(segment) - offset
			if room := xsha1BlockSize - position; take > room {
				take = room
			}
			copy(block[position:position+take], segment[offset:offset+take])
			position += take
			offset += take

			if position == xsha1BlockSize {
				xsha1Transform(&state, block)
				position = 0
			}
		}
	}

	if position > 0 {
		for i := position; i < xsha1BlockSize; i++ {
			block[i] = 0
		}
		xsha1Transform(&state, block)
	}

	result := make([]byte, 20)
	for i := 0; i < 5; i++ {
		binary.LittleEndian.PutUint32(result[i*4:], state[i])
	}
	return result
}

func xsha1Transform(state *[5]uint32, block []byte) {
	var w [80]uint32
	for i := 0; i < 16; i++ {
		w[i] = binary.LittleEndian.Uint32(block[i*4:])
	}

	for i := 16; i < 80; i++ {
		value := w[i-16] ^ w[i-8] ^ w[i-14] ^ w[i-3]
		w[i] = 1 << (value & 31)
	}

	a, b, c, d, e := state[0], state[1], state[2], state[3], state[4]

	for i := 0; i < 80; i++ {
		var f uint32
		switch {
		case i < 20:
			f = (b & c) | (^b & d)
		case i < 40:
			f = b ^ c ^ d
		case i < 60:
			f = (b & c) | (b & d) | (c & d)
		default:
			f = b ^ c ^ d
		}

		temp := bits.RotateLeft32(a, 5) + f + e + w[i] + xsha1RoundConstants[i/20]
		e = d
		d = c
		c = bits.RotateLeft32(b, 30)
		b = a
		a = temp
	}

	state[0] += a
	state[1] += b
	state[2] += c
	state[3] += d
	state[4] += e
}
