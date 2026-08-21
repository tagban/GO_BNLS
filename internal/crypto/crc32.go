// Package crypto implements the small set of algorithms BNLS needs:
// standard CRC-32 (for the AUTHORIZE challenge/response), Battle.net's
// "Broken SHA-1", and the classic/modern CD-key ciphers. Ported from the
// working, tested implementations in the companion Invigoration project
// (github.com/tagban/invigoration, dotnet/src/Invigoration.Core/Auth/) —
// reusing already-solved math, not copied from JBLS or any other existing
// BNLS server implementation.
package crypto

// crc32Polynomial is the standard reflected CRC-32 polynomial (0xEDB88320).
const crc32Polynomial = 0xEDB88320

var crc32Table = buildCRC32Table()

func buildCRC32Table() [256]uint32 {
	var table [256]uint32
	for i := uint32(0); i < 256; i++ {
		value := i
		for bit := 0; bit < 8; bit++ {
			if value&1 != 0 {
				value = (value >> 1) ^ crc32Polynomial
			} else {
				value = value >> 1
			}
		}
		table[i] = value
	}
	return table
}

// CRC32 computes the standard reflected CRC-32 (poly 0xEDB88320, init
// 0xFFFFFFFF, final XOR) BNLS's AUTHORIZE checksum is built on.
func CRC32(data []byte) uint32 {
	crc := uint32(0xFFFFFFFF)
	for _, b := range data {
		index := b ^ byte(crc&0xFF)
		crc = (crc >> 8) ^ crc32Table[index]
	}
	return ^crc
}
