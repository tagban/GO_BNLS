package checkrevision

// mpqFileHashCodes are the per-mpq-index "hash codes" CheckRevision XORs
// into its seed A value once, before processing any file's bytes. Confirmed
// against two independent sources: the project owner's own original
// CheckRevision implementation, and the MIT-licensed, actively-maintained
// github.com/BNETDocs/MBNCSUtil/blob/develop/src/CheckRevision.cs.
var mpqFileHashCodes = [8]uint32{
	0xE7F4CB62, 0xF6A14FFC, 0xAA5504AF, 0x871FCDC2,
	0x11BF6A18, 0xC57292E6, 0x7927D27E, 0x2FEC8733,
}

// HashCodeForMpqFileName derives the CheckRevision hash code from the
// mpqFileName field of a BNLS_VERSIONCHECKEX2 request, matching the two
// filename conventions observed both in real captures this session and in
// the reference implementation: "ver-IX86-N.mpq" (the index digit sits at
// position 9) and "IX86verN.mpq" (index digit at position 7). Returns
// ok=false if the name doesn't match either shape or the digit is out of
// the table's 0-7 range.
func HashCodeForMpqFileName(name string) (uint32, bool) {
	var indexChar byte
	switch {
	case len(name) > 9 && name[0:3] == "ver":
		indexChar = name[9]
	case len(name) > 7 && name[4:7] == "ver":
		indexChar = name[7]
	default:
		return 0, false
	}

	if indexChar < '0' || indexChar > '9' {
		return 0, false
	}
	index := indexChar - '0'
	if int(index) >= len(mpqFileHashCodes) {
		return 0, false
	}
	return mpqFileHashCodes[index], true
}

// PadToBoundary pads data up to the next multiple of boundary bytes
// (returned as-is if already a multiple), filling the new bytes with a
// descending sequence starting at 0xFF and wrapping every 256 bytes
// (0xFF, 0xFE, ..., 0x01, 0x00, 0xFF, ...). Every hash file is padded to a
// 1024-byte boundary this way before hashing — confirmed against both the
// project owner's own original implementation and the MIT-licensed
// github.com/BNETDocs/MBNCSUtil/blob/develop/src/CheckRevision.cs, which
// applies this same padding unconditionally (no separate "unpadded"
// variant), settling what was an earlier open question in this package.
func PadToBoundary(data []byte, boundary int) []byte {
	if boundary <= 0 || len(data)%boundary == 0 {
		return data
	}

	padded := make([]byte, ((len(data)/boundary)+1)*boundary)
	copy(padded, data)

	value := byte(0xFF)
	for i := len(data); i < len(padded); i++ {
		padded[i] = value
		value--
	}
	return padded
}
