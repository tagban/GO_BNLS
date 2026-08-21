package crypto

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"
)

// toBigEndianWordHex mirrors XSha1Tests.ToBigEndianWordHex from the
// companion C# project: reads each 4-byte little-endian word back out and
// formats it big-endian, to compare against a reference vector printed via
// printf("%08x%08x%08x%08x%08x", ...) on the five raw state words.
func toBigEndianWordHex(digest []byte) string {
	var sb strings.Builder
	for i := 0; i < len(digest); i += 4 {
		value := binary.LittleEndian.Uint32(digest[i : i+4])
		fmt.Fprintf(&sb, "%08x", value)
	}
	return sb.String()
}

// From wjlafrance/broken-sha1's main.c (a C port of Rob Paveza's
// MBNCSUtil), printed there via printf("%08x%08x%08x%08x%08x", ...) on the
// five raw state words.
func TestXSha1_MatchesBrokenSha1CReferenceVector(t *testing.T) {
	result := XSha1([]byte("1234567890"))

	got := toBigEndianWordHex(result)
	want := "99f0fab8b5b4523e0d58e5efe126fa5f12633b4b"
	if got != want {
		t.Errorf("XSha1 big-endian-word hex = %q, want %q", got, want)
	}
}

// From Davnit/bncs.py's bsha.py docstring, documenting that library's own
// .hexdigest() output — i.e. the actual little-endian wire bytes
// hex-encoded directly, the same convention XSha1 uses here.
func TestXSha1_MatchesBncsPyReferenceVector(t *testing.T) {
	result := XSha1([]byte("The quick brown fox jumps over the lazy dog"))

	got := strings.ToLower(hex.EncodeToString(result))
	want := "a0db6e70616033a7b5fdda37cee2d43f2da10288"
	if got != want {
		t.Errorf("XSha1 hex = %q, want %q", got, want)
	}
}

func TestXSha1_MultipleSegments_MatchesEquivalentSingleSegment(t *testing.T) {
	whole := XSha1([]byte("1234567890"))
	split := XSha1([]byte("12345"), []byte("67890"))

	if !bytes.Equal(whole, split) {
		t.Errorf("split segments = %x, want %x", split, whole)
	}
}
