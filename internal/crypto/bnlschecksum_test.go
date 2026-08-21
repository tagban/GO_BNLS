package crypto

import (
	"fmt"
	"testing"
)

func TestAuthorizeChecksum_MatchesManualCRC32OfConcatenatedSecretAndHexServerCode(t *testing.T) {
	expected := CRC32([]byte(fmt.Sprintf("Invigoration%08X", 0xFF)))

	got := AuthorizeChecksum("Invigoration", 0xFF)

	if got != expected {
		t.Errorf("AuthorizeChecksum() = 0x%08X, want 0x%08X", got, expected)
	}
}
