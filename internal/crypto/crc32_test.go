package crypto

import "testing"

func TestCRC32_MatchesStandardCheckValue(t *testing.T) {
	// "123456789" is the standard CRC-32/ISO-HDLC check value: 0xCBF43926.
	got := CRC32([]byte("123456789"))
	if got != 0xCBF43926 {
		t.Errorf("CRC32(\"123456789\") = 0x%08X, want 0xCBF43926", got)
	}
}

func TestCRC32_EmptyInput_ReturnsZero(t *testing.T) {
	if got := CRC32(nil); got != 0 {
		t.Errorf("CRC32(nil) = 0x%08X, want 0", got)
	}
}
