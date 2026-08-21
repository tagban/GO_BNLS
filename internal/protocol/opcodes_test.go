package protocol

import "testing"

func TestOpcodeString(t *testing.T) {
	cases := []struct {
		op   Opcode
		want string
	}{
		{OpNull, "BNLS_NULL"},
		{OpAuthorize, "BNLS_AUTHORIZE"},
		{OpCDKeyEx, "BNLS_CDKEY_EX"},
		{OpVersionCheckEx2, "BNLS_VERSIONCHECKEX2"},
		{OpWarden, "BNLS_WARDEN"},
		{Opcode(0x99), "BNLS_UNKNOWN"},
	}

	for _, c := range cases {
		if got := c.op.String(); got != c.want {
			t.Errorf("Opcode(0x%02X).String() = %q, want %q", byte(c.op), got, c.want)
		}
	}
}
