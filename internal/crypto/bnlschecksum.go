package crypto

import "fmt"

// AuthorizeChecksum computes the CRC-32 challenge response BNLS_AUTHORIZE
// expects: CRC32 of the shared secret followed by the 8-digit uppercase hex
// server code.
func AuthorizeChecksum(sharedSecret string, serverCode uint32) uint32 {
	text := fmt.Sprintf("%s%08X", sharedSecret, serverCode)
	return CRC32([]byte(text))
}
