package server

import (
	"fmt"

	"github.com/tagban/GO_BNLS/internal/checkrevision"
	"github.com/tagban/GO_BNLS/internal/crypto"
	"github.com/tagban/GO_BNLS/internal/protocol"
)

// handleAuthorize answers BNLS_AUTHORIZE with a fresh random challenge.
// bnetdocs marks this whole exchange (AUTHORIZE/AUTHORIZEPROOF) as defunct,
// but real clients — including Invigoration — still send it, so it's
// answered harmlessly rather than left unimplemented.
func (s *Session) handleAuthorize(r *protocol.Reader) error {
	if _, err := r.ReadNTString(); err != nil { // bot name, unused
		return fmt.Errorf("AUTHORIZE: %w", err)
	}

	challenge, err := randomUint32()
	if err != nil {
		return err
	}
	s.challenge = challenge

	return s.send(protocol.NewWriter().WriteDword(challenge).Frame(protocol.OpAuthorize))
}

// handleAuthorizeProof answers BNLS_AUTHORIZEPROOF. A mismatched checksum
// is logged, not rejected — no known client (including Invigoration) checks
// this reply's payload, matching the exchange's documented defunct status.
func (s *Session) handleAuthorizeProof(r *protocol.Reader) error {
	response, err := r.ReadDword()
	if err != nil {
		return fmt.Errorf("AUTHORIZEPROOF: %w", err)
	}

	if expected := crypto.AuthorizeChecksum(s.sharedSecret, s.challenge); response != expected {
		s.logger.Printf("%s: AUTHORIZEPROOF checksum mismatch (defunct exchange, continuing anyway)", s.remoteAddr)
	}

	return s.send(protocol.NewWriter().Frame(protocol.OpAuthorizeProof))
}

// handleRequestVersionByte answers BNLS_REQUESTVERSIONBYTE with the
// product's configured default profile's version byte. Reply is two
// DWORDs — the echoed product byte, then the actual version byte — matching
// what Invigoration's client (and, per its own history, real BNCS servers)
// expects; a single-DWORD reply was a real bug caught earlier this project.
func (s *Session) handleRequestVersionByte(r *protocol.Reader) error {
	productDword, err := r.ReadDword()
	if err != nil {
		return fmt.Errorf("REQUESTVERSIONBYTE: %w", err)
	}

	name, ok := protocol.ProductName(productByteFromDword(productDword))
	if !ok {
		s.logger.Printf("%s: REQUESTVERSIONBYTE for unrecognized product byte 0x%02X", s.remoteAddr, byte(productDword))
		return s.send(protocol.NewWriter().WriteDword(productDword).WriteDword(0).Frame(protocol.OpRequestVersionByte))
	}
	s.product = name
	s.stats.RecordProductRequest(name)

	profile, ok := s.catalog.Default(name)
	if !ok {
		s.logger.Printf("%s: no profile configured for product %s, replying with version byte 0", s.remoteAddr, name)
		return s.send(protocol.NewWriter().WriteDword(productDword).WriteDword(0).Frame(protocol.OpRequestVersionByte))
	}

	return s.send(protocol.NewWriter().WriteDword(productDword).WriteDword(profile.VersionByte).Frame(protocol.OpRequestVersionByte))
}

// handleCDKey answers the legacy single-key BNLS_CDKEY, used for every
// product that doesn't need an expansion key. Reply carries the full
// 36-byte AuthCheckBlock, not just the raw 20-byte hash — confirmed against
// Invigoration's client, which reads exactly 36 raw bytes into the field it
// later writes untouched into SID_AUTH_CHECK.
func (s *Session) handleCDKey(r *protocol.Reader) error {
	serverToken, err := r.ReadDword()
	if err != nil {
		return fmt.Errorf("CDKEY: %w", err)
	}
	key, err := r.ReadNTString()
	if err != nil {
		return fmt.Errorf("CDKEY: %w", err)
	}

	decoded, ok := crypto.DecodeCdKey(key)
	if !ok {
		return s.send(protocol.NewWriter().WriteDword(0).Frame(protocol.OpCDKey)) // Success = false
	}

	clientToken, err := randomUint32()
	if err != nil {
		return err
	}
	block := decoded.AuthCheckBlock(len(key), clientToken, serverToken)

	reply := protocol.NewWriter().
		WriteDword(1). // Success
		WriteDword(clientToken).
		WriteBytes(block).
		Frame(protocol.OpCDKey)
	return s.send(reply)
}

// cdKeyExFlagSameSessionKey is the only BNLS_CDKEY_EX request flag
// Invigoration's client — and, per its own comments, every dual-key product
// it supports — ever sends: one shared server session key for all keys in
// the request, rather than per-key ones.
const cdKeyExFlagSameSessionKey = 0x1

// handleCDKeyEx answers BNLS_CDKEY_EX (used for dual-key products like
// Diablo II: LoD and Warcraft III: TFT). The reply's per-key data blocks
// are bounded by the number of keys that SUCCEEDED, not the number
// requested — the exact mistake that crashed Invigoration's client earlier
// this session when a real server sent fewer successes than requests.
func (s *Session) handleCDKeyEx(r *protocol.Reader) error {
	cookie, err := r.ReadDword()
	if err != nil {
		return fmt.Errorf("CDKEY_EX: %w", err)
	}
	numberOfKeys, err := r.ReadByte()
	if err != nil {
		return fmt.Errorf("CDKEY_EX: %w", err)
	}
	flags, err := r.ReadDword()
	if err != nil {
		return fmt.Errorf("CDKEY_EX: %w", err)
	}

	if flags != cdKeyExFlagSameSessionKey {
		s.logger.Printf("%s: CDKEY_EX with unsupported flags 0x%X, rejecting all keys", s.remoteAddr, flags)
		reply := protocol.NewWriter().WriteDword(cookie).PutByte(numberOfKeys).PutByte(0).WriteDword(0).Frame(protocol.OpCDKeyEx)
		return s.send(reply)
	}

	serverSessionKey, err := r.ReadDword()
	if err != nil {
		return fmt.Errorf("CDKEY_EX: %w", err)
	}

	keys := make([]string, numberOfKeys)
	for i := range keys {
		keys[i], err = r.ReadNTString()
		if err != nil {
			return fmt.Errorf("CDKEY_EX: reading key %d: %w", i, err)
		}
	}

	blocks := protocol.NewWriter()
	var bitMask uint32
	var succeeded byte

	for i, key := range keys {
		decoded, ok := crypto.DecodeCdKey(key)
		if !ok {
			continue
		}

		clientSessionKey, err := randomUint32()
		if err != nil {
			return err
		}
		block := decoded.AuthCheckBlock(len(key), clientSessionKey, serverSessionKey)

		blocks.WriteDword(clientSessionKey).WriteBytes(block)
		bitMask |= 1 << uint(i)
		succeeded++
	}

	reply := protocol.NewWriter().
		WriteDword(cookie).
		PutByte(numberOfKeys).
		PutByte(succeeded).
		WriteDword(bitMask).
		WriteBytes(blocks.Bytes()).
		Frame(protocol.OpCDKeyEx)
	return s.send(reply)
}

// handleVersionCheckEx2 answers BNLS_VERSIONCHECKEX2 by running the
// server-supplied CheckRevision formula against the product's configured
// profile's game files. See internal/checkrevision's package doc for the
// documented-vs-assumed parts of this computation — unverified against a
// real BNLS server as of this commit.
func (s *Session) handleVersionCheckEx2(r *protocol.Reader) error {
	productDword, err := r.ReadDword()
	if err != nil {
		return fmt.Errorf("VERSIONCHECKEX2: %w", err)
	}
	if _, err := r.ReadDword(); err != nil { // flags, unused
		return fmt.Errorf("VERSIONCHECKEX2: flags: %w", err)
	}
	cookie, err := r.ReadDword()
	if err != nil {
		return fmt.Errorf("VERSIONCHECKEX2: cookie: %w", err)
	}
	if _, err := r.ReadDword(); err != nil { // MPQ file time low, unused
		return fmt.Errorf("VERSIONCHECKEX2: mpq file time low: %w", err)
	}
	if _, err := r.ReadDword(); err != nil { // MPQ file time high, unused
		return fmt.Errorf("VERSIONCHECKEX2: mpq file time high: %w", err)
	}
	if _, err := r.ReadNTString(); err != nil { // MPQ file name, unused
		return fmt.Errorf("VERSIONCHECKEX2: mpq file name: %w", err)
	}
	formulaText, err := r.ReadNTString()
	if err != nil {
		return fmt.Errorf("VERSIONCHECKEX2: formula: %w", err)
	}

	name, ok := protocol.ProductName(productByteFromDword(productDword))
	if !ok {
		return s.sendVersionCheckEx2Failure(cookie)
	}

	profile, ok := s.catalog.Default(name)
	if !ok {
		s.logger.Printf("%s: VERSIONCHECKEX2 for %s with no configured profile", s.remoteAddr, name)
		return s.sendVersionCheckEx2Failure(cookie)
	}

	formula, err := checkrevision.ParseFormula(formulaText)
	if err != nil {
		s.logger.Printf("%s: VERSIONCHECKEX2 formula parse error: %v", s.remoteAddr, err)
		return s.sendVersionCheckEx2Failure(cookie)
	}

	files, err := profile.LoadFiles()
	if err != nil {
		s.logger.Printf("%s: VERSIONCHECKEX2 loading profile files: %v", s.remoteAddr, err)
		return s.sendVersionCheckEx2Failure(cookie)
	}

	checksum, err := checkrevision.Evaluate(formula, files, profile.FileHashCodes)
	if err != nil {
		s.logger.Printf("%s: VERSIONCHECKEX2 evaluate error: %v", s.remoteAddr, err)
		return s.sendVersionCheckEx2Failure(cookie)
	}

	reply := protocol.NewWriter().
		WriteDword(1). // Success
		WriteDword(profile.ExeVersion).
		WriteDword(checksum).
		WriteNTString(profile.ExeInfoTemplate).
		WriteDword(cookie).
		WriteDword(0). // Version code, unused by Invigoration's client
		Frame(protocol.OpVersionCheckEx2)
	return s.send(reply)
}

func (s *Session) sendVersionCheckEx2Failure(cookie uint32) error {
	reply := protocol.NewWriter().
		WriteDword(0). // Success = false
		WriteDword(0).
		WriteDword(0).
		WriteNTString("").
		WriteDword(cookie).
		WriteDword(0).
		Frame(protocol.OpVersionCheckEx2)
	return s.send(reply)
}

// BNLS_HASHDATA flags, per bnetdocs.org/packet/293/bnls-hashdata: 0x01 has
// no documented effect, 0x02 requests the double-hash (prepend client+
// server key to the single hash, then hash again), 0x04 echoes an
// application-defined cookie back in the reply.
const (
	hashDataFlagDoubleHash = 0x02
	hashDataFlagCookie     = 0x04
)

// handleHashData answers BNLS_HASHDATA, used by every non-NLS product for
// old-login-system password hashing (and by the account-creation flow).
func (s *Session) handleHashData(r *protocol.Reader) error {
	size, err := r.ReadDword()
	if err != nil {
		return fmt.Errorf("HASHDATA: %w", err)
	}
	flags, err := r.ReadDword()
	if err != nil {
		return fmt.Errorf("HASHDATA: %w", err)
	}
	data, err := r.ReadRaw(int(size))
	if err != nil {
		return fmt.Errorf("HASHDATA: reading %d-byte payload: %w", size, err)
	}

	result := crypto.XSha1(data)

	if flags&hashDataFlagDoubleHash != 0 {
		clientKey, err := r.ReadDword()
		if err != nil {
			return fmt.Errorf("HASHDATA: client key: %w", err)
		}
		serverKey, err := r.ReadDword()
		if err != nil {
			return fmt.Errorf("HASHDATA: server key: %w", err)
		}

		keys := protocol.NewWriter().WriteDword(clientKey).WriteDword(serverKey).Bytes()
		result = crypto.XSha1(keys, result)
	}

	reply := protocol.NewWriter().WriteBytes(result)

	if flags&hashDataFlagCookie != 0 {
		cookie, err := r.ReadDword()
		if err != nil {
			return fmt.Errorf("HASHDATA: cookie: %w", err)
		}
		reply.WriteDword(cookie)
	}

	return s.send(reply.Frame(protocol.OpHashData))
}
