package server

import (
	"bytes"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/tagban/GO_BNLS/internal/crypto"
	"github.com/tagban/GO_BNLS/internal/profiles"
	"github.com/tagban/GO_BNLS/internal/protocol"
)

// These are integration tests: a real Server on a real loopback TCP
// listener, driven by a hand-rolled client using the same protocol.Reader/
// Writer the production handlers use — the wire format is exercised
// end-to-end rather than asserted against handler internals.

const testSharedSecret = "TestSecret"

func startTestServer(t *testing.T, catalog *profiles.Catalog) net.Conn {
	t.Helper()

	logger := log.New(io.Discard, "", 0)
	srv := New(catalog, testSharedSecret, logger)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen() error = %v", err)
	}
	go srv.Serve(listener)
	t.Cleanup(func() { srv.Close() })

	conn, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatalf("net.Dial() error = %v", err)
	}
	t.Cleanup(func() { conn.Close() })

	return conn
}

func readFrame(t *testing.T, conn net.Conn) []byte {
	t.Helper()

	header := make([]byte, 2)
	if _, err := io.ReadFull(conn, header); err != nil {
		t.Fatalf("reading frame header: %v", err)
	}
	length := int(header[0]) | int(header[1])<<8
	frame := make([]byte, length)
	copy(frame, header)
	if _, err := io.ReadFull(conn, frame[2:]); err != nil {
		t.Fatalf("reading frame body: %v", err)
	}
	return frame
}

func emptyCatalog(t *testing.T) *profiles.Catalog {
	t.Helper()
	catalog, err := profiles.LoadCatalog(t.TempDir(), nil)
	if err != nil {
		t.Fatalf("profiles.LoadCatalog() error = %v", err)
	}
	return catalog
}

func writeTestProfile(t *testing.T, root, dirName, manifestJSON string, files map[string][]byte) {
	t.Helper()
	dir := filepath.Join(root, dirName)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("MkdirAll(%q) error = %v", dir, err)
	}
	if err := os.WriteFile(filepath.Join(dir, "manifest.json"), []byte(manifestJSON), 0o644); err != nil {
		t.Fatalf("WriteFile(manifest.json) error = %v", err)
	}
	for name, data := range files {
		if err := os.WriteFile(filepath.Join(dir, name), data, 0o644); err != nil {
			t.Fatalf("WriteFile(%q) error = %v", name, err)
		}
	}
}

func TestAuthorizeHandshake_ChallengeAndProofRoundTrip(t *testing.T) {
	conn := startTestServer(t, emptyCatalog(t))

	if _, err := conn.Write(protocol.NewWriter().WriteNTString("TestBot").Frame(protocol.OpAuthorize)); err != nil {
		t.Fatalf("Write(AUTHORIZE) error = %v", err)
	}
	reply := readFrame(t, conn)
	if protocol.FrameOpcode(reply) != protocol.OpAuthorize {
		t.Fatalf("opcode = %v, want OpAuthorize", protocol.FrameOpcode(reply))
	}
	challenge, err := protocol.PayloadReader(reply).ReadDword()
	if err != nil {
		t.Fatalf("ReadDword() error = %v", err)
	}

	response := crypto.AuthorizeChecksum(testSharedSecret, challenge)
	if _, err := conn.Write(protocol.NewWriter().WriteDword(response).Frame(protocol.OpAuthorizeProof)); err != nil {
		t.Fatalf("Write(AUTHORIZEPROOF) error = %v", err)
	}
	proofReply := readFrame(t, conn)
	if protocol.FrameOpcode(proofReply) != protocol.OpAuthorizeProof {
		t.Errorf("opcode = %v, want OpAuthorizeProof", protocol.FrameOpcode(proofReply))
	}
}

func TestRequestVersionByte_KnownProduct_ReturnsProfileVersionByte(t *testing.T) {
	root := t.TempDir()
	writeTestProfile(t, root, "d2", `{"product":"D2DV","profileId":"d2","versionByte":10,"hashFiles":["Game.exe"]}`,
		map[string][]byte{"Game.exe": {1, 2, 3}})
	catalog, err := profiles.LoadCatalog(root, map[string]string{"D2DV": "d2"})
	if err != nil {
		t.Fatalf("profiles.LoadCatalog() error = %v", err)
	}

	conn := startTestServer(t, catalog)

	productByte, ok := protocol.ProductByteForName("D2DV")
	if !ok {
		t.Fatal("protocol.ProductByteForName(\"D2DV\") ok = false")
	}
	if _, err := conn.Write(protocol.NewWriter().WriteDword(uint32(productByte)).Frame(protocol.OpRequestVersionByte)); err != nil {
		t.Fatalf("Write() error = %v", err)
	}

	r := protocol.PayloadReader(readFrame(t, conn))
	echoed, _ := r.ReadDword()
	versionByte, _ := r.ReadDword()

	if echoed != uint32(productByte) {
		t.Errorf("echoed product byte = %d, want %d", echoed, productByte)
	}
	if versionByte != 10 {
		t.Errorf("version byte = %d, want 10", versionByte)
	}
}

func TestRequestVersionByte_UnknownProduct_RepliesWithZero(t *testing.T) {
	conn := startTestServer(t, emptyCatalog(t))

	if _, err := conn.Write(protocol.NewWriter().WriteDword(0xFF).Frame(protocol.OpRequestVersionByte)); err != nil {
		t.Fatalf("Write() error = %v", err)
	}

	r := protocol.PayloadReader(readFrame(t, conn))
	echoed, _ := r.ReadDword()
	versionByte, _ := r.ReadDword()

	if echoed != 0xFF {
		t.Errorf("echoed product byte = %d, want 0xFF", echoed)
	}
	if versionByte != 0 {
		t.Errorf("version byte = %d, want 0 for an unconfigured product", versionByte)
	}
}

func TestCDKey_ValidModernKey_ReturnsSuccessWithAuthCheckBlock(t *testing.T) {
	conn := startTestServer(t, emptyCatalog(t))

	req := protocol.NewWriter().WriteDword(0xAABBCCDD).WriteNTString("2222222222222222").Frame(protocol.OpCDKey)
	if _, err := conn.Write(req); err != nil {
		t.Fatalf("Write() error = %v", err)
	}

	r := protocol.PayloadReader(readFrame(t, conn))
	success, err := r.ReadBoolean()
	if err != nil {
		t.Fatalf("ReadBoolean() error = %v", err)
	}
	if !success {
		t.Fatal("success = false, want true for a valid key")
	}
	if _, err := r.ReadDword(); err != nil { // client token
		t.Fatalf("ReadDword(clientToken) error = %v", err)
	}
	block, err := r.ReadRaw(36)
	if err != nil || len(block) != 36 {
		t.Errorf("AuthCheckBlock = %v, %v, want 36 bytes, nil", block, err)
	}
}

func TestCDKey_InvalidKey_ReturnsFailure(t *testing.T) {
	conn := startTestServer(t, emptyCatalog(t))

	req := protocol.NewWriter().WriteDword(0).WriteNTString("NOTAVALIDKEY").Frame(protocol.OpCDKey)
	if _, err := conn.Write(req); err != nil {
		t.Fatalf("Write() error = %v", err)
	}

	success, err := protocol.PayloadReader(readFrame(t, conn)).ReadBoolean()
	if err != nil {
		t.Fatalf("ReadBoolean() error = %v", err)
	}
	if success {
		t.Error("success = true, want false for an invalid key")
	}
}

func TestCDKeyEx_OneValidOneInvalid_PartialSuccess(t *testing.T) {
	conn := startTestServer(t, emptyCatalog(t))

	req := protocol.NewWriter().
		WriteDword(0).                              // cookie
		PutByte(2).                                  // number of keys
		WriteDword(cdKeyExFlagSameSessionKey).
		WriteDword(0x11223344).                       // shared server session key
		WriteNTString("2222222222222222").            // valid modern key
		WriteNTString("NOTVALID").                     // invalid
		Frame(protocol.OpCDKeyEx)
	if _, err := conn.Write(req); err != nil {
		t.Fatalf("Write() error = %v", err)
	}

	r := protocol.PayloadReader(readFrame(t, conn))
	cookie, _ := r.ReadDword()
	numRequested, _ := r.ReadByte()
	numSucceeded, _ := r.ReadByte()
	bitMask, _ := r.ReadDword()

	if cookie != 0 {
		t.Errorf("cookie = %d, want 0", cookie)
	}
	if numRequested != 2 {
		t.Errorf("numRequested = %d, want 2", numRequested)
	}
	if numSucceeded != 1 {
		t.Errorf("numSucceeded = %d, want 1", numSucceeded)
	}
	if bitMask != 0x1 {
		t.Errorf("bitMask = 0x%X, want 0x1 (only the first key succeeded)", bitMask)
	}
	if remaining := r.Remaining(); remaining != 40 {
		t.Errorf("remaining payload = %d bytes, want exactly one 40-byte block (4-byte session key + 36-byte AuthCheckBlock)", remaining)
	}
}

func TestVersionCheckEx2_ComputesChecksumFromProfile(t *testing.T) {
	root := t.TempDir()
	// Same formula/file/expected-checksum as
	// internal/checkrevision's TestEvaluate_SingleChunkSingleFile test —
	// exercised here through the actual wire protocol end to end.
	writeTestProfile(t, root, "test-profile", `{
		"product": "STAR",
		"profileId": "test-profile",
		"versionByte": 1,
		"exeVersion": 42,
		"exeInfoTemplate": "starcraft.exe test",
		"hashFiles": ["file.bin"],
		"fileHashCodes": [0]
	}`, map[string][]byte{"file.bin": {1, 0, 0, 0}})

	catalog, err := profiles.LoadCatalog(root, map[string]string{"STAR": "test-profile"})
	if err != nil {
		t.Fatalf("profiles.LoadCatalog() error = %v", err)
	}

	conn := startTestServer(t, catalog)

	productByte, _ := protocol.ProductByteForName("STAR")
	req := protocol.NewWriter().
		WriteDword(uint32(productByte)).
		WriteDword(0).      // flags
		WriteDword(0xCAFE). // cookie
		WriteDword(0).WriteDword(0). // mpq file time
		WriteNTString("ver-IX86-1.mpq").
		WriteNTString("A=1 B=2 C=3 4 A=A+S B=B+S C=C+S A=A+B").
		Frame(protocol.OpVersionCheckEx2)
	if _, err := conn.Write(req); err != nil {
		t.Fatalf("Write() error = %v", err)
	}

	r := protocol.PayloadReader(readFrame(t, conn))
	success, _ := r.ReadBoolean()
	exeVersion, _ := r.ReadDword()
	checksum, _ := r.ReadDword()
	exeInfo, _ := r.ReadNTString()
	cookieEcho, _ := r.ReadDword()

	if !success {
		t.Fatal("success = false, want true")
	}
	if exeVersion != 42 {
		t.Errorf("exeVersion = %d, want 42", exeVersion)
	}
	if checksum != 4 {
		t.Errorf("checksum = %d, want 4 (see checkrevision.TestEvaluate_SingleChunkSingleFile for the hand-computed trace)", checksum)
	}
	if exeInfo != "starcraft.exe test" {
		t.Errorf("exeInfo = %q, want %q", exeInfo, "starcraft.exe test")
	}
	if cookieEcho != 0xCAFE {
		t.Errorf("cookieEcho = 0x%X, want 0xCAFE", cookieEcho)
	}
}

func TestHashData_SingleHash_MatchesXSha1(t *testing.T) {
	conn := startTestServer(t, emptyCatalog(t))

	data := []byte("hello")
	req := protocol.NewWriter().WriteDword(uint32(len(data))).WriteDword(0).WriteBytes(data).Frame(protocol.OpHashData)
	if _, err := conn.Write(req); err != nil {
		t.Fatalf("Write() error = %v", err)
	}

	got, err := protocol.PayloadReader(readFrame(t, conn)).ReadRaw(20)
	if err != nil {
		t.Fatalf("ReadRaw(20) error = %v", err)
	}

	want := crypto.XSha1(data)
	if !bytes.Equal(got, want) {
		t.Errorf("hash = %x, want %x", got, want)
	}
}

func TestHashData_DoubleHash_PrependsKeysAndRehashes(t *testing.T) {
	conn := startTestServer(t, emptyCatalog(t))

	data := []byte("password")
	clientKey := uint32(0x11111111)
	serverKey := uint32(0x22222222)
	req := protocol.NewWriter().
		WriteDword(uint32(len(data))).
		WriteDword(0x02). // double hash flag
		WriteBytes(data).
		WriteDword(clientKey).
		WriteDword(serverKey).
		Frame(protocol.OpHashData)
	if _, err := conn.Write(req); err != nil {
		t.Fatalf("Write() error = %v", err)
	}

	got, err := protocol.PayloadReader(readFrame(t, conn)).ReadRaw(20)
	if err != nil {
		t.Fatalf("ReadRaw(20) error = %v", err)
	}

	singleHash := crypto.XSha1(data)
	keys := protocol.NewWriter().WriteDword(clientKey).WriteDword(serverKey).Bytes()
	want := crypto.XSha1(keys, singleHash)
	if !bytes.Equal(got, want) {
		t.Errorf("hash = %x, want %x", got, want)
	}
}

func TestHashData_CookieFlag_EchoesCookie(t *testing.T) {
	conn := startTestServer(t, emptyCatalog(t))

	data := []byte("x")
	req := protocol.NewWriter().
		WriteDword(uint32(len(data))).
		WriteDword(0x04). // cookie flag
		WriteBytes(data).
		WriteDword(0xABCD1234).
		Frame(protocol.OpHashData)
	if _, err := conn.Write(req); err != nil {
		t.Fatalf("Write() error = %v", err)
	}

	r := protocol.PayloadReader(readFrame(t, conn))
	if _, err := r.ReadRaw(20); err != nil {
		t.Fatalf("ReadRaw(20) error = %v", err)
	}
	cookie, err := r.ReadDword()
	if err != nil {
		t.Fatalf("ReadDword(cookie) error = %v", err)
	}
	if cookie != 0xABCD1234 {
		t.Errorf("cookie = 0x%X, want 0xABCD1234", cookie)
	}
}
