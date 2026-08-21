// Package server implements the BNLS TCP accept loop and per-connection
// opcode handling.
package server

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"

	"github.com/tagban/GO_BNLS/internal/profiles"
	"github.com/tagban/GO_BNLS/internal/protocol"
)

// Session handles one client connection: reads length-prefixed BNLS
// frames, dispatches them by opcode, and writes replies.
type Session struct {
	conn         net.Conn
	catalog      *profiles.Catalog
	sharedSecret string
	logger       *log.Logger
	stats        *Stats

	remoteAddr string

	// Handshake state accumulated across the session.
	challenge uint32
	product   string // short BNLS product name (e.g. "W3XP"), once known
}

func newSession(conn net.Conn, catalog *profiles.Catalog, sharedSecret string, logger *log.Logger, stats *Stats) *Session {
	return &Session{
		conn:         conn,
		catalog:      catalog,
		sharedSecret: sharedSecret,
		logger:       logger,
		stats:        stats,
		remoteAddr:   conn.RemoteAddr().String(),
	}
}

// Serve reads and dispatches frames until the connection closes or a fatal
// framing error occurs. Recovers from any panic in a handler so one bad
// connection can't take the whole server down — this reads untrusted
// network input, and defense in depth here is cheap.
func (s *Session) Serve() {
	defer func() {
		if r := recover(); r != nil {
			s.logger.Printf("%s: recovered from panic in handler: %v", s.remoteAddr, r)
		}
		s.conn.Close()
	}()

	var buf bytes.Buffer
	readChunk := make([]byte, 4096)

	for {
		length, ok := protocol.TryFrameLength(buf.Bytes())
		if ok && buf.Len() >= length {
			frame := make([]byte, length)
			copy(frame, buf.Bytes()[:length])
			buf.Next(length)

			if err := s.dispatch(frame); err != nil {
				s.logger.Printf("%s: %v", s.remoteAddr, err)
				return
			}
			continue
		}

		n, err := s.conn.Read(readChunk)
		if n > 0 {
			buf.Write(readChunk[:n])
		}
		if err != nil {
			if err != io.EOF {
				s.logger.Printf("%s: read error: %v", s.remoteAddr, err)
			}
			return
		}
	}
}

func (s *Session) dispatch(frame []byte) error {
	op := protocol.FrameOpcode(frame)
	payload := protocol.PayloadReader(frame)

	switch op {
	case protocol.OpNull:
		return nil // no-op keepalive, no reply
	case protocol.OpAuthorize:
		return s.handleAuthorize(payload)
	case protocol.OpAuthorizeProof:
		return s.handleAuthorizeProof(payload)
	case protocol.OpRequestVersionByte:
		return s.handleRequestVersionByte(payload)
	case protocol.OpCDKey:
		return s.handleCDKey(payload)
	case protocol.OpCDKeyEx:
		return s.handleCDKeyEx(payload)
	case protocol.OpVersionCheckEx2:
		return s.handleVersionCheckEx2(payload)
	case protocol.OpHashData:
		return s.handleHashData(payload)
	default:
		s.logger.Printf("%s: unimplemented opcode %s (0x%02X), ignoring", s.remoteAddr, op, byte(op))
		return nil
	}
}

func (s *Session) send(frame []byte) error {
	_, err := s.conn.Write(frame)
	return err
}

// randomUint32 returns a cryptographically random 32-bit value, used
// anywhere this server needs to generate a fresh challenge/session token —
// there's no reason to use a weaker source for values an attacker could
// otherwise try to predict.
func randomUint32() (uint32, error) {
	var buf [4]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return 0, fmt.Errorf("generating random value: %w", err)
	}
	return binary.LittleEndian.Uint32(buf[:]), nil
}

// productByteFromDword narrows a wire DWORD product byte field down to
// protocol.ProductByte, matching how the client always sends it as a full
// DWORD with only the low byte meaningful.
func productByteFromDword(v uint32) protocol.ProductByte {
	return protocol.ProductByte(byte(v))
}
