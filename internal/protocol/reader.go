package protocol

import (
	"encoding/binary"
	"errors"
)

// ErrShortBuffer is returned when a read would go past the end of the
// buffer. Unlike a client reading from a semi-trusted BNLS server, this
// server reads packets from arbitrary network clients, so reads are bounds-
// checked and return an error instead of panicking on malformed/truncated
// input.
var ErrShortBuffer = errors.New("protocol: short buffer")

// Reader is a sequential little-endian reader over a packet payload.
type Reader struct {
	buf []byte
	pos int
}

// NewReader wraps buf for sequential reading, starting at offset.
func NewReader(buf []byte, offset int) *Reader {
	return &Reader{buf: buf, pos: offset}
}

// Position returns the current read offset into the buffer.
func (r *Reader) Position() int { return r.pos }

// Remaining returns the number of unread bytes left in the buffer.
func (r *Reader) Remaining() int { return len(r.buf) - r.pos }

// Skip advances the read position by count bytes without reading them.
func (r *Reader) Skip(count int) { r.pos += count }

func (r *Reader) ReadByte() (byte, error) {
	if r.Remaining() < 1 {
		return 0, ErrShortBuffer
	}
	v := r.buf[r.pos]
	r.pos++
	return v, nil
}

func (r *Reader) ReadWord() (uint16, error) {
	if r.Remaining() < 2 {
		return 0, ErrShortBuffer
	}
	v := binary.LittleEndian.Uint16(r.buf[r.pos:])
	r.pos += 2
	return v, nil
}

func (r *Reader) ReadDword() (uint32, error) {
	if r.Remaining() < 4 {
		return 0, ErrShortBuffer
	}
	v := binary.LittleEndian.Uint32(r.buf[r.pos:])
	r.pos += 4
	return v, nil
}

// ReadBoolean reads a full DWORD, per BNLS convention: 0 = false, nonzero = true.
func (r *Reader) ReadBoolean() (bool, error) {
	v, err := r.ReadDword()
	return v != 0, err
}

func (r *Reader) ReadRaw(length int) ([]byte, error) {
	if r.Remaining() < length {
		return nil, ErrShortBuffer
	}
	result := make([]byte, length)
	copy(result, r.buf[r.pos:r.pos+length])
	r.pos += length
	return result, nil
}

// FileTime is a raw Win32 FILETIME (low/high DWORD pair), kept unparsed
// since callers echo it back verbatim.
type FileTime struct {
	Low, High uint32
}

// ReadFileTime reads a Win32 FILETIME (two little-endian DWORDs: low, then high).
func (r *Reader) ReadFileTime() (FileTime, error) {
	low, err := r.ReadDword()
	if err != nil {
		return FileTime{}, err
	}
	high, err := r.ReadDword()
	if err != nil {
		return FileTime{}, err
	}
	return FileTime{Low: low, High: high}, nil
}

// ReadNTString reads a null-terminated Latin-1/ASCII string, consuming the
// terminator. Returns ErrShortBuffer if the buffer ends before a terminator
// is found.
func (r *Reader) ReadNTString() (string, error) {
	start := r.pos
	for r.pos < len(r.buf) && r.buf[r.pos] != 0 {
		r.pos++
	}
	if r.pos >= len(r.buf) {
		r.pos = start
		return "", ErrShortBuffer
	}
	value := string(r.buf[start:r.pos])
	r.pos++ // consume the null terminator
	return value, nil
}
