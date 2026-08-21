package protocol

// Writer builds a single outbound BNLS packet payload, then frames it.
type Writer struct {
	buf []byte
}

// NewWriter returns an empty Writer.
func NewWriter() *Writer { return &Writer{} }

// PutByte appends a single byte. (Named PutByte rather than WriteByte to
// avoid colliding with io.ByteWriter's WriteByte(byte) error signature,
// which go vet checks method names against even for unrelated types.)
func (w *Writer) PutByte(v byte) *Writer {
	w.buf = append(w.buf, v)
	return w
}

func (w *Writer) WriteWord(v uint16) *Writer {
	w.buf = append(w.buf, byte(v), byte(v>>8))
	return w
}

func (w *Writer) WriteDword(v uint32) *Writer {
	w.buf = append(w.buf, byte(v), byte(v>>8), byte(v>>16), byte(v>>24))
	return w
}

func (w *Writer) WriteBytes(data []byte) *Writer {
	w.buf = append(w.buf, data...)
	return w
}

// WriteAscii writes raw text with no terminator.
func (w *Writer) WriteAscii(text string) *Writer {
	w.buf = append(w.buf, []byte(text)...)
	return w
}

// WriteNTString writes text followed by a null terminator.
func (w *Writer) WriteNTString(text string) *Writer {
	w.WriteAscii(text)
	w.buf = append(w.buf, 0)
	return w
}

// Frame wraps the accumulated payload in a BNLS packet header: a
// little-endian WORD length (including this 3-byte header), then the
// opcode byte, then the payload.
func (w *Writer) Frame(op Opcode) []byte {
	length := len(w.buf) + 3
	result := make([]byte, length)
	result[0] = byte(length)
	result[1] = byte(length >> 8)
	result[2] = byte(op)
	copy(result[3:], w.buf)
	return result
}
