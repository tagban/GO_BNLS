package protocol

// TryFrameLength returns the total frame length (3-byte header + payload)
// once enough bytes have arrived to read the little-endian length prefix,
// or false if more data is needed. Mirrors the accept-loop framing rule a
// BNLS client uses on its own read side.
func TryFrameLength(buf []byte) (length int, ok bool) {
	if len(buf) < 2 {
		return 0, false
	}
	return int(buf[0]) | int(buf[1])<<8, true
}

// FrameOpcode returns a fully-buffered frame's opcode (byte index 2, right
// after the 2-byte length prefix).
func FrameOpcode(frame []byte) Opcode {
	return Opcode(frame[2])
}

// PayloadReader returns a Reader positioned right after the 3-byte BNLS header.
func PayloadReader(frame []byte) *Reader {
	return NewReader(frame, 3)
}
