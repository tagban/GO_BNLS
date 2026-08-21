package protocol

import (
	"bytes"
	"testing"
)

func TestFrame_ProducesCorrectHeaderAndLength(t *testing.T) {
	frame := NewWriter().WriteByte(0x42).Frame(OpHashData)

	length := int(frame[0]) | int(frame[1])<<8
	if length != len(frame) {
		t.Errorf("header length = %d, want %d", length, len(frame))
	}
	if frame[2] != byte(OpHashData) {
		t.Errorf("opcode byte = 0x%02X, want 0x%02X", frame[2], byte(OpHashData))
	}
	if len(frame) != 3+1 {
		t.Errorf("frame length = %d, want %d", len(frame), 3+1)
	}
}

func TestReadWriteRoundTrip_PreservesValues(t *testing.T) {
	frame := NewWriter().
		WriteByte(0xAB).
		WriteWord(0x1234).
		WriteDword(0xDEADBEEF).
		WriteNTString("hello").
		WriteBytes([]byte{1, 2, 3}).
		Frame(OpNull)

	r := PayloadReader(frame)

	if b, err := r.ReadByte(); err != nil || b != 0xAB {
		t.Fatalf("ReadByte() = %v, %v, want 0xAB, nil", b, err)
	}
	if w, err := r.ReadWord(); err != nil || w != 0x1234 {
		t.Fatalf("ReadWord() = %v, %v, want 0x1234, nil", w, err)
	}
	if d, err := r.ReadDword(); err != nil || d != 0xDEADBEEF {
		t.Fatalf("ReadDword() = %v, %v, want 0xDEADBEEF, nil", d, err)
	}
	if s, err := r.ReadNTString(); err != nil || s != "hello" {
		t.Fatalf("ReadNTString() = %q, %v, want %q, nil", s, err, "hello")
	}
	if raw, err := r.ReadRaw(3); err != nil || !bytes.Equal(raw, []byte{1, 2, 3}) {
		t.Fatalf("ReadRaw(3) = %v, %v, want [1 2 3], nil", raw, err)
	}
}

func TestReadBoolean_ReadsFullDwordAsNonZeroCheck(t *testing.T) {
	frame := NewWriter().WriteDword(0).WriteDword(1).Frame(OpNull)
	r := PayloadReader(frame)

	if v, err := r.ReadBoolean(); err != nil || v {
		t.Fatalf("first ReadBoolean() = %v, %v, want false, nil", v, err)
	}
	if v, err := r.ReadBoolean(); err != nil || !v {
		t.Fatalf("second ReadBoolean() = %v, %v, want true, nil", v, err)
	}
}

func TestReadFileTime_ReadsLowThenHighDword(t *testing.T) {
	frame := NewWriter().WriteDword(0x11111111).WriteDword(0x22222222).Frame(OpNull)
	r := PayloadReader(frame)

	ft, err := r.ReadFileTime()
	if err != nil {
		t.Fatalf("ReadFileTime() error = %v", err)
	}
	if ft.Low != 0x11111111 || ft.High != 0x22222222 {
		t.Errorf("ReadFileTime() = %+v, want {Low:0x11111111 High:0x22222222}", ft)
	}
}

func TestReadPastEnd_ReturnsErrShortBuffer(t *testing.T) {
	frame := NewWriter().WriteByte(0x01).Frame(OpNull)
	r := PayloadReader(frame)

	if _, err := r.ReadByte(); err != nil {
		t.Fatalf("first ReadByte() error = %v, want nil", err)
	}
	if _, err := r.ReadByte(); err != ErrShortBuffer {
		t.Errorf("second ReadByte() error = %v, want ErrShortBuffer", err)
	}
}

func TestTryFrameLength_MatchesFrameHeader(t *testing.T) {
	frame := NewWriter().WriteNTString("abc").Frame(OpAuthorize)

	length, ok := TryFrameLength(frame)
	if !ok {
		t.Fatal("TryFrameLength() ok = false, want true")
	}
	if length != len(frame) {
		t.Errorf("TryFrameLength() = %d, want %d", length, len(frame))
	}
	if FrameOpcode(frame) != OpAuthorize {
		t.Errorf("FrameOpcode() = %v, want %v", FrameOpcode(frame), OpAuthorize)
	}
}
