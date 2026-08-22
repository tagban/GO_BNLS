package checkrevision

import (
	"bytes"
	"testing"
)

func TestEvaluate_SingleChunkSingleFile_MatchesHandComputedResult(t *testing.T) {
	// Formula: A=1 B=2 C=3, then per chunk: A+=S, B+=S, C+=S, A+=B.
	// One file, one 4-byte chunk with S=1 (bytes 01 00 00 00 little-endian).
	//
	// Hand-computed trace:
	//   seed:  A=1  B=2  C=3
	//   step1: A=A+S = 1+1 = 2
	//   step2: B=B+S = 2+1 = 3
	//   step3: C=C+S = 3+1 = 4
	//   step4: A=A+B = 2+3 = 5
	//   final C = 4
	f, err := ParseFormula("A=1 B=2 C=3 4 A=A+S B=B+S C=C+S A=A+B")
	if err != nil {
		t.Fatalf("ParseFormula() error = %v", err)
	}

	files := [][]byte{{1, 0, 0, 0}}
	checksum, err := Evaluate(f, files, 0)
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}
	if checksum != 4 {
		t.Errorf("Evaluate() = %d, want 4", checksum)
	}
}

func TestEvaluate_TwoChunksSameFile_ProcessesSequentially(t *testing.T) {
	// Same formula as above, but two chunks: S=1 then S=2.
	//
	//   seed:  A=1  B=2  C=3
	// chunk 1 (S=1): A=2, B=3, C=4, A=A+B=2+3=5
	// chunk 2 (S=2): A=A+S=5+2=7, B=B+S=3+2=5, C=C+S=4+2=6, A=A+B=7+5=12
	//   final C = 6
	f, err := ParseFormula("A=1 B=2 C=3 4 A=A+S B=B+S C=C+S A=A+B")
	if err != nil {
		t.Fatalf("ParseFormula() error = %v", err)
	}

	files := [][]byte{{1, 0, 0, 0, 2, 0, 0, 0}}
	checksum, err := Evaluate(f, files, 0)
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}
	if checksum != 6 {
		t.Errorf("Evaluate() = %d, want 6", checksum)
	}
}

func TestEvaluate_XorFormula_MatchesHandComputedResult(t *testing.T) {
	// Formula: A=0 B=0 C=0, then per chunk: A^=S, B^=S, C^=S, A^=B.
	// One chunk, S=0xFF.
	//
	//   seed: A=0 B=0 C=0
	//   A = 0^0xFF = 0xFF
	//   B = 0^0xFF = 0xFF
	//   C = 0^0xFF = 0xFF
	//   A = 0xFF^0xFF = 0
	//   final C = 0xFF
	f, err := ParseFormula("A=0 B=0 C=0 4 A=A^S B=B^S C=C^S A=A^B")
	if err != nil {
		t.Fatalf("ParseFormula() error = %v", err)
	}

	files := [][]byte{{0xFF, 0, 0, 0}}
	checksum, err := Evaluate(f, files, 0)
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}
	if checksum != 0xFF {
		t.Errorf("Evaluate() = 0x%X, want 0xFF", checksum)
	}
}

func TestEvaluate_HashCodeXorsIntoSeedAOnce(t *testing.T) {
	// Formula: A=0 B=0 C=0, one step: C=A+S. The hash code XORs into A
	// before any file is processed, so it should be visible in the result.
	f, err := ParseFormula("A=0 B=0 C=0 1 C=A+S")
	if err != nil {
		t.Fatalf("ParseFormula() error = %v", err)
	}

	files := [][]byte{{0, 0, 0, 0}}
	checksum, err := Evaluate(f, files, 5)
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}
	if checksum != 5 {
		t.Errorf("Evaluate() = %d, want 5 (hash code XOR'd into A, S=0)", checksum)
	}
}

func TestEvaluate_HashCodeAppliesOnceAcrossMultipleFiles(t *testing.T) {
	// Two files, same formula as above (C=A+S, one step). If the hash code
	// were (wrongly) applied per-file rather than once for the whole
	// request, this would double-XOR it going into the second file's chunk
	// and produce a different result than a single 2-chunk file with the
	// hash code applied once.
	f, err := ParseFormula("A=0 B=0 C=0 1 C=A+S")
	if err != nil {
		t.Fatalf("ParseFormula() error = %v", err)
	}

	singleFile := [][]byte{{0, 0, 0, 0, 0, 0, 0, 0}}
	twoFiles := [][]byte{{0, 0, 0, 0}, {0, 0, 0, 0}}

	want, err := Evaluate(f, singleFile, 5)
	if err != nil {
		t.Fatalf("Evaluate(singleFile) error = %v", err)
	}
	got, err := Evaluate(f, twoFiles, 5)
	if err != nil {
		t.Fatalf("Evaluate(twoFiles) error = %v", err)
	}
	if got != want {
		t.Errorf("Evaluate(twoFiles) = %d, want %d (hash code applied once, not per file)", got, want)
	}
}

func TestEvaluate_PartialFinalChunk_IsZeroPadded(t *testing.T) {
	// A 5-byte file: one full chunk (S=1) then a partial chunk with only
	// byte 0xAB present — should be read as S=0x000000AB (zero-padded), not
	// rejected or truncated.
	f, err := ParseFormula("A=0 B=0 C=0 1 C=C+S")
	if err != nil {
		t.Fatalf("ParseFormula() error = %v", err)
	}

	files := [][]byte{{1, 0, 0, 0, 0xAB}}
	checksum, err := Evaluate(f, files, 0)
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}
	want := uint32(1) + uint32(0xAB)
	if checksum != want {
		t.Errorf("Evaluate() = %d, want %d", checksum, want)
	}
}

func TestEvaluate_MultipleFiles_StateCarriesBetweenFiles(t *testing.T) {
	// Two 1-chunk files should behave identically to one 2-chunk file with
	// the same bytes.
	f, err := ParseFormula("A=1 B=2 C=3 4 A=A+S B=B+S C=C+S A=A+B")
	if err != nil {
		t.Fatalf("ParseFormula() error = %v", err)
	}

	singleFile := [][]byte{{1, 0, 0, 0, 2, 0, 0, 0}}
	twoFiles := [][]byte{{1, 0, 0, 0}, {2, 0, 0, 0}}

	want, err := Evaluate(f, singleFile, 0)
	if err != nil {
		t.Fatalf("Evaluate(singleFile) error = %v", err)
	}
	got, err := Evaluate(f, twoFiles, 0)
	if err != nil {
		t.Fatalf("Evaluate(twoFiles) error = %v", err)
	}
	if got != want {
		t.Errorf("Evaluate(twoFiles) = %d, want %d (same as equivalent single multi-chunk file)", got, want)
	}
}

func TestEvaluate_DivisionByZero_ReturnsError(t *testing.T) {
	f, err := ParseFormula("A=0 B=0 C=0 1 C=A/S")
	if err != nil {
		t.Fatalf("ParseFormula() error = %v", err)
	}

	if _, err := Evaluate(f, [][]byte{{0, 0, 0, 0}}, 0); err == nil {
		t.Error("Evaluate() error = nil, want an error for division by zero")
	}
}

func TestEvaluate_TooManyFiles_ReturnsError(t *testing.T) {
	f, err := ParseFormula("A=0 B=0 C=0 1 C=C+S")
	if err != nil {
		t.Fatalf("ParseFormula() error = %v", err)
	}

	files := [][]byte{{0, 0, 0, 0}, {0, 0, 0, 0}, {0, 0, 0, 0}, {0, 0, 0, 0}}
	if _, err := Evaluate(f, files, 0); err == nil {
		t.Error("Evaluate() error = nil, want an error for more than 3 files")
	}
}

func TestHashCodeForMpqFileName_VerPrefixConvention(t *testing.T) {
	// "ver-IX86-1.mpq": index digit at position 9.
	code, ok := HashCodeForMpqFileName("ver-IX86-1.mpq")
	if !ok {
		t.Fatal("ok = false, want true")
	}
	if code != mpqFileHashCodes[1] {
		t.Errorf("code = 0x%X, want 0x%X", code, mpqFileHashCodes[1])
	}
}

func TestHashCodeForMpqFileName_PlatVerConvention(t *testing.T) {
	// "IX86ver1.mpq": index digit at position 7.
	code, ok := HashCodeForMpqFileName("IX86ver1.mpq")
	if !ok {
		t.Fatal("ok = false, want true")
	}
	if code != mpqFileHashCodes[1] {
		t.Errorf("code = 0x%X, want 0x%X", code, mpqFileHashCodes[1])
	}
}

func TestHashCodeForMpqFileName_UnrecognizedShape_ReturnsFalse(t *testing.T) {
	if _, ok := HashCodeForMpqFileName("not-a-known-shape.mpq"); ok {
		t.Error("ok = true, want false")
	}
}

func TestPadToBoundary_AlreadyAligned_ReturnsUnchanged(t *testing.T) {
	data := make([]byte, 1024)
	padded := PadToBoundary(data, 1024)
	if len(padded) != 1024 {
		t.Errorf("len(padded) = %d, want 1024 (no padding needed)", len(padded))
	}
}

func TestPadToBoundary_PadsWithDescendingBytes(t *testing.T) {
	data := []byte{0x11, 0x22, 0x33}
	padded := PadToBoundary(data, 8)

	want := []byte{0x11, 0x22, 0x33, 0xFF, 0xFE, 0xFD, 0xFC, 0xFB}
	if !bytes.Equal(padded, want) {
		t.Errorf("padded = %x, want %x", padded, want)
	}
}

func TestPadToBoundary_WrapsEvery256Bytes(t *testing.T) {
	data := make([]byte, 1)
	padded := PadToBoundary(data, 1024)

	if len(padded) != 1024 {
		t.Fatalf("len(padded) = %d, want 1024", len(padded))
	}
	// Padding runs 0xFF down to 0x00 (256 values) then wraps to 0xFF again,
	// covering the 1023 padding bytes needed.
	if padded[1] != 0xFF {
		t.Errorf("padded[1] = 0x%X, want 0xFF", padded[1])
	}
	if padded[1+255] != 0x00 {
		t.Errorf("padded[256] = 0x%X, want 0x00 (256th descending value)", padded[1+255])
	}
	if padded[1+256] != 0xFF {
		t.Errorf("padded[257] = 0x%X, want 0xFF (wrapped)", padded[1+256])
	}
}
