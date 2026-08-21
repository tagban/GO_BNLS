package checkrevision

import "testing"

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
	checksum, err := Evaluate(f, files, []uint32{0})
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
	checksum, err := Evaluate(f, files, []uint32{0})
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
	checksum, err := Evaluate(f, files, []uint32{0})
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}
	if checksum != 0xFF {
		t.Errorf("Evaluate() = 0x%X, want 0xFF", checksum)
	}
}

func TestEvaluate_FileHashCodeXorsIntoA(t *testing.T) {
	// Formula: A=0 B=0 C=0, one step: C=A+S. File hash code XORs into A
	// before the chunk loop, so it should be visible in the result.
	f, err := ParseFormula("A=0 B=0 C=0 1 C=A+S")
	if err != nil {
		t.Fatalf("ParseFormula() error = %v", err)
	}

	files := [][]byte{{0, 0, 0, 0}}
	checksum, err := Evaluate(f, files, []uint32{5})
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}
	if checksum != 5 {
		t.Errorf("Evaluate() = %d, want 5 (file hash code XOR'd into A, S=0)", checksum)
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
	checksum, err := Evaluate(f, files, []uint32{0})
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}
	want := uint32(1) + uint32(0xAB)
	if checksum != want {
		t.Errorf("Evaluate() = %d, want %d", checksum, want)
	}
}

func TestEvaluate_MultipleFiles_StateCarriesBetweenFiles(t *testing.T) {
	// Documents the "running state carries across files" assumption
	// (unverified — see the package doc comment) as a regression test: two
	// 1-chunk files should behave identically to one 2-chunk file with the
	// same bytes and hash codes both zero.
	f, err := ParseFormula("A=1 B=2 C=3 4 A=A+S B=B+S C=C+S A=A+B")
	if err != nil {
		t.Fatalf("ParseFormula() error = %v", err)
	}

	singleFile := [][]byte{{1, 0, 0, 0, 2, 0, 0, 0}}
	twoFiles := [][]byte{{1, 0, 0, 0}, {2, 0, 0, 0}}

	want, err := Evaluate(f, singleFile, []uint32{0})
	if err != nil {
		t.Fatalf("Evaluate(singleFile) error = %v", err)
	}
	got, err := Evaluate(f, twoFiles, []uint32{0, 0})
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

	if _, err := Evaluate(f, [][]byte{{0, 0, 0, 0}}, []uint32{0}); err == nil {
		t.Error("Evaluate() error = nil, want an error for division by zero")
	}
}

func TestEvaluate_TooManyFiles_ReturnsError(t *testing.T) {
	f, err := ParseFormula("A=0 B=0 C=0 1 C=C+S")
	if err != nil {
		t.Fatalf("ParseFormula() error = %v", err)
	}

	files := [][]byte{{0, 0, 0, 0}, {0, 0, 0, 0}, {0, 0, 0, 0}, {0, 0, 0, 0}}
	if _, err := Evaluate(f, files, []uint32{0, 0, 0, 0}); err == nil {
		t.Error("Evaluate() error = nil, want an error for more than 3 files")
	}
}
