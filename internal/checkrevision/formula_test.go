package checkrevision

import "testing"

func TestParseFormula_RealCapturedShape(t *testing.T) {
	// Shape matches formulas captured live against real PVPGN servers this
	// session (exact numeric seeds are illustrative, not transcribed from a
	// specific capture) — three seed assignments in A/C/B order (not
	// alphabetical), a "4" step-count token, then 4 steps.
	f, err := ParseFormula("A=1239576727 C=1604096186 B=41985212 4 A=A^S B=B-C C=C^A A=A+B")
	if err != nil {
		t.Fatalf("ParseFormula() error = %v", err)
	}

	if f.SeedA != 1239576727 || f.SeedB != 41985212 || f.SeedC != 1604096186 {
		t.Errorf("seeds = A:%d B:%d C:%d, want A:1239576727 B:41985212 C:1604096186", f.SeedA, f.SeedB, f.SeedC)
	}

	want := []Step{
		{Target: VarA, Left: VarA, Op: OpXor, Right: VarS},
		{Target: VarB, Left: VarB, Op: OpSub, Right: VarC},
		{Target: VarC, Left: VarC, Op: OpXor, Right: VarA},
		{Target: VarA, Left: VarA, Op: OpAdd, Right: VarB},
	}
	if len(f.Steps) != len(want) {
		t.Fatalf("len(Steps) = %d, want %d", len(f.Steps), len(want))
	}
	for i, s := range f.Steps {
		if s != want[i] {
			t.Errorf("Steps[%d] = %+v, want %+v", i, s, want[i])
		}
	}
}

func TestParseFormula_SeedOrderDoesNotMatter(t *testing.T) {
	f, err := ParseFormula("C=3 A=1 B=2 4 A=A+S B=B+S C=C+S A=A+B")
	if err != nil {
		t.Fatalf("ParseFormula() error = %v", err)
	}
	if f.SeedA != 1 || f.SeedB != 2 || f.SeedC != 3 {
		t.Errorf("seeds = A:%d B:%d C:%d, want A:1 B:2 C:3", f.SeedA, f.SeedB, f.SeedC)
	}
}

func TestParseFormula_TooShort_ReturnsError(t *testing.T) {
	if _, err := ParseFormula("A=1 B=2 C=3"); err == nil {
		t.Error("ParseFormula() error = nil, want an error for a formula with no steps")
	}
}

func TestParseFormula_StepCountMismatch_ReturnsError(t *testing.T) {
	if _, err := ParseFormula("A=1 B=2 C=3 4 A=A+S B=B+S"); err == nil {
		t.Error("ParseFormula() error = nil, want an error for a step count that doesn't match the declared count")
	}
}

func TestParseFormula_UnknownOperator_ReturnsError(t *testing.T) {
	if _, err := ParseFormula("A=1 B=2 C=3 4 A=A%S B=B+S C=C+S A=A+B"); err == nil {
		t.Error("ParseFormula() error = nil, want an error for an unrecognized operator")
	}
}

func TestParseFormula_UnknownVariable_ReturnsError(t *testing.T) {
	if _, err := ParseFormula("A=1 B=2 C=3 4 A=Z+S B=B+S C=C+S A=A+B"); err == nil {
		t.Error("ParseFormula() error = nil, want an error for an unrecognized variable")
	}
}

func TestParseFormula_MissingSeed_ReturnsError(t *testing.T) {
	if _, err := ParseFormula("A=1 B=2 4 A=A+S B=B+S C=C+S A=A+B"); err == nil {
		t.Error("ParseFormula() error = nil, want an error when a seed assignment (C) is missing")
	}
}
