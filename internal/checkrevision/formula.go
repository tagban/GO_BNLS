// Package checkrevision implements BNLS's CheckRevision version-check
// formula: a tiny stack-free interpreter the game server hands out (via
// SID_AUTH_INFO, forwarded verbatim through BNLS_VERSIONCHECKEX2) that
// computes an exe checksum from a small set of local game files.
//
// Sourced from bnetdocs.org/document/47/checkrevision, verbatim-confirmed
// (2026-08-21): operators are "+ - * / ^"; the formula shape is
// "A={int} B={int} C={int} 4 A=A{op}S B=B{op}C C=C{op}A A=A{op}B"; up to 3
// hash files are read in 4-byte chunks as S, all 4 steps run per chunk,
// final C is the checksum; each file's own "hash code" (0-7 variant) is
// XOR'd into A. Byte order for the 4-byte chunk reads and exactly how
// multiple files' results combine are NOT documented anywhere found — see
// evaluator.go's doc comment and the project plan's Risk section. This
// implementation encodes the documented behavior plus explicit, clearly-
// flagged assumptions; treat it as unverified until cross-checked against a
// real BNLS server's reply for a known formula/file pair.
package checkrevision

import (
	"fmt"
	"strconv"
	"strings"
)

// Op is one of the operators bnetdocs documents for a formula step.
type Op byte

const (
	OpAdd Op = '+'
	OpSub Op = '-'
	OpMul Op = '*'
	OpDiv Op = '/'
	OpXor Op = '^'
)

// Var identifies one of the formula's four operands: the three running
// values A/B/C, or S, the current 4-byte file chunk.
type Var byte

const (
	VarA Var = 'A'
	VarB Var = 'B'
	VarC Var = 'C'
	VarS Var = 'S'
)

// Step is one "X=Y{op}Z" formula line.
type Step struct {
	Target Var
	Left   Var
	Op     Op
	Right  Var
}

// Formula is a parsed CheckRevision formula: three seed values for A/B/C,
// and the ordered list of steps run once per 4-byte file chunk.
type Formula struct {
	SeedA, SeedB, SeedC int32
	Steps               []Step
}

// ParseFormula parses a formula string like
// "A=1239576727 C=1604096186 B=41985212 4 A=A^S B=B-C C=C^A A=A+B" into its
// seed values and steps. The token order for the three seed assignments is
// not assumed to be A,B,C — each is matched by its variable letter, since
// live captures this session showed the order varies (e.g. "A=... C=... B=...").
func ParseFormula(formula string) (*Formula, error) {
	fields := strings.Fields(formula)
	if len(fields) < 4 {
		return nil, fmt.Errorf("checkrevision: formula too short: %q", formula)
	}

	f := &Formula{}
	seedsSeen := 0
	i := 0

	// The first 3 whitespace-separated tokens are the "A=N"/"B=N"/"C=N" seed
	// assignments, in any order.
	for ; i < len(fields) && seedsSeen < 3; i++ {
		v, n, ok := parseSeedAssignment(fields[i])
		if !ok {
			break
		}
		switch v {
		case VarA:
			f.SeedA = n
		case VarB:
			f.SeedB = n
		case VarC:
			f.SeedC = n
		default:
			return nil, fmt.Errorf("checkrevision: unexpected seed variable in %q", fields[i])
		}
		seedsSeen++
	}
	if seedsSeen != 3 {
		return nil, fmt.Errorf("checkrevision: expected 3 seed assignments (A/B/C), got %d in %q", seedsSeen, formula)
	}

	// Next token is the repeat/group-count marker — documented examples
	// always show "4" (one per step that follows). Parsed and validated
	// against the actual step count below, rather than assumed fixed,
	// in case a future/other CheckRevision version varies it.
	if i >= len(fields) {
		return nil, fmt.Errorf("checkrevision: missing step-count token in %q", formula)
	}
	stepCount, err := strconv.Atoi(fields[i])
	if err != nil {
		return nil, fmt.Errorf("checkrevision: invalid step-count token %q: %w", fields[i], err)
	}
	i++

	for ; i < len(fields); i++ {
		step, err := parseStep(fields[i])
		if err != nil {
			return nil, err
		}
		f.Steps = append(f.Steps, step)
	}

	if len(f.Steps) != stepCount {
		return nil, fmt.Errorf("checkrevision: step-count token said %d, found %d steps in %q", stepCount, len(f.Steps), formula)
	}

	return f, nil
}

// parseSeedAssignment parses a token like "A=1239576727".
func parseSeedAssignment(token string) (Var, int32, bool) {
	if len(token) < 3 || token[1] != '=' {
		return 0, 0, false
	}
	v := Var(token[0])
	if v != VarA && v != VarB && v != VarC {
		return 0, 0, false
	}
	n, err := strconv.ParseInt(token[2:], 10, 64)
	if err != nil {
		return 0, 0, false
	}
	return v, int32(n), true
}

// parseStep parses a token like "A=A^S" into a Step.
func parseStep(token string) (Step, error) {
	if len(token) != 5 || token[1] != '=' {
		return Step{}, fmt.Errorf("checkrevision: malformed step token %q", token)
	}

	target := Var(token[0])
	left := Var(token[2])
	op := Op(token[3])
	right := Var(token[4])

	if !isValidVar(target) || !isValidVar(left) || !isValidVar(right) {
		return Step{}, fmt.Errorf("checkrevision: unknown variable in step token %q", token)
	}
	if !isValidOp(op) {
		return Step{}, fmt.Errorf("checkrevision: unknown operator in step token %q", token)
	}

	return Step{Target: target, Left: left, Op: op, Right: right}, nil
}

func isValidVar(v Var) bool {
	return v == VarA || v == VarB || v == VarC || v == VarS
}

func isValidOp(op Op) bool {
	switch op {
	case OpAdd, OpSub, OpMul, OpDiv, OpXor:
		return true
	default:
		return false
	}
}
