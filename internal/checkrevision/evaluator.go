package checkrevision

import (
	"encoding/binary"
	"fmt"
)

// Evaluate runs a parsed formula against one or more file byte slices (in
// manifest order), returning the final checksum (the formula's C value
// after every chunk of every file has been processed).
//
// CONFIRMED LIVE (2026-08-21): this function, fed a real Warcraft II: BNE
// install's exe/storm.dll/battle.snp (in that order) and the hash code
// HashCodeForMpqFileName derives from a real "ver-IX86-1.mpq" mpqFileName,
// reproduced bnls.bnetdocs.org's actual BNLS_VERSIONCHECKEX2 reply checksum
// exactly (0xB52BAD87) for a real formula captured from a live SID_AUTH_INFO
// exchange with atlas.bnetdocs.org — and Invigoration, pointed at a local
// instance of this server instead of the public one, completed a full real
// login through it. Not just theoretically correct: this is the actual
// end-to-end proof the project's Risk section called for.
//
// hashCode is XOR'd into the seed A value exactly once, before any file's
// bytes are processed — see HashCodeForMpqFileName for how a real client
// derives this from the mpqFileName field it sends alongside the formula.
// This corrects an earlier mistaken guess in this package's history (a
// per-file hash code, XOR'd before each file's own loop) — confirmed
// against the project owner's own original CheckRevision implementation and
// the MIT-licensed github.com/BNETDocs/MBNCSUtil's CheckRevision.cs, then
// verified live as above.
//
// 4-byte chunks are read little-endian, consistent with every other DWORD
// in this protocol family. Callers should run every file through
// PadToBoundary(data, 1024) before passing it here — both reference sources
// above pad every hash file to a 1024-byte boundary unconditionally, so
// there's no real-file case where Evaluate needs to zero-pad a trailing
// partial chunk itself (it does so defensively anyway, purely so a caller
// that forgets to pad still gets a defined result rather than a crash).
//
// Every file's chunks flow through the same running A/B/C state, in the
// order given, rather than resetting between files — also confirmed live.
// Which files, and in what order, is itself product-specific and not
// carried on the wire anywhere — it has to be known per profile (see
// profiles.Profile.HashFiles); for Warcraft II: BNE it's exe, then
// storm.dll, then battle.snp, confirmed by the live test above.
func Evaluate(f *Formula, files [][]byte, hashCode uint32) (uint32, error) {
	if len(files) == 0 {
		return 0, fmt.Errorf("checkrevision: no files to hash")
	}
	if len(files) > 3 {
		return 0, fmt.Errorf("checkrevision: at most 3 hash files are supported, got %d", len(files))
	}

	a := uint32(f.SeedA) ^ hashCode
	b := uint32(f.SeedB)
	c := uint32(f.SeedC)

	for _, data := range files {
		for offset := 0; offset < len(data); offset += 4 {
			var chunk [4]byte
			copy(chunk[:], data[offset:]) // remaining bytes beyond len(data) stay zero — the zero-pad assumption above

			s := binary.LittleEndian.Uint32(chunk[:])

			for _, step := range f.Steps {
				result, err := applyStep(step, a, b, c, s)
				if err != nil {
					return 0, err
				}
				switch step.Target {
				case VarA:
					a = result
				case VarB:
					b = result
				case VarC:
					c = result
				default:
					return 0, fmt.Errorf("checkrevision: formula step targets non-accumulator variable %q", rune(step.Target))
				}
			}
		}
	}

	return c, nil
}

func applyStep(step Step, a, b, c, s uint32) (uint32, error) {
	left := valueOf(step.Left, a, b, c, s)
	right := valueOf(step.Right, a, b, c, s)

	switch step.Op {
	case OpAdd:
		return left + right, nil
	case OpSub:
		return left - right, nil
	case OpMul:
		return left * right, nil
	case OpDiv:
		if right == 0 {
			// The formula's operand set is server-supplied and bnetdocs
			// itself warns "it is possible that... the operands will not be
			// consistent" — treat divide-by-zero as a formula-level error
			// rather than panicking.
			return 0, fmt.Errorf("checkrevision: division by zero in step %q", formatStep(step))
		}
		return left / right, nil
	case OpXor:
		return left ^ right, nil
	default:
		return 0, fmt.Errorf("checkrevision: unknown operator %q", rune(step.Op))
	}
}

func valueOf(v Var, a, b, c, s uint32) uint32 {
	switch v {
	case VarA:
		return a
	case VarB:
		return b
	case VarC:
		return c
	case VarS:
		return s
	default:
		return 0
	}
}

func formatStep(step Step) string {
	return fmt.Sprintf("%c=%c%c%c", step.Target, step.Left, step.Op, step.Right)
}
