package checkrevision

import (
	"encoding/binary"
	"fmt"
)

// Evaluate runs a parsed formula against one or more file byte slices (in
// manifest order), returning the final checksum (the formula's C value
// after every chunk of every file has been processed).
//
// ASSUMPTIONS — not documented anywhere found, and NOT yet cross-checked
// against a real BNLS server's actual reply for a known formula/file pair.
// Resolve empirically before trusting this in production (see the project
// plan's Risk section):
//
//   - 4-byte chunks are read little-endian, consistent with every other
//     DWORD in this protocol family.
//   - A final partial chunk (file length not a multiple of 4) is zero-padded
//     rather than dropped or erroring.
//   - Each file's own "hash code" (bnetdocs documents this as a 0-7
//     variant, but not which value belongs to which file/product/patch) is
//     XOR'd into A once, immediately before that file's chunk loop. The
//     actual value is supplied per-file by the caller (sourced from a
//     profile's manifest) rather than guessed here — a wrong hardcoded
//     guess would silently produce a plausible-but-wrong checksum, which is
//     worse than making the unknown explicit and tunable.
//   - How multiple files' results combine is unspecified. This runs every
//     file's chunks through the same running A/B/C state, in the order
//     given, rather than resetting between files — the most natural reading
//     of "the resulting value of C is returned as the checksum" for a
//     formula documented as covering "up to 3" files together, but
//     unverified against a real multi-file product.
func Evaluate(f *Formula, files [][]byte, fileHashCodes []uint32) (uint32, error) {
	if len(files) == 0 {
		return 0, fmt.Errorf("checkrevision: no files to hash")
	}
	if len(files) > 3 {
		return 0, fmt.Errorf("checkrevision: at most 3 hash files are supported, got %d", len(files))
	}
	if len(fileHashCodes) != len(files) {
		return 0, fmt.Errorf("checkrevision: %d file hash codes supplied for %d files", len(fileHashCodes), len(files))
	}

	a := uint32(f.SeedA)
	b := uint32(f.SeedB)
	c := uint32(f.SeedC)

	for fi, data := range files {
		a ^= fileHashCodes[fi]

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
