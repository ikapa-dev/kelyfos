//go:build linux

package main

// A classic-BPF abstract interpreter, enough to answer one question about a
// seccomp program: for syscall number N on this architecture, which return
// actions can this program reach?
//
// It is an abstract interpreter rather than a pattern matcher because pattern
// matching somebody else's compiler output is a way to be confidently wrong the
// day they change their code generator. Here the only assumption is the
// instruction set, which is frozen.
//
// Two seccomp_data fields are known when we start — nr and arch, because we are
// asking about a specific pair — and everything else (the instruction pointer,
// the six arguments) is unknown. A comparison against an unknown value takes
// both branches, so a syscall whose permission depends on its arguments reports
// both the allow and the deny as reachable, and gets classified as conditional
// rather than silently as one or the other.
//
// Classic BPF jump offsets are unsigned and forward-only, so the program is a
// DAG and this terminates. The visit budget is a backstop against that
// assumption being wrong, not a normal exit.

const (
	// Instruction classes.
	bpfLD   = 0x00
	bpfLDX  = 0x01
	bpfST   = 0x02
	bpfSTX  = 0x03
	bpfALU  = 0x04
	bpfJMP  = 0x05
	bpfRET  = 0x06
	bpfMISC = 0x07

	// Load/store width.
	bpfW = 0x00
	bpfH = 0x08
	bpfB = 0x10

	// Addressing mode.
	bpfIMM = 0x00
	bpfABS = 0x20
	bpfIND = 0x40
	bpfMEM = 0x60
	bpfLEN = 0x80
	bpfMSH = 0xa0

	// ALU / JMP operation.
	bpfADD = 0x00
	bpfSUB = 0x10
	bpfMUL = 0x20
	bpfDIV = 0x30
	bpfOR  = 0x40
	bpfAND = 0x50
	bpfLSH = 0x60
	bpfRSH = 0x70
	bpfNEG = 0x80
	bpfMOD = 0x90
	bpfXOR = 0xa0

	bpfJA   = 0x00
	bpfJEQ  = 0x10
	bpfJGT  = 0x20
	bpfJGE  = 0x30
	bpfJSET = 0x40

	// Source operand.
	bpfK = 0x00
	bpfX = 0x08

	// MISC operation.
	bpfTAX = 0x00
	bpfTXA = 0x80
)

// The layout of struct seccomp_data, which is what an installed seccomp filter
// is handed instead of a packet:
//
//	int   nr;                  // offset  0
//	__u32 arch;                // offset  4
//	__u64 instruction_pointer; // offset  8
//	__u64 args[6];             // offset 16..63
const (
	offNR   = 0
	offArch = 4
	dataLen = 64
)

// value is a 32-bit register that may or may not be known. Unknown is not
// "zero" — it is "any comparison against this must take both branches".
type value struct {
	known bool
	v     uint32
}

var unknown = value{}

func known(v uint32) value { return value{known: true, v: v} }

// state is the whole machine: where we are and what the registers hold. It is
// an array-only struct so it can be a map key, which is what makes the memo
// table possible.
type state struct {
	pc int
	a  value
	x  value
	m  [16]value
}

const visitBudget = 1 << 20

// reachableActions returns the set of return values this program can produce
// for the given syscall number and audit architecture, and reports whether the
// walk completed within its budget. A false second return means the answer is
// incomplete and must not be presented as one.
func reachableActions(prog []sockFilter, nr, arch uint32) (map[uint32]bool, bool) {
	actions := map[uint32]bool{}
	seen := map[state]bool{}
	visits := 0

	// An explicit stack rather than recursion: a malformed program should cost
	// a budget, not the process's stack.
	stack := []state{{pc: 0, a: unknown, x: unknown}}

	for len(stack) > 0 {
		s := stack[len(stack)-1]
		stack = stack[:len(stack)-1]

		for {
			if s.pc < 0 || s.pc >= len(prog) {
				// Running off the end is a malformed program. Record it as an
				// unreachable-action marker rather than pretending it allowed.
				actions[actionMalformed] = true
				break
			}
			if seen[s] {
				break
			}
			seen[s] = true
			visits++
			if visits > visitBudget {
				return actions, false
			}

			ins := prog[s.pc]
			class := int(ins.Code & 0x07)

			switch class {
			case bpfRET:
				if ins.Code&bpfX != 0 { // BPF_RET | BPF_A
					if s.a.known {
						actions[s.a.v] = true
					} else {
						actions[actionUnknown] = true
					}
				} else {
					actions[ins.K] = true
				}
				goto nextPath

			case bpfLD, bpfLDX:
				v := loadValue(ins, s, nr, arch)
				if class == bpfLD {
					s.a = v
				} else {
					s.x = v
				}
				s.pc++

			case bpfST:
				if int(ins.K) < len(s.m) {
					s.m[ins.K] = s.a
				}
				s.pc++

			case bpfSTX:
				if int(ins.K) < len(s.m) {
					s.m[ins.K] = s.x
				}
				s.pc++

			case bpfALU:
				s.a = aluResult(ins, s.a, s.x)
				s.pc++

			case bpfMISC:
				if ins.Code&0x80 == bpfTXA {
					s.a = s.x
				} else {
					s.x = s.a
				}
				s.pc++

			case bpfJMP:
				op := int(ins.Code & 0xf0)
				if op == bpfJA {
					s.pc += 1 + int(ins.K)
					continue
				}
				operand := known(ins.K)
				if ins.Code&bpfX != 0 {
					operand = s.x
				}
				takeTrue, takeFalse := branchOutcomes(op, s.a, operand)
				jt := s.pc + 1 + int(ins.JT)
				jf := s.pc + 1 + int(ins.JF)
				switch {
				case takeTrue && takeFalse:
					alt := s
					alt.pc = jf
					stack = append(stack, alt)
					s.pc = jt
				case takeTrue:
					s.pc = jt
				default:
					s.pc = jf
				}

			default:
				actions[actionMalformed] = true
				goto nextPath
			}
		}
	nextPath:
	}
	return actions, true
}

// loadValue resolves one load. Only the two fields we fixed are known; every
// other offset — the instruction pointer and all six arguments — is unknown by
// construction, which is exactly what makes an argument-conditioned rule show
// up as conditional instead of being guessed at.
func loadValue(ins sockFilter, s state, nr, arch uint32) value {
	mode := int(ins.Code & 0xe0)
	width := int(ins.Code & 0x18)

	switch mode {
	case bpfIMM:
		return known(ins.K)
	case bpfLEN:
		return known(dataLen)
	case bpfMEM:
		if int(ins.K) < len(s.m) {
			return s.m[ins.K]
		}
		return unknown
	case bpfABS:
		if width != bpfW {
			// seccompiler emits word loads only; a narrower load of a field we
			// track would need byte-order reasoning we would rather not assume.
			return unknown
		}
		switch ins.K {
		case offNR:
			return known(nr)
		case offArch:
			return known(arch)
		default:
			return unknown
		}
	default: // BPF_IND, BPF_MSH — index-relative, never emitted for seccomp.
		return unknown
	}
}

func aluResult(ins sockFilter, a, x value) value {
	op := int(ins.Code & 0xf0)
	if op == bpfNEG {
		if !a.known {
			return unknown
		}
		return known(-a.v)
	}
	operand := known(ins.K)
	if ins.Code&bpfX != 0 {
		operand = x
	}
	if !a.known || !operand.known {
		return unknown
	}
	b := operand.v
	switch op {
	case bpfADD:
		return known(a.v + b)
	case bpfSUB:
		return known(a.v - b)
	case bpfMUL:
		return known(a.v * b)
	case bpfDIV:
		if b == 0 {
			return unknown
		}
		return known(a.v / b)
	case bpfMOD:
		if b == 0 {
			return unknown
		}
		return known(a.v % b)
	case bpfOR:
		return known(a.v | b)
	case bpfAND:
		return known(a.v & b)
	case bpfXOR:
		return known(a.v ^ b)
	case bpfLSH:
		if b > 31 {
			return known(0)
		}
		return known(a.v << b)
	case bpfRSH:
		if b > 31 {
			return known(0)
		}
		return known(a.v >> b)
	}
	return unknown
}

// branchOutcomes says which way a conditional jump can go. When either side of
// the comparison is unknown, the honest answer is "both".
func branchOutcomes(op int, a, operand value) (takeTrue, takeFalse bool) {
	if !a.known || !operand.known {
		return true, true
	}
	var cond bool
	switch op {
	case bpfJEQ:
		cond = a.v == operand.v
	case bpfJGT:
		cond = a.v > operand.v
	case bpfJGE:
		cond = a.v >= operand.v
	case bpfJSET:
		cond = a.v&operand.v != 0
	default:
		return true, true
	}
	return cond, !cond
}
