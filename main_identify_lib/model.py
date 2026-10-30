from dataclasses import dataclass, field
from typing import Optional, Tuple


@dataclass(frozen=True)
class Value:
    kind: str
    value: object = 0

    def add(self, delta, bits=64):
        if self.kind == "const":
            return const((self.value + delta) & ((1 << bits) - 1))
        if self.kind == "stack":
            frame, offset = self.value
            # Microcode immediates encode negative displacements as unsigned
            # bit patterns. Stack locations are signed frame-relative offsets,
            # including when passed to get_stk_chain(sval_t, width).
            offset = (offset + delta) & ((1 << bits) - 1)
            if offset >= 1 << (bits - 1):
                offset -= 1 << bits
            return Value("stack", (frame, offset))
        return UNKNOWN


UNKNOWN = Value("unknown")


def const(n):
    return Value("const", n)


@dataclass(frozen=True)
class DecodedOperand:
    """IDA machine operand; register/base/index are processor IDs, not names.

    None denotes an absent register. Register zero is a real register.
    """
    kind: str
    reg: Optional[int] = None
    value: int = 0
    base: Optional[int] = None
    index: Optional[int] = None
    scale: int = 1
    width: int = 0


@dataclass(frozen=True)
class Instruction:
    ea: int
    size: int
    mnemonic: str
    operands: Tuple[DecodedOperand, ...] = ()


@dataclass
class State:
    regs: dict = field(default_factory=dict)
    memory: dict = field(default_factory=dict)
    flags: dict = field(default_factory=dict)

    def copy(self):
        return State(self.regs.copy(), self.memory.copy(), self.flags.copy())


@dataclass
class Call:
    ea: int
    target: Optional[int]
    args: tuple
    regs: dict
    memory: dict
    tail: bool = False
    indirect: bool = False
    reference: Optional[int] = None


@dataclass
class Trace:
    calls: list = field(default_factory=list)
    truncated: bool = False


@dataclass(frozen=True)
class CallSite:
    """Resolved microcode target plus original call/constant-reference evidence."""
    ea: int
    target: Optional[int]
    indirect: bool
    data_refs: tuple = ()
    funcval_context: Optional[int] = None


@dataclass
class CallGraph:
    calls: list = field(default_factory=list)
    truncated: bool = False


@dataclass
class Candidate:
    ea: int
    wrapper: int
    score: int
    method: str
    evidence: list = field(default_factory=list)
    chain: list = field(default_factory=list)
    role: str = "rust_main"

    def to_dict(self):
        return dict(address=hex(self.ea), wrapper=hex(self.wrapper),
                    score=self.score, method=self.method, role=self.role,
                    evidence=self.evidence, chain=[hex(e) for e in self.chain])


@dataclass
class Report:
    candidates: list = field(default_factory=list)
    diagnostics: list = field(default_factory=list)
    rust_evidence: list = field(default_factory=list)
    scanned_functions: int = 0
    language: str = ""
    timings: dict = field(default_factory=dict)
    analysis_backend: str = ""
    go_evidence: list = field(default_factory=list)
    c_mains: list = field(default_factory=list)
    c_main_diagnostics: list = field(default_factory=list)

    @property
    def entries(self):
        """Display user entries and the separately verified C ABI layer."""
        return self.candidates + self.c_mains

    @property
    def best(self):
        return self.candidates[0] if self.candidates else None

    def to_dict(self):
        return dict(candidates=[c.to_dict() for c in self.candidates],
                    diagnostics=self.diagnostics, rust_evidence=self.rust_evidence,
                    scanned_functions=self.scanned_functions, language=self.language,
                    timings=self.timings, analysis_backend=self.analysis_backend,
                    go_evidence=self.go_evidence,
                    c_mains=[c.to_dict() for c in self.c_mains],
                    c_main_diagnostics=self.c_main_diagnostics)
