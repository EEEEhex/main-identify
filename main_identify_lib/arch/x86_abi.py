"""The x86/x64 processor-to-microcode and calling-convention boundary.

Canonical register names are resolved once through IDA. Subregisters come from
op_t.reg and reg2mreg(), never a handwritten alias table. Context dictionary
keys are micro-register IDs; byte ranges keep partial writes distinct.
"""
from dataclasses import dataclass
from functools import lru_cache

import ida_funcs
import ida_frame
import ida_hexrays as h
import ida_idp

from ..model import UNKNOWN, Value


@dataclass(frozen=True)
class ProcessorRegisters:
    accumulator: int
    counter: int
    data: int
    base: int
    stack: int
    frame: int
    source: int
    destination: int
    extended: tuple


@lru_cache(maxsize=2)
def processor_registers(bits):
    prefix = "r" if bits == 64 else "e"
    basic = tuple(ida_idp.str2reg(prefix + suffix)
                  for suffix in ("ax", "cx", "dx", "bx", "sp", "bp", "si", "di"))
    extended = tuple(ida_idp.str2reg("r%d" % n) for n in range(8, 16)) if bits == 64 else ()
    if any(reg < 0 for reg in basic + extended):
        raise ValueError("IDA did not provide the expected x86 register IDs.")
    return ProcessorRegisters(*basic, extended)


class X86ABI:
    def __init__(self, backend):
        self.ptr = backend.bits // 8
        self.processor = processor_registers(backend.bits)
        p = self.processor
        self.result = self.to_micro(p.accumulator)
        self.stack = self.to_micro(p.stack)
        self.frame = self.to_micro(p.frame)
        self.counter = self.to_micro(p.counter)
        self.data = self.to_micro(p.data)
        extended = tuple(self.to_micro(r) for r in p.extended)
        source, destination = self.to_micro(p.source), self.to_micro(p.destination)
        self.argument_registers = ()
        if self.ptr == 8:
            self.argument_registers = ((self.counter, self.data) + extended[:2]
                                       if backend.format == "PE" else
                                       (destination, source, self.data, self.counter) + extended[:2])
        self.volatile_registers = (self.result, self.counter, self.data) + extended[:4]
        if self.ptr == 8 and backend.format == "ELF":
            self.volatile_registers += (source, destination)
        self.callback_registers = (self.counter, self.data, self.result)
        self.candidate_registers = (self.counter, self.data)
        self.context_registers = self.argument_registers or self.callback_registers

    @staticmethod
    def to_micro(processor_reg):
        if processor_reg is None:
            return None
        result = h.reg2mreg(processor_reg)
        return result if result >= 0 else None

    @staticmethod
    def _single(values):
        return next(iter(values)) if len(values) == 1 else UNKNOWN

    def callback_values(self, call):
        return tuple(call.regs.get(reg, UNKNOWN) for reg in self.callback_registers)

    def funcval_context(self, context, bi, pos):
        # Go's x86 closure context is DX, independent of C ABI arguments.
        value = self._single(context.reaching(bi, pos, "r", self.data, self.ptr))
        return value.value if value.kind == "const" else None

    def candidate_values(self, call):
        return tuple(call.regs.get(reg, UNKNOWN) for reg in self.candidate_registers)

    def environment_context(self, environment):
        return {self.counter: environment} if self.ptr == 4 else {}

    def is_volatile(self, off, size):
        return any(reg < off+size and off < reg+self.ptr for reg in self.volatile_registers)

    def fallback_call_effect(self, off, size):
        returned = self.result <= off and off+size <= self.result+self.ptr
        return returned, self.is_volatile(off, size)

    def entry_value(self, kind, off, size, context):
        if kind == "r":
            if off == self.stack:
                return Value("stack", (context.frame, 0))
            if off in self.argument_registers:
                index = self.argument_registers.index(off)
                return context.args[index] if index < len(context.args) else Value("arg", index)
            return context.regs.get(off, UNKNOWN)
        if kind == "s":
            delta = off - context.im.mba.argbase()
            if delta >= 0 and delta % self.ptr == 0:
                index = delta // self.ptr + len(self.argument_registers)
                return context.args[index] if index < len(context.args) else Value("arg", index)
        return UNKNOWN

    def stack_value(self, context, bi, pos):
        instructions = context.im.blocks[bi]
        ea = instructions[min(pos, len(instructions)-1)].ea if instructions else context.im.start
        owner = ida_funcs.get_func(context.im.start)
        if owner and owner.start_ea == context.im.start:
            offset = context.im.mba.argbase() - self.ptr + ida_frame.get_spd(owner, ea)
            return Value("stack", (context.frame, offset))
        return None

    def arguments(self, context, bi, pos, ins):
        values = []
        if context.im.call_analysis and ins.d.t == h.mop_f:
            values = [context.eval(arg, bi, pos) for arg in ins.d.f.args]
        if not values:
            if self.argument_registers:
                values = [context.reaching(bi, pos, "r", reg, self.ptr) for reg in self.argument_registers]
            elif ins.d.t == h.mop_f:
                values = [context.eval(arg, bi, pos) for arg in ins.d.f.args]
        if not self.argument_registers and not values:
            owner = ida_funcs.get_func(context.im.start)
            if owner and owner.start_ea == context.im.start:
                off = context.im.mba.argbase() - self.ptr + ida_frame.get_spd(owner, ins.ea)
                if ins.opcode == h.m_ijmp:
                    off += self.ptr  # a tail transfer reuses the return address
                values = [context.reaching(bi, pos, "s", off+i*self.ptr, self.ptr) for i in range(6)]
        return values

    def snapshot(self, context, bi, pos):
        return {reg: self._single(context.reaching(bi, pos, "r", reg, self.ptr))
                for reg in self.context_registers}

    def bind_arguments(self, registers, args, call_analysis):
        result = dict(registers)
        if self.argument_registers and not call_analysis:
            result.update(zip(self.argument_registers, args))
        return result
