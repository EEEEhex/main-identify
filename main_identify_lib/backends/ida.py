"""IDA 9.x adapter for Hex-Rays microcode main recovery."""
import ida_bytes
import ida_funcs
import ida_fixup
import ida_ida
import ida_idaapi
import ida_kernwin
import ida_name
import ida_nalt
import ida_segment
import ida_ua
import ida_xref
import idautils

from ..arch.x86_operands import decode_memory_operand
from .regions import CodeRegion, collect_region
from ..model import Instruction, DecodedOperand
from ..arch.x86_abi import processor_registers
from ..formats.go import MAGICS as GO_MAGICS, parse_table


class Cancelled(Exception):
    pass


class IDABackend:
    @staticmethod
    def is_switch_dispatch(ea):
        return ida_nalt.get_switch_info(ea) is not None

    def __init__(self, use_names=True, interactive=False):
        if ida_ida.inf_get_procname() != "metapc":
            raise ValueError("Only x86/x64 processors are supported.")
        self.bits = 64 if ida_ida.inf_is_64bit() else 32
        if ida_ida.inf_is_16bit():
            raise ValueError("16-bit programs are not supported.")
        filetype = ida_ida.inf_get_filetype()
        self.format = "PE" if filetype == ida_ida.f_PE else "ELF" if filetype == ida_ida.f_ELF else ""
        if not self.format:
            raise ValueError("Only PE and ELF executables are supported.")
        self.entry = ida_ida.inf_get_start_ea()
        self.use_names = use_names
        self.interactive = interactive
        self._instructions = {}
        self.processor_registers = processor_registers(self.bits)
        self._names = dict(idautils.Names()) if use_names else {}
        self._functions = None
        self._imports = {}
        self._go_tables = []
        self._go_evidence = None
        for module in range(ida_nalt.get_import_module_qty()):
            def record_import(ea, name, ordinal):
                if name:
                    self._imports[ea] = name
                return True
            ida_nalt.enum_import_names(module, record_import)

    def create_tracer(self, call_analysis=False):
        from .hexrays import MicroTracer
        return MicroTracer(self, call_analysis=call_analysis)

    def import_name(self, ea):
        """Loader import metadata survives stripping; never consult user names."""
        return self._imports.get(ea, "")

    def data_refs_from(self, ea):
        return tuple(idautils.DataRefsFrom(ea))

    def is_readonly(self, ea, size=1):
        seg = ida_segment.getseg(ea)
        return bool(seg and seg.type != ida_segment.SEG_XTRN
                    and not seg.perm & ida_segment.SEGPERM_WRITE
                    and ea + size <= seg.end_ea)

    def literal_references(self, literals, max_hits=64):
        """Find exact bytes in packed string pools, independent of IDA names.

        Go strings need not be terminated or individually defined as IDA items.
        Scan overlapped chunks, then use exact interior-address data xrefs.
        """
        found = {literal: [] for literal in literals}
        seen = set()
        overlap = max(map(len, literals), default=1) - 1
        for start in idautils.Segments():
            seg = ida_segment.getseg(start)
            if seg.type == ida_segment.SEG_XTRN:
                continue
            for address in range(seg.start_ea, seg.end_ea, 1024 * 1024):
                self.check_cancelled()
                data = ida_bytes.get_bytes(address, min(1024 * 1024 + overlap, seg.end_ea-address)) or b""
                for literal in literals:
                    offset = data.find(literal)
                    while offset >= 0:
                        ea = address + offset
                        if (literal, ea) not in seen and len(found[literal]) < max_hits:
                            seen.add((literal, ea))
                            for ref in idautils.DataRefsTo(ea):
                                if self.is_code(ref):
                                    found[literal].append((ea, ref))
                                    if len(found[literal]) >= max_hits:
                                        break
                        offset = data.find(literal, offset+1)
        return found

    def go_markers(self):
        if self._go_evidence is not None:
            return list(self._go_evidence)
        evidence, seen, modified_seen = set(), set(), set()
        for start in idautils.Segments():
            seg = ida_segment.getseg(start)
            if seg.type == ida_segment.SEG_XTRN:
                continue
            for ea in range(seg.start_ea, seg.end_ea, 1024 * 1024):
                self.check_cancelled()
                data = ida_bytes.get_bytes(ea, min(1024 * 1024 + 32, seg.end_ea - ea))
                if data and b"\xff Go buildinf:" in data:
                    evidence.add("Go build information magic")
                if not data:
                    continue
                for magic in GO_MAGICS:
                    signature = magic+bytes((0,0,1,self.bits//8))
                    offset = data.find(signature)
                    while offset >= 0:
                        header = ea+offset
                        if header not in seen and len(seen) < 64:
                            seen.add(header)
                            table = parse_table(header,self.bits,ida_bytes.get_bytes,
                                                idautils.DataRefsTo,self.is_code)
                            if table is not None:
                                self._go_tables.append(table)
                                evidence.add("Validated Go pclntab function ranges")
                        offset = data.find(signature,offset+1)
                # Modified runtimes can change the four magic bytes while
                # retaining the PC table layout. Accept only full moduledata
                # correlation; this does not infer any function from its name.
                suffix = bytes((0,0,1,self.bits//8))
                offset = data.find(suffix)
                while offset >= 0:
                    header = ea+offset-4
                    if (header >= seg.start_ea and header % (self.bits//8) == 0
                            and offset >= 4 and data[offset-4:offset] not in GO_MAGICS
                            and header not in modified_seen and len(modified_seen) < 256):
                        modified_seen.add(header)
                        table = parse_table(header,self.bits,ida_bytes.get_bytes,
                                            idautils.DataRefsTo,self.is_code,allow_modified=True)
                        if table is not None:
                            self._go_tables.append(table)
                            evidence.add("Go PC table with modified magic verified by moduledata")
                    offset = data.find(suffix,offset+1)
        self._go_evidence = sorted(evidence)
        return list(self._go_evidence)

    def go_function_bounds(self, ea):
        for table in self._go_tables:
            bounds = table.bounds(ea)
            if bounds:
                return bounds
        return None

    def go_function_start(self, ea):
        self.go_markers()
        bounds = self.go_function_bounds(ea)
        return bounds[0] if bounds else self.function_start(ea)

    def is_static_go_funcval(self, ea, target):
        """Corroborate an initialized pointer, without claiming RW is readonly."""
        bounds = self.go_function_bounds(target)
        if not bounds or bounds[0] != target or self.read_int(ea,self.bits//8) != target:
            return False
        fixup = ida_fixup.fixup_data_t()
        if (not fixup.get(ea) or fixup.is_unused() or fixup.calc_size() != self.bits//8
                or fixup.get_base()+fixup.off+fixup.displacement != target):
            return False
        return not any(x.type == ida_xref.dr_W for at in range(ea,ea+self.bits//8)
                       for x in idautils.XrefsTo(at,0))

    def is_library(self):
        # PE headers are often not mapped into the IDB address space.
        return self.format == "PE" and ida_ida.inf_is_dll()

    def check_cancelled(self):
        if self.interactive and ida_kernwin.user_cancelled():
            raise Cancelled()

    def functions(self):
        if self._functions is None:
            self._functions = tuple(idautils.Functions())
        return self._functions

    def function_start(self, ea):
        if ea is None or not 0 <= ea < (1 << self.bits) or ea == ida_idaapi.BADADDR:
            return None
        f = ida_funcs.get_func(ea)
        return f.start_ea if f else None

    def is_function(self, ea):
        return self.function_start(ea) == ea and self.is_code(ea)

    def is_code(self, ea):
        if ea is None or not 0 <= ea < (1 << self.bits):
            return False
        seg = ida_segment.getseg(ea)
        # Unpacked/loaded databases can retain RW section permissions even
        # where IDA has defined real instructions. Require explicit code in a
        # mapped, non-external segment; never decode arbitrary data as code.
        return bool(seg and seg.type != ida_segment.SEG_XTRN and
                    ida_bytes.is_code(ida_bytes.get_full_flags(ea)))

    def is_callable(self, ea):
        # Evidence that this is a call/vtable target comes from the analyzer;
        # accept a defined instruction head even if IDA missed the function.
        return self.is_code(ea) and ida_bytes.is_head(ida_bytes.get_full_flags(ea))

    def name(self, ea):
        if not self.use_names or ea is None:
            return ""
        raw = self._names.get(ea) or ida_name.get_name(ea) or ""
        demangled = ida_name.demangle_name(raw, ida_ida.inf_get_short_demnames())
        return (demangled or raw)

    def read_int(self, ea, size):
        if size not in (1, 2, 4, 8) or ea < 0:
            return None
        data = ida_bytes.get_bytes(ea, size)
        return int.from_bytes(data, "little") if data is not None and len(data) == size else None

    def _operand(self, insn, op):
        width = ida_ua.get_dtype_size(op.dtype)
        if width < 0:
            width = 0
        if op.type == ida_ua.o_reg:
            return DecodedOperand("reg", reg=op.reg, width=width)
        if op.type == ida_ua.o_imm:
            return DecodedOperand("imm", value=op.value, width=width)
        if op.type in (ida_ua.o_near, ida_ua.o_far):
            return DecodedOperand("near", value=op.addr, width=width)
        if op.type in (ida_ua.o_mem, ida_ua.o_phrase, ida_ua.o_displ):
            return decode_memory_operand(
                absolute=op.type == ida_ua.o_mem, phrase=op.phrase,
                has_sib=bool(op.specflag1), sib=op.specflag2, rex=insn.insnpref,
                displacement=op.addr if op.type != ida_ua.o_phrase else 0,
                width=width, bits=self.bits, segment=insn.segpref,
                native_address=bool(insn.auxpref & 0x1000),
                vector_index="gather" in insn.get_canon_mnem() or "scatter" in insn.get_canon_mnem())
        return DecodedOperand("unknown", width=width)

    def instructions(self, start, limit=4096):
        key = (start, limit)
        if key in self._instructions:
            return self._instructions[key]
        if not self.is_callable(start):
            return {}
        owner = ida_funcs.get_func(start)
        go_bounds = self.go_function_bounds(start)

        def decode(ea):
            ins = ida_ua.insn_t()
            if not ida_ua.decode_insn(ins, ea):
                return None
            ops = tuple(self._operand(ins, o) for o in ins.ops if o.type != ida_ua.o_void)
            return Instruction(ea, ins.size, ins.get_canon_mnem().lower(), ops)

        def boundary(ea):
            if ea == start:
                return False
            if go_bounds and not go_bounds[0] <= ea < go_bounds[1]:
                return True
            other = ida_funcs.get_func(ea)
            if other is not None:
                if other.start_ea == ea:
                    return True
                if owner is not None and other.start_ea != owner.start_ea:
                    return True
            # Calls can reveal entry points that IDA merged into another
            # function. Ordinary conditional jumps and data refs do not.
            return any(x.type in (ida_xref.fl_CN, ida_xref.fl_CF)
                       for x in idautils.XrefsTo(ea, 0))

        result = collect_region(start, decode, self.is_callable, boundary,
                                self.is_noreturn, limit=limit,
                                check_cancelled=self.check_cancelled,
                                stack_register=self.processor_registers.stack)
        self._instructions[key] = result
        return result

    def go_call_instructions(self, start, limit=4096):
        """Defined code across a validated Go function's fragmented IDA ranges.

        Only call-graph discovery uses this view. Gaps stay disconnected: no
        decoding of data/undefined bytes and no invented fallthrough edges.
        """
        bounds = self.go_function_bounds(start)
        if not bounds or bounds[0] != start:
            return self.instructions(start, limit)
        key = (start, limit, "go_calls")
        if key in self._instructions:
            return self._instructions[key]
        result = CodeRegion()
        result.all_blocks = True
        for ea in idautils.Heads(*bounds):
            self.check_cancelled()
            if not self.is_callable(ea):
                continue
            if len(result) >= limit:
                result.truncated = True
                break
            ins = ida_ua.insn_t()
            if not ida_ua.decode_insn(ins, ea) or ea + ins.size > bounds[1]:
                continue
            ops = tuple(self._operand(ins, o) for o in ins.ops if o.type != ida_ua.o_void)
            result[ea] = Instruction(ea, ins.size, ins.get_canon_mnem().lower(), ops)
        self._instructions[key] = result
        return result

    def is_noreturn(self, target):
        f = ida_funcs.get_func(target) if target is not None else None
        return bool(f and f.start_ea == target and f.flags & ida_funcs.FUNC_NORET)

    def rust_markers(self):
        needles = (b"/rustc/", b"library/std/src/", b"library\\std\\src\\",
                   b".rustup", b"RUST_BACKTRACE", b"Rust cannot catch foreign exceptions",
                   b"fatal runtime error: initialization or cleanup bug")
        found = set()
        for start in idautils.Segments():
            seg = ida_segment.getseg(start)
            if seg.type == ida_segment.SEG_XTRN:
                continue
            for ea in range(seg.start_ea, seg.end_ea, 1024 * 1024):
                self.check_cancelled()
                size = min(1024 * 1024 + 128, seg.end_ea - ea)
                data = ida_bytes.get_bytes(ea, size)
                if data:
                    found.update(n.decode("ascii") for n in needles if n in data)
            if len(found) >= 3:
                break
        return sorted(found)

    @property
    def input_path(self):
        return ida_nalt.get_input_file_path()
