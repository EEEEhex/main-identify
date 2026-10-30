"""Hex-Rays microcode backward slicing; no assembly instruction simulation.

CALLS preserves explicit call arguments for CRT analysis. LOCOPT preserves the
machine ABI of Rust shims whose inferred prototypes can discard real arguments.
All objects and reaching-definition caches belong to one scan, never an IDB.
"""
from itertools import product, islice

import ida_funcs
import ida_hexrays as h
import ida_range
import idautils

from ..model import Call, Trace, CallGraph, CallSite, UNKNOWN, Value, const
from ..arch.x86_abi import X86ABI


class MicrocodeError(RuntimeError):
    pass


def single(values):
    return next(iter(values)) if len(values) == 1 else UNKNOWN


class MicroTracer:
    name = "hexrays_microcode"

    def __init__(self, backend, call_analysis=False):
        if not h.init_hexrays_plugin():
            raise MicrocodeError("Hex-Rays decompiler for this processor is required.")
        self.b = backend
        self.ptr = backend.bits // 8
        self.call_analysis = call_analysis
        self.images = {}
        self.diagnostics = []
        self.frames = 0
        self.slices = 0
        self.abi = X86ABI(backend)

    def metrics(self):
        return {"microcode_functions": len(self.images), "microcode_slice_queries": self.slices}

    def read(self, address, state, width=None):
        width = width or self.ptr
        cell = state.memory.get(address)
        if cell is not None and cell[0] == width:
            return cell[1]
        if address.kind == "const":
            if self.b.import_name(address.value):
                return Value("import", address.value)
            n = self.b.read_int(address.value, width)
            if n is not None:
                return const(n)
        return UNKNOWN

    def value(self, op, state):
        # Used only to resolve a single jump-only linker thunk.
        if op.kind in ("near", "imm"):
            return const(op.value)
        if op.kind == "reg":
            return state.regs.get(self.abi.to_micro(op.reg), UNKNOWN)
        if op.kind == "mem" and op.base is None and op.index is None:
            return self.read(const(op.value), state, op.width)
        return UNKNOWN

    def image(self, start, limit, abi_only=False, go_ranges=False):
        key = ((start, limit, "go_calls") if go_ranges else
               (start, limit, "abi") if abi_only else (start, limit))
        if key in self.images:
            return self.images[key]
        self.b.check_cancelled()
        getter = getattr(self.b, "go_call_instructions", self.b.instructions) if go_ranges else self.b.instructions
        code = getter(start, limit)
        if not code:
            self.images[key] = None
            return None
        owner = ida_funcs.get_func(start)
        # 9.4 uses ea-based ranges; earlier 9.x uses func_t-based ranges.
        modern = hasattr(h, "decomp_ranges_t")
        ranges = h.decomp_ranges_t() if modern else h.mba_ranges_t()
        all_blocks = getattr(code, "all_blocks", False)
        complete = not all_blocks and owner is not None and owner.start_ea == start and not getattr(code, "truncated", False)
        complete = complete and all(ida_funcs.func_contains(owner, ea) for ea in code)
        if complete:
            # Function-mode generation must also respect the region budget;
            # IDA may have merged a tiny startup stub with a huge next body.
            complete = len(list(islice(idautils.FuncItems(start), limit+1))) <= limit
        if complete:
            if modern:
                ranges.func_ea = start
            else:
                ranges.pfn = owner
        else:
            # No splitting/creating IDA functions: snippet mode also supports
            # missed functions and entry points inside a merged function.
            intervals = []
            for ea, ins in sorted(code.items()):
                end = ea + ins.size
                if intervals and intervals[-1][1] == ea:
                    intervals[-1] = (intervals[-1][0], end)
                else:
                    intervals.append((ea, end))
            for lo, hi in intervals:
                ranges.ranges.push_back(ida_range.range_t(lo, hi))
        failure = h.hexrays_failure_t()
        tails = []
        for ins in code.values():
            if (ins.mnemonic == "call" and ins.operands and ins.operands[0].kind == "near"
                    and ins.operands[0].value == ins.ea + ins.size
                    and ins.operands[0].value not in code):
                # IDA can split a call-to-next PC acquisition into two code
                # regions; Hex-Rays folds it away. Keep the continuation edge.
                tails.append(ins)
            if ins.mnemonic == "jmp" and ins.operands:
                if getattr(self.b, "is_switch_dispatch", lambda ea: False)(ins.ea):
                    continue
                op = ins.operands[0]
                if op.kind != "near" or op.value not in code:
                    tails.append(ins)
        calls = (self.call_analysis or (start == self.b.entry and self.b.format == "ELF")) and not tails and not abi_only
        maturity = h.MMAT_CALLS if calls else h.MMAT_LOCOPT
        flags = h.DECOMP_NO_WAIT | (h.DECOMP_ALL_BLKS if all_blocks else 0)
        mba = h.gen_microcode(ranges, failure, None, flags, maturity)
        if mba is None:
            self.diagnostics.append("Microcode failed at 0x%x: %s" % (start, failure))
            self.images[key] = None
            return None
        image = MicroImage(self, start, mba, bool(getattr(code, "truncated", False)), calls, tails)
        image.code = code
        self.images[key] = image
        return image

    def run(self, start, args=(), memory=None, regs=None, max_instructions=4096, abi_only=False):
        image = self.image(start, max_instructions, abi_only)
        if image is None:
            return Trace(truncated=True)
        self.frames += 1
        context = Slice(self, image, self.frames, args, memory or {}, regs or {})
        try:
            result = context.trace()
        except RecursionError:
            self.diagnostics.append("Microcode slice recursion budget reached at 0x%x" % start)
            result = Trace(truncated=True)
        self.slices += context.total_steps
        result.truncated |= context.reached_bound
        return result

    def run_abi(self, start):
        """Recover platform arguments before inferred call types discard them."""
        return self.run(start,abi_only=True)

    def call_graph(self, start, max_instructions=4096):
        """Resolve call targets without assuming a source language's ABI.

        Unlike run(), this does not materialize platform-ABI argument snapshots
        or prune paths using initial values of mutable Go runtime globals.
        It describes possible calls, not an execution trace. Original operand
        kinds survive Hex-Rays folding an indirect call into a direct microcall.
        """
        image = self.image(start, max_instructions, go_ranges=True)
        if image is None:
            return CallGraph(truncated=True)
        self.frames += 1
        context = Slice(self, image, self.frames, (), {}, {})
        code = image.code
        ordered = sorted(code)
        previous = {ea: ordered[n-1] if n else None for n, ea in enumerate(ordered)}
        result, seen = CallGraph(), set()
        for bi, pos, ins in image.calls:
            self.b.check_cancelled()
            original = code.get(ins.ea)
            if original is None or original.mnemonic != "call" or not original.operands:
                continue  # intrinsics and synthetic tail/PC-acquisition edges
            refs = set()
            cursor = previous[ins.ea]
            following = ins.ea
            for _ in range(16):
                if cursor is None:
                    break
                source = code[cursor]
                if cursor + source.size != following:
                    break
                if (source.mnemonic.startswith("j") or source.mnemonic.startswith("loop")
                        or source.mnemonic in ("call", "ret", "retn", "ud2", "int3")):
                    break
                refs.update(self.b.data_refs_from(cursor))
                following = cursor
                cursor = previous[cursor]
            refs.update(self.b.data_refs_from(ins.ea))
            indirect = original.operands[0].kind != "near"
            funcval_context = self.abi.funcval_context(context, bi, pos) if indirect else None
            for value in context.target(ins, bi, pos):
                target = value.value if value.kind == "const" else None
                key = (ins.ea, target)
                if key not in seen:
                    seen.add(key)
                    result.calls.append(CallSite(ins.ea, target,
                                                 indirect, tuple(sorted(refs)), funcval_context))
        self.slices += context.total_steps
        result.truncated = image.truncated or context.reached_bound
        return result


class MicroImage:
    def __init__(self, tracer, start, mba, truncated, call_analysis, tails):
        self.t, self.start, self.mba, self.truncated = tracer, start, mba, truncated
        self.call_analysis = call_analysis
        self.blocks = []
        self.defs = {}
        self.uses = {}
        self.calls = []
        self.stack_offsets = set()
        self.stack_addressed = False
        self.addressed_ranges = []
        self.pointer_definitions = []
        for bi in range(mba.qty):
            block = mba.get_mblock(bi)
            insns = []
            ins = block.head
            while ins:
                pos = len(insns)
                insns.append(ins)
                self.uses[bi, pos] = block.build_use_list(ins, h.MAY_ACCESS)
                self.defs[bi, pos] = (block.build_def_list(ins, h.MUST_ACCESS),
                                      block.build_def_list(ins, h.MAY_ACCESS))
                self.walk(ins, bi, pos)
                ins = ins.next
            self.blocks.append(insns)
        # Keep the MBA alive with its chains. Never mutate microcode, so chain
        # pointers remain valid throughout this image's lifetime.
        self.ud = mba.get_graph().get_ud(h.GC_REGS_AND_STKVARS)
        for tail in tails:
            self.calls = [(bi, pos, ins) for bi, pos, ins in self.calls
                          if not tail.ea <= ins.ea < tail.ea + tail.size]
            # Hex-Rays represents transfers leaving a function/snippet as exits
            # and may omit the jump itself. Retain that CFG edge, evaluating
            # its target/ABI arguments against the microcode before the exit.
            best = None
            for bi, insns in enumerate(self.blocks):
                for pos, ins in enumerate(insns):
                    if ins.ea < tail.ea and (best is None or ins.ea >= best[0]):
                        best = (ins.ea, bi, pos+1)
            if best is None:
                best = (start, 0, 0)
            _, bi, pos = best
            op = tail.operands[0]
            target = h.mop_t()
            if op.kind == "near":
                target.make_gvar(op.value)
                target.size = tracer.ptr
            elif op.kind == "reg":
                reg = tracer.abi.to_micro(op.reg)
                if reg is None:
                    continue
                target.make_reg(reg, op.width or tracer.ptr)
            elif op.kind == "mem" and op.base is None and op.index is None:
                target.make_gvar(op.value)
                target.size = tracer.ptr
            else:
                continue
            synthetic = h.minsn_t(tail.ea)
            synthetic.opcode = h.m_ijmp
            synthetic.r.assign(target)
            self.calls.append((bi, pos, synthetic))

    def walk(self, ins, bi, pos):
        if (ins.opcode in (h.m_add, h.m_sub, h.m_mov) and ins.d.t == h.mop_r
                and ins.d.r not in (self.t.abi.stack, self.t.abi.frame)
                and any(op.t == h.mop_r and op.r in (self.t.abi.stack, self.t.abi.frame)
                        for op in (ins.l, ins.r))):
            self.stack_addressed = True
            self.pointer_definitions.append((bi, pos, ins))
        if ins.opcode in (h.m_call, h.m_icall, h.m_ijmp):
            self.calls.append((bi, pos, ins))
        operands = [ins.l, ins.r, ins.d]
        if ins.d.t == h.mop_f:
            operands.extend(ins.d.f.args)
        for op in operands:
            if op.t == h.mop_d:
                self.walk(op.d, bi, pos)
            elif op.t == h.mop_S:
                self.stack_offsets.add(op.s.off)
            elif op.t == h.mop_a and op.a.t == h.mop_S:
                self.stack_addressed = True
                width = op.a.insize
                if width <= 0 or width > 0x10000:
                    width = self.t.ptr
                self.addressed_ranges.append((op.a.s.off, width, bi, pos))


class Slice:
    MAX_STEPS = 24000
    MAX_VALUES = 12

    def __init__(self, tracer, image, frame, args, memory, regs, condition_mode=False):
        self.t, self.b, self.im = tracer, tracer.b, image
        self.ptr, self.frame = tracer.ptr, frame
        self.args, self.memory, self.regs = args, memory, regs
        self.memo, self.active = {}, set()
        self.escape_cache = {}
        self.predecessor_cache = {}
        self.finding_escape = False
        self.steps = 0
        self.truncated = image.truncated
        self.abi = tracer.abi
        self.condition_mode = condition_mode
        self.condition_slice = None

    @property
    def total_steps(self):
        return self.steps + (self.condition_slice.steps if self.condition_slice else 0)

    @property
    def reached_bound(self):
        return self.truncated or bool(self.condition_slice and self.condition_slice.truncated)

    def values(self, vs):
        result = frozenset(vs)
        if len(result) > self.MAX_VALUES:
            self.truncated = True
            return frozenset((UNKNOWN,))
        return result or frozenset((UNKNOWN,))

    def entry(self, kind, off, size):
        return self.abi.entry_value(kind, off, size, self)

    def location(self, op):
        if op.t == h.mop_r:
            return "r", op.r, op.size
        if op.t == h.mop_S:
            return "s", op.s.off, op.size
        if op.t == h.mop_v:
            return "g", op.g, op.size
        return None

    def location_list(self, kind, off, size):
        result = h.mlist_t()
        if kind == "r":
            result.add(off, size)
        else:
            op = h.mop_t()
            if kind == "s":
                op.make_stkvar(self.im.mba, off)
            else:
                op.make_gvar(off)
            op.size = size
            self.im.mba.get_mblock(0).append_use_list(result, op, h.MUST_ACCESS)
        return result

    def address_precedes(self, source, at, bi, pos):
        if bi is None or (source == bi and at <= pos):
            return True
        if bi not in self.predecessor_cache:
            pending = list(self.im.mba.get_mblock(bi).predset)
            seen = set()
            while pending:
                block = pending.pop()
                if block in seen:
                    continue
                seen.add(block)
                if len(seen) % 128 == 0:
                    self.b.check_cancelled()
                pending.extend(self.im.mba.get_mblock(block).predset)
            self.predecessor_cache[bi] = seen
        # Include loop back-edges: a later address formation in this block
        # can precede the call on the next iteration.
        return source in self.predecessor_cache[bi]

    def escapes(self, off, size, bi=None, pos=None):
        key = (off, size, bi, pos)
        if key in self.escape_cache:
            return self.escape_cache[key]
        if self.finding_escape:
            return True
        self.finding_escape = True
        try:
            ranges = [(lo,width) for lo,width,source,at in self.im.addressed_ranges
                      if self.address_precedes(source,at,bi,pos)]
            uncertain = False
            for source, at, ins in self.im.pointer_definitions:
                if not self.address_precedes(source,at,bi,pos):
                    continue
                for v in self.eval_ins(ins, source, at):
                    if v.kind == "stack" and v.value[0] == self.frame:
                        ranges.append((v.value[1], self.ptr))
                    elif v.kind == "unknown":
                        uncertain = True
            result = uncertain or any(lo < off+size and off < lo+width for lo,width in ranges)
            self.escape_cache[key] = result
            return result
        finally:
            self.finding_escape = False

    def reaching(self, bi, pos, kind, off, size):
        if kind == "r" and off == self.abi.stack:
            value = self.abi.stack_value(self, bi, pos)
            if value is not None:
                return frozenset((value,))
        key = (bi, pos, kind, off, size)
        if key in self.memo:
            return self.memo[key]
        if key in self.active or self.steps >= self.MAX_STEPS:
            self.truncated = True
            return frozenset((UNKNOWN,))
        self.active.add(key)
        wanted = self.location_list(kind, off, size)
        pending, visited, vals = [(bi, pos)], set(), set()
        # A CFG back-edge is not a new unknown definition. Walk each location
        # once, collecting actual definitions/entry values. Expression cycles
        # still hit the active-query guard above (e.g. an induction variable).
        while pending:
            block_id, at = pending.pop()
            location = (block_id, at)
            if location in visited:
                continue
            visited.add(location)
            self.steps += 1
            if self.steps > self.MAX_STEPS:
                self.truncated = True
                vals.add(UNKNOWN)
                break
            if self.steps % 128 == 0:
                self.b.check_cancelled()
            cached = self.memo.get((block_id, at, kind, off, size))
            if cached is not None:
                vals.update(cached)
                continue
            local = self.local_definition(block_id, at, kind, off, size, wanted)
            if local is not None:
                vals.update(local)
                continue
            block = self.im.mba.get_mblock(block_id)
            preds = list(block.predset)
            if not preds:
                vals.add(self.entry(kind, off, size))
                continue
            chain = None
            if kind in ("r", "s"):
                chains = self.im.ud[block_id]
                chain = chains.get_reg_chain(off, size) if kind == "r" else chains.get_stk_chain(off, size)
            origins = list(chain) if chain is not None else []
            safe_shortcut = ((kind == "r" and not self.abi.is_volatile(off, size))
                             or (kind == "s" and not self.escapes(off, size)))
            if (safe_shortcut and chain is not None and chain.width >= size and len(origins) == 1
                    and origins[0] != block_id and not chain.is_overlapped()):
                source = origins[0]
                if source == 0:
                    vals.add(self.entry(kind, off, size))
                else:
                    pending.append((source, len(self.im.blocks[source])))
            else:
                pending.extend((pred, len(self.im.blocks[pred])) for pred in preds
                               if self.edge_possible(pred, block_id))
        self.active.remove(key)
        result = self.values(vals)
        self.memo[key] = result
        return result

    def local_definition(self, bi, pos, kind, off, size, wanted):
        for p in range(pos - 1, -1, -1):
            ins = self.im.blocks[bi][p]
            must, may = self.im.defs[bi, p]
            dest = self.location(ins.d)
            if dest is not None and dest[0] == kind and dest[1] == off and dest[2] >= size and must.includes(wanted):
                return self.eval_ins(ins, bi, p)
            # At LOCOPT, call argument/return metadata is intentionally absent.
            # Calls still obey the platform ABI; never propagate volatile values
            # across them merely because build_def_list is empty at this stage.
            calls = self.calls_in(ins)
            if kind == "r" and calls:
                returned, spoiled = None, False
                for call in calls:
                    if call.d.t == h.mop_f:
                        spoiled |= call.d.f.spoiled.has_common(wanted)
                        if call.d.f.return_regs.includes(wanted):
                            returned = self.return_value(call, bi, p)
                    else:
                        is_return, is_spoiled = self.abi.fallback_call_effect(off, size)
                        spoiled |= is_spoiled
                        if is_return:
                            returned = self.return_value(call, bi, p)
                if returned is not None or spoiled:
                    return returned or frozenset((UNKNOWN,))
            if kind == "s" and calls and self.escapes(off, size, bi, p):
                # Restricted-stack use/def sets may omit writes through an
                # escaped pointer. Retain an alias barrier even when the call's
                # register/global may-def list does not mention this slot.
                return frozenset((UNKNOWN,))
            if not may.has_common(wanted):
                continue
            if (kind == "s" and ins.opcode == h.m_stx and not must.has_common(wanted)
                    and not self.escapes(off, size, bi, p)):
                # Relocation-table writes have unrestricted may-def sets. An
                # indirect store cannot alias a private slot unless its address
                # actually derives from that frame; retain explicit overlaps.
                addresses = self.eval(ins.d, bi, p)
                width = max(ins.l.size, 1)
                if not any(v.kind == "stack" and v.value[0] == self.frame
                           and v.value[1] < off+size and off < v.value[1]+width for v in addresses):
                    continue
            if kind == "s" and calls and not self.escapes(off, size, bi, p) and not must.has_common(wanted):
                # A call's unrestricted may-write set is not evidence that it
                # overwrites a private, non-address-taken scalar stack slot.
                # Explicit/partial stores still kill it. Address-taken frames
                # keep the conservative alias barrier.
                continue
            # Partial writes and uncertain aliases must not preserve provenance.
            return frozenset((UNKNOWN,))
        return None

    def edge_possible(self, pred, target):
        if not self.condition_mode:
            # Address recovery can use relocated image pointers. Those bytes
            # are not runtime constants for writable globals: initializers or
            # earlier calls may change a CRT flag. Keep an independent memoized
            # slice for predicates so optimistic pointer values cannot leak
            # into branch decisions through registers or stack temporaries.
            if self.condition_slice is None:
                self.condition_slice = Slice(self.t, self.im, self.frame, self.args,
                                             self.memory, self.regs, condition_mode=True)
            return self.condition_slice.edge_possible(pred, target)
        insns = self.im.blocks[pred]
        if not insns:
            return True
        ins = insns[-1]
        conds = {h.m_jz: lambda a,b:a==b, h.m_jnz:lambda a,b:a!=b,
                 h.m_jae:lambda a,b:a>=b, h.m_jb:lambda a,b:a<b,
                 h.m_ja:lambda a,b:a>b, h.m_jbe:lambda a,b:a<=b}
        fn = conds.get(ins.opcode)
        if fn is None or ins.d.t != h.mop_b:
            return True
        a = single(self.eval(ins.l, pred, len(insns)-1))
        b = single(self.eval(ins.r, pred, len(insns)-1))
        if a.kind != "const" or b.kind != "const":
            return True
        return (target == ins.d.b) == fn(a.value, b.value)

    def load(self, address, size, bi, pos):
        if address.kind == "stack" and address.value[0] == self.frame:
            return self.reaching(bi, pos, "s", address.value[1], size)
        cell = self.memory.get(address)
        if cell and cell[0] == size:
            return frozenset((cell[1],))
        if address.kind == "const":
            if self.b.import_name(address.value):
                return frozenset((Value("import", address.value),))
            if self.condition_mode and not self.b.is_readonly(address.value, size):
                # Only a reaching microcode definition can establish a mutable
                # global's value here. Unmodeled calls/stores are may-def
                # barriers; absence of a definition yields UNKNOWN at entry.
                return self.reaching(bi, pos, "g", address.value, size)
            value = self.b.read_int(address.value, size)
            if value is not None:
                return frozenset((const(value),))
        return frozenset((UNKNOWN,))

    def eval(self, op, bi, pos):
        if op.t == h.mop_n:
            return frozenset((const(op.nnn.value),))
        if op.t == h.mop_a:
            addr = op.a
            if addr.t == h.mop_v:
                return frozenset((const(addr.g),))
            if addr.t == h.mop_S:
                return frozenset((Value("stack", (self.frame, addr.s.off)),))
            return frozenset((UNKNOWN,))
        if op.t == h.mop_d:
            return self.eval_ins(op.d, bi, pos)
        loc = self.location(op)
        if loc:
            if loc[0] == "g":
                # Direct code operands denote a target, data operands a load.
                if self.b.is_callable(loc[1]):
                    return frozenset((const(loc[1]),))
                return self.load(const(loc[1]), loc[2], bi, pos)
            return self.reaching(bi, pos, *loc)
        return frozenset((UNKNOWN,))

    def target(self, ins, bi, pos):
        op = ins.l if ins.opcode == h.m_call else ins.r
        return self.eval(op, bi, pos)

    def return_value(self, ins, bi, pos):
        vals = []
        for target in self.target(ins, bi, pos):
            vals.append(Value("return", (ins.ea, target.value if target.kind == "const" else None)))
        return self.values(vals)

    def eval_ins(self, ins, bi, pos):
        if ins.opcode in (h.m_call, h.m_icall):
            return self.return_value(ins, bi, pos)
        left = self.eval(ins.l, bi, pos)
        if ins.opcode in (h.m_mov, h.m_xdu, h.m_xds, h.m_low):
            # Preserve origin through scalar width conversions. Constants still
            # obey microcode widths; code pointers are consumed at pointer size.
            vals = []
            for v in left:
                if v.kind == "const":
                    n = v.value
                    if ins.opcode == h.m_xds and ins.l.size > 0:
                        sign = 1 << (ins.l.size*8-1)
                        n = (n ^ sign) - sign
                    if ins.d.size > 0:
                        n &= (1 << (8*ins.d.size))-1
                    vals.append(const(n))
                else:
                    vals.append(v)
            return self.values(vals)
        if ins.opcode == h.m_ldx:
            vals = set()
            for address in self.eval(ins.r, bi, pos):
                vals.update(self.load(address, ins.d.size, bi, pos))
            return self.values(vals)
        if ins.opcode in (h.m_add, h.m_sub, h.m_and, h.m_or, h.m_xor, h.m_mul, h.m_shl, h.m_shr):
            vals = []
            for a, b in product(left, self.eval(ins.r, bi, pos)):
                if ins.opcode in (h.m_add, h.m_sub) and b.kind == "const":
                    delta = b.value if ins.opcode == h.m_add else -b.value
                    vals.append(a.add(delta, self.b.bits))
                elif a.kind == b.kind == "const":
                    n, m = a.value, b.value
                    fn = {h.m_and:lambda:n&m,h.m_or:lambda:n|m,h.m_xor:lambda:n^m,
                          h.m_mul:lambda:n*m,h.m_shl:lambda:n<<m if m<64 else 0,
                          h.m_shr:lambda:n>>m if m<64 else 0}.get(ins.opcode)
                    vals.append(const(fn() & ((1 << self.b.bits)-1)) if fn else UNKNOWN)
                else:
                    vals.append(UNKNOWN)
            return self.values(vals)
        return frozenset((UNKNOWN,))

    def calls_in(self, ins):
        result = [ins] if ins.opcode in (h.m_call, h.m_icall) else []
        for op in (ins.l, ins.r, ins.d):
            if op.t == h.mop_d:
                result.extend(self.calls_in(op.d))
        return result

    def trace(self):
        result = Trace(truncated=self.truncated)
        reachable, pending = set(), [0]
        while pending:
            bi = pending.pop()
            if bi in reachable:
                continue
            reachable.add(bi)
            block = self.im.mba.get_mblock(bi)
            for successor in block.succset:
                if self.edge_possible(bi, successor):
                    pending.append(successor)
        for bi, pos, ins in self.im.calls:
            if bi not in reachable:
                continue
            self.b.check_cancelled()
            if ins.opcode == h.m_ijmp:
                targets = self.eval(ins.r, bi, pos)
            else:
                targets = self.target(ins, bi, pos)
            arg_values = self.abi.arguments(self, bi, pos, ins)
            regs = self.abi.snapshot(self, bi, pos)
            ordered = [sorted(vs, key=lambda v: (v.kind == "unknown", v.kind, repr(v.value)))
                       for vs in arg_values]
            combinations = list(islice(product(*ordered), self.MAX_VALUES + 1)) if ordered else [()]
            if len(combinations) > self.MAX_VALUES:
                combinations = combinations[:self.MAX_VALUES]
                self.truncated = True
            for args in combinations:
                call_regs = self.abi.bind_arguments(regs, args, self.im.call_analysis)
                environments = list(dict.fromkeys(v for v in args + tuple(call_regs.values())
                                                   if v.kind == "stack" and v.value[0] == self.frame))
                cells = [self.load(v, self.ptr, bi, pos) for v in environments]
                # Preserve alternative closure contents instead of collapsing
                # {captured_function, unknown} into one unknown environment.
                variants = list(islice(product(*cells), self.MAX_VALUES+1)) if cells else [()]
                if len(variants) > self.MAX_VALUES:
                    self.truncated = True
                    variants = variants[:self.MAX_VALUES]
                for contents in variants:
                    memory = dict(self.memory)
                    for address, value in zip(environments, contents):
                        memory[address] = (self.ptr, value)
                    for target in targets:
                        reference = target.value if target.kind == "import" else None
                        ea = target.value if target.kind == "const" else None
                        result.calls.append(Call(ins.ea, ea, tuple(args), call_regs, memory,
                                                 ins.opcode == h.m_ijmp, ins.opcode != h.m_call, reference))
        result.truncated |= self.truncated
        return result
