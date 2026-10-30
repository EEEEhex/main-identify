"""Read-only, bounded control-flow regions rooted at actual code addresses.

An entry can be inside an incorrectly merged IDA function, or have no function
definition. Region discovery never creates/splits IDA functions. Call targets
are inspected independently; tail jumps across known boundaries remain edges.
"""
from collections import deque


class CodeRegion(dict):
    truncated = False
    all_blocks = False


def pc_acquisition(ins, following, stack_register=None):
    if not following or ins.mnemonic != "call" or not ins.operands:
        return False
    if ins.operands[0].kind != "near" or ins.operands[0].value != ins.ea + ins.size:
        return False
    ops = following.operands
    if following.mnemonic == "pop" and ops and ops[0].kind == "reg":
        return True
    # musl i386 static PIE adjusts the saved return PC directly on the stack.
    return (following.mnemonic == "add" and len(ops) == 2
            and ops[0].kind == "mem" and stack_register is not None and ops[0].base == stack_register
            and ops[0].index in (None, "") and ops[0].value == 0 and ops[1].kind == "imm")


def collect_region(start, decode, is_code, is_boundary, is_noreturn,
                   limit=4096, max_span=0x10000, check_cancelled=lambda: None,
                   stack_register=None):
    result = CodeRegion()
    queue = deque([start])
    seen = set()
    pic_entries = set()
    terminals = ("ret", "retn", "retf", "iret", "ud2", "hlt", "int3")
    while queue:
        ea = queue.popleft()
        while ea not in seen:
            if len(result) >= limit:
                result.truncated = True
                return result
            if abs(ea - start) > max_span:
                result.truncated = True
                break
            if ea != start and ea not in pic_entries and is_boundary(ea):
                break
            if not is_code(ea):
                break
            seen.add(ea)
            if len(result) % 128 == 0:
                check_cancelled()
            ins = decode(ea)
            if ins is None:
                break
            result[ea] = ins
            m, ops = ins.mnemonic, ins.operands
            nxt = ea + ins.size
            if m in terminals:
                break
            if m == "jmp":
                if ops and ops[0].kind == "near":
                    target = ops[0].value
                    if target == start or not is_boundary(target):
                        queue.append(target)
                break
            if m.startswith("j") or m.startswith("loop"):
                if ops and ops[0].kind == "near":
                    queue.append(ops[0].value)
            if m == "call" and ops:
                target = ops[0].value if ops[0].kind == "near" else None
                if is_noreturn(target):
                    break
                if target == nxt:
                    if not pc_acquisition(ins, decode(nxt), stack_register):
                        # A real call into the adjacent function, not call/pop.
                        break
                    pic_entries.add(nxt)
            ea = nxt
    return result
