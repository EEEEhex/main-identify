"""C/C++ CRT main recovery from libc arguments or return-to-exit data flow."""
from collections import deque

from ..model import Candidate, State, UNKNOWN, Value
from .base import StartupAnalyzer


def normalize_import(name):
    name = name.split("!")[-1]
    name = name.lstrip("@").split("@", 1)[0]
    return name.lstrip("_").lower()


class CppAnalyzer(StartupAnalyzer):
    def __init__(self, backend):
        super().__init__(backend, max_startup_functions=160, max_startup_depth=4, call_analysis=True)
        self.report.language = "native"
        self.identities = {}
        self.termination_summaries = {}
        self.termination_trace_count = 0
        self.max_termination_summaries = 128

    def identity(self, address):
        """Resolve jump-only ILT/PLT/IAT thunks without consuming source names."""
        if address in self.identities:
            return self.identities[address]
        original, hops = address, []
        seen = set()
        name = ""
        while address is not None and address not in seen and len(hops) < 8:
            seen.add(address)
            name = getattr(self.b, "import_name", lambda ea: "")(address)
            if name or not self.b.is_callable(address):
                break
            ins = list(self.b.instructions(address, 8).values())
            useful = [i for i in ins if i.mnemonic not in ("nop", "endbr64", "endbr32")]
            if not useful or useful[0].mnemonic != "jmp" or not useful[0].operands:
                break
            v = self.t.value(useful[0].operands[0], State())
            if v.kind == "import":
                name = getattr(self.b, "import_name", lambda ea: "")(v.value)
                break
            if v.kind != "const":
                break
            hops.append(address)
            address = v.value
        result = (address, hops, normalize_import(name))
        self.identities[original] = result
        return result

    def call_name(self, call):
        if call.reference is not None:
            name = getattr(self.b, "import_name", lambda ea: "")(call.reference)
            if name:
                return normalize_import(name)
        return self.identity(call.target)[2]

    def calls_main(self, function, context, main, depth=0, seen=None):
        function = self.identity(function)[0]
        main_target = self.identity(main)[0]
        if depth > 4 or not self.b.is_callable(function) or function == main_target:
            return None
        seen = set(seen or ())
        if function in seen:
            return None
        seen.add(function)
        for limit in (768, 4096):
            trace = self.t.run(function, context.args, context.memory, context.regs,
                               max_instructions=limit)
            for call in trace.calls:
                if call.indirect and self.identity(call.target)[0] == main_target:
                    return [function, main]
            for call in trace.calls:
                if any(self.code(v) == main for v in call.args[:3]):
                    chain = self.calls_main(call.target, call, main, depth + 1, seen)
                    if chain:
                        return [function] + chain
            if not trace.truncated:
                break
        return None

    def elf(self):
        excluded, earliest = set(), None
        for function, path, depth in self.iter_crt_paths(excluded):
            if (earliest is not None and depth > earliest) or depth > 2:
                break
            calls = list(self.trace(function).calls)
            missing = {c.ea for c in calls if self.call_name(c) == "libc_start_main"
                       and (not c.args or self.code(c.args[0]) is None)}
            recover = getattr(self.t,"run_abi",None)
            if missing and recover is not None:
                # A Go/Rust calling-convention guess on the ELF stub can move
                # or drop the C main argument at CALLS. The loader-confirmed
                # libc API has a platform ABI; recover it at LOCOPT instead.
                calls.extend(c for c in recover(function).calls
                             if c.ea in missing and self.call_name(c) == "libc_start_main")
            for call in calls:
                main = self.code(call.args[0]) if call.args else None
                if main is None or main in path:
                    continue
                excluded.add(main)
                name = self.call_name(call)
                chain = None
                if name == "libc_start_main":
                    chain = [main]
                    method, score = "libc_start_main_argument", 99
                    proof = "Loader import identifies __libc_start_main"
                else:
                    chain = self.calls_main(call.target, call, main)
                    method, score = "static_libc_main_callback", 96
                    proof = "Static startup adapter invokes the supplied main pointer"
                if chain:
                    self.report.candidates.append(Candidate(
                        main, function, score, method,
                        ["Startup call at 0x%x passes 0x%x as argument 0" % (call.ea, main), proof],
                        path + chain, role="native_main"))
                    earliest = depth if earliest is None else min(earliest, depth)

    def iter_crt_paths(self, excluded=None):
        """Yield shallow CRT callers before inspecting any of their callees."""
        excluded = excluded if excluded is not None else set()
        queue = deque([(self.b.entry, [self.b.entry], 0)])
        paths = {}
        while queue and len(paths) < self.max_startup_functions:
            target, path, depth = queue.popleft()
            function, hops, name = self.identity(target)
            if name or function in paths or function in excluded or not self.b.is_callable(function):
                continue
            resolved_path = list(path)
            for ea in hops + [function]:
                if resolved_path[-1] != ea:
                    resolved_path.append(ea)
            paths[function] = (resolved_path, depth)
            yield function, resolved_path, depth
            if depth >= self.max_startup_depth:
                continue
            for call in self.trace(function).calls:
                if call.target not in resolved_path and self.b.is_callable(call.target):
                    queue.append((call.target, resolved_path + [call.target], depth + 1))
        if queue:
            self.report.diagnostics.append("CRT traversal reached its function budget.")
    def termination_chain(self, call, value, depth=0, seen=None):
        if not call.args or call.args[0] != value:
            return None
        name = self.call_name(call)
        if name in ("exit", "exitprocess", "rtlexituserprocess", "quick_exit"):
            return [name]
        function = self.identity(call.target)[0]
        if depth >= 4 or not self.b.is_callable(function):
            return None
        seen = set(seen or ())
        if function in seen:
            return None
        seen.add(function)
        # Termination receives a scalar status. Analyze that parameter rather
        # than carrying thousands of unrelated caller stack cells into every
        # recursive invocation. Preserve constant control arguments (exit mode
        # etc.); unknown caller values do not become address assumptions.
        parameter = Value("arg", 0)
        auxiliary = tuple(v if v.kind in ("const", "import") else UNKNOWN for v in call.args[1:])
        key = (function, auxiliary, 4 - depth)
        if key in self.termination_summaries:
            return self.termination_summaries[key]
        if self.termination_trace_count >= self.max_termination_summaries:
            return None
        self.termination_trace_count += 1
        trace = self.t.run(function, (parameter,) + auxiliary, max_instructions=768)
        for nested in trace.calls:
            if nested.args and nested.args[0] == parameter:
                proof = self.termination_chain(nested, parameter, depth + 1, seen)
                if proof:
                    result = ["0x%x" % function] + proof
                    self.termination_summaries[key] = result
                    return result
        self.termination_summaries[key] = None
        return None

    def pe(self):
        hits = []
        earliest = None
        for function, path, depth in self.iter_crt_paths():
            if earliest is not None and depth > earliest:
                break
            calls = self.trace(function).calls
            sources = {(c.ea, c.target): c for c in calls}
            for sink in calls:
                if not sink.args or sink.args[0].kind != "return":
                    continue
                source = sources.get(sink.args[0].value)
                if source is None:
                    continue
                main, thunks, imported = self.identity(source.target)
                if imported or main in path or not self.b.is_callable(main):
                    continue
                termination = self.termination_chain(sink, sink.args[0])
                if not termination:
                    continue
                evidence = ["CRT call at 0x%x returns the value supplied to termination at 0x%x" % (source.ea, sink.ea),
                            "Termination is %s" % " -> ".join(termination)]
                if thunks:
                    evidence.append("Jump-only linker thunks resolved to the implementation")
                candidate = Candidate(main, function, 97,
                                      "crt_main_return_to_exit", evidence,
                                      path + thunks + [main], role="native_main")
                hits.append((depth, candidate))
                earliest = depth if earliest is None else min(earliest, depth)
        # Prefer the earliest CRT caller; application code can itself call exit
        # with another function's result, which is not a second application main.
        if hits:
            earliest = min(depth for depth, _ in hits)
            self.report.candidates.extend(c for depth, c in hits if depth == earliest)

    def analyze(self):
        if getattr(self.b, "is_library", lambda: False)():
            self.report.diagnostics.append("DLLs do not have a standard executable main.")
            return self.report
        if not self.b.is_callable(self.b.entry):
            self.report.diagnostics.append("No defined entry instruction is available.")
            return self.report
        if self.b.format == "ELF":
            self.elf()
        else:
            self.pe()
        unique = {}
        for c in sorted(self.report.candidates, key=lambda c: (-c.score, len(c.chain), c.ea)):
            unique.setdefault(c.ea, c)
        self.report.candidates = list(unique.values())
        self.report.scanned_functions = len(self.cache)
        if not unique:
            self.report.diagnostics.append("No verified native CRT main was recovered.")
        elif len(unique) > 1:
            self.report.diagnostics.append("Multiple native main candidates remain; review the evidence.")
        if any(trace.truncated for trace in self.cache.values()):
            self.report.diagnostics.append("Some CRT paths reached an analysis bound.")
        if self.termination_trace_count >= self.max_termination_summaries:
            self.report.diagnostics.append("Termination verification reached its shared work budget.")
        return self.finish()
