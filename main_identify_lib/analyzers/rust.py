"""Rust std entry-chain recognition, independent of compiler symbol names."""

from ..model import Candidate, State
from .base import StartupAnalyzer


class RustAnalyzer(StartupAnalyzer):
    @staticmethod
    def has_runtime_evidence(markers):
        return bool(set(markers) & {
            "RUST_BACKTRACE", "Rust cannot catch foreign exceptions",
            "fatal runtime error: initialization or cleanup bug",
        })

    def __init__(self, backend, max_startup_functions=240, max_startup_depth=4):
        super().__init__(backend, max_startup_functions, max_startup_depth)
        self.vtables = {}
        self.report.language = "rust"

    def captured_code(self, value, memory):
        if value.kind not in ("stack", "const"):
            return None
        return self.code(self.t.read(value, State(memory=memory)))

    def vtable(self, address):
        if address in self.vtables:
            return self.vtables[address]
        b, p = self.b, self.ptr
        result = None
        if b.read_int(address + p, p) == p and b.read_int(address + 2 * p, p) == p:
            drop = b.read_int(address, p)
            methods = [b.read_int(address + n * p, p) for n in (3, 4, 5)]
            if (drop == 0 or b.is_callable(drop)) and all(b.is_callable(ea) for ea in methods):
                result = tuple(dict.fromkeys(methods))
        self.vtables[address] = result
        return result

    def callback_reaches(self, function, args, regs, memory, expected, depth=0, seen=None):
        """Prove a supplied fn pointer is invoked through a small adapter.

        Walk only adapters, never the prospective application main body.
        This covers FnOnce shims, lang_start closures, and short backtraces.
        """
        if depth > 4 or not self.b.is_callable(function):
            return None
        seen = set(seen or ())
        if function in seen or function == expected:
            return None
        seen.add(function)
        trace = self.t.run(function, args, memory, regs, max_instructions=160)
        for call in trace.calls:
            if call.target == expected and call.indirect:
                return [function, expected]
        for call in trace.calls:
            if call.target is None or call.target == expected or call.tail and call.target in seen:
                continue
            # Only forward values carrying the expected fn pointer or its
            # environment; do not walk unrelated application/runtime calls.
            values = call.args + self.abi.callback_values(call)
            if not any(self.code(v) == expected or self.captured_code(v, call.memory) == expected for v in values):
                continue
            chain = self.callback_reaches(call.target, call.args, call.regs,
                                          call.memory, expected, depth + 1, seen)
            if chain:
                return [function] + chain
        return None

    def closure(self, call):
        if len(call.args) < 2:
            return None
        environment, table = call.args[:2]
        main = self.captured_code(environment, call.memory)
        if main is None or table.kind != "const":
            return None
        methods = self.vtable(table.value)
        if not methods:
            return None
        # Validate the vtable actually invokes the captured function. A table
        # with the right size/alignment alone is insufficient.
        for method in methods:
            args = (environment,)
            regs = self.abi.environment_context(environment)
            chain = self.callback_reaches(method, args, regs, call.memory, main)
            if chain:
                return main, table.value, chain
        return None

    def add(self, main, wrapper, method, evidence, path, adapters=(), score=95):
        if main == wrapper or not self.b.is_callable(main):
            return
        chain = list(path)
        for addr in adapters:
            if not chain or chain[-1] != addr:
                chain.append(addr)
        if not chain or chain[-1] != main:
            chain.append(main)
        self.report.candidates.append(Candidate(main, wrapper, score, method, evidence, chain))

    def inspect_wrapper(self, function, path, native_mains):
        trace = self.trace(function)
        anchor = function in native_mains
        for call in trace.calls:
            found = self.closure(call)
            if found:
                main, table, adapters = found
                self.add(main, function, "lang_start_closure",
                         ["CRT-reachable call at 0x%x carries a closure containing 0x%x" % (call.ea, main),
                          "Fn vtable 0x%x has pointer-sized environment and three executable methods" % table,
                          "A vtable adapter invokes that captured pointer"],
                         path, adapters, 98 if anchor else 96)
                continue
            # Non-inlined lang_start takes the fn pointer directly, constructs
            # its closure in its own frame, and calls lang_start_internal.
            main = self.code(call.args[0]) if call.args else None
            if main is not None and self.b.is_callable(call.target):
                inner = self.t.run(call.target, call.args, call.memory, call.regs,
                                   max_instructions=192)
                for nested in inner.calls:
                    found = self.closure(nested)
                    if found and found[0] == main:
                        self.add(main, function, "lang_start_argument",
                                 ["C ABI wrapper passes 0x%x as argument 0 at 0x%x" % (main, call.ea),
                                  "The callee stores it in a pointer-sized Fn environment",
                                  "Validated vtable 0x%x dispatches the captured pointer" % found[1]],
                                 path, [call.target] + found[2], 99 if anchor else 97)
            # With LTO the std runtime can be inside C main. Prove the actual
            # fn pointer is invoked by a short adapter, rather than labelling
            # the runtime initializer itself as the user's function.
            if self.b.is_callable(call.target):
                values = call.args[:2] + self.abi.candidate_values(call)
                mains = set()
                for v in values:
                    direct = self.code(v)
                    # A static array of constructor callbacks is a CRT detail,
                    # not a Rust main environment. LTO closures here must be
                    # local stack environments (direct fn pointers also work).
                    captured = self.captured_code(v, call.memory) if v.kind == "stack" else None
                    if direct is not None: mains.add(direct)
                    if captured is not None: mains.add(captured)
                for main in mains:
                    if main == call.target or main in path or main in native_mains:
                        continue
                    chain = self.callback_reaches(call.target, call.args, call.regs,
                                                  call.memory, main)
                    if chain:
                        self.add(main, function, "runtime_callback",
                                 ["Startup function supplies callback 0x%x at 0x%x" % (main, call.ea),
                                  "Address propagation proves the adapter calls that pointer",
                                  "Rust runtime markers are present in the image"],
                                 path, chain, 94 if anchor else 90)

    def analyze(self, native_roots=None, evidence=None):
        self.report.rust_evidence = self.b.rust_markers() if evidence is None else list(evidence)
        if not self.report.rust_evidence:
            self.report.diagnostics.append("No Rust std runtime evidence found; custom/no_std entry points are not inferred.")
            return self.report
        if native_roots is None:
            paths, native_mains = self.startup()
        else:
            # A mixed-language binary may carry Rust source paths in a library.
            # Probe only proven C ABI main roots for a Rust entry wrapper.
            paths = {c.ea: c.chain for c in native_roots}
            native_mains = set(paths)
        # First inspect C mains recovered from ELF startup, then shallow CRT
        # call paths. Keep the root wrapper rather than its application callees.
        ordered = sorted(paths, key=lambda f: (f not in native_mains, len(paths[f]), f))
        proven_roots = set()
        for function in ordered:
            path = paths[function]
            if self.b.format == "ELF" and native_mains and function not in native_mains:
                continue
            if any(root in path[:-1] for root in proven_roots):
                continue
            before = len(self.report.candidates)
            self.inspect_wrapper(function, path, native_mains)
            if len(self.report.candidates) > before:
                proven_roots.add(function)
        self.report.scanned_functions = len(self.cache)
        # Multiple proofs for the same address are combined; different addresses
        # remain visible instead of silently selecting an arbitrary winner.
        unique = {}
        for candidate in sorted(self.report.candidates, key=lambda c: (-c.score, len(c.chain), c.ea)):
            if candidate.ea not in unique:
                unique[candidate.ea] = candidate
        self.report.candidates = list(unique.values())
        if not self.report.candidates:
            self.report.diagnostics.append("No verified Rust main survived the bounded startup/callback analysis.")
        elif len(self.report.candidates) > 1:
            self.report.diagnostics.append("Multiple candidates remain; inspect the evidence before renaming.")
        if any(trace.truncated for trace in self.cache.values()):
            self.report.diagnostics.append("Some traces reached a path/instruction bound; the analysis is conservative and incomplete.")
        return self.finish()
