"""Shared bounded CRT traversal and address propagation for language analyzers."""
from collections import deque
from ..model import Report


class StartupAnalyzer:
    def __init__(self, backend, max_startup_functions=240, max_startup_depth=4, call_analysis=False):
        self.b = backend
        self.t = backend.create_tracer(call_analysis=call_analysis)
        self.abi = self.t.abi
        self.ptr = backend.bits // 8
        self.max_startup_functions = max_startup_functions
        self.max_startup_depth = max_startup_depth
        self.cache = {}
        self.report = Report(analysis_backend=self.t.name)

    def finish(self):
        self.report.diagnostics.extend(self.t.diagnostics)
        self.report.timings.update(self.t.metrics())
        return self.report

    def trace(self, ea):
        if ea not in self.cache:
            self.b.check_cancelled()
            self.cache[ea] = self.t.run(ea)
        return self.cache[ea]

    def code(self, value):
        return value.value if value.kind == "const" and self.b.is_callable(value.value) else None

    def startup(self):
        start = self.b.entry
        if not self.b.is_callable(start):
            self.report.diagnostics.append("The image entry point is not a defined instruction head; finish IDA auto-analysis first.")
            return {}, set()
        queue = deque([(start, [start], 0)])
        paths = {}
        native_mains = set()
        while queue and len(paths) < self.max_startup_functions:
            function, path, depth = queue.popleft()
            if function in paths or (function != start and not self.b.is_callable(function)):
                continue
            paths[function] = path
            trace = self.trace(function)
            if depth >= self.max_startup_depth:
                continue
            for call in trace.calls:
                if self.b.is_callable(call.target) and call.target not in path:
                    queue.append((call.target, path + [call.target], depth + 1))
                # ELF libc startup receives C main as its first argument. This
                # also works when a static musl __libc_start_main is unnamed.
                if (self.b.format == "ELF" and depth <= 2 and call.args
                        and not any(root in path for root in native_mains)):
                    main = self.code(call.args[0])
                    if main is not None and main not in path:
                        native_mains.add(main)
                        queue.appendleft((main, path + [main], depth + 1))
        if queue:
            self.report.diagnostics.append("Startup traversal hit its function budget; some paths were not inspected.")
        return paths, native_mains

