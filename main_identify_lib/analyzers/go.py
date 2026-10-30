"""Recover Go main.main from runtime diagnostics and a verified funcval call.

No application symbols or pclntab function names are consumed. Diagnostic
strings identify the runtime caller; Hex-Rays resolves its actual call target.
A readonly function-value cell or a corroborated static relocation distinguishes
the linked main entry from cgo variables, callbacks, closures and morestack stubs.
"""
from ..model import Candidate, Report


ANCHORS = (
    b"runtime.main not on m0",
    b"nanotime returning zero",
    b"_cgo_thread_start missing",
    b"_cgo_pthread_key_created missing",
    b"_cgo_notify_runtime_init_done missing",
    b"set_crosscall2 missing",
)
PRIMARY_ANCHORS = frozenset(ANCHORS[:2])


class GoAnalyzer:
    def __init__(self, backend):
        self.b = backend
        self.ptr = backend.bits // 8
        self.t = backend.create_tracer(call_analysis=False)
        self.report = Report(language="go", analysis_backend=self.t.name)

    def analyze(self):
        if getattr(self.b, "is_library", lambda: False)():
            self.report.diagnostics.append("Go shared libraries do not execute a standard executable main chain.")
            return self.report
        references = self.b.literal_references(ANCHORS)
        roots = {}
        for literal, rows in references.items():
            for address, ref in rows:
                owner = getattr(self.b, "go_function_start", self.b.function_start)(ref)
                if owner is not None:
                    roots.setdefault(owner, {}).setdefault(literal, []).append((address, ref))
        eligible = [(root, hits) for root, hits in roots.items()
                    if len(hits) >= 2 and PRIMARY_ANCHORS.intersection(hits)]
        eligible.sort(key=lambda pair: (-len(pair[1]), pair[0]))
        if len(eligible) > 8:
            self.report.diagnostics.append("Go runtime diagnostic search reached its caller budget.")
        for runtime_main, hits in eligible[:8]:
            self.b.check_cancelled()
            graph = self.t.call_graph(runtime_main)
            self.report.scanned_functions += 1
            self.report.go_evidence.extend(literal.decode() for literal in hits)
            for call in graph.calls:
                target = call.target
                if (not call.indirect or target == runtime_main
                        or not self.b.is_callable(target)):
                    continue
                descriptors = [ea for ea in call.data_refs if self.b.is_readonly(ea, self.ptr)
                               and self.b.read_int(ea, self.ptr) == target]
                static = [ea for ea in call.data_refs
                          if ea == call.funcval_context
                          and getattr(self.b, "is_static_go_funcval", lambda ea,target: False)(ea,target)]
                if not descriptors and not static:
                    continue
                proof = ("Readonly function value at 0x%x contains that exact code pointer" % min(descriptors)
                         if descriptors else
                         "Relocated function value at 0x%x is passed as the Go closure context; its pointer has no recorded code writes" % min(static))
                self.report.candidates.append(Candidate(
                    target, runtime_main, 98 if descriptors else 96,
                    "go_runtime_main_funcval" if descriptors else "go_runtime_main_static_funcval",
                    ["%d distinct Go runtime diagnostics reference caller 0x%x" % (len(hits), runtime_main),
                     "Microcode resolves the original indirect call at 0x%x to 0x%x" % (call.ea, target),
                     proof],
                    [runtime_main, target], role="go_main"))
            if graph.truncated:
                self.report.diagnostics.append("Go runtime target slicing reached an analysis bound.")
        unique = {}
        for candidate in self.report.candidates:
            unique.setdefault(candidate.ea, candidate)
        self.report.candidates = list(unique.values())
        self.report.go_evidence = sorted(set(self.report.go_evidence))
        if not unique:
            self.report.diagnostics.append("No verified Go main survived diagnostic and function-value validation.")
        elif len(unique) > 1:
            self.report.diagnostics.append("Multiple Go main candidates remain; inspect their evidence.")
        self.report.diagnostics.extend(self.t.diagnostics)
        self.report.timings.update(self.t.metrics())
        return self.report
