"""Language dispatch: Go/Rust runtime proof precedes generic native CRT rules."""
from dataclasses import replace
from .analyzers.rust import RustAnalyzer
from .analyzers.cpp import CppAnalyzer
from .analyzers.go import GoAnalyzer


class MainAnalyzer:
    def __init__(self, backend, language="auto"):
        if language not in ("auto", "rust", "native", "go"):
            raise ValueError("language must be auto, rust, native, or go")
        self.b = backend
        self.language = language
        self.native_report = None

    def analyze(self):
        report = self.analyze_language()
        if report.language in ("go", "rust"):
            native = self.native(auxiliary=report.language == "go")
            report.c_mains = [replace(c, role="c_main") for c in native.candidates]
            report.c_main_diagnostics = list(native.diagnostics)
            report.timings.update({"c_main_" + key: value for key,value in native.timings.items()})
        return report

    def native(self, auxiliary=False):
        if self.native_report is None:
            analyzer = CppAnalyzer(self.b)
            if auxiliary:
                # Go often enters its runtime directly, without C CRT main.
                # Keep optional discovery bounded around the startup layers.
                analyzer.max_startup_functions = 16
                analyzer.max_startup_depth = 2
            self.native_report = analyzer.analyze()
        return self.native_report

    def analyze_language(self):
        if self.language == "go":
            return GoAnalyzer(self.b).analyze()
        if self.language == "rust":
            return RustAnalyzer(self.b).analyze()
        if self.language == "native":
            return self.native()
        go = getattr(self.b, "go_markers", lambda: [])()
        if go:
            return GoAnalyzer(self.b).analyze()
        markers = self.b.rust_markers()
        if markers and not RustAnalyzer.has_runtime_evidence(markers):
            native = self.native()
            if native.candidates:
                rust = RustAnalyzer(self.b).analyze(native_roots=native.candidates, evidence=markers)
                if rust.candidates:
                    return rust
                native.rust_evidence = list(markers)
                native.timings.update({"rust_probe_" + key: value for key, value in rust.timings.items()})
                native.diagnostics.extend("Rust wrapper probe: " + message for message in rust.diagnostics
                                          if not message.startswith("No verified Rust main"))
                native.diagnostics.append(
                    "Rust source paths are present, but no Rust entry wrapper was verified at the recovered C ABI main; reporting the native CRT main.")
                return native
        rust = RustAnalyzer(self.b).analyze(evidence=markers)
        if rust.rust_evidence:
            if not rust.candidates:
                rust.diagnostics.append("Rust evidence present: native CRT main is not substituted for Rust user main.")
            return rust
        return self.native()
