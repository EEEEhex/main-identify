"""IDA 9.x plugin entry: recover Rust, Go and C/C++ application main."""
from pathlib import Path
import json
import sys
import traceback
import time

# Support IDA's directory loader and File > Script file on all three hosts.
_HERE = str(Path(__file__).resolve().parent)
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

import ida_auto
import ida_bytes
import ida_funcs
import ida_idaapi
import ida_kernwin
import ida_name

from main_identify_lib.analyzer import MainAnalyzer
from main_identify_lib.backends.ida import Cancelled, IDABackend


def scan(use_names=False, interactive=False, language="auto", wait_for_analysis=False):
    """Read-only API. Return a Report with candidates, proof chains, diagnostics."""
    if wait_for_analysis:
        ida_auto.auto_wait()
    begin = time.monotonic()
    report = MainAnalyzer(IDABackend(use_names=use_names, interactive=interactive), language).analyze()
    report.timings["scan_seconds"] = round(time.monotonic() - begin, 4)
    if not ida_auto.auto_is_ok():
        report.diagnostics.append("IDA auto-analysis is still running; this scan used the currently available code and may be incomplete.")
    return report


def apply_candidate(candidate, name=None):
    """Explicit opt-in mutation; preserve existing user names and comments."""
    name = name or {"rust_main": "rust_main", "go_main": "go_main",
                    "native_main": "native_main", "c_main": "c_main"}[candidate.role]
    flags = ida_bytes.get_full_flags(candidate.ea)
    old = ida_name.get_name(candidate.ea)
    if ida_bytes.has_user_name(flags) and old != name:
        raise ValueError("Existing user name %r is preserved; rename it manually if needed." % old)
    collision = ida_name.get_name_ea(ida_idaapi.BADADDR, name)
    if collision not in (ida_idaapi.BADADDR, candidate.ea):
        name = "%s_%X" % (name, candidate.ea)
    if not ida_name.set_name(candidate.ea, name, ida_name.SN_CHECK):
        raise ValueError("IDA rejected the name %r" % name)
    function = ida_funcs.get_func(candidate.ea)
    if function:
        old_comment = ida_funcs.get_func_cmt(function, True) or ""
        text = "[Main Identify] %s; method=%s, score=%d/100; wrapper=0x%X" % (
            candidate.role, candidate.method, candidate.score, candidate.wrapper)
        if text not in old_comment:
            ida_funcs.set_func_cmt(function, (old_comment + "\n" + text).strip(), True)
    return name


class Results(ida_kernwin.Choose):
    def __init__(self, report):
        self.report = report
        self.entries = report.entries
        super().__init__("Main Identify", [
            ["Address", 18], ["Kind", 18], ["Score", 7], ["Startup caller", 18],
            ["Method", 30], ["Current name", 24], ["Startup chain", 64]],
            flags=ida_kernwin.Choose.CH_CAN_EDIT)

    def OnGetSize(self):
        return len(self.entries)

    def OnGetLine(self, index):
        c = self.entries[index]
        kind = {"rust_main": "Rust main", "go_main": "Go main.main",
                "native_main": "C/C++ main", "c_main": "C ABI main"}[c.role]
        return ["%X" % c.ea, kind, str(c.score), "%X" % c.wrapper, c.method,
                ida_name.get_name(c.ea) or "", " -> ".join("%X" % ea for ea in c.chain)]

    def OnSelectLine(self, index):
        ida_kernwin.jumpto(self.entries[index].ea)
        return (ida_kernwin.Choose.NOTHING_CHANGED,)

    def OnEditLine(self, index):
        try:
            name = apply_candidate(self.entries[index])
            ida_kernwin.msg("[Main Identify] Applied name %s and proof comment.\n" % name)
            return (ida_kernwin.Choose.ALL_CHANGED, index)
        except ValueError as error:
            ida_kernwin.warning(str(error))
            return (ida_kernwin.Choose.NOTHING_CHANGED,)


class MainIdentifyMod(ida_idaapi.plugmod_t):
    def __init__(self):
        super().__init__()
        self.window = None

    def run(self, arg):
        ida_kernwin.show_wait_box("Main Identify: tracing application startup (Esc cancels)...")
        try:
            report = scan(interactive=True)
            ida_kernwin.msg("[Main Identify]\n%s\n" % json.dumps(report.to_dict(), indent=2, ensure_ascii=False))
        except Cancelled:
            ida_kernwin.msg("[Main Identify] Cancelled.\n")
            return
        except Exception as error:
            ida_kernwin.msg(traceback.format_exc())
            ida_kernwin.warning("Main Identify: %s" % error)
            return
        finally:
            ida_kernwin.hide_wait_box()
        if self.window is not None:
            self.window.Close()
            self.window = None
        if report.entries:
            self.window = Results(report)
            self.window.Show(False)
        else:
            ida_kernwin.warning("Main Identify: no verified application main. See the Output window for diagnostics.")


class MainIdentifyPlugin(ida_idaapi.plugin_t):
    flags = ida_idaapi.PLUGIN_MULTI
    comment = "Locate Rust, Go and C/C++ main in stripped x86/x64 PE/ELF executables"
    help = "Ctrl-Shift-M: scan; Enter: jump; Edit: apply the selected main name."
    wanted_name = "Main Identify"
    wanted_hotkey = "Ctrl-Shift-M"

    def init(self):
        return MainIdentifyMod()


def PLUGIN_ENTRY():
    return MainIdentifyPlugin()


if __name__ == "__main__":
    _SCRIPT_MOD = MainIdentifyMod()
    _SCRIPT_MOD.run(0)
