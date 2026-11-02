"""Run Main Identify inside IDAPython, without loading its plugin/UI module.

idat -A -S"/path/to/script.py --output /tmp/main.json --exit" /path/to/input
MCP: ns = runpy.run_path('/path/to/script.py'); result = ns['run']()
"""
import argparse
import json
from pathlib import Path
import sys

_HERE = str(Path(__file__).resolve().parent)
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)


def write_result(result, output):
    if output is not None:
        path = Path(output).expanduser()
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def run(output=None, language="auto", wait_for_analysis=False):
    """Return a JSON-ready report; optionally save it. Never exit the IDA host."""
    from main_identify_lib.api import scan

    result = scan(language=language, wait_for_analysis=wait_for_analysis).to_dict()
    write_result(result, output)
    return result


def main(argv=None):
    """CLI entry; idc.ARGV contains arguments supplied after IDA's -S script."""
    if argv is None:
        import idc
        argv = idc.ARGV[1:]
    argv = list(argv)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", help="Save the JSON report to this file.")
    parser.add_argument("--language", choices=("auto", "rust", "go", "native"), default="auto")
    parser.add_argument("--no-wait", action="store_true", help="Use current analysis instead of waiting for auto-analysis.")
    parser.add_argument("--exit", action="store_true", help="Exit IDA when done; omit for an MCP server or GUI.")
    try:
        args = parser.parse_args(argv)
    except SystemExit as error:
        status = int(error.code or 0)
        if "--exit" in argv:
            import ida_pro
            ida_pro.qexit(status)
        return status
    try:
        result = run(args.output, args.language, wait_for_analysis=not args.no_wait)
        status = 0 if len(result["candidates"]) == 1 else 1
    except Exception as error:
        result = {"error": str(error), "error_type": type(error).__name__}
        status = 2
        try:
            write_result(result, args.output)
        except OSError as output_error:
            result["output_error"] = str(output_error)
    print(json.dumps(result, ensure_ascii=False, indent=2), flush=True)
    if args.exit:
        import ida_pro
        ida_pro.qexit(status)
    return status


if __name__ == "__main__":
    main()
