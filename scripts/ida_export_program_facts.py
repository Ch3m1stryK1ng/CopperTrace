#!/usr/bin/env python3
"""Export decompiler-neutral ProgramFacts from IDA/Hex-Rays.

This script is intended to run inside IDA with:

    idat -A -S"ida_export_program_facts.py --out facts.json --functions f1,f2" firmware.elf

It deliberately exports facts, not final CopperTrace chains. Mini miners should
consume these facts and derive sink summaries, callsite bindings, carrier usage,
producer traces, and transform closure.
"""

from __future__ import annotations

import json
import os
import re
import sys
import time
import traceback
from typing import Any, Dict, List, Optional, Sequence, Tuple

import ida_auto  # type: ignore
import ida_bytes  # type: ignore
import ida_funcs  # type: ignore
import ida_hexrays  # type: ignore
import ida_ida  # type: ignore
import ida_idaapi  # type: ignore
import ida_lines  # type: ignore
import ida_name  # type: ignore
import ida_nalt  # type: ignore
import ida_pro  # type: ignore
import ida_segment  # type: ignore
import ida_ua  # type: ignore
import ida_xref  # type: ignore
import idautils  # type: ignore
import idc  # type: ignore


SCHEMA_VERSION = "0.1-ida-program-facts"
DEFAULT_TARGETS = (
    "bt_spi_rx_thread",
    "bt_spi_transceive",
    "net_buf_simple_add_mem",
    "net_buf_add_mem",
    "bt_buf_get_rx",
    "memcpy",
)
_HEX_RE = re.compile(r"^0x[0-9a-fA-F]+$")


def _clean(text: Any) -> str:
    try:
        return ida_lines.tag_remove(str(text or "")).strip()
    except Exception:
        return str(text or "").strip()


def _hex(ea: Any) -> str:
    try:
        value = int(ea)
    except Exception:
        return ""
    if value < 0 or value == int(getattr(ida_idaapi, "BADADDR", -1)):
        return ""
    return "0x%x" % value


def _safe_call(fn, default=None):
    try:
        return fn()
    except Exception:
        return default


def _script_args() -> List[str]:
    """Return arguments passed after the script name.

    IDA exposes script arguments differently across versions. In practice,
    idc.ARGV is the most stable source for -S"script.py arg..." invocations.
    """

    argv = []
    try:
        argv = list(getattr(idc, "ARGV", []) or [])
    except Exception:
        argv = []
    if not argv:
        argv = list(sys.argv or [])
    if argv and str(argv[0]).endswith(".py"):
        return [str(v) for v in argv[1:]]
    return [str(v) for v in argv]


def _parse_args(argv: Sequence[str]) -> Dict[str, Any]:
    opts: Dict[str, Any] = {
        "out": "/tmp/coppertrace_mini_ida_program_facts.json",
        "functions": list(DEFAULT_TARGETS),
        "max_functions": 0,
        "include_xref_callers": False,
        "include_all": False,
    }
    i = 0
    while i < len(argv):
        arg = str(argv[i])
        if arg == "--out" and i + 1 < len(argv):
            opts["out"] = argv[i + 1]
            i += 2
            continue
        if arg.startswith("--out="):
            opts["out"] = arg.split("=", 1)[1]
            i += 1
            continue
        if arg == "--functions" and i + 1 < len(argv):
            opts["functions"] = _split_csv(argv[i + 1])
            i += 2
            continue
        if arg.startswith("--functions="):
            opts["functions"] = _split_csv(arg.split("=", 1)[1])
            i += 1
            continue
        if arg == "--max-functions" and i + 1 < len(argv):
            opts["max_functions"] = int(argv[i + 1])
            i += 2
            continue
        if arg.startswith("--max-functions="):
            opts["max_functions"] = int(arg.split("=", 1)[1])
            i += 1
            continue
        if arg == "--include-xref-callers":
            opts["include_xref_callers"] = True
            i += 1
            continue
        if arg == "--all":
            opts["include_all"] = True
            i += 1
            continue
        i += 1
    return opts


def _split_csv(value: str) -> List[str]:
    return [part.strip() for part in str(value or "").split(",") if part.strip()]


def _function_name(ea: int) -> str:
    raw = ida_name.get_name(ea) or ida_funcs.get_func_name(ea) or ""
    return _clean(raw) or ("FUN_%08x" % int(ea))


def _segment_name(ea: int) -> str:
    seg = ida_segment.getseg(ea)
    if seg is None:
        return ""
    return _clean(ida_segment.get_segm_name(seg))


def _symbol_record(ea: int) -> Dict[str, Any]:
    func = ida_funcs.get_func(ea)
    start = int(func.start_ea) if func is not None else int(ea)
    end = int(func.end_ea) if func is not None else int(ea)
    raw_name = ida_name.get_name(start) or ida_funcs.get_func_name(start) or ""
    demangled = _safe_call(lambda: ida_name.demangle_name(raw_name, ida_name.MNG_SHORT_FORM), "") or ""
    return {
        "name": _function_name(start),
        "original_name": _clean(raw_name),
        "demangled_name": _clean(demangled),
        "address": _hex(start),
        "end_address": _hex(end),
        "size": max(0, end - start),
        "segment": _segment_name(start),
        "flags": int(idc.get_func_attr(start, idc.FUNCATTR_FLAGS) or 0),
    }


def _all_function_starts() -> List[int]:
    return [int(ea) for ea in idautils.Functions()]


def _find_function_start(query: str) -> Optional[int]:
    text = str(query or "").strip()
    if not text:
        return None
    if _HEX_RE.match(text):
        ea = int(text, 16)
        func = ida_funcs.get_func(ea)
        return int(func.start_ea) if func is not None else ea

    exact: List[int] = []
    fuzzy: List[int] = []
    lowered = text.lower()
    for ea in _all_function_starts():
        name = _function_name(ea)
        raw = ida_name.get_name(ea) or ida_funcs.get_func_name(ea) or ""
        names = {name, _clean(raw)}
        if text in names:
            exact.append(ea)
        elif lowered in name.lower() or lowered in _clean(raw).lower():
            fuzzy.append(ea)
    if exact:
        return sorted(exact)[0]
    if fuzzy:
        return sorted(fuzzy)[0]
    return None


def _incoming_xrefs(start_ea: int, limit: int = 64) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    seen = set()
    for xref in idautils.XrefsTo(start_ea):
        from_ea = int(getattr(xref, "frm", 0) or 0)
        to_ea = int(getattr(xref, "to", start_ea) or start_ea)
        try:
            ref_type = ida_xref.get_xref_type_name(int(getattr(xref, "type", 0) or 0)) or ""
        except Exception:
            ref_type = ""
        func = ida_funcs.get_func(from_ea)
        caller = ""
        caller_start = ""
        if func is not None:
            caller = _function_name(int(func.start_ea))
            caller_start = _hex(int(func.start_ea))
        key = (from_ea, to_ea, ref_type)
        if key in seen:
            continue
        seen.add(key)
        out.append({
            "from": _hex(from_ea),
            "to": _hex(to_ea),
            "type": _clean(ref_type) or "XREF",
            "caller": caller,
            "caller_address": caller_start,
        })
        if len(out) >= limit:
            break
    return out


def _pseudocode_lines(cfunc: Any) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    try:
        sv = cfunc.get_pseudocode()
        for idx, line in enumerate(sv):
            out.append({"line": idx + 1, "text": _clean(line.line)})
    except Exception:
        for idx, line in enumerate(str(cfunc).splitlines()):
            out.append({"line": idx + 1, "text": _clean(line)})
    return out


def _local_vars(cfunc: Any) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    try:
        lvars = cfunc.get_lvars()
    except Exception:
        return out
    for var in lvars:
        name = _clean(getattr(var, "name", ""))
        if not name:
            continue
        out.append({
            "name": name,
            "type": _clean(_safe_call(lambda v=var: v.tif.dstr(), "")),
            "width": int(getattr(var, "width", 0) or 0),
            "is_arg": bool(_safe_call(lambda v=var: v.is_arg_var, False)),
        })
    return out


class _CtreeCollector(ida_hexrays.ctree_visitor_t):
    def __init__(self) -> None:
        ida_hexrays.ctree_visitor_t.__init__(self, ida_hexrays.CV_FAST)
        self.calls: List[Dict[str, Any]] = []
        self.assignments: List[Dict[str, Any]] = []
        self.exprs: List[Dict[str, Any]] = []

    def visit_expr(self, expr):  # type: ignore[override]
        try:
            op = int(expr.op)
        except Exception:
            return 0

        op_name = _hexrays_op_name(op)
        rendered = _clean(_safe_call(lambda: expr.dstr(), ""))
        ea = int(getattr(expr, "ea", ida_idaapi.BADADDR))

        if op == ida_hexrays.cot_call:
            callee = _clean(_safe_call(lambda: expr.x.dstr(), ""))
            args: List[str] = []
            try:
                for i in range(expr.a.size()):
                    args.append(_clean(expr.a.at(i).dstr()))
            except Exception:
                args = []
            self.calls.append({
                "ea": _hex(ea),
                "callee_expr": callee,
                "args": args,
                "text": rendered,
            })
        elif op in _assignment_ops():
            lhs = _clean(_safe_call(lambda: expr.x.dstr(), ""))
            rhs = _clean(_safe_call(lambda: expr.y.dstr(), ""))
            self.assignments.append({
                "ea": _hex(ea),
                "op": op_name,
                "lhs": lhs,
                "rhs": rhs,
                "text": rendered,
            })

        if len(self.exprs) < 4096:
            self.exprs.append({"ea": _hex(ea), "op": op_name, "text": rendered})
        return 0


def _assignment_ops() -> set:
    names = [
        "cot_asg",
        "cot_asgbor",
        "cot_asgxor",
        "cot_asgband",
        "cot_asgadd",
        "cot_asgsub",
        "cot_asgmul",
        "cot_asgsshr",
        "cot_asgushr",
        "cot_asgshl",
        "cot_asgsdiv",
        "cot_asgudiv",
        "cot_asgsmod",
        "cot_asgumod",
    ]
    return {int(getattr(ida_hexrays, name)) for name in names if hasattr(ida_hexrays, name)}


_OP_NAME_BY_VALUE: Optional[Dict[int, str]] = None


def _hexrays_op_name(value: int) -> str:
    global _OP_NAME_BY_VALUE
    if _OP_NAME_BY_VALUE is None:
        mapping: Dict[int, str] = {}
        for name in dir(ida_hexrays):
            if not name.startswith("cot_"):
                continue
            try:
                mapping[int(getattr(ida_hexrays, name))] = name
            except Exception:
                continue
        _OP_NAME_BY_VALUE = mapping
    return _OP_NAME_BY_VALUE.get(int(value), str(value))


def _disasm_calls(start_ea: int, end_ea: int, limit: int = 256) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for head in idautils.Heads(start_ea, end_ea):
        if not ida_bytes.is_code(ida_bytes.get_full_flags(head)):
            continue
        refs = list(idautils.CodeRefsFrom(head, 0))
        if not refs:
            continue
        mnem = _clean(ida_ua.ua_mnem(head))
        for target in refs:
            target_func = ida_funcs.get_func(int(target))
            out.append({
                "ea": _hex(head),
                "mnemonic": mnem,
                "target": _hex(int(target)),
                "target_function": _function_name(int(target_func.start_ea)) if target_func else "",
            })
            if len(out) >= limit:
                return out
    return out


def _decompile(start_ea: int) -> Tuple[Optional[Any], str]:
    try:
        if not ida_hexrays.init_hexrays_plugin():
            return None, "Hex-Rays decompiler is unavailable"
        cfunc = ida_hexrays.decompile(start_ea)
        if cfunc is None:
            return None, "decompile returned None"
        return cfunc, ""
    except Exception as exc:
        return None, str(exc)


def _export_function(start_ea: int) -> Dict[str, Any]:
    func = ida_funcs.get_func(start_ea)
    end_ea = int(func.end_ea) if func is not None else start_ea
    rec = _symbol_record(start_ea)
    rec["incoming_xrefs"] = _incoming_xrefs(start_ea)
    rec["disasm_calls"] = _disasm_calls(start_ea, end_ea)
    cfunc, err = _decompile(start_ea)
    if cfunc is None:
        rec["decompile_error"] = err
        rec["pseudocode"] = []
        rec["ctree_calls"] = []
        rec["ctree_assignments"] = []
        rec["local_vars"] = []
        return rec

    rec["decompiled_text"] = str(cfunc)
    rec["pseudocode"] = _pseudocode_lines(cfunc)
    rec["local_vars"] = _local_vars(cfunc)

    collector = _CtreeCollector()
    try:
        collector.apply_to(cfunc.body, None)
    except Exception as exc:
        rec["ctree_error"] = str(exc)
    rec["ctree_calls"] = collector.calls
    rec["ctree_assignments"] = collector.assignments
    rec["ctree_exprs_sample"] = collector.exprs[:256]
    return rec


def _target_function_starts(opts: Dict[str, Any]) -> Tuple[List[int], List[str]]:
    starts: List[int] = []
    missing: List[str] = []
    if bool(opts.get("include_all")):
        starts = _all_function_starts()
    else:
        for query in list(opts.get("functions") or []):
            start = _find_function_start(str(query))
            if start is None:
                missing.append(str(query))
                continue
            if start not in starts:
                starts.append(start)

    if bool(opts.get("include_xref_callers")):
        for start in list(starts):
            for row in _incoming_xrefs(start, limit=128):
                caller_addr = row.get("caller_address") or ""
                if caller_addr:
                    caller = _find_function_start(str(caller_addr))
                    if caller is not None and caller not in starts:
                        starts.append(caller)

    max_functions = int(opts.get("max_functions") or 0)
    if max_functions > 0:
        starts = starts[:max_functions]
    return starts, missing


def _metadata(argv: Sequence[str], opts: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "created_at_unix": time.time(),
        "argv": list(argv),
        "options": dict(opts),
        "input_file_path": _clean(_safe_call(lambda: ida_nalt.get_input_file_path(), "")),
        "root_filename": _clean(_safe_call(lambda: ida_nalt.get_root_filename(), "")),
        "imagebase": _hex(_safe_call(lambda: ida_ida.inf_get_min_ea(), 0)),
        "max_ea": _hex(_safe_call(lambda: ida_ida.inf_get_max_ea(), 0)),
        "processor": _clean(_safe_call(lambda: ida_ida.inf_get_procname(), "")),
        "ida_version": _clean(_safe_call(lambda: ida_pro.IDA_SDK_VERSION, "")),
    }


def _write_json(path: str, payload: Dict[str, Any]) -> None:
    out = os.path.abspath(os.path.expanduser(path))
    parent = os.path.dirname(out)
    if parent:
        os.makedirs(parent, exist_ok=True)
    with open(out, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, sort_keys=True)
        handle.write("\n")


def main() -> int:
    argv = _script_args()
    opts = _parse_args(argv)
    ida_auto.auto_wait()

    starts, missing = _target_function_starts(opts)
    payload: Dict[str, Any] = {
        "metadata": _metadata(argv, opts),
        "missing_targets": missing,
        "function_count": len(starts),
        "functions": [],
    }
    for start in starts:
        payload["functions"].append(_export_function(start))

    _write_json(str(opts["out"]), payload)
    print("[coppertrace-mini] wrote IDA ProgramFacts to %s" % opts["out"])
    return 0


if __name__ == "__main__":
    code = 1
    try:
        code = main()
    except Exception:
        out = "/tmp/coppertrace_mini_ida_program_facts.error.json"
        try:
            argv = _script_args()
            opts = _parse_args(argv)
            out = str(opts.get("out") or out) + ".error.json"
            _write_json(out, {
                "schema_version": SCHEMA_VERSION,
                "error": traceback.format_exc(),
                "argv": argv,
            })
        except Exception:
            pass
        print(traceback.format_exc())
        code = 1
    finally:
        ida_pro.qexit(code)
