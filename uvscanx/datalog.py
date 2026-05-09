from __future__ import annotations

import csv
import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from .schemas import normalize_api
from .arch import datalog_rows_for_binary
from .util import ensure_dir, project_root, safe_name, write_json


def _load_core():
    from . import binary_analysis
    return binary_analysis

def find_souffle() -> str | None:
    for cand in [
        os.getenv("SOUFFLE_BIN"),
        shutil.which("souffle"),
    ]:
        if cand and Path(cand).exists():
            return cand
    return None


def find_ddisasm() -> str | None:
    for cand in [
        os.getenv("DDISASM_BIN"),
        shutil.which("ddisasm"),
    ]:
        if cand and Path(cand).exists():
            return cand
    return None


def can_execute(path: str, args: Sequence[str] = ("--version",), timeout: int = 10) -> Tuple[bool, str]:
    try:
        cp = subprocess.run([path, *args], text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
        return cp.returncode == 0, (cp.stdout + cp.stderr).strip()
    except Exception as exc:
        return False, str(exc)


def _write_tsv(path: Path, rows: Iterable[Sequence[Any]]) -> None:
    ensure_dir(path.parent)
    with path.open("w", encoding="utf-8", newline="") as f:
        w = csv.writer(f, delimiter="\t", lineterminator="\n", quoting=csv.QUOTE_MINIMAL)
        for row in rows:
            safe = []
            for x in row:
                if x is None:
                    safe.append("")
                else:
                    safe.append(str(x).replace("\t", " ").replace("\n", " ").replace("\r", " "))
            w.writerow(safe)


def _likely_return_handle_api(api: str) -> bool:
    """Heuristic for lifecycle APIs whose owned object is returned in retval.

    Some lifecycle pairs are init/free pairs where ownership is passed through an
    argument (e.g. sqlite3_open's sqlite3** or mbedtls_*_init structs).  The
    first same-handle implementation intentionally focuses on return-owned
    handles, where objdump facts can conservatively follow the return register.
    Non-return lifecycle pairs still fall back to call-order/window checks.
    """
    a = api.lower()
    if a in {"sqlite3_open", "sqlite3_open_v2", "upnpinit", "upnpinit2"}:
        return False
    if a.startswith("mbedtls_") and (a.endswith("_init") or a.endswith("_setup")):
        return False
    if "register" in a and a.startswith("upnp"):
        return False
    return any(tok in a for tok in (
        "new", "alloc", "malloc", "calloc", "realloc", "strdup",
        "fopen", "popen", "dlopen", "xmlread", "xmlparse", "xmlget",
        "nodegetcontent", "curl_easy_init", "curl_slist_append",
    ))


def _canonical_reg(core, operand: str, preferred: Sequence[str] = ()) -> str | None:
    op = operand.lower().strip()
    search = list(preferred) + [r for r in core.REG_ALIASES.keys() if r not in preferred]
    for reg in search:
        if core.contains_reg(op, core.REG_ALIASES.get(reg, {reg})):
            return reg
    return None


def _mem_key(operand: str) -> str | None:
    op = operand.lower().replace(" ", "")
    if "[" in op and "]" in op:
        return op[op.find("["):op.rfind("]") + 1]
    # MIPS/older objdump style: offset(reg)
    if "(" in op and ")" in op:
        return op[op.find("("):op.rfind(")") + 1] + op[:op.find("(")]
    return None


def _immediate_expr(core, operand: str) -> str | None:
    val = core.parse_int(operand)
    if val is None:
        return None
    return f"imm:{val:x}"


def _pointer_expr(core, operand: str) -> str | None:
    import re
    # Intel objdump annotates RIP-relative addresses as:
    #   [rip+0xff9]        # 402000 <ctx>
    # Prefer the resolved target so two different RIP displacements to the same
    # object compare equal.
    m = re.search(r"#\s*([0-9a-fA-F]+)(?:\s+<([^>]+)>)?", operand)
    if m:
        sym = normalize_api(m.group(2)) if m.group(2) else None
        return f"sym:{sym}" if sym else f"abs:{m.group(1).lower()}"
    return _mem_key(operand) or _immediate_expr(core, operand)


def _sqlite_out_arg_index(api: str | None) -> int | None:
    a = (api or "").lower()
    if a in {"sqlite3_open", "sqlite3_open_v2"}:
        return 2
    return None


def _arg_owned_lifecycle_api(api: str | None) -> bool:
    """Return True for APIs that initialize/acquire ownership through an arg.

    Examples: mbedtls_x509_crt_init(ctx) -> mbedtls_x509_crt_free(ctx).
    These are not return-owned handles, but same-object lifecycle still matters.
    """
    a = (api or "").lower()
    if not a:
        return False
    if a.startswith("mbedtls_") and (a.endswith("_init") or a.endswith("_setup")):
        return True
    if a.startswith("upnpregister"):
        return True
    if a in {"pthread_mutex_init"}:
        return True
    return False


def _handle_flow_rows(core, bf, rules: Dict[str, Any]):
    """Derive conservative same-handle facts from register/stack dataflow.

    This is intentionally small but architecture-aware:

    * return-owned handles: ``h = curl_easy_init(); curl_easy_cleanup(h)``
    * pointer-out handles: ``sqlite3_open(..., &db); sqlite3_close(db)``
    * arg-owned objects: ``mbedtls_x509_crt_init(ctx); mbedtls_x509_crt_free(ctx)``

    It follows simple register copies, LEA pointer expressions, stack
    spills/loads, and memory loads from known out-pointer slots.  Anything more
    complex remains a normal call-order finding rather than a fabricated
    same-handle conclusion.
    """
    lifecycle = rules.get("resource_lifecycle", [])
    open_apis = {normalize_api(r.get("open_api")) for r in lifecycle if normalize_api(r.get("open_api"))}
    close_apis = {normalize_api(r.get("close_api")) for r in lifecycle if normalize_api(r.get("close_api"))}
    return_open_apis = {a for a in open_apis if _likely_return_handle_api(a)}
    tracked_non_return = {a for a in open_apis if _sqlite_out_arg_index(a) or _arg_owned_lifecycle_api(a)}
    if not (return_open_apis or tracked_non_return) or not bf.arch.arg_registers:
        return [], [], [], []

    ret_reg = None
    if bf.arch.return_registers:
        ret_reg = _canonical_reg(core, bf.arch.return_registers[0], bf.arch.return_registers) or bf.arch.return_registers[0]
    arg_regs = list(bf.arch.arg_registers)
    returns = []
    consumes = []
    aliases = set()
    escapes = set()

    state_by_func: Dict[str, Dict[str, str]] = {}
    stack_by_func: Dict[str, Dict[str, str]] = {}
    ptr_by_func: Dict[str, Dict[str, str]] = {}
    stack_ptr_by_func: Dict[str, Dict[str, str]] = {}
    call_mn = set(bf.arch.call_mnemonics)

    def reg_for_arg(arg_index: int) -> str | None:
        if arg_index < 1 or arg_index > len(arg_regs):
            return None
        return _canonical_reg(core, arg_regs[arg_index - 1], arg_regs) or arg_regs[arg_index - 1]

    def arg_expr(regs: Dict[str, str], ptrs: Dict[str, str], arg_index: int) -> str | None:
        reg = reg_for_arg(arg_index)
        if not reg:
            return None
        if reg in regs:
            return regs[reg]
        if reg in ptrs:
            return ptrs[reg]
        return None

    for ins in bf.instructions:
        func = ins.function
        regs = state_by_func.setdefault(func, {})
        stack = stack_by_func.setdefault(func, {})
        ptrs = ptr_by_func.setdefault(func, {})
        stack_ptrs = stack_ptr_by_func.setdefault(func, {})
        parts = core.split_operands(ins.operands.lower())

        if ins.mnemonic in call_mn:
            api = ins.norm_target
            # Before the call, see whether this API consumes an owned handle in
            # its first argument.  Most close/free APIs use arg1; if a future
            # rule schema carries close_arg_index, this is the only place that
            # needs to change.
            if api in close_apis and arg_regs:
                arg_reg = reg_for_arg(1) or arg_regs[0]
                handle = regs.get(arg_reg)
                if not handle and arg_reg in ptrs:
                    handle = f"obj:{ptrs[arg_reg]}"
                if handle:
                    consumes.append((ins.addr, api, 1, handle))

            # A non-open call may overwrite the return register.  Keep other
            # registers/stack facts; this is an over-approximation but useful for
            # stripped firmware where only PLT callsites remain.
            for rr in bf.arch.return_registers:
                cr = _canonical_reg(core, rr, bf.arch.return_registers)
                if cr:
                    regs.pop(cr, None)
                    ptrs.pop(cr, None)

            if api in return_open_apis and ret_reg:
                handle = f"h_{ins.addr:x}"
                returns.append((ins.addr, api, handle))
                regs[ret_reg] = handle
            elif api in tracked_non_return:
                out_idx = _sqlite_out_arg_index(api)
                if out_idx:
                    out_slot = arg_expr(regs, ptrs, out_idx)
                    if out_slot:
                        handle = f"out:{out_slot}"
                        returns.append((ins.addr, api, handle))
                        stack[out_slot] = handle
                elif _arg_owned_lifecycle_api(api):
                    obj = arg_expr(regs, ptrs, 1)
                    if obj:
                        handle = f"obj:{obj}"
                        returns.append((ins.addr, api, handle))
            continue

        if not parts:
            continue

        # Register-to-register or immediate-to-register moves.
        if ins.mnemonic in {"lea", "adr", "adrp"} and len(parts) >= 2:
            dst_reg = _canonical_reg(core, parts[0])
            src_expr = _pointer_expr(core, parts[1])
            if dst_reg and src_expr:
                regs.pop(dst_reg, None)
                ptrs[dst_reg] = src_expr
            continue

        if ins.mnemonic in {"mov", "movabs", "move", "or", "orr", "addi", "addiu", "li", "ldr", "ld", "lw", "str", "st", "sw"}:
            dst = parts[0]
            src = parts[1] if len(parts) > 1 else ""
            dst_reg = _canonical_reg(core, dst)
            src_reg = _canonical_reg(core, src)
            dst_mem = _pointer_expr(core, dst)
            src_mem = _pointer_expr(core, src)
            src_imm = _immediate_expr(core, src)

            if dst_reg and src_reg and src_reg in regs:
                regs[dst_reg] = regs[src_reg]
                ptrs.pop(dst_reg, None)
                aliases.add((regs[dst_reg], regs[src_reg]))
                continue
            if dst_reg and src_reg and src_reg in ptrs:
                ptrs[dst_reg] = ptrs[src_reg]
                regs.pop(dst_reg, None)
                continue
            if dst_reg and src_mem and src_mem in stack:
                regs[dst_reg] = stack[src_mem]
                ptrs.pop(dst_reg, None)
                continue
            if dst_reg and src_mem and src_mem in stack_ptrs:
                ptrs[dst_reg] = stack_ptrs[src_mem]
                regs.pop(dst_reg, None)
                continue
            if dst_mem and src_reg and src_reg in regs:
                stack[dst_mem] = regs[src_reg]
                continue
            if dst_mem and src_reg and src_reg in ptrs:
                stack_ptrs[dst_mem] = ptrs[src_reg]
                continue
            if dst_reg and src_imm:
                regs.pop(dst_reg, None)
                ptrs[dst_reg] = src_imm
                continue
            if dst_reg:
                regs.pop(dst_reg, None)
                ptrs.pop(dst_reg, None)
            continue

        # Common zeroing idiom: xor reg, reg kills an old handle value.
        if ins.mnemonic in {"xor", "eor"} and len(parts) >= 2:
            dst_reg = _canonical_reg(core, parts[0])
            src_reg = _canonical_reg(core, parts[1])
            if dst_reg and src_reg and dst_reg == src_reg:
                regs.pop(dst_reg, None)
                ptrs.pop(dst_reg, None)

    return returns, consumes, sorted(aliases), sorted(escapes)


def generate_facts(binary: Path, rules: Dict[str, Any], facts_dir: Path) -> Dict[str, Any]:
    """Generate a ddisasm-compatible fact subset plus UVScan rule facts.

    The relation names `instruction`, `direct_call`, `cfg_edge_to_symbol`, `function_symbol`,
    and `next` mirror ddisasm fact names. When the system ddisasm binary is unavailable on the
    host, these facts are populated from objdump so the same Soufflé rules can still run.
    """
    core = _load_core()
    bf = core.parse_disassembly(binary)
    ensure_dir(facts_dir)

    instructions = bf.instructions
    addr_to_index = {ins.addr: idx for idx, ins in enumerate(instructions)}
    calls = [(idx, ins) for idx, ins in enumerate(instructions) if ins.mnemonic in set(bf.arch.call_mnemonics)]

    _write_tsv(facts_dir / "instruction.facts", (
        (ins.addr, 0, "", ins.mnemonic.upper(), 0, 0, 0, 0, 0, 0) for ins in instructions
    ))
    _write_tsv(facts_dir / "function_symbol.facts", (
        (addr, name) for addr, name in sorted(bf.functions.items())
    ))
    _write_tsv(facts_dir / "cfg_edge_to_symbol.facts", (
        (ins.addr, ins.norm_target or "") for _, ins in calls if ins.norm_target
    ))
    _write_tsv(facts_dir / "direct_call.facts", (
        (ins.addr, ins.target_addr or 0) for _, ins in calls if ins.target_addr is not None
    ))
    _write_tsv(facts_dir / "next.facts", (
        (instructions[i].addr, instructions[i + 1].addr) for i in range(len(instructions) - 1)
        if instructions[i].function == instructions[i + 1].function
    ))

    # Architecture facts are emitted for every ELF.  They are not yet required by
    # the v1 rules, but provide the contract for multi-architecture call-site
    # extraction (MIPS/ARM/AArch64) without changing the checker interface.
    arch_rows = datalog_rows_for_binary(binary)
    for rel, rows_ in arch_rows.items():
        _write_tsv(facts_dir / f"{rel}.facts", rows_)

    call_rows = []
    api_call_rows = []
    by_func_ord: Dict[str, int] = {}
    for idx, ins in calls:
        by_func_ord[ins.function] = by_func_ord.get(ins.function, 0) + 1
        ordinal = by_func_ord[ins.function]
        text = ins.text.strip()
        call_rows.append((ins.addr, ins.function, ordinal, text))
        if ins.norm_target:
            api_call_rows.append((ins.addr, ins.function, ordinal, ins.norm_target, text))
    _write_tsv(facts_dir / "call_context.facts", call_rows)
    # Architecture-neutral normalized call-site relation.  The Soufflé program
    # also derives call_api from ddisasm-style facts; this input relation makes
    # the v2 schema explicit and lets future Capstone/Ghidra backends feed the
    # same Datalog rules directly.
    _write_tsv(facts_dir / "api_call.facts", api_call_rows)

    # Rule facts.
    _write_tsv(facts_dir / "rule_return_value.facts", (
        (normalize_api(r.get("api")) or "", r.get("constraint") or "", r.get("expected") or "", r.get("source") or "", r.get("llm_confidence", ""))
        for r in rules.get("return_value", [])
    ))
    _write_tsv(facts_dir / "rule_deprecated.facts", (
        (normalize_api(r.get("api")) or "", r.get("expected") or "", r.get("source") or "", r.get("llm_confidence", ""))
        for r in rules.get("deprecated", [])
    ))
    _write_tsv(facts_dir / "rule_argument.facts", (
        (normalize_api(r.get("api")) or "", int(r.get("arg_index", 0)), r.get("operator") or "", str(r.get("value", "")), r.get("expected") or "", r.get("source") or "", r.get("llm_confidence", ""))
        for r in rules.get("argument", [])
    ))
    causality_rows = []
    for r in rules.get("causality", []):
        causality_rows.append((normalize_api(r.get("api")) or "", normalize_api(r.get("must_call_after")) or "", normalize_api(r.get("before")) or "", int(r.get("window", 5)), r.get("expected") or "", r.get("source") or "", r.get("llm_confidence", "")))
    for r in rules.get("resource_lifecycle", []):
        causality_rows.append((normalize_api(r.get("open_api")) or "", normalize_api(r.get("close_api")) or "", "", int(r.get("window", 30)), r.get("expected") or "", r.get("source") or "", r.get("llm_confidence", "")))
    _write_tsv(facts_dir / "rule_causality.facts", causality_rows)
    _write_tsv(facts_dir / "rule_resource_lifecycle.facts", (
        (normalize_api(r.get("open_api")) or "", normalize_api(r.get("close_api")) or "", int(r.get("window", 30)), r.get("expected") or "", r.get("source") or "", r.get("llm_confidence", ""))
        for r in rules.get("resource_lifecycle", [])
    ))

    # Analysis facts derived from local ddisasm-compatible instruction facts.
    return_specs = {normalize_api(r.get("api")): r for r in rules.get("return_value", [])}
    return_rows = []
    arg_specs = {normalize_api(r.get("api")): r for r in rules.get("argument", [])}
    arg_rows = []
    arg_symbol_rows = []
    for idx, call in calls:
        target = call.norm_target
        if target in return_specs:
            check = core.find_return_check_after(instructions, idx)
            check_i = check[0] if check else None
            br_i = check[1] if check else None
            return_rows.append((call.addr, target, check_i.addr if check_i else 0, check_i.mnemonic if check_i else "", br_i.addr if br_i else 0, br_i.mnemonic if br_i else ""))
        if target in arg_specs:
            spec = arg_specs[target]
            arg_index = int(spec.get("arg_index", 0))
            window = int(spec.get("window", 8))
            value, setter = core.previous_arg_value(instructions, idx, arg_index, window, bf.arch.arg_registers)
            arg_rows.append((call.addr, target, arg_index, "__unknown__" if value is None else str(value), setter.addr if setter else 0))
            sym, sym_setter = core.previous_arg_symbol(instructions, idx, arg_index, window, bf.arch.arg_registers)
            if sym:
                arg_symbol_rows.append((call.addr, target, arg_index, sym, sym_setter.addr if sym_setter else 0))
    _write_tsv(facts_dir / "return_check.facts", return_rows)
    _write_tsv(facts_dir / "argument_value.facts", arg_rows)

    handle_return_rows, handle_consume_rows, handle_alias_rows, handle_escape_rows = _handle_flow_rows(core, bf, rules)

    # v2 dataflow/handle facts.  These are conservative return-register
    # same-handle facts; APIs whose lifecycle object is passed by pointer still
    # use call-order/window checking until richer memory facts are added.
    _write_tsv(facts_dir / "return_value.facts", (
        (ins.addr, ins.norm_target or "", "ret") for _, ins in calls if ins.norm_target
    ))
    _write_tsv(facts_dir / "argument_symbol.facts", arg_symbol_rows)
    _write_tsv(facts_dir / "api_returns_handle.facts", handle_return_rows)
    _write_tsv(facts_dir / "api_consumes_handle.facts", handle_consume_rows)
    _write_tsv(facts_dir / "handle_alias.facts", handle_alias_rows)
    _write_tsv(facts_dir / "handle_escape.facts", handle_escape_rows)
    _write_tsv(facts_dir / "string_literal.facts", [])

    meta = {
        "binary": str(binary),
        "facts_dir": str(facts_dir),
        "fact_format": "ddisasm-subset+uvscan",
        "num_instructions": len(instructions),
        "num_calls": len(calls),
        "arch": arch_rows.get("binary_arch", [["", "unknown"]])[0][1] if arch_rows.get("binary_arch") else "unknown",
        "bits": arch_rows.get("binary_arch", [["", "unknown", 0]])[0][2] if arch_rows.get("binary_arch") else 0,
        "endian": arch_rows.get("binary_arch", [["", "unknown", 0, "unknown"]])[0][3] if arch_rows.get("binary_arch") else "unknown",
        "ddisasm_binary": find_ddisasm(),
        "disassembler": getattr(bf, "disassembler", None),
        "note": "Generated ddisasm-compatible facts from objdump/cross-objdump when core ddisasm is unavailable.",
    }
    write_json(facts_dir / "facts_metadata.json", meta)
    return meta


DATALOG_PROGRAM = r'''
.type address <: unsigned

// ddisasm-compatible fact subset
.decl instruction(ea:address, size:unsigned, prefix:symbol, opcode:symbol, op1:unsigned, op2:unsigned, op3:unsigned, op4:unsigned, immOffset:unsigned, displacementOffset:unsigned)
.input instruction(delimiter="\t")
.decl direct_call(src:address, dest:address)
.input direct_call(delimiter="\t")
.decl cfg_edge_to_symbol(src:address, symbol:symbol)
.input cfg_edge_to_symbol(delimiter="\t")
.decl function_symbol(addr:address, name:symbol)
.input function_symbol(delimiter="\t")
.decl next(src:address, dest:address)
.input next(delimiter="\t")
.decl call_context(call:address, func:symbol, ordinal:unsigned, text:symbol)
.input call_context(delimiter="\t")
.decl api_call(call:address, func:symbol, ordinal:unsigned, api:symbol, text:symbol)
.input api_call(delimiter="\t")

// Architecture / calling-convention facts for multi-architecture extraction.
.decl binary_arch(binary:symbol, arch:symbol, bits:unsigned, endian:symbol, machine:symbol, branch_delay_slot:symbol)
.input binary_arch(delimiter="\t")
.decl calling_convention(arch:symbol, arg_index:unsigned, reg:symbol)
.input calling_convention(delimiter="\t")
.decl return_register(arch:symbol, reg:symbol)
.input return_register(delimiter="\t")
.decl call_mnemonic(arch:symbol, mnemonic:symbol)
.input call_mnemonic(delimiter="\t")
.decl branch_mnemonic(arch:symbol, mnemonic:symbol)
.input branch_mnemonic(delimiter="\t")

// LLM-extracted UVScan rule facts
.decl rule_return_value(api:symbol, constraint:symbol, expected:symbol, source:symbol, confidence:symbol)
.input rule_return_value(delimiter="\t")
.decl rule_deprecated(api:symbol, expected:symbol, source:symbol, confidence:symbol)
.input rule_deprecated(delimiter="\t")
.decl rule_argument(api:symbol, arg_index:unsigned, operator:symbol, expected_value:symbol, expected:symbol, source:symbol, confidence:symbol)
.input rule_argument(delimiter="\t")
.decl rule_causality(api:symbol, must:symbol, before:symbol, window:unsigned, expected:symbol, source:symbol, confidence:symbol)
.input rule_causality(delimiter="\t")
.decl rule_resource_lifecycle(open_api:symbol, close_api:symbol, window:unsigned, expected:symbol, source:symbol, confidence:symbol)
.input rule_resource_lifecycle(delimiter="\t")

// Analysis support facts over ddisasm facts
.decl return_check(call:address, api:symbol, check_addr:address, check_op:symbol, branch_addr:address, branch_op:symbol)
.input return_check(delimiter="\t")
.decl argument_value(call:address, api:symbol, arg_index:unsigned, observed_value:symbol, set_addr:address)
.input argument_value(delimiter="\t")

// v2 dataflow/handle/string fact skeletons.
.decl return_value(call:address, api:symbol, value:symbol)
.input return_value(delimiter="\t")
.decl argument_symbol(call:address, api:symbol, arg_index:unsigned, symbol:symbol)
.input argument_symbol(delimiter="\t")
.decl api_returns_handle(call:address, api:symbol, handle:symbol)
.input api_returns_handle(delimiter="\t")
.decl api_consumes_handle(call:address, api:symbol, arg_index:unsigned, handle:symbol)
.input api_consumes_handle(delimiter="\t")
.decl handle_alias(h1:symbol, h2:symbol)
.input handle_alias(delimiter="\t")
.decl handle_escape(handle:symbol, kind:symbol)
.input handle_escape(delimiter="\t")
.decl string_literal(addr:address, value:symbol)
.input string_literal(delimiter="\t")

.decl tls_verify_api(api:symbol)
tls_verify_api("SSL_CTX_set_verify").
tls_verify_api("wolfSSL_CTX_set_verify").
tls_verify_api("mbedtls_ssl_conf_authmode").

.decl call_api(call:address, func:symbol, ordinal:unsigned, api:symbol, text:symbol)
call_api(C,F,O,A,T) :- api_call(C,F,O,A,T).
call_api(C,F,O,A,T) :- call_context(C,F,O,T), cfg_edge_to_symbol(C,A).
call_api(C,F,O,A,T) :- call_context(C,F,O,T), direct_call(C,D), function_symbol(D,A).

.decl causality_ok(call:address, api:symbol, must:symbol)
causality_ok(C,A,M) :- rule_causality(A,M,"",W,_,_,_), call_api(C,F,O,A,_), call_api(_,F,O2,M,_), O2 > O, O2 <= O + W.
causality_ok(C,A,M) :- rule_causality(A,M,B,W,_,_,_), B != "", call_api(C,F,O,A,_), call_api(_,F,OB,B,_), OB > O, OB <= O + W, call_api(_,F,OM,M,_), OM > O, OM < OB.
causality_ok(C,A,M) :- rule_causality(A,M,B,W,_,_,_), B != "", call_api(C,F,O,A,_), !call_api(_,F,_,B,_), call_api(_,F,OM,M,_), OM > O, OM <= O + W.

.decl handle_equiv(h1:symbol, h2:symbol)
handle_equiv(H,H) :- api_returns_handle(_,_,H).
handle_equiv(H1,H2) :- handle_alias(H1,H2).
handle_equiv(H1,H2) :- handle_alias(H2,H1).

.decl lifecycle_same_handle_ok(call:address, open_api:symbol, close_api:symbol)
lifecycle_same_handle_ok(C,A,M) :-
  rule_resource_lifecycle(A,M,W,_,_,_),
  call_api(C,F,O,A,_),
  api_returns_handle(C,A,H1),
  api_consumes_handle(C2,M,_,H2),
  call_api(C2,F,O2,M,_),
  O2 > O,
  O2 <= O + W,
  handle_equiv(H1,H2).

.decl datalog_violation(kind:symbol, call:address, api:symbol, checker:symbol, reason:symbol, evidence:symbol, expected:symbol, source:symbol, confidence:symbol)
.output datalog_violation(delimiter="\t")

// Deprecated API checker.
datalog_violation("deprecated_api", C, A, "deprecated", "deprecated API appears at call site", T, E, S, Conf) :-
  rule_deprecated(A,E,S,Conf), call_api(C,_,_,A,T).

// Return-value checker.
datalog_violation("missing_return_value_check", C, A, "return_value", "no compare/test of the return register was found near the call", "", E, S, Conf) :-
  rule_return_value(A,_,E,S,Conf), call_api(C,_,_,A,_), return_check(C,A,0,"",0,"").

datalog_violation("incorrect_return_value_check", C, A, "return_value", "branch checks only < 0, but the API treats <= 0 as error", Br, E, S, Conf) :-
  rule_return_value(A,"error_le_zero",E,S,Conf), return_check(C,A,_,_,_,Br), (Br = "jl"; Br = "jnge"; Br = "js").

datalog_violation("incorrect_return_value_check", C, A, "return_value", "branch condition is inconsistent with the API's < 0 error contract", Br, E, S, Conf) :-
  rule_return_value(A,"error_lt_zero",E,S,Conf), return_check(C,A,_,_,_,Br), (Br = "jle"; Br = "jng"; Br = "je"; Br = "jz"; Br = "jne"; Br = "jnz").

datalog_violation("weak_return_value_check", C, A, "return_value", "return register is compared/tested, but no nearby conditional branch was found", Op, E, S, Conf) :-
  rule_return_value(A,"must_check",E,S,Conf), return_check(C,A,Check,Op,0,""), Check != 0.

// Argument checker.
datalog_violation("argument_violation", C, A, "argument", "observed argument value does not match rule", V, E, S, Conf) :-
  rule_argument(A,I,"==",ExpectedValue,E,S,Conf), argument_value(C,A,I,V,_), V != ExpectedValue.

datalog_violation("argument_violation", C, A, "argument", "observed forbidden argument value", V, E, S, Conf) :-
  rule_argument(A,I,"!=",ForbiddenValue,E,S,Conf), argument_value(C,A,I,V,_), V = ForbiddenValue, !tls_verify_api(A).

datalog_violation("tls_verification_disabled", C, A, "argument", "TLS peer verification is disabled by an argument value", V, E, S, Conf) :-
  tls_verify_api(A), rule_argument(A,I,"!=",ForbiddenValue,E,S,Conf), argument_value(C,A,I,V,_), V = ForbiddenValue.

// Causality / lifecycle checker.
datalog_violation("causality_violation", C, A, "causality", "missing required call after API", M, E, S, Conf) :-
  rule_causality(A,M,_,_,E,S,Conf), call_api(C,_,_,A,_), !causality_ok(C,A,M).

// Same-handle lifecycle checker for return-owned handles.  This complements the
// call-order causality rule: a later free/close of a different handle no longer
// suppresses a resource-lifecycle finding when return-register dataflow can
// identify the produced handle.
datalog_violation("resource_lifecycle_violation", C, A, "resource_lifecycle", "owned handle/object is not released by the matching close/free API in the same function/window", M, E, S, Conf) :-
  rule_resource_lifecycle(A,M,_,E,S,Conf), api_returns_handle(C,A,_), !lifecycle_same_handle_ok(C,A,M).
'''


def write_program(path: Path) -> None:
    ensure_dir(path.parent)
    path.write_text(DATALOG_PROGRAM.strip() + "\n", encoding="utf-8")


def run_souffle(facts_dir: Path, out_dir: Path, program_path: Path, souffle_bin: str | None = None) -> Tuple[bool, str]:
    souffle = souffle_bin or find_souffle()
    if not souffle:
        return False, "souffle binary not found"
    ok, version_or_error = can_execute(souffle)
    if not ok:
        return False, version_or_error
    ensure_dir(out_dir)
    cp = subprocess.run([souffle, "-F", str(facts_dir), "-D", str(out_dir), str(program_path)], text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=120)
    if cp.returncode != 0:
        return False, (cp.stdout + cp.stderr).strip()
    return True, (cp.stdout + cp.stderr).strip()


def parse_datalog_output(output_dir: Path, binary: Path, firmware_id: str | None, tpc: List[Dict[str, Any]] | None = None) -> List[Dict[str, Any]]:
    path = output_dir / "datalog_violation.csv"
    if not path.exists():
        # Some Soufflé builds use relation name without .csv depending on IO config.
        path = output_dir / "datalog_violation.facts"
    rows: List[Dict[str, Any]] = []
    if not path.exists():
        return rows
    with path.open("r", encoding="utf-8", newline="") as f:
        reader = csv.reader(f, delimiter="\t")
        for row in reader:
            if len(row) < 9:
                continue
            kind, call, api, checker, reason, evidence, expected, source, confidence = row[:9]
            rows.append({
                "status": "potential_usage_violation",
                "firmware_id": firmware_id,
                "binary": str(binary),
                "function": None,
                "call_addr": hex(int(call)) if call.isdigit() else call,
                "api": api,
                "checker": kind,
                "reason": reason,
                "expected": expected,
                "rule_source": source,
                "llm_rule_confidence": _float_or_none(confidence),
                "tpc_candidates": tpc or [],
                "binary_evidence": {"datalog_evidence": evidence, "engine": "souffle"},
                "review_recommendation": "Review the call site in a disassembler/source if available; UVScanX reports potential usage violations, not confirmed CVEs.",
            })
    return rows


def _float_or_none(v: str) -> float | None:
    try:
        return float(v)
    except Exception:
        return None


def evaluate_fallback(facts_dir: Path, binary: Path, firmware_id: str | None, tpc: List[Dict[str, Any]] | None = None) -> List[Dict[str, Any]]:
    """Python evaluator for the same Datalog relations, used only when Soufflé cannot run."""
    def rows(name: str) -> List[List[str]]:
        p = facts_dir / f"{name}.facts"
        if not p.exists():
            return []
        with p.open("r", encoding="utf-8", newline="") as f:
            return [r for r in csv.reader(f, delimiter="\t")]

    cfg = {r[0]: r[1] for r in rows("cfg_edge_to_symbol") if len(r) >= 2}
    call_ctx = [r for r in rows("call_context") if len(r) >= 4]
    call_api = [(c, f, int(o), cfg[c], text) for c, f, o, text in call_ctx if c in cfg]
    seen_call_api = {(c, a) for c, _f, _o, a, _text in call_api}
    for r in rows("api_call"):
        if len(r) >= 5:
            c, f, o, a, text = r[:5]
            if (c, a) not in seen_call_api:
                call_api.append((c, f, int(o or 0), a, text))
                seen_call_api.add((c, a))
    by_call = {c: (f, o, a, text) for c, f, o, a, text in call_api}
    out: List[Dict[str, Any]] = []

    def emit(kind: str, call: str, api: str, checker: str, reason: str, evidence: str, expected: str, source: str, conf: str):
        out.append({
            "status": "potential_usage_violation",
            "firmware_id": firmware_id,
            "binary": str(binary),
            "function": by_call.get(call, (None,))[0],
            "call_addr": hex(int(call)),
            "api": api,
            "checker": kind,
            "reason": reason,
            "expected": expected,
            "rule_source": source,
            "llm_rule_confidence": _float_or_none(conf),
            "tpc_candidates": tpc or [],
            "binary_evidence": {"datalog_evidence": evidence, "engine": "python-datalog-fallback", "facts_dir": str(facts_dir)},
            "review_recommendation": "Review the call site in a disassembler/source if available; UVScanX reports potential usage violations, not confirmed CVEs.",
        })

    # Deprecated
    for api, expected, source, conf in [r[:4] for r in rows("rule_deprecated") if len(r) >= 4]:
        for c, _f, _o, a, text in call_api:
            if a == api:
                emit("deprecated_api", c, api, "deprecated", "deprecated API appears at call site", text, expected, source, conf)

    rv_rules = {r[0]: r for r in rows("rule_return_value") if len(r) >= 5}
    for r in rows("return_check"):
        if len(r) < 6:
            continue
        call, api, check_addr, check_op, branch_addr, branch_op = r[:6]
        rr = rv_rules.get(api)
        if not rr:
            continue
        _, constraint, expected, source, conf = rr[:5]
        if check_addr == "0":
            emit("missing_return_value_check", call, api, "return_value", "no compare/test of the return register was found near the call", "", expected, source, conf)
        elif constraint == "error_le_zero" and branch_op in {"jl", "jnge", "js"}:
            emit("incorrect_return_value_check", call, api, "return_value", "branch checks only < 0, but the API treats <= 0 as error", branch_op, expected, source, conf)
        elif constraint == "error_lt_zero" and branch_op in {"jle", "jng", "je", "jz", "jne", "jnz"}:
            emit("incorrect_return_value_check", call, api, "return_value", "branch condition is inconsistent with the API's < 0 error contract", branch_op, expected, source, conf)
        elif constraint == "must_check" and branch_addr == "0" and check_addr != "0":
            emit("weak_return_value_check", call, api, "return_value", "return register is compared/tested, but no nearby conditional branch was found", check_op, expected, source, conf)

    arg_rules = {(r[0], r[1]): r for r in rows("rule_argument") if len(r) >= 7}
    for r in rows("argument_value"):
        if len(r) < 5:
            continue
        call, api, idx, observed, setaddr = r[:5]
        rr = arg_rules.get((api, idx))
        if rr and rr[2] == "==" and observed != rr[3]:
            emit("argument_violation", call, api, "argument", "observed argument value does not match rule", observed, rr[4], rr[5], rr[6])
        if rr and rr[2] == "!=" and observed == rr[3]:
            if api in {"SSL_CTX_set_verify", "wolfSSL_CTX_set_verify", "mbedtls_ssl_conf_authmode"}:
                emit("tls_verification_disabled", call, api, "argument", "TLS peer verification is disabled by an argument value", observed, rr[4], rr[5], rr[6])
            else:
                emit("argument_violation", call, api, "argument", "observed forbidden argument value", observed, rr[4], rr[5], rr[6])

    # Causality
    calls_by_func: Dict[str, List[Tuple[int, str, str]]] = {}
    for c, f, o, a, text in call_api:
        calls_by_func.setdefault(f, []).append((o, c, a))
    for rule in rows("rule_causality"):
        if len(rule) < 7:
            continue
        api, must, before, window_s, expected, source, conf = rule[:7]
        window = int(window_s or 0)
        for f, calls in calls_by_func.items():
            for pos, (ord0, c, a) in enumerate(calls):
                if a != api:
                    continue
                segment = [(o, cc, aa) for o, cc, aa in calls if o > ord0 and o <= ord0 + window]
                if before:
                    before_positions = [o for o, _, aa in segment if aa == before]
                    if before_positions:
                        bpos = min(before_positions)
                        segment = [(o, cc, aa) for o, cc, aa in segment if o < bpos]
                if not any(aa == must for _, _, aa in segment):
                    emit("causality_violation", c, api, "causality", "missing required call after API", must, expected, source, conf)

    # Same-handle lifecycle over return-owned handle facts.
    lifecycle_rules = {(r[0], r[1]): r for r in rows("rule_resource_lifecycle") if len(r) >= 6}
    returns = [(r[0], r[1], r[2]) for r in rows("api_returns_handle") if len(r) >= 3]
    consumes = [(r[0], r[1], r[2], r[3]) for r in rows("api_consumes_handle") if len(r) >= 4]
    aliases = {(r[0], r[1]) for r in rows("handle_alias") if len(r) >= 2}
    aliases |= {(b, a) for a, b in list(aliases)}

    def equiv(h1: str, h2: str) -> bool:
        return h1 == h2 or (h1, h2) in aliases

    for open_call, open_api, handle in returns:
        open_meta = by_call.get(open_call)
        if not open_meta:
            continue
        func, ord0, _api, _text = open_meta
        for (oa, close_api), rule in lifecycle_rules.items():
            if oa != open_api:
                continue
            _oa, _ca, window_s, expected, source, conf = rule[:6]
            window = int(window_s or 0)
            ok = False
            for close_call, c_api, _idx, c_handle in consumes:
                if c_api != close_api or not equiv(handle, c_handle):
                    continue
                c_meta = by_call.get(close_call)
                if not c_meta:
                    continue
                c_func, c_ord, _capi, _ctext = c_meta
                if c_func == func and c_ord > ord0 and c_ord <= ord0 + window:
                    ok = True
                    break
            if not ok:
                emit(
                    "resource_lifecycle_violation",
                    open_call,
                    open_api,
                    "resource_lifecycle",
                    "owned handle/object is not released by the matching close/free API in the same function/window",
                    close_api,
                    expected,
                    source,
                    conf,
                )
    return out


def datalog_scan_binary(binary: Path, rules: Dict[str, Any], work_dir: Path, firmware_id: str | None = None, tpc: List[Dict[str, Any]] | None = None, require_souffle: bool = False) -> Dict[str, Any]:
    facts_dir = ensure_dir(work_dir / safe_name(str(binary)) / "facts")
    output_dir = ensure_dir(work_dir / safe_name(str(binary)) / "souffle_out")
    program_path = work_dir / "uvscan_ddisasm_rules.dl"
    meta = generate_facts(binary, rules, facts_dir)
    write_program(program_path)
    ok, msg = run_souffle(facts_dir, output_dir, program_path)
    if ok:
        findings = parse_datalog_output(output_dir, binary, firmware_id, tpc)
        engine = "souffle"
    else:
        if require_souffle:
            raise RuntimeError(f"Soufflé failed/unavailable: {msg}")
        findings = evaluate_fallback(facts_dir, binary, firmware_id, tpc)
        engine = "python-datalog-fallback"
    result = {"binary": str(binary), "facts_dir": str(facts_dir), "datalog_program": str(program_path), "datalog_output_dir": str(output_dir), "engine": engine, "souffle_status": msg, "findings": findings, "facts_metadata": meta}
    write_json(work_dir / safe_name(str(binary)) / "datalog_report.json", result)
    return result
