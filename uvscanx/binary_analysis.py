#!/usr/bin/env python3
"""
UVScan binary-analysis helpers for ELF fact extraction.

This module provides local ELF parsing, fact extraction, and compact checkers used by the Datalog backend and optional Python engine.
"""
from __future__ import annotations

import argparse
import csv
import dataclasses
import json
import os
import re
import subprocess
import sys
import shutil
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from .arch import ArchSpec, ARCH_DEFAULTS, spec_for_binary


X86_64_ARG_REGS = ["rdi", "rsi", "rdx", "rcx", "r8", "r9"]
REG_ALIASES = {
    # x86/x86_64
    "rax": {"rax", "eax", "ax", "al"},
    "eax": {"eax", "ax", "al"},
    "rdi": {"rdi", "edi", "di", "dil"},
    "rsi": {"rsi", "esi", "si", "sil"},
    "rdx": {"rdx", "edx", "dx", "dl"},
    "rcx": {"rcx", "ecx", "cx", "cl"},
    "r8": {"r8", "r8d", "r8w", "r8b"},
    "r9": {"r9", "r9d", "r9w", "r9b"},
    "rbx": {"rbx", "ebx", "bx", "bl"},
    "rbp": {"rbp", "ebp", "bp", "bpl"},
    "rsp": {"rsp", "esp", "sp", "spl"},
    "r10": {"r10", "r10d", "r10w", "r10b"},
    "r11": {"r11", "r11d", "r11w", "r11b"},
    "r12": {"r12", "r12d", "r12w", "r12b"},
    "r13": {"r13", "r13d", "r13w", "r13b"},
    "r14": {"r14", "r14d", "r14w", "r14b"},
    "r15": {"r15", "r15d", "r15w", "r15b"},
    # MIPS o32/n32/n64 common ABI names as printed by objdump variants.
    "a0": {"a0", "$a0", "4"}, "a1": {"a1", "$a1", "5"}, "a2": {"a2", "$a2", "6"}, "a3": {"a3", "$a3", "7"},
    "a4": {"a4", "$a4", "8"}, "a5": {"a5", "$a5", "9"}, "a6": {"a6", "$a6", "10"}, "a7": {"a7", "$a7", "11"},
    "v0": {"v0", "$v0", "2"}, "v1": {"v1", "$v1", "3"},
    **{f"s{i}": {f"s{i}", f"$s{i}"} for i in range(8)},
    "gp": {"gp", "$gp"}, "sp": {"sp", "$sp"}, "fp": {"fp", "$fp"}, "ra": {"ra", "$ra"},
    # ARM/AArch64.  Keep aliases conservative to avoid matching numeric immediates.
    **{f"r{i}": {f"r{i}"} for i in range(16)},
    **{f"x{i}": {f"x{i}", f"w{i}"} for i in range(31)},
    **{f"w{i}": {f"w{i}"} for i in range(31)},
}
RET_REG_ALIASES = set().union(*(REG_ALIASES.get(r, {r}) for r in ("rax", "eax", "v0", "v1", "r0", "x0", "w0")))
# Union of branch/call mnemonics from the architecture registry.  Individual
# binaries also carry arch-specific mnemonic sets in BinaryFacts.
COND_BRANCHES = set().union(*(set(v.get("branches", ())) for v in ARCH_DEFAULTS.values()))
CALL_MNEMONICS = set().union(*(set(v.get("calls", ())) for v in ARCH_DEFAULTS.values()))
RETURN_STOP = {"ret", "retq", "iret", "syscall", "hlt", "jr", "bx", "br"}
PREFIX_MNEMONICS = {"addr32", "data16", "rex", "rep", "repe", "repz", "repne", "repnz", "lock", "bnd", "notrack"}

OBJDUMP_CANDIDATES = {
    "x86_64": ["objdump", "x86_64-linux-gnu-objdump"],
    "x86": ["objdump", "i686-linux-gnu-objdump"],
    "arm32": ["arm-linux-gnueabi-objdump", "arm-linux-gnueabihf-objdump", "arm-none-eabi-objdump", "objdump"],
    "aarch64": ["aarch64-linux-gnu-objdump", "objdump"],
    "mips32": ["mipsel-linux-gnu-objdump", "mips-linux-gnu-objdump", "mipsisa32-linux-gnu-objdump", "objdump"],
    "mips64": ["mips64el-linux-gnuabi64-objdump", "mips64-linux-gnuabi64-objdump", "objdump"],
    "powerpc": ["powerpc-linux-gnu-objdump", "powerpc64-linux-gnu-objdump", "objdump"],
    "riscv": ["riscv64-linux-gnu-objdump", "objdump"],
    "unknown": ["objdump"],
}


def run(cmd: Sequence[str]) -> str:
    try:
        return subprocess.check_output(cmd, stderr=subprocess.STDOUT, text=True, errors="replace")
    except FileNotFoundError as exc:
        raise SystemExit(f"missing required command: {cmd[0]}") from exc
    except subprocess.CalledProcessError as exc:
        raise RuntimeError(f"command failed: {' '.join(cmd)}\n{exc.output}") from exc


def is_elf(path: Path) -> bool:
    try:
        with path.open("rb") as f:
            return f.read(4) == b"\x7fELF"
    except OSError:
        return False


def iter_elf_inputs(paths: Sequence[Path]) -> Iterable[Path]:
    for p in paths:
        if p.is_dir():
            for child in sorted(p.rglob("*")):
                if child.is_file() and is_elf(child):
                    yield child
        elif p.is_file() and is_elf(p):
            yield p
        elif p.is_file():
            print(f"[warn] skip non-ELF file: {p}", file=sys.stderr)
        else:
            print(f"[warn] input path does not exist: {p}", file=sys.stderr)


def normalize_symbol(sym: Optional[str]) -> Optional[str]:
    if not sym:
        return None
    s = sym.strip()
    # Drop offset suffix, PLT suffix, ELF symbol versions, C++ clone suffixes used in objdump labels.
    s = s.split("+")[0]
    s = s.split("@@")[0]
    s = s.split("@")[0]
    for suffix in (".plt",):
        if s.endswith(suffix):
            s = s[: -len(suffix)]
    return s


def parse_int(s: str) -> Optional[int]:
    s = s.strip().lower()
    s = s.replace("$", "").replace("#", "")
    # Remove common decoration in objdump operands.
    s = s.strip(" ,")
    try:
        return int(s, 0)
    except ValueError:
        return None


def operand_tokens(operand_text: str) -> List[str]:
    return re.findall(r"[A-Za-z_][A-Za-z0-9_]*|0x[0-9a-fA-F]+|-?\d+", operand_text)


def contains_reg(operand_text: str, aliases: Iterable[str]) -> bool:
    aliases_set = {a.lower() for a in aliases}
    toks = [t.lower() for t in operand_tokens(operand_text)]
    return any(t in aliases_set for t in toks)


def split_operands(operand_text: str) -> List[str]:
    # Good enough for objdump Intel syntax used by our examples and most ELF output.
    parts: List[str] = []
    depth = 0
    buf: List[str] = []
    for ch in operand_text:
        if ch in "[<":
            depth += 1
        elif ch in "]>":
            depth = max(0, depth - 1)
        if ch == "," and depth == 0:
            parts.append("".join(buf).strip())
            buf = []
        else:
            buf.append(ch)
    if buf:
        parts.append("".join(buf).strip())
    return parts


@dataclasses.dataclass
class Instruction:
    addr: int
    function: str
    mnemonic: str
    operands: str
    text: str
    target_symbol: Optional[str] = None
    target_addr: Optional[int] = None

    @property
    def norm_target(self) -> Optional[str]:
        return normalize_symbol(self.target_symbol)


@dataclasses.dataclass
class BinaryFacts:
    path: Path
    instructions: List[Instruction]
    functions: Dict[int, str]
    arch: ArchSpec
    disassembler: str

    @property
    def calls(self) -> List[Instruction]:
        return [ins for ins in self.instructions if ins.mnemonic in set(self.arch.call_mnemonics)]


def _objdump_command(path: Path, spec: ArchSpec) -> List[str]:
    env_specific = os.getenv(f"UVSCAN_OBJDUMP_{spec.arch.upper()}")
    env_generic = os.getenv("UVSCAN_OBJDUMP")
    candidates = [x for x in [env_specific, env_generic] if x] + OBJDUMP_CANDIDATES.get(spec.arch, ["objdump"])
    seen = set()
    for cand in candidates:
        if not cand or cand in seen:
            continue
        seen.add(cand)
        exe = shutil.which(cand) if os.sep not in cand else cand
        if not exe:
            continue
        cmd = [exe, "-d", "--no-show-raw-insn"]
        if spec.arch in {"x86_64", "x86"}:
            cmd[2:2] = ["-M", "intel"]
        cmd.append(str(path))
        return cmd
    return ["objdump", "-d", "--no-show-raw-insn", str(path)]




def has_callsite_disassembler(path: Path) -> bool:
    """Return whether this host likely has a disassembler for call-site facts.

    x86/x86_64 can use the system objdump in normal development setups.  For
    firmware architectures we require an arch-specific objdump or explicit
    UVSCAN_OBJDUMP(_ARCH) override; otherwise scanner should use symbol-level
    fallback instead of producing thousands of noisy disassembly failures.
    """
    spec = spec_for_binary(path)
    if os.getenv("UVSCAN_OBJDUMP") or os.getenv(f"UVSCAN_OBJDUMP_{spec.arch.upper()}"):
        return True
    if spec.arch in {"x86", "x86_64"}:
        return shutil.which("objdump") is not None or shutil.which("x86_64-linux-gnu-objdump") is not None
    for cand in OBJDUMP_CANDIDATES.get(spec.arch, []):
        if cand != "objdump" and shutil.which(cand):
            return True
    return False

def parse_disassembly(path: Path) -> BinaryFacts:
    spec = spec_for_binary(path)
    cmd = _objdump_command(path, spec)
    text = run(cmd)
    functions: Dict[int, str] = {}
    instructions: List[Instruction] = []
    current_func = "<unknown>"
    # Function/header examples:
    # 0000000000401000 <_start>:
    # Instruction examples:
    #   401000: call   401017 <SSL_write>
    header_re = re.compile(r"^\s*([0-9a-fA-F]+)\s+<([^>]+)>:\s*$")
    instr_re = re.compile(r"^\s*([0-9a-fA-F]+):\s*([^\s]+)\s*(.*?)\s*$")
    target_re = re.compile(r"\b([0-9a-fA-F]+)\s+<([^>]+)>")
    addr_only_target_re = re.compile(r"^\s*([0-9a-fA-F]+)\b")

    for line in text.splitlines():
        mh = header_re.match(line)
        if mh:
            addr = int(mh.group(1), 16)
            current_func = normalize_symbol(mh.group(2)) or mh.group(2)
            functions[addr] = current_func
            continue
        mi = instr_re.match(line)
        if not mi:
            continue
        mnemonic = mi.group(2).lower()
        operands = mi.group(3).strip()
        # Objdump may print instruction prefixes as the first token, e.g.
        # "addr32 call 137e90 <RAND_pseudo_bytes>". Fold the prefix away so
        # downstream checkers still see a CALL instruction.
        if mnemonic in PREFIX_MNEMONICS and operands:
            pieces = operands.split(None, 1)
            if pieces:
                mnemonic = pieces[0].lower()
                operands = pieces[1].strip() if len(pieces) > 1 else ""
        # Skip data pseudo-lines that objdump may emit.
        if not re.match(r"^[a-zA-Z][a-zA-Z0-9_.]*$", mnemonic):
            continue
        target_addr: Optional[int] = None
        target_symbol: Optional[str] = None
        mt = target_re.search(operands)
        if mt:
            target_addr = int(mt.group(1), 16)
            target_symbol = normalize_symbol(mt.group(2))
        elif mnemonic in set(spec.call_mnemonics) or mnemonic in set(spec.branch_mnemonics) or mnemonic.startswith("j"):
            ma = addr_only_target_re.match(operands)
            if ma:
                target_addr = int(ma.group(1), 16)
                target_symbol = functions.get(target_addr)
        instructions.append(
            Instruction(
                addr=int(mi.group(1), 16),
                function=current_func,
                mnemonic=mnemonic,
                operands=operands,
                text=line.rstrip(),
                target_symbol=target_symbol,
                target_addr=target_addr,
            )
        )
    return BinaryFacts(path=path, instructions=instructions, functions=functions, arch=spec, disassembler=cmd[0])


def find_return_check_after(instructions: List[Instruction], call_index: int, lookahead: int = 14) -> Optional[Tuple[Instruction, Optional[Instruction]]]:
    caller = instructions[call_index].function
    checked: Optional[Instruction] = None
    end = min(len(instructions), call_index + lookahead + 1)
    for j in range(call_index + 1, end):
        ins = instructions[j]
        if ins.function != caller:
            break
        if ins.mnemonic in RETURN_STOP:
            break
        # A later call often means the return value was already consumed or lost.
        if j != call_index + 1 and ins.mnemonic in CALL_MNEMONICS and checked is None:
            break
        if is_return_compare(ins):
            checked = ins
            # Find nearby conditional branch.
            for k in range(j + 1, min(len(instructions), j + 5)):
                br = instructions[k]
                if br.function != caller:
                    break
                if is_conditional_branch(br):
                    return checked, br
                if br.mnemonic in CALL_MNEMONICS or br.mnemonic in RETURN_STOP:
                    break
            return checked, None
    return None


def is_return_compare(ins: Instruction) -> bool:
    ops = ins.operands.lower()
    mn = ins.mnemonic
    # x86 cmp/test/or, ARM cmp/tst/cmn, MIPS slt/slti-style checks.
    if mn in {"test", "cmp", "or", "tst", "cmn", "slt", "slti", "sltu", "sltiu"} and contains_reg(ops, RET_REG_ALIASES):
        if mn in {"cmp", "cmn"}:
            return any(parse_int(tok) == 0 for tok in operand_tokens(ops)) or contains_reg(ops, RET_REG_ALIASES)
        return True
    # Some ISAs compare and branch in one instruction, e.g. MIPS beqz/bltz and
    # AArch64 cbz/cbnz.  Treat these as a return check when the return register
    # appears in the branch operands.
    if mn in COND_BRANCHES and contains_reg(ops, RET_REG_ALIASES):
        return True
    return False


def is_conditional_branch(ins: Instruction) -> bool:
    return ins.mnemonic in COND_BRANCHES


def classify_return_violation(spec: Dict[str, Any], check: Optional[Tuple[Instruction, Optional[Instruction]]]) -> Optional[Tuple[str, str, Optional[Instruction], Optional[Instruction]]]:
    constraint = spec.get("constraint")
    if check is None:
        return ("missing_return_value_check", "no compare/test of the return register was found near the call", None, None)
    check_ins, br = check
    if br is None:
        if constraint == "non_null_required":
            return None
        return ("weak_return_value_check", "return register is compared/tested, but no nearby conditional branch was found", check_ins, None)
    cond = br.mnemonic
    if constraint == "non_null_required":
        # For pointer-return APIs, the existence of a zero check is the key property in this compact checker.
        return None
    if constraint == "error_le_zero":
        # Correct error-side branch normally includes equality (jle/jng or je/jz depending on code shape).
        # Paper/CVE examples are vulnerable when only <0 is checked (jl/js), missing zero.
        if cond in {"jl", "jnge", "js"}:
            return ("incorrect_return_value_check", "branch checks only < 0, but the API treats <= 0 as error", check_ins, br)
    elif constraint == "error_lt_zero":
        # Correct error-side branch should be strict negative. Treating zero/non-zero as error is suspicious.
        if cond in {"jle", "jng", "je", "jz", "jne", "jnz"}:
            return ("incorrect_return_value_check", "branch condition is inconsistent with the API's < 0 error contract", check_ins, br)
    return None


def previous_arg_value(instructions: List[Instruction], call_index: int, arg_index: int, window: int, arg_registers: Sequence[str] | None = None) -> Tuple[Optional[int], Optional[Instruction]]:
    regs = list(arg_registers or X86_64_ARG_REGS)
    if arg_index < 1 or arg_index > len(regs):
        return None, None
    reg = regs[arg_index - 1]
    aliases = REG_ALIASES.get(reg, {reg})
    caller = instructions[call_index].function
    for j in range(call_index - 1, max(-1, call_index - window - 1), -1):
        ins = instructions[j]
        if ins.function != caller:
            break
        if ins.mnemonic in CALL_MNEMONICS:
            break
        parts = split_operands(ins.operands.lower())
        if ins.mnemonic == "xor" and len(parts) >= 2 and contains_reg(parts[0], aliases) and contains_reg(parts[1], aliases):
            return 0, ins
        if ins.mnemonic in {"mov", "movabs", "li", "movi", "movz", "orr"} and len(parts) >= 2 and contains_reg(parts[0], aliases):
            val = parse_int(parts[1])
            if val is not None:
                return val, ins
        if ins.mnemonic in {"addiu", "addi"} and len(parts) >= 3 and contains_reg(parts[0], aliases):
            val = parse_int(parts[2])
            if val is not None and any(parse_int(tok) == 0 for tok in operand_tokens(parts[1])):
                return val, ins
    return None, None




def previous_arg_symbol(instructions: List[Instruction], call_index: int, arg_index: int, window: int, arg_registers: Sequence[str] | None = None) -> Tuple[Optional[str], Optional[Instruction]]:
    regs = list(arg_registers or X86_64_ARG_REGS)
    if arg_index < 1 or arg_index > len(regs):
        return None, None
    reg = regs[arg_index - 1]
    aliases = REG_ALIASES.get(reg, {reg})
    caller = instructions[call_index].function
    sym_re = re.compile(r"<([^>]+)>|\b([A-Za-z_][A-Za-z0-9_]*)(?:@|\b)")
    for j in range(call_index - 1, max(-1, call_index - window - 1), -1):
        ins = instructions[j]
        if ins.function != caller:
            break
        if ins.mnemonic in CALL_MNEMONICS:
            break
        parts = split_operands(ins.operands.lower())
        if len(parts) < 2 or not contains_reg(parts[0], aliases):
            continue
        # Avoid reporting register names or numeric immediates as symbolic args.
        for m in sym_re.finditer(ins.operands):
            sym = normalize_symbol(m.group(1) or m.group(2))
            if not sym:
                continue
            if sym.lower() in REG_ALIASES or parse_int(sym) is not None:
                continue
            if sym.lower() in {"pc", "sp", "lr", "ip", "fp"}:
                continue
            return sym, ins
    return None, None

def encode_facts(facts: BinaryFacts, outdir: Path, checks: List[Dict[str, Any]], arg_facts: List[Dict[str, Any]]) -> None:
    outdir.mkdir(parents=True, exist_ok=True)
    facts_dir = outdir / "facts"
    facts_dir.mkdir(parents=True, exist_ok=True)

    def write_tsv(name: str, rows: Iterable[Sequence[Any]]) -> None:
        with (facts_dir / name).open("w", newline="", encoding="utf-8") as f:
            w = csv.writer(f, delimiter="\t", lineterminator="\n")
            for row in rows:
                w.writerow(row)

    write_tsv("function.facts", ((hex(addr), name) for addr, name in sorted(facts.functions.items())))
    write_tsv("instruction.facts", ((hex(i.addr), i.function, i.mnemonic, i.operands) for i in facts.instructions))
    write_tsv("call.facts", ((hex(i.addr), i.function, i.norm_target or "", i.operands) for i in facts.calls))
    write_tsv(
        "return_check.facts",
        (
            (
                hex(c["call_addr"]),
                c["api"],
                hex(c["check_addr"]) if c.get("check_addr") is not None else "",
                c.get("check_mnemonic") or "",
                hex(c["branch_addr"]) if c.get("branch_addr") is not None else "",
                c.get("branch_mnemonic") or "",
            )
            for c in checks
        ),
    )
    write_tsv(
        "argument_value.facts",
        (
            (hex(a["call_addr"]), a["api"], a["arg_index"], "" if a.get("value") is None else a["value"], hex(a["set_addr"]) if a.get("set_addr") is not None else "")
            for a in arg_facts
        ),
    )


def scan_binary(path: Path, specs: Dict[str, Any], out_root: Path, fact_only: bool = False) -> Dict[str, Any]:
    bf = parse_disassembly(path)
    reports: List[Dict[str, Any]] = []
    return_check_facts: List[Dict[str, Any]] = []
    arg_value_facts: List[Dict[str, Any]] = []

    call_indices = [(idx, ins) for idx, ins in enumerate(bf.instructions) if ins.mnemonic in set(bf.arch.call_mnemonics)]

    # Deprecated API checker.
    deprecated = {normalize_symbol(d.get("api")): d for d in specs.get("deprecated", [])}
    for idx, call in call_indices:
        target = call.norm_target
        if target in deprecated:
            spec = deprecated[target]
            reports.append(make_report(path, "deprecated_api", call, target, spec.get("expected", "deprecated API used"), spec))

    # Return-value checker.
    return_specs = {normalize_symbol(s.get("api")): s for s in specs.get("return_value", [])}
    for idx, call in call_indices:
        target = call.norm_target
        if target not in return_specs:
            continue
        spec = return_specs[target]
        check = find_return_check_after(bf.instructions, idx)
        check_ins = check[0] if check else None
        br_ins = check[1] if check else None
        return_check_facts.append(
            {
                "call_addr": call.addr,
                "api": target,
                "check_addr": check_ins.addr if check_ins else None,
                "check_mnemonic": check_ins.mnemonic if check_ins else None,
                "branch_addr": br_ins.addr if br_ins else None,
                "branch_mnemonic": br_ins.mnemonic if br_ins else None,
            }
        )
        violation = classify_return_violation(spec, check)
        if violation:
            kind, reason, check_i, br_i = violation
            reports.append(
                make_report(
                    path,
                    kind,
                    call,
                    target,
                    reason,
                    spec,
                    extra={
                        "check_addr": hex(check_i.addr) if check_i else None,
                        "check_instruction": check_i.text.strip() if check_i else None,
                        "branch_addr": hex(br_i.addr) if br_i else None,
                        "branch_instruction": br_i.text.strip() if br_i else None,
                    },
                )
            )

    # Argument checker.
    arg_specs = {normalize_symbol(s.get("api")): s for s in specs.get("argument", [])}
    for idx, call in call_indices:
        target = call.norm_target
        if target not in arg_specs:
            continue
        spec = arg_specs[target]
        arg_index = int(spec.get("arg_index", 0))
        expected = int(spec.get("value", 0))
        window = int(spec.get("window", 8))
        value, setter = previous_arg_value(bf.instructions, idx, arg_index, window, bf.arch.arg_registers)
        arg_value_facts.append(
            {"call_addr": call.addr, "api": target, "arg_index": arg_index, "value": value, "set_addr": setter.addr if setter else None}
        )
        if spec.get("operator") == "==" and value != expected:
            reports.append(
                make_report(
                    path,
                    "argument_violation",
                    call,
                    target,
                    f"argument {arg_index} is {value!r}, expected {expected}",
                    spec,
                    extra={"arg_index": arg_index, "observed": value, "setter": setter.text.strip() if setter else None},
                )
            )

    # Causality checker.
    causality_specs = specs.get("causality", [])
    by_func: Dict[str, List[Instruction]] = {}
    for _, call in call_indices:
        by_func.setdefault(call.function, []).append(call)
    for func, calls in by_func.items():
        names = [c.norm_target for c in calls]
        for pos, call in enumerate(calls):
            for spec in causality_specs:
                api = normalize_symbol(spec.get("api"))
                must = normalize_symbol(spec.get("must_call_after"))
                before = normalize_symbol(spec.get("before")) if spec.get("before") else None
                window = int(spec.get("window", 5))
                if names[pos] != api:
                    continue
                end = min(len(calls), pos + window + 1)
                if before and before in names[pos + 1 : end]:
                    end = pos + 1 + names[pos + 1 : end].index(before)
                segment = names[pos + 1 : end]
                # If `before` is specified, only check the segment leading to it. If `before` is absent,
                # check the window after api.
                if must not in segment:
                    reports.append(
                        make_report(
                            path,
                            "causality_violation",
                            call,
                            api,
                            f"missing required call {must} after {api}" + (f" before {before}" if before else ""),
                            spec,
                            extra={"function": func, "observed_following_calls": [n for n in segment if n]},
                        )
                    )

    rel_out = out_root / safe_name(path)
    encode_facts(bf, rel_out, return_check_facts, arg_value_facts)
    result = {
        "binary": str(path),
        "facts_dir": str(rel_out / "facts"),
        "num_instructions": len(bf.instructions),
        "num_calls": len(bf.calls),
        "violations": reports,
    }
    (rel_out / "report.json").write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")
    write_csv_report(rel_out / "report.csv", reports)
    return result


def safe_name(path: Path) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", str(path.resolve()).strip(os.sep))[-180:]


def make_report(path: Path, kind: str, call: Instruction, api: Optional[str], reason: str, spec: Dict[str, Any], extra: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    r = {
        "kind": kind,
        "binary": str(path),
        "function": call.function,
        "call_addr": hex(call.addr),
        "api": api,
        "reason": reason,
        "call_instruction": call.text.strip(),
        "expected": spec.get("expected"),
        "source": spec.get("source"),
    }
    if extra:
        r.update(extra)
    return r


def write_csv_report(path: Path, reports: List[Dict[str, Any]]) -> None:
    fields = ["kind", "binary", "function", "call_addr", "api", "reason", "expected", "source"]
    with path.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
        w.writeheader()
        for r in reports:
            w.writerow(r)


def load_specs(path: Path) -> Dict[str, Any]:
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def main(argv: Optional[Sequence[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="Run the UVScan binary-analysis helper on ELF files.")
    ap.add_argument("inputs", nargs="+", type=Path, help="ELF files or directories containing ELF files")
    ap.add_argument("-s", "--specs", type=Path, default=Path(__file__).with_name("api_specs.json"), help="API programming-expression JSON")
    ap.add_argument("-o", "--out", type=Path, default=Path(__file__).with_name("results"), help="output directory")
    ap.add_argument("--json", action="store_true", help="print full JSON report to stdout")
    args = ap.parse_args(argv)

    specs = load_specs(args.specs)
    args.out.mkdir(parents=True, exist_ok=True)
    binaries = list(iter_elf_inputs(args.inputs))
    if not binaries:
        print("no ELF inputs found", file=sys.stderr)
        return 2

    all_results = [scan_binary(p, specs, args.out) for p in binaries]
    all_reports = [v for r in all_results for v in r["violations"]]
    summary = {
        "inputs": [str(p) for p in binaries],
        "output_dir": str(args.out),
        "num_binaries": len(binaries),
        "num_violations": len(all_reports),
        "violations": all_reports,
    }
    (args.out / "summary.json").write_text(json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")
    write_csv_report(args.out / "summary.csv", all_reports)

    if args.json:
        print(json.dumps(summary, indent=2, ensure_ascii=False))
    else:
        print(f"[UVScanX] scanned {len(binaries)} ELF file(s); found {len(all_reports)} potential violation(s)")
        print(f"[UVScanX] summary: {args.out / 'summary.json'}")
        for rep in all_reports:
            print(f"  - {rep['kind']}: {rep['api']} at {rep['binary']}:{rep['call_addr']} ({rep['reason']})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
