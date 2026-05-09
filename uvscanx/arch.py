from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Tuple

from .elf import readelf_header


@dataclass(frozen=True)
class ArchSpec:
    arch: str
    bits: int
    endian: str
    machine: str
    arg_registers: Tuple[str, ...]
    return_registers: Tuple[str, ...]
    call_mnemonics: Tuple[str, ...]
    branch_mnemonics: Tuple[str, ...]
    branch_delay_slot: bool = False


BR_X86 = (
    "ja", "jae", "jb", "jbe", "jc", "jcxz", "je", "jecxz", "jg", "jge",
    "jl", "jle", "jna", "jnae", "jnb", "jnbe", "jnc", "jne", "jng", "jnge",
    "jnl", "jnle", "jno", "jnp", "jns", "jnz", "jo", "jp", "jpe", "jpo",
    "js", "jz", "loop", "loope", "loopne", "loopnz", "loopz",
)
BR_MIPS = ("beq", "bne", "bgez", "bgtz", "blez", "bltz", "beqz", "bnez", "b", "bal")
BR_ARM = ("b", "beq", "bne", "bcs", "bcc", "bmi", "bpl", "bvs", "bvc", "bhi", "bls", "bge", "blt", "bgt", "ble")
BR_AARCH64 = BR_ARM + ("cbz", "cbnz", "tbz", "tbnz")


ARCH_DEFAULTS: Dict[str, Dict[str, object]] = {
    "x86_64": {
        "args": ("rdi", "rsi", "rdx", "rcx", "r8", "r9"),
        "ret": ("rax", "eax", "ax", "al"),
        "calls": ("call", "callq"),
        "branches": BR_X86,
    },
    "x86": {
        "args": tuple(),  # mostly stack-based; model later with stack_arg facts
        "ret": ("eax", "ax", "al"),
        "calls": ("call",),
        "branches": BR_X86,
    },
    "mips32": {
        "args": ("a0", "a1", "a2", "a3"),
        "ret": ("v0", "v1"),
        "calls": ("jal", "jalr", "bal"),
        "branches": BR_MIPS,
        "branch_delay_slot": True,
    },
    "mips64": {
        "args": ("a0", "a1", "a2", "a3", "a4", "a5", "a6", "a7"),
        "ret": ("v0", "v1"),
        "calls": ("jal", "jalr", "bal"),
        "branches": BR_MIPS,
        "branch_delay_slot": True,
    },
    "arm32": {
        "args": ("r0", "r1", "r2", "r3"),
        "ret": ("r0",),
        "calls": ("bl", "blx"),
        "branches": BR_ARM,
    },
    "aarch64": {
        "args": ("x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7"),
        "ret": ("x0", "w0"),
        "calls": ("bl", "blr"),
        "branches": BR_AARCH64,
    },
    "powerpc": {
        "args": ("r3", "r4", "r5", "r6", "r7", "r8", "r9", "r10"),
        "ret": ("r3",),
        "calls": ("bl", "bctrl"),
        "branches": ("b", "beq", "bne", "blt", "ble", "bgt", "bge", "bc"),
    },
    "riscv": {
        "args": ("a0", "a1", "a2", "a3", "a4", "a5", "a6", "a7"),
        "ret": ("a0", "a1"),
        "calls": ("call", "jal", "jalr"),
        "branches": ("beq", "bne", "blt", "bge", "bltu", "bgeu", "c.beqz", "c.bnez"),
    },
    "unknown": {"args": tuple(), "ret": tuple(), "calls": tuple(), "branches": tuple()},
}


def _bits(class_text: str | None) -> int:
    text = (class_text or "").lower()
    if "elf64" in text:
        return 64
    if "elf32" in text:
        return 32
    return 0


def _endian(data_text: str | None) -> str:
    text = (data_text or "").lower()
    if "little" in text:
        return "little"
    if "big" in text:
        return "big"
    return "unknown"


def canonical_arch(machine: str | None, bits: int) -> str:
    m = (machine or "").lower()
    if "x86-64" in m or "advanced micro devices x86-64" in m:
        return "x86_64"
    if "80386" in m or "intel 80386" in m or "i386" in m:
        return "x86"
    if "mips" in m:
        return "mips64" if bits == 64 else "mips32"
    if "aarch64" in m or "arm aarch64" in m:
        return "aarch64"
    if m.strip() == "arm" or "arm," in m or "arm" in m:
        return "arm32"
    if "powerpc" in m or "ppc" in m:
        return "powerpc"
    if "risc-v" in m or "riscv" in m:
        return "riscv"
    return "unknown"


def spec_from_header(header: Dict[str, str]) -> ArchSpec:
    machine = header.get("Machine", "")
    bits = _bits(header.get("Class"))
    endian = _endian(header.get("Data"))
    arch = canonical_arch(machine, bits)
    defaults = ARCH_DEFAULTS.get(arch, ARCH_DEFAULTS["unknown"])
    return ArchSpec(
        arch=arch,
        bits=bits,
        endian=endian,
        machine=machine,
        arg_registers=tuple(defaults.get("args", ())),
        return_registers=tuple(defaults.get("ret", ())),
        call_mnemonics=tuple(defaults.get("calls", ())),
        branch_mnemonics=tuple(defaults.get("branches", ())),
        branch_delay_slot=bool(defaults.get("branch_delay_slot", False)),
    )


def spec_for_binary(path: Path) -> ArchSpec:
    return spec_from_header(readelf_header(path))


def datalog_rows_for_binary(path: Path) -> Dict[str, List[Tuple[object, ...]]]:
    spec = spec_for_binary(path)
    binary = str(path)
    return {
        "binary_arch": [(binary, spec.arch, spec.bits, spec.endian, spec.machine, "1" if spec.branch_delay_slot else "0")],
        "calling_convention": [(spec.arch, i + 1, reg) for i, reg in enumerate(spec.arg_registers)],
        "return_register": [(spec.arch, reg) for reg in spec.return_registers],
        "call_mnemonic": [(spec.arch, m) for m in spec.call_mnemonics],
        "branch_mnemonic": [(spec.arch, m) for m in spec.branch_mnemonics],
    }
