from pathlib import Path

from uvscanx.arch import canonical_arch, datalog_rows_for_binary, spec_for_binary
from uvscanx.datalog import generate_facts
from uvscanx.rules import load_rules


def test_canonical_arch_mapping():
    assert canonical_arch("Advanced Micro Devices X86-64", 64) == "x86_64"
    assert canonical_arch("MIPS R3000", 32) == "mips32"
    assert canonical_arch("ARM", 32) == "arm32"
    assert canonical_arch("AArch64", 64) == "aarch64"


def test_arch_facts_for_synthetic_binary(tmp_path):
    binary = Path("examples/synthetic/bin/ssl_write_bad")
    spec = spec_for_binary(binary)
    assert spec.arch == "x86_64"
    rows = datalog_rows_for_binary(binary)
    assert rows["binary_arch"][0][1] == "x86_64"
    assert any(r[2] == "rdi" for r in rows["calling_convention"])
    meta = generate_facts(binary, load_rules(), tmp_path / "facts")
    assert meta["arch"] == "x86_64"
    assert (tmp_path / "facts" / "binary_arch.facts").exists()


def test_callsite_disassembler_detection_for_synthetic():
    from uvscanx import binary_analysis as core

    assert core.has_callsite_disassembler(Path("examples/synthetic/bin/ssl_write_bad"))
