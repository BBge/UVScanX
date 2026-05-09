from pathlib import Path

from uvscanx.elf import is_elf, iter_elfs
from uvscanx.tpc import identify


def test_iter_elfs_on_regression_bins():
    bins = list(iter_elfs([Path("examples/synthetic/bin")]))
    assert bins, "run scripts/build_synthetic.sh before tests if bins are missing"
    assert all(is_elf(p) for p in bins[:3])


def test_tpc_identify_mock(tmp_path):
    obj = identify([Path("examples/synthetic/bin")], tmp_path, limit=2)
    assert obj["num_binaries"] >= 1
    assert (tmp_path / "tpc_summary.json").exists()


def test_tpc_heuristics_cover_expanded_components():
    from uvscanx.llm import heuristic_components

    evidence = " ".join([
        "libcurl/8.4.0", "xmlReadFile", "mbed TLS 3.6.0", "wolfSSL 5.7.0",
        "OpenSSH_9.6", "GLIBC_2.31", "uClibc 1.0.42", "libupnp/1.14.18",
        "Dnsmasq version 2.89", "Dropbear 2022.83",
    ])
    names = {c["name"] for c in heuristic_components(evidence)}
    for name in {"libcurl", "libxml2", "mbedTLS", "wolfSSL", "OpenSSH", "uClibc / glibc", "libupnp", "dnsmasq", "dropbear"}:
        assert name in names
