from pathlib import Path

from uvscanx.scanner import scan


def test_scan_regression_examples(tmp_path):
    out = tmp_path / "scan"
    summary = scan([Path("examples/synthetic/bin")], out, firmware_id="synthetic-test", engine="datalog")
    assert summary["num_binaries"] >= 10
    assert summary["num_findings"] >= 8
    kinds = {f["checker"] for f in summary["findings"]}
    assert "deprecated_api" in kinds
    assert "causality_violation" in kinds
    assert (out / "summary.json").exists()
    assert (out / "report.md").exists()


def test_same_handle_lifecycle_checker(tmp_path):
    out = tmp_path / "lifecycle"
    summary = scan(
        [
            Path("examples/synthetic/bin/lifecycle_return_handle_good"),
            Path("examples/synthetic/bin/lifecycle_return_handle_bad"),
            Path("examples/synthetic/bin/lifecycle_wrong_handle_bad"),
        ],
        out,
        firmware_id="same-handle-test",
        engine="datalog",
    )
    lifecycle = [f for f in summary["findings"] if f["checker"] == "resource_lifecycle_violation"]
    assert len(lifecycle) == 2
    assert not any("lifecycle_return_handle_good" in f["binary"] for f in lifecycle)
    assert any("lifecycle_wrong_handle_bad" in f["binary"] for f in lifecycle)


def test_arg_owned_and_pointer_out_lifecycle_checker(tmp_path):
    out = tmp_path / "arg-owned"
    summary = scan(
        [
            Path("examples/synthetic/bin/sqlite_handle_good"),
            Path("examples/synthetic/bin/sqlite_handle_bad"),
            Path("examples/synthetic/bin/sqlite_handle_wrong_bad"),
            Path("examples/synthetic/bin/mbedtls_arg_owned_good"),
            Path("examples/synthetic/bin/mbedtls_arg_owned_bad"),
        ],
        out,
        firmware_id="arg-owned-test",
        engine="datalog",
    )
    lifecycle = [f for f in summary["findings"] if f["checker"] == "resource_lifecycle_violation"]
    assert len(lifecycle) == 3
    assert not any("sqlite_handle_good" in f["binary"] for f in lifecycle)
    assert not any("mbedtls_arg_owned_good" in f["binary"] for f in lifecycle)
    assert any("sqlite_handle_wrong_bad" in f["binary"] for f in lifecycle)
    assert any("mbedtls_arg_owned_bad" in f["binary"] for f in lifecycle)


def test_priority_only_summary_fields(tmp_path):
    out = tmp_path / "priority"
    summary = scan([Path("examples/synthetic/bin")], out, firmware_id="priority-test", engine="datalog", priority_only=True)
    assert summary["priority_only"] is True
    assert summary["dedupe_enabled"] is True
    assert summary["num_input_binaries"] >= summary["num_binaries"]
    assert all(f["report_priority"] == "priority" for f in summary["findings"])
