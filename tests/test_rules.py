from pathlib import Path

from uvscanx.rules import extract_rules, load_rules
from uvscanx.schemas import python_checker_specs, validate_rules


def test_default_rules_valid(tmp_path):
    out = tmp_path / "rules.json"
    rules = extract_rules([], out)
    res = validate_rules(rules)
    assert res.ok, res.errors
    assert out.exists()
    assert any(r["api"] == "SSL_write" for r in rules["return_value"])
    specs = python_checker_specs(rules)
    assert any(r["api"] == "sqlite3_open" for r in specs["causality"])
