"""Every shipped rule must be valid, tested, and compile on every backend."""

from pathlib import Path

import pytest

from sigmasmith.rules import load_rules, validate_rules
from sigmasmith.testing import run_all, run_rule_tests

ROOT = Path(__file__).resolve().parents[1]
RULES = load_rules(ROOT / "rules")


def test_rules_exist() -> None:
    assert len(RULES) >= 10


def test_every_rule_is_valid_with_no_errors() -> None:
    report = validate_rules(RULES)
    assert not report.errors, "\n".join(str(p) for p in report.errors)


def test_every_rule_has_technique_tags_and_references() -> None:
    for r in RULES:
        assert r.techniques, r.path
        assert r.data.get("references"), r.path
        assert r.data.get("falsepositives"), r.path


@pytest.mark.parametrize("rule", RULES, ids=[r.path.stem for r in RULES])
def test_rule_sample_events(rule) -> None:
    report = run_rule_tests(rule)
    assert not report.problems, report.problems
    assert not report.failures, [
        f"{f.case}: expected {f.expected}, got {f.actual} {f.error or ''}" for f in report.failures
    ]


def test_combined_report_is_green() -> None:
    assert run_all(RULES).ok


@pytest.mark.parametrize("backend", ["splunk", "elasticsearch", "opensearch", "kusto"])
def test_rules_compile_on_every_backend(backend: str) -> None:
    pytest.importorskip("sigma")
    from sigmasmith.compile import compile_rules

    compiled = compile_rules(RULES, backend)
    failures = [f"{c.rule.path.name}: {c.error}" for c in compiled if not c.ok]
    assert not failures, "\n".join(failures)
    assert all(c.query for c in compiled)
