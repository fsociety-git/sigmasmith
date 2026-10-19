"""Run each rule against its positive and negative sample events."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from sigmasmith.matcher import UnsupportedRuleError, rule_matches
from sigmasmith.rules import Rule

MIN_POSITIVE = 2
MIN_NEGATIVE = 2


@dataclass
class CaseResult:
    rule: Path
    case: str
    expected: bool
    actual: bool | None
    error: str | None = None

    @property
    def passed(self) -> bool:
        return self.error is None and self.actual == self.expected


@dataclass
class TestReport:
    results: list[CaseResult] = field(default_factory=list)
    problems: list[str] = field(default_factory=list)

    @property
    def failures(self) -> list[CaseResult]:
        return [r for r in self.results if not r.passed]

    @property
    def ok(self) -> bool:
        return not self.failures and not self.problems

    def summary(self) -> str:
        total = len(self.results)
        return f"{total - len(self.failures)}/{total} cases passed, {len(self.problems)} structural problem(s)"


def load_cases(path: Path) -> dict[str, list[dict[str, Any]]]:
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    if not isinstance(data, dict):
        raise ValueError(f"{path}: test file must be a mapping with 'positive' and 'negative' lists")
    out: dict[str, list[dict[str, Any]]] = {}
    for key in ("positive", "negative"):
        items = data.get(key) or []
        if not isinstance(items, list):
            raise ValueError(f"{path}: '{key}' must be a list")
        cases: list[dict[str, Any]] = []
        for idx, item in enumerate(items):
            if not isinstance(item, dict) or "event" not in item or not isinstance(item["event"], dict):
                raise ValueError(f"{path}: {key}[{idx}] needs an 'event' mapping")
            cases.append({"name": str(item.get("name", f"{key}[{idx}]")), "event": item["event"]})
        out[key] = cases
    return out


def run_rule_tests(rule: Rule) -> TestReport:
    report = TestReport()
    if not rule.test_path.exists():
        report.problems.append(f"{rule.path}: missing test file {rule.test_path.name}")
        return report
    try:
        cases = load_cases(rule.test_path)
    except ValueError as exc:
        report.problems.append(str(exc))
        return report
    if len(cases["positive"]) < MIN_POSITIVE:
        report.problems.append(f"{rule.path}: needs at least {MIN_POSITIVE} positive cases")
    if len(cases["negative"]) < MIN_NEGATIVE:
        report.problems.append(f"{rule.path}: needs at least {MIN_NEGATIVE} negative cases")
    for expected, key in ((True, "positive"), (False, "negative")):
        for case in cases[key]:
            try:
                actual = rule_matches(rule.data, case["event"])
                report.results.append(CaseResult(rule.path, case["name"], expected, actual))
            except UnsupportedRuleError as exc:
                report.results.append(CaseResult(rule.path, case["name"], expected, None, error=str(exc)))
    return report


def run_all(rules: list[Rule]) -> TestReport:
    combined = TestReport()
    for rule in rules:
        r = run_rule_tests(rule)
        combined.results.extend(r.results)
        combined.problems.extend(r.problems)
    return combined
