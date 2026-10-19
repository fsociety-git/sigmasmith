"""Rule loading and SigmaHQ-style validation."""

from __future__ import annotations

import re
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

REQUIRED_FIELDS = ("title", "id", "status", "description", "author", "date", "logsource", "detection", "level")
RECOMMENDED_FIELDS = ("references", "tags", "falsepositives")
STATUSES = {"stable", "test", "experimental", "deprecated", "unsupported"}
LEVELS = {"informational", "low", "medium", "high", "critical"}
_TAG = re.compile(
    r"^(attack\.(t\d{4}(\.\d{3})?|[a-z-]+)|cve\.\d{4}\.\d+|detection\.[a-z_]+|car\.\d{4}-\d{2}-\d{3}|tlp\.[a-z]+)$"
)
_DATE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
_FILENAME = re.compile(r"^[a-z0-9_]+\.yml$")


@dataclass
class Rule:
    path: Path
    data: dict[str, Any]

    @property
    def title(self) -> str:
        return str(self.data.get("title", self.path.stem))

    @property
    def id(self) -> str:
        return str(self.data.get("id", ""))

    @property
    def level(self) -> str:
        return str(self.data.get("level", ""))

    @property
    def tags(self) -> list[str]:
        return [str(t) for t in self.data.get("tags", [])]

    @property
    def techniques(self) -> list[str]:
        return sorted({t.split(".", 1)[1].upper() for t in self.tags if re.match(r"^attack\.t\d{4}", t)})

    @property
    def tactics(self) -> list[str]:
        return sorted({t.split(".", 1)[1] for t in self.tags if re.match(r"^attack\.[a-z-]+$", t)})

    @property
    def test_path(self) -> Path:
        return self.path.with_name(self.path.name[: -len(".yml")] + ".test.yaml")

    @property
    def logsource(self) -> dict[str, str]:
        return {k: str(v) for k, v in (self.data.get("logsource") or {}).items()}


@dataclass
class Problem:
    rule: Path
    message: str
    severity: str = "error"

    def __str__(self) -> str:
        return f"{self.rule}: {self.severity}: {self.message}"


@dataclass
class ValidationReport:
    problems: list[Problem] = field(default_factory=list)

    @property
    def errors(self) -> list[Problem]:
        return [p for p in self.problems if p.severity == "error"]

    @property
    def warnings(self) -> list[Problem]:
        return [p for p in self.problems if p.severity == "warning"]

    @property
    def ok(self) -> bool:
        return not self.errors


def is_rule_file(path: Path) -> bool:
    return path.suffix == ".yml"


def load_rules(root: Path) -> list[Rule]:
    rules: list[Rule] = []
    for path in sorted(root.rglob("*.yml")):
        if not is_rule_file(path):
            continue
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            raise ValueError(f"{path}: rule file must contain a single YAML mapping")
        rules.append(Rule(path=path, data=data))
    return rules


def validate_rule(rule: Rule) -> list[Problem]:
    d = rule.data
    out: list[Problem] = []

    def err(msg: str) -> None:
        out.append(Problem(rule.path, msg))

    def warn(msg: str) -> None:
        out.append(Problem(rule.path, msg, "warning"))

    for key in REQUIRED_FIELDS:
        if key not in d:
            err(f"missing required field '{key}'")
    for key in RECOMMENDED_FIELDS:
        if key not in d:
            warn(f"missing recommended field '{key}'")

    if not _FILENAME.match(rule.path.name):
        err("filename must be lowercase snake_case with a .yml extension")

    try:
        parsed = uuid.UUID(str(d.get("id", "")))
        if parsed.version != 4:
            err("id must be a version 4 UUID")
    except ValueError:
        err("id must be a valid UUID")

    if d.get("status") not in STATUSES:
        err(f"status must be one of {sorted(STATUSES)}")
    if d.get("level") not in LEVELS:
        err(f"level must be one of {sorted(LEVELS)}")

    date = d.get("date")
    if date is not None and not _DATE.match(str(date)):
        err("date must be YYYY-MM-DD")

    title = str(d.get("title", ""))
    if len(title) > 110:
        err("title longer than 110 characters")
    if title and title[-1] in ".!":
        err("title must not end with punctuation")

    desc = str(d.get("description", ""))
    if len(desc.strip()) < 40:
        err("description is too short to be useful (under 40 characters)")

    tags = d.get("tags") or []
    if not isinstance(tags, list):
        err("tags must be a list")
    else:
        for t in tags:
            if not _TAG.match(str(t)):
                err(f"tag '{t}' does not follow the attack.* / cve.* / detection.* convention")
        if not any(re.match(r"^attack\.t\d{4}", str(t)) for t in tags):
            warn("no ATT&CK technique tag (attack.tXXXX)")

    logsource = d.get("logsource")
    if not isinstance(logsource, dict) or not ({"category", "product", "service"} & set(logsource)):
        err("logsource must define at least one of category, product, service")

    detection = d.get("detection")
    if not isinstance(detection, dict) or "condition" not in detection:
        err("detection must be a mapping with a condition")
    else:
        names = [k for k in detection if k not in {"condition", "timeframe"}]
        if not names:
            err("detection has no selections")
        for name in names:
            if not re.match(r"^[A-Za-z0-9_]+$", name):
                err(f"selection name '{name}' contains invalid characters")
        cond = str(detection["condition"])
        for name in names:
            if name not in cond and not any(
                re.search(rf"\b(1|all) of {re.escape(prefix)}\*", cond) or " of them" in cond
                for prefix in [name.rstrip("0123456789_"), name.split("_")[0] + "_"]
            ):
                warn(f"selection '{name}' is not referenced by the condition")

    fps = d.get("falsepositives")
    if isinstance(fps, list) and any(str(x).strip().lower() in {"unknown", "none", ""} for x in fps):
        warn("falsepositives should describe real scenarios rather than 'Unknown'")

    if not rule.test_path.exists():
        err(f"no test file at {rule.test_path.name}")

    return out


def validate_rules(rules: list[Rule]) -> ValidationReport:
    report = ValidationReport()
    seen: dict[str, Path] = {}
    for rule in rules:
        report.problems.extend(validate_rule(rule))
        if rule.id in seen:
            report.problems.append(Problem(rule.path, f"duplicate id shared with {seen[rule.id]}"))
        seen[rule.id] = rule.path
    return report
