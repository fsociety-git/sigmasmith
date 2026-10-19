"""A small, dependency-free Sigma rule evaluator for testing rules against events.

It implements the parts of the Sigma specification that detection rules in
this repository use, so every rule can ship with positive and negative sample
events and be checked in CI without a SIEM:

* selections as field maps or keyword lists
* value lists (OR within a field), ``|all`` (AND within a field)
* modifiers: ``contains``, ``startswith``, ``endswith``, ``re``, ``cidr``,
  ``base64``, ``base64offset``, ``windash``, ``gt``, ``gte``, ``lt``, ``lte``
* wildcards ``*`` and ``?`` in plain values, case-insensitive matching
* ``null`` values (field absent)
* conditions with ``and`` / ``or`` / ``not`` / parentheses, ``1 of x*``,
  ``all of x*``, ``1 of them``, ``all of them``

It is deliberately strict: unsupported modifiers raise instead of silently
matching nothing.
"""

from __future__ import annotations

import base64
import fnmatch
import ipaddress
import re
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any

SUPPORTED_MODIFIERS = {
    "contains",
    "startswith",
    "endswith",
    "all",
    "re",
    "cidr",
    "base64",
    "base64offset",
    "windash",
    "gt",
    "gte",
    "lt",
    "lte",
}

Event = dict[str, Any]


class UnsupportedRuleError(ValueError):
    """Raised when a rule uses a Sigma feature the matcher does not implement."""


# --------------------------------------------------------------------------- values


def _get_field(event: Event, field: str) -> list[Any]:
    """Return every value an event holds for a field (supports dotted paths)."""
    if field in event:
        value = event[field]
    else:
        current: Any = event
        for part in field.split("."):
            if isinstance(current, dict) and part in current:
                current = current[part]
            else:
                return []
        value = current
    if value is None:
        return []
    return list(value) if isinstance(value, list) else [value]


def _windash_variants(value: str) -> list[str]:
    """Expand ``-flag`` into the dash variants Windows accepts."""
    variants = {value}
    for dash in ("-", "/", "\u2013", "\u2014", "\u2015"):
        variants.add(re.sub(r"(?<!\S)[-/\u2013\u2014\u2015]", dash, value))
    return sorted(variants)


def _base64_offsets(value: str) -> list[str]:
    """Return the three base64 encodings that can contain ``value`` at any alignment.

    Mirrors pySigma: pad with 0, 1 or 2 bytes, encode, then trim the characters
    influenced by the padding so the result is a pure substring match.
    """
    raw = value.encode()
    start_offsets = (0, 2, 3)
    end_offsets = (None, -3, -2)
    out: list[str] = []
    for i in range(3):
        encoded = base64.b64encode(b" " * i + raw).decode()
        trimmed = encoded[start_offsets[i] : end_offsets[(len(raw) + i) % 3]]
        if trimmed:
            out.append(trimmed)
    return out


def _match_value(actual: Any, expected: Any, modifiers: list[str]) -> bool:
    if expected is None:
        return False  # handled at the field level
    mods = [m for m in modifiers if m != "all"]
    unknown = set(mods) - SUPPORTED_MODIFIERS
    if unknown:
        raise UnsupportedRuleError(f"unsupported modifier(s): {sorted(unknown)}")

    if any(m in mods for m in ("gt", "gte", "lt", "lte")):
        try:
            a, e = float(actual), float(expected)
        except (TypeError, ValueError):
            return False
        return {"gt": a > e, "gte": a >= e, "lt": a < e, "lte": a <= e}[mods[-1]]

    if "cidr" in mods:
        try:
            return ipaddress.ip_address(str(actual)) in ipaddress.ip_network(str(expected), strict=False)
        except ValueError:
            return False

    if "re" in mods:
        return re.search(str(expected), str(actual)) is not None

    actual_s = str(actual).lower()
    candidates: Iterable[str] = [str(expected)]
    if "windash" in mods:
        candidates = _windash_variants(str(expected))
    if "base64offset" in mods:
        candidates = [c for v in candidates for c in _base64_offsets(v)]
    elif "base64" in mods:
        candidates = [base64.b64encode(v.encode()).decode() for v in candidates]

    for candidate in candidates:
        cand = candidate.lower()
        if "contains" in mods:
            if cand in actual_s:
                return True
        elif "startswith" in mods:
            if actual_s.startswith(cand):
                return True
        elif "endswith" in mods:
            if actual_s.endswith(cand):
                return True
        elif any(ch in cand for ch in "*?"):
            if fnmatch.fnmatchcase(actual_s, cand):
                return True
        elif actual_s == cand:
            return True
    return False


def _match_field(event: Event, spec: str, expected: Any) -> bool:
    field, *modifiers = spec.split("|")
    values = _get_field(event, field)
    expected_list = expected if isinstance(expected, list) else [expected]

    if expected is None or (isinstance(expected, list) and expected == [None]):
        return not values

    if "all" in modifiers:
        return all(any(_match_value(v, e, modifiers) for v in values) for e in expected_list)
    return any(_match_value(v, e, modifiers) for e in expected_list for v in values)


def _match_keywords(event: Event, keywords: list[Any]) -> bool:
    blob = " ".join(str(v) for v in _flatten(event)).lower()
    return any(fnmatch.fnmatchcase(blob, f"*{str(k).lower()}*") for k in keywords)


def _flatten(value: Any) -> list[Any]:
    if isinstance(value, dict):
        return [x for v in value.values() for x in _flatten(v)]
    if isinstance(value, list):
        return [x for v in value for x in _flatten(v)]
    return [value]


def _match_selection(event: Event, selection: Any) -> bool:
    if isinstance(selection, dict):
        return all(_match_field(event, spec, expected) for spec, expected in selection.items())
    if isinstance(selection, list):
        if all(isinstance(item, dict) for item in selection):
            return any(_match_selection(event, item) for item in selection)
        return _match_keywords(event, selection)
    raise UnsupportedRuleError(f"unsupported selection shape: {type(selection).__name__}")


# --------------------------------------------------------------------------- condition


_TOKEN = re.compile(r"\(|\)|\band\b|\bor\b|\bnot\b|\b(?:1|all) of\b|[A-Za-z0-9_*]+", re.I)


@dataclass
class _Parser:
    tokens: list[str]
    names: list[str]
    results: dict[str, bool]
    pos: int = 0

    def peek(self) -> str | None:
        return self.tokens[self.pos] if self.pos < len(self.tokens) else None

    def take(self) -> str:
        if self.pos >= len(self.tokens):
            raise UnsupportedRuleError("unexpected end of condition")
        tok = self.tokens[self.pos]
        self.pos += 1
        return tok

    def parse_or(self) -> bool:
        left = self.parse_and()
        while (self.peek() or "").lower() == "or":
            self.take()
            right = self.parse_and()
            left = left or right
        return left

    def parse_and(self) -> bool:
        left = self.parse_not()
        while (self.peek() or "").lower() == "and":
            self.take()
            right = self.parse_not()
            left = left and right
        return left

    def parse_not(self) -> bool:
        if (self.peek() or "").lower() == "not":
            self.take()
            return not self.parse_not()
        return self.parse_atom()

    def parse_atom(self) -> bool:
        tok = self.take()
        low = tok.lower()
        if tok == "(":
            value = self.parse_or()
            if self.take() != ")":
                raise UnsupportedRuleError("unbalanced parentheses in condition")
            return value
        if low in {"1 of", "all of"}:
            pattern = self.take()
            matched = self._expand(pattern)
            if not matched:
                raise UnsupportedRuleError(f"'{tok} {pattern}' matches no selection")
            return any(matched) if low == "1 of" else all(matched)
        if tok in self.results:
            return self.results[tok]
        raise UnsupportedRuleError(f"unknown identifier '{tok}' in condition")

    def _expand(self, pattern: str) -> list[bool]:
        if pattern.lower() == "them":
            return [self.results[n] for n in self.names]
        return [self.results[n] for n in self.names if fnmatch.fnmatchcase(n, pattern)]


def evaluate_condition(condition: str, results: dict[str, bool]) -> bool:
    tokens = _TOKEN.findall(condition)
    parser = _Parser(tokens=tokens, names=list(results), results=results)
    value = parser.parse_or()
    if parser.peek() is not None:
        raise UnsupportedRuleError(f"trailing tokens in condition: {parser.tokens[parser.pos :]}")
    return value


# --------------------------------------------------------------------------- public API


def rule_matches(rule: dict[str, Any], event: Event) -> bool:
    """Return True if ``event`` satisfies the rule's detection block."""
    detection = rule.get("detection")
    if not isinstance(detection, dict) or "condition" not in detection:
        raise UnsupportedRuleError("rule has no detection.condition")
    condition = detection["condition"]
    if isinstance(condition, list):
        condition = " or ".join(f"({c})" for c in condition)
    if "|" in condition:
        raise UnsupportedRuleError("aggregation expressions are not supported")
    results = {
        name: _match_selection(event, sel) for name, sel in detection.items() if name not in {"condition", "timeframe"}
    }
    return evaluate_condition(str(condition), results)
