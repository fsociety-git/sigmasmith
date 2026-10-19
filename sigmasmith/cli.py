"""Command-line interface: ``sigmasmith validate | test | build | coverage | new``."""

from __future__ import annotations

import argparse
import sys
import uuid
from collections import defaultdict
from datetime import date
from pathlib import Path

from sigmasmith import __version__
from sigmasmith.rules import load_rules, validate_rules
from sigmasmith.testing import run_all

DEFAULT_RULES = Path("rules")


def cmd_validate(args: argparse.Namespace) -> int:
    rules = load_rules(Path(args.rules))
    report = validate_rules(rules)
    for p in report.problems:
        print(p)
    print(f"{len(rules)} rule(s): {len(report.errors)} error(s), {len(report.warnings)} warning(s)")
    if args.strict and report.warnings:
        return 1
    return 0 if report.ok else 1


def cmd_test(args: argparse.Namespace) -> int:
    rules = load_rules(Path(args.rules))
    report = run_all(rules)
    for r in report.results:
        if r.passed and not args.verbose:
            continue
        status = "PASS" if r.passed else "FAIL"
        detail = (
            r.error or f"expected {'match' if r.expected else 'no match'}, got {'match' if r.actual else 'no match'}"
        )
        print(f"{status}  {r.rule.name}  [{r.case}]  {'' if r.passed else detail}".rstrip())
    for p in report.problems:
        print(f"PROBLEM  {p}")
    print(report.summary())
    return 0 if report.ok else 1


def cmd_build(args: argparse.Namespace) -> int:
    from sigmasmith.compile import BACKENDS, compile_rules, write_compiled

    rules = load_rules(Path(args.rules))
    backends = args.backend or sorted(BACKENDS)
    failed = 0
    for backend in backends:
        compiled = compile_rules(rules, backend, args.pipeline)
        written = write_compiled(compiled, Path(args.out))
        errors = [c for c in compiled if not c.ok]
        failed += len(errors)
        print(f"{backend:14} {len(written)} query file(s) written, {len(errors)} failure(s)")
        for c in errors:
            print(f"  FAIL {c.rule.path.name}: {c.error}")
        if args.show:
            for c in compiled:
                if c.ok:
                    print(f"\n--- {c.rule.path.name} [{backend}]\n{c.query}")
    return 1 if failed else 0


def cmd_coverage(args: argparse.Namespace) -> int:
    rules = load_rules(Path(args.rules))
    by_tactic: dict[str, set[str]] = defaultdict(set)
    by_technique: dict[str, list[str]] = defaultdict(list)
    for r in rules:
        for t in r.tactics:
            by_tactic[t].add(r.title)
        for tech in r.techniques:
            by_technique[tech].append(r.title)
    lines = [
        "# ATT&CK coverage",
        "",
        f"{len(rules)} rules, {len(by_technique)} techniques, {len(by_tactic)} tactics.",
        "",
    ]
    lines += ["| Technique | Rules |", "|---|---|"]
    for tech in sorted(by_technique):
        link = f"https://attack.mitre.org/techniques/{tech.replace('.', '/')}/"
        lines.append(f"| [{tech}]({link}) | {'; '.join(sorted(by_technique[tech]))} |")
    lines += ["", "| Tactic | Rules |", "|---|---|"]
    for tactic in sorted(by_tactic):
        lines.append(f"| {tactic} | {len(by_tactic[tactic])} |")
    text = "\n".join(lines) + "\n"
    if args.out:
        Path(args.out).write_text(text, encoding="utf-8")
        print(f"wrote {args.out}")
    else:
        print(text)
    return 0


_TEMPLATE = """title: {title}
id: {id}
status: experimental
description: |
  Describe what the rule detects, why it matters, and what an analyst should do when it fires.
references:
  - https://attack.mitre.org/techniques/T1059/
author: {author}
date: {date}
tags:
  - attack.execution
  - attack.t1059
logsource:
  category: process_creation
  product: {product}
detection:
  selection:
    Image|endswith: '\\\\example.exe'
  condition: selection
falsepositives:
  - Describe a realistic benign scenario
level: medium
"""

_TEST_TEMPLATE = """positive:
  - name: Describe the attack event
    event:
      Image: C:\\\\Windows\\\\System32\\\\example.exe
      CommandLine: example.exe --bad
  - name: A second positive case
    event:
      Image: C:\\\\Tools\\\\example.exe
negative:
  - name: Benign process
    event:
      Image: C:\\\\Windows\\\\explorer.exe
  - name: A second negative case
    event:
      Image: C:\\\\Windows\\\\System32\\\\notepad.exe
"""


def cmd_new(args: argparse.Namespace) -> int:
    name = args.name
    if not name.endswith(".yml"):
        name += ".yml"
    target = Path(args.rules) / args.product / args.category / name
    if target.exists():
        print(f"error: {target} already exists", file=sys.stderr)
        return 1
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(
        _TEMPLATE.format(
            title=args.title or name[:-4].replace("_", " ").title(),
            id=uuid.uuid4(),
            author=args.author,
            date=date.today().isoformat(),
            product=args.product,
        ),
        encoding="utf-8",
    )
    test_path = target.with_name(target.name[:-4] + ".test.yaml")
    test_path.write_text(_TEST_TEMPLATE, encoding="utf-8")
    print(f"created {target}\ncreated {test_path}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="sigmasmith", description="Detection-as-code for Sigma rules.")
    parser.add_argument("--version", action="version", version=f"sigmasmith {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("validate", help="Check rules against SigmaHQ conventions")
    p.add_argument("--rules", default=str(DEFAULT_RULES))
    p.add_argument("--strict", action="store_true", help="Treat warnings as errors")
    p.set_defaults(func=cmd_validate)

    p = sub.add_parser("test", help="Run every rule against its sample events")
    p.add_argument("--rules", default=str(DEFAULT_RULES))
    p.add_argument("-v", "--verbose", action="store_true")
    p.set_defaults(func=cmd_test)

    p = sub.add_parser("build", help="Compile rules to SIEM queries")
    p.add_argument("--rules", default=str(DEFAULT_RULES))
    p.add_argument("--backend", nargs="*", help="splunk, elasticsearch, opensearch, kusto (default: all)")
    p.add_argument("--pipeline", nargs="*", help="pySigma pipeline names to apply (default per backend)")
    p.add_argument("--out", default="dist")
    p.add_argument("--show", action="store_true", help="Print compiled queries")
    p.set_defaults(func=cmd_build)

    p = sub.add_parser("coverage", help="ATT&CK coverage table from rule tags")
    p.add_argument("--rules", default=str(DEFAULT_RULES))
    p.add_argument("--out")
    p.set_defaults(func=cmd_coverage)

    p = sub.add_parser("new", help="Scaffold a rule and its test file")
    p.add_argument("name", help="snake_case filename, e.g. proc_creation_win_thing")
    p.add_argument("--product", default="windows")
    p.add_argument("--category", default="process_creation")
    p.add_argument("--title")
    p.add_argument("--author", default="Your Name")
    p.add_argument("--rules", default=str(DEFAULT_RULES))
    p.set_defaults(func=cmd_new)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return int(args.func(args))
    except (FileNotFoundError, ValueError, ImportError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
