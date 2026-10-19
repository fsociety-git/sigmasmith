# Contributing

## Setup

```bash
git clone https://github.com/fsociety-git/sigmasmith && cd sigmasmith
python -m venv .venv && source .venv/bin/activate
pip install -e ".[compile,dev]" sigma-cli
```

## Before opening a pull request

```bash
ruff check sigmasmith tests && ruff format --check sigmasmith tests
mypy sigmasmith
sigmasmith validate --strict
sigma check rules
sigmasmith test
pytest
sigmasmith build
```

## What we welcome

- New rules with at least two positive and two negative sample events, written from real observations.
- Matcher support for Sigma features that currently raise `UnsupportedRuleError`, with tests.
- Additional backends, as long as every shipped rule still compiles.

Keep sample events fictional: `.example` domains, invented hostnames, no real IP addresses outside documentation ranges.
