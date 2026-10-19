<h1 align="center">SigmaSmith</h1>

<p align="center"><b>Detection as code for Sigma rules: write, test against real events, compile to every SIEM, gate in CI.</b></p>

<p align="center">
  <a href="https://github.com/fsociety-git/sigmasmith/actions/workflows/ci.yml"><img src="https://github.com/fsociety-git/sigmasmith/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <img src="https://img.shields.io/badge/rules-10-blue" alt="Rules">
  <img src="https://img.shields.io/badge/backends-Splunk%20%7C%20Elastic%20%7C%20OpenSearch%20%7C%20Kusto-informational" alt="Backends">
  <img src="https://img.shields.io/badge/ATT%26CK-v20-red" alt="ATT&CK v20">
  <img src="https://img.shields.io/badge/license-MIT-green" alt="MIT">
</p>

---

A Sigma rule without a test is a guess. SigmaSmith makes every rule carry its own evidence: positive events it must catch, negative events it must ignore, SigmaHQ-style validation, and compilation to four query languages, all enforced on every push.

```
$ sigmasmith validate --strict
10 rule(s): 0 error(s), 0 warning(s)

$ sigmasmith test
64/64 cases passed, 0 structural problem(s)

$ sigmasmith build
elasticsearch  10 query file(s) written, 0 failure(s)
kusto          10 query file(s) written, 0 failure(s)
opensearch     10 query file(s) written, 0 failure(s)
splunk         10 query file(s) written, 0 failure(s)
```

## What is in the box

**A rule pack written from real incidents.** Ten original detections, each with references, false-positive notes, ATT&CK v20 tags, and sample events:

| Rule | Logsource | Level | Why it exists |
|---|---|---|---|
| Suspicious child process of WhatsApp Desktop | Windows process | high | Malware lures sent from a hijacked business WhatsApp account launch their interpreter from the chat client |
| Executable or script written by a messaging app | Windows file | medium | Catches the download before the execution |
| Log forwarder service stopped on Windows | Windows process | high | The event that precedes a silent SIEM log source |
| Log forwarder or audit service stopped on Linux | Linux process | high | Same, for rsyslog, auditd, filebeat, Graylog sidecar, Wazuh and friends |
| SSH daemon configuration weakened | Linux process | high | PermitRootLogin or PasswordAuthentication flipped back on |
| SSH root login accepted with password | Linux sshd | high | Proof the hardening is gone |
| Tor, torsocks or proxychains execution | Linux process | medium | Tor on a production server is never routine |
| Tor SOCKS proxy usage from command line | Windows process | medium | curl, browsers and PowerShell routed through 9050/9150 |
| DNS query for Tor onion gateway | Windows DNS | medium | Tor2web gateways reach hidden services without a Tor client |
| Web proxy access to onion gateway | Proxy | medium | The same, seen at the egress |

**A test runner that needs no SIEM.** `sigmasmith/matcher.py` is a 300-line Sigma evaluator covering selections, keyword lists, `|contains`, `|startswith`, `|endswith`, `|all`, `|re`, `|cidr`, `|base64`, `|base64offset`, `|windash`, numeric comparisons, wildcards, null checks, and full condition logic including `1 of selection_*` and `all of them`. Unsupported features raise instead of silently matching nothing.

**A validator that enforces SigmaHQ conventions.** UUID v4 ids, snake_case filenames, status and level vocabularies, date format, title length and punctuation, tag syntax, logsource presence, selections referenced by the condition, and a test file next to every rule. `--strict` turns warnings into failures.

**A compiler for four backends.** pySigma with per-backend pipeline fallbacks, so a Linux rule is not blocked by a Windows-only field mapping. Compiled queries land in `dist/<backend>/` with the rule id and level in a header.

**A coverage matrix.** `sigmasmith coverage` writes an ATT&CK technique and tactic table from the tags.

## Quick start

```bash
pip install "sigmasmith[compile]"
git clone https://github.com/fsociety-git/sigmasmith && cd sigmasmith

sigmasmith validate --strict   # conventions
sigmasmith test                # sample events through the matcher
sigmasmith build --show        # SPL, Lucene, OpenSearch, KQL
sigmasmith coverage            # ATT&CK table
```

Write a new rule with a scaffolded test file:

```bash
sigmasmith new proc_creation_win_my_detection --product windows --category process_creation --author "Your Name"
```

## How a rule is tested

Every `rule.yml` has a sibling `rule.test.yaml`:

```yaml
positive:
  - name: sc stop winlogbeat
    event:
      Image: C:\Windows\System32\sc.exe
      CommandLine: sc.exe stop winlogbeat
negative:
  - name: sc start winlogbeat
    event:
      Image: C:\Windows\System32\sc.exe
      CommandLine: sc.exe start winlogbeat
```

Field names follow the Sigma generic taxonomy (`Image`, `CommandLine`, `ParentImage`, `TargetFilename`, `QueryName`, `cs-host`, `c-uri`), so the same events stay valid when the rule is compiled for any backend. Each rule needs at least two positive and two negative cases; the CI fails otherwise.

## Pipeline

```
rules/**/*.yml ──▶ validate (conventions) ──▶ sigma check (pySigma) ──▶ test (matcher)
                                                                           │
                              dist/{splunk,elasticsearch,opensearch,kusto} ◀─┘ build
```

The GitHub Actions workflow runs this on Python 3.10 through 3.13 and uploads the compiled queries as an artifact. See [docs/PIPELINE.md](docs/PIPELINE.md) for wiring it into your own repository, and [docs/WRITING-RULES.md](docs/WRITING-RULES.md) for the authoring guide.

## Upstreaming to SigmaHQ

The rules follow the SigmaHQ style guide so they can be submitted as-is. The validator here is deliberately a superset of the upstream checks: if `sigmasmith validate --strict` and `sigma check` are both clean, the upstream review will be about detection logic, not formatting.

## Python API

```python
from pathlib import Path
from sigmasmith import load_rules, rule_matches

rules = load_rules(Path("rules"))
event = {"Image": r"C:\Windows\System32\sc.exe", "CommandLine": "sc stop winlogbeat"}
hits = [r.title for r in rules if rule_matches(r.data, event)]
```

## Design notes

- The matcher is for *testing*. It is not a SIEM and does not pretend to be one. It exists so that a rule's logic can be checked in milliseconds, in CI, with no infrastructure.
- Pipelines are tried in order per rule (`microsoft_xdr`, then `sentinel_asim`, then none for Kusto). The pipeline used is recorded in each compiled file.
- ATT&CK tags are validated against the ATT&CK version bundled with pySigma, currently v20, which is why `defense-impairment` and `T1685` appear instead of the older `defense-evasion` and `T1562`.

## Contributing

New rules with tests are the most valuable contribution. Run `sigmasmith validate --strict && sigmasmith test` before opening a pull request. See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

MIT. Built by [Aman Sonkamble](https://amansploit.com).
