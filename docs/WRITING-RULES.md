# Writing rules

## Start from a scaffold

```bash
sigmasmith new proc_creation_win_thing --product windows --category process_creation --author "Your Name"
```

This creates `rules/windows/process_creation/proc_creation_win_thing.yml` and the matching `.test.yaml`, both of which already pass `validate` and `test`.

## Anatomy of a good rule

```yaml
title: Log Forwarder Service Stopped or Disabled on Windows   # ≤110 chars, no trailing punctuation
id: e9cebe49-6ad3-494a-a57c-8542292bdd64                      # uuid4, generated once, never changed
status: experimental                                           # stable | test | experimental | deprecated | unsupported
description: |
  What it detects, why that matters, and what an analyst should do. Three sentences is a good length.
references:
  - https://attack.mitre.org/techniques/T1685/001/
author: Your Name
date: 2026-10-19
tags:
  - attack.defense-impairment
  - attack.t1685.001
logsource:
  category: process_creation
  product: windows
detection:
  selection_tool:
    Image|endswith: '\sc.exe'
  selection_action:
    CommandLine|contains:
      - ' stop '
      - 'start= disabled'
  service_name:
    CommandLine|contains:
      - 'winlogbeat'
  condition: all of selection_* and service_name
falsepositives:
  - Agent upgrades by software deployment tools
level: high
```

## Rules of thumb

1. **Name selections by role.** `selection_*` for what you want, `filter_*` for what you exclude. The validator warns about selections the condition never references.
2. **Prefer `endswith` on image paths** and `contains` on command lines. Avoid bare `contains` on very short strings; ` stop` is fine, `stop` alone will match `stopwatch`.
3. **Write the negative cases first.** The easiest way to find an over-broad rule is to write the benign event you expect to see a thousand times a day and watch it match.
4. **One behaviour per rule.** If you need `or` across unrelated techniques, you need two rules.
5. **Say what the analyst should do** in the description. "Investigate" is not an action.
6. **Document false positives honestly.** "Unknown" is rejected by the validator. If a hardening script will trip the rule, say so.
7. **Tag with ATT&CK v20.** The validator uses the version bundled with pySigma; `sigma check rules` will tell you if a tag does not exist.

## Test files

```yaml
positive:        # at least 2
  - name: human-readable case name
    event: { Image: ..., CommandLine: ... }
negative:        # at least 2
  - name: ...
    event: { ... }
```

Use generic Sigma field names, the same ones the rule uses. Events may contain extra fields; the matcher ignores them. Nested documents work with dotted field names (`process.name`).

## What the matcher supports

| Feature | Supported |
|---|---|
| Field maps, value lists, list-of-maps selections | yes |
| Keyword lists | yes |
| `contains`, `startswith`, `endswith`, `all` | yes |
| `re`, `cidr`, `gt`, `gte`, `lt`, `lte` | yes |
| `base64`, `base64offset`, `windash` | yes |
| `*` and `?` wildcards, case-insensitive matching, `null` | yes |
| `and`, `or`, `not`, parentheses, `1 of x*`, `all of x*`, `1 of them`, `all of them` | yes |
| Aggregations (`count() by`), `utf16`, `wide`, `fieldref` | no, raises `UnsupportedRuleError` |
