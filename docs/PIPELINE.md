# Using the pipeline in your own repository

SigmaSmith is a library and CLI; the rules here are an example pack. To run the same pipeline over your rules:

1. Put rules under `rules/<product>/<category>/`, one `.yml` per rule, each with a `.test.yaml` beside it.
2. Install: `pip install "sigmasmith[compile]"`.
3. Copy `.github/workflows/ci.yml` and adjust paths if needed.

## The stages

| Stage | Command | Fails when |
|---|---|---|
| Conventions | `sigmasmith validate --strict` | any SigmaHQ style error or warning |
| Schema | `sigma check rules` | pySigma cannot parse a rule, or a tag is not in ATT&CK |
| Logic | `sigmasmith test` | a positive event does not match, a negative event matches, or a rule has fewer than 2 of each |
| Compilation | `sigmasmith build` | any backend cannot convert a rule after all pipeline candidates |
| Coverage | `sigmasmith coverage --out dist/COVERAGE.md` | never; it produces the ATT&CK table |

## Backend pipelines

| Backend | Candidates tried in order |
|---|---|
| splunk | `splunk_windows`, then none |
| elasticsearch | `ecs_windows`, then none |
| opensearch | `ecs_windows`, then none |
| kusto | `microsoft_xdr`, then `sentinel_asim`, then none |

Override with `--pipeline <name> [<name> ...]` to force a specific mapping, for example `--backend kusto --pipeline sentinel_asim`.

## Deploying compiled queries

`dist/<backend>/<rule>.txt` files carry the rule title, id, level and pipeline in a comment header, which makes them easy to diff between releases and to load with a SIEM's API or Terraform provider. The CI uploads `dist/` as an artifact on every run so a deployment job can pick it up.
