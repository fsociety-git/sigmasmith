"""Compile rules to SIEM query languages with pySigma (optional extra: ``sigmasmith[compile]``)."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from sigmasmith.rules import Rule

# backend name -> (pySigma module, class, pipeline candidates tried in order per rule)
BACKENDS: dict[str, tuple[str, str, list[list[str]]]] = {
    "splunk": ("sigma.backends.splunk", "SplunkBackend", [["splunk_windows"], []]),
    "elasticsearch": ("sigma.backends.elasticsearch", "LuceneBackend", [["ecs_windows"], []]),
    "opensearch": ("sigma.backends.opensearch", "OpensearchLuceneBackend", [["ecs_windows"], []]),
    "kusto": ("sigma.backends.kusto", "KustoBackend", [["microsoft_xdr"], ["sentinel_asim"], []]),
}


@dataclass
class CompiledRule:
    rule: Rule
    backend: str
    query: str | None
    error: str | None = None
    pipeline: str = ""

    @property
    def ok(self) -> bool:
        return self.error is None


def _load_backend(name: str, pipelines: list[str]):
    import importlib

    from sigma.plugins import InstalledSigmaPlugins
    from sigma.processing.resolver import ProcessingPipelineResolver

    module_name, class_name, _ = BACKENDS[name]
    module = importlib.import_module(module_name)
    backend_cls = getattr(module, class_name)
    pipeline = None
    if pipelines:
        plugins = InstalledSigmaPlugins.autodiscover()
        resolver = ProcessingPipelineResolver(dict(plugins.pipelines.items()))
        pipeline = resolver.resolve(pipelines)
    return backend_cls(processing_pipeline=pipeline)


def compile_rules(rules: list[Rule], backend: str, pipelines: list[str] | None = None) -> list[CompiledRule]:
    """Compile every rule. Each rule is tried against the pipeline candidates in order and the
    first that converts cleanly wins, so a Windows-only pipeline never blocks a Linux rule."""
    if backend not in BACKENDS:
        raise ValueError(f"unknown backend '{backend}'. Known: {sorted(BACKENDS)}")
    try:
        from sigma.collection import SigmaCollection
    except ImportError as exc:  # pragma: no cover - only without the extra
        raise ImportError("pySigma is not installed. Run: pip install 'sigmasmith[compile]'") from exc

    candidates: list[list[str]] = [pipelines] if pipelines is not None else BACKENDS[backend][2]
    backends = [(cand, _load_backend(backend, cand)) for cand in candidates]
    out: list[CompiledRule] = []
    for rule in rules:
        last_error = "no pipeline candidates"
        for cand, be in backends:
            try:
                collection = SigmaCollection.from_yaml(rule.path.read_text(encoding="utf-8"))
                queries = be.convert(collection)
                query = "\n".join(str(q) for q in queries)
                if not query.strip():
                    raise ValueError("backend produced an empty query")
                out.append(CompiledRule(rule, backend, query, pipeline="+".join(cand) or "none"))
                break
            except Exception as exc:
                last_error = f"{type(exc).__name__}: {exc}"
        else:
            out.append(CompiledRule(rule, backend, None, error=last_error))
    return out


def write_compiled(compiled: list[CompiledRule], out_dir: Path) -> list[Path]:
    written: list[Path] = []
    for item in compiled:
        if not item.ok or item.query is None:
            continue
        target = out_dir / item.backend / (item.rule.path.stem + ".txt")
        target.parent.mkdir(parents=True, exist_ok=True)
        header = (
            f"# {item.rule.title}\n# id: {item.rule.id}\n# level: {item.rule.level}\n"
            f"# backend: {item.backend}\n# pipeline: {item.pipeline}\n\n"
        )
        target.write_text(header + item.query + "\n", encoding="utf-8")
        written.append(target)
    return written
