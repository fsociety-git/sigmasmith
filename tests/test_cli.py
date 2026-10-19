from pathlib import Path

from sigmasmith.cli import main

ROOT = Path(__file__).resolve().parents[1]


def test_validate_and_test_commands(capsys) -> None:
    assert main(["validate", "--rules", str(ROOT / "rules")]) == 0
    assert main(["test", "--rules", str(ROOT / "rules")]) == 0
    out = capsys.readouterr().out
    assert "cases passed" in out


def test_coverage_writes_markdown(tmp_path: Path) -> None:
    out = tmp_path / "coverage.md"
    assert main(["coverage", "--rules", str(ROOT / "rules"), "--out", str(out)]) == 0
    text = out.read_text()
    assert "T1685" in text and "| Tactic |" in text


def test_new_scaffolds_a_passing_rule(tmp_path: Path) -> None:
    assert main(["new", "proc_creation_win_demo", "--rules", str(tmp_path), "--author", "Tester"]) == 0
    assert main(["validate", "--rules", str(tmp_path)]) == 0
    assert main(["test", "--rules", str(tmp_path)]) == 0
    assert main(["new", "proc_creation_win_demo", "--rules", str(tmp_path)]) == 1


def test_validate_fails_on_broken_rule(tmp_path: Path, capsys) -> None:
    (tmp_path / "bad_rule.yml").write_text("title: Broken.\nid: not-a-uuid\nlevel: huge\n")
    assert main(["validate", "--rules", str(tmp_path)]) == 1
    err = capsys.readouterr().out
    assert "UUID" in err and "level" in err and "test file" in err
