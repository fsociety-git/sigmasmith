import base64

import pytest

from sigmasmith.matcher import UnsupportedRuleError, evaluate_condition, rule_matches


def _rule(detection: dict) -> dict:
    return {"detection": detection}


def test_exact_and_case_insensitive() -> None:
    rule = _rule({"sel": {"Image": "C:\\Windows\\cmd.exe"}, "condition": "sel"})
    assert rule_matches(rule, {"Image": "c:\\windows\\CMD.EXE"})
    assert not rule_matches(rule, {"Image": "c:\\windows\\cmd.exe.bak"})


def test_list_is_or_and_all_modifier_is_and() -> None:
    rule = _rule({"sel": {"CommandLine|contains": ["foo", "bar"]}, "condition": "sel"})
    assert rule_matches(rule, {"CommandLine": "x bar y"})
    rule_all = _rule({"sel": {"CommandLine|contains|all": ["foo", "bar"]}, "condition": "sel"})
    assert not rule_matches(rule_all, {"CommandLine": "x bar y"})
    assert rule_matches(rule_all, {"CommandLine": "foo and bar"})


def test_startswith_endswith_wildcards() -> None:
    assert rule_matches(_rule({"s": {"Image|endswith": "\\a.exe"}, "condition": "s"}), {"Image": "C:\\x\\A.EXE"})
    assert rule_matches(_rule({"s": {"Image|startswith": "C:\\x"}, "condition": "s"}), {"Image": "c:\\x\\a.exe"})
    assert rule_matches(_rule({"s": {"Image": "C:\\*\\a.exe"}, "condition": "s"}), {"Image": "C:\\deep\\path\\a.exe"})
    assert rule_matches(_rule({"s": {"Image": "C:\\?\\a.exe"}, "condition": "s"}), {"Image": "C:\\x\\a.exe"})


def test_regex_cidr_and_numeric_modifiers() -> None:
    assert rule_matches(
        _rule({"s": {"CommandLine|re": r"\d{3}-\d{4}"}, "condition": "s"}), {"CommandLine": "x 555-1234"}
    )
    assert rule_matches(_rule({"s": {"src_ip|cidr": "10.0.0.0/8"}, "condition": "s"}), {"src_ip": "10.1.2.3"})
    assert not rule_matches(_rule({"s": {"src_ip|cidr": "10.0.0.0/8"}, "condition": "s"}), {"src_ip": "192.168.1.1"})
    assert rule_matches(_rule({"s": {"EventID|gte": 4624}, "condition": "s"}), {"EventID": 4625})
    assert not rule_matches(_rule({"s": {"EventID|lt": 4624}, "condition": "s"}), {"EventID": 4625})


def test_base64_and_base64offset() -> None:
    payload = "Invoke-Mimikatz"
    rule = _rule({"s": {"CommandLine|base64offset|contains": payload}, "condition": "s"})
    for prefix in ("", "x", "xy"):
        encoded = base64.b64encode((prefix + payload + " tail").encode()).decode()
        assert rule_matches(rule, {"CommandLine": f"powershell -enc {encoded}"}), prefix
    plain = _rule({"s": {"CommandLine|base64|contains": "abc"}, "condition": "s"})
    assert rule_matches(plain, {"CommandLine": base64.b64encode(b"abc").decode()})


def test_windash() -> None:
    rule = _rule({"s": {"CommandLine|windash|contains": " -enc "}, "condition": "s"})
    assert rule_matches(rule, {"CommandLine": "powershell /enc abc"})
    assert rule_matches(rule, {"CommandLine": "powershell -enc abc"})


def test_null_and_missing_fields() -> None:
    rule = _rule({"s": {"ParentImage": None}, "condition": "s"})
    assert rule_matches(rule, {"Image": "x"})
    assert not rule_matches(rule, {"Image": "x", "ParentImage": "y"})


def test_keywords_and_nested_fields() -> None:
    rule = _rule({"keywords": ["Accepted password for root"], "condition": "keywords"})
    assert rule_matches(rule, {"log": {"message": "sshd: Accepted password for ROOT from 1.2.3.4"}})
    assert not rule_matches(rule, {"log": {"message": "Accepted publickey for root"}})
    nested = _rule({"s": {"process.name": "cmd.exe"}, "condition": "s"})
    assert rule_matches(nested, {"process": {"name": "CMD.EXE"}})


def test_list_of_maps_selection_is_or() -> None:
    rule = _rule({"s": [{"a": 1}, {"b": 2}], "condition": "s"})
    assert rule_matches(rule, {"b": 2})
    assert not rule_matches(rule, {"a": 2})


def test_conditions() -> None:
    results = {"a": True, "b": False, "sel_x": True, "sel_y": False, "filter": True}
    assert evaluate_condition("a and not b", results)
    assert evaluate_condition("(a or b) and not (b and a)", results)
    assert evaluate_condition("1 of sel_*", results)
    assert not evaluate_condition("all of sel_*", results)
    assert evaluate_condition("1 of them", results)
    assert not evaluate_condition("all of them", results)
    assert not evaluate_condition("1 of sel_* and not filter", results)


def test_condition_list_is_or() -> None:
    rule = _rule({"a": {"x": 1}, "b": {"y": 2}, "condition": ["a", "b"]})
    assert rule_matches(rule, {"y": 2})


def test_unsupported_features_raise() -> None:
    with pytest.raises(UnsupportedRuleError):
        rule_matches(_rule({"s": {"x|utf16": "a"}, "condition": "s"}), {"x": "a"})
    with pytest.raises(UnsupportedRuleError):
        rule_matches(_rule({"s": {"x": 1}, "condition": "s | count() > 5"}), {"x": 1})
    with pytest.raises(UnsupportedRuleError):
        evaluate_condition("nope", {"a": True})
    with pytest.raises(UnsupportedRuleError):
        evaluate_condition("1 of zzz*", {"a": True})
    with pytest.raises(UnsupportedRuleError):
        evaluate_condition("(a", {"a": True})
