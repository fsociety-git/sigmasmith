"""SigmaSmith: detection-as-code for Sigma rules."""

from sigmasmith.matcher import UnsupportedRuleError, rule_matches
from sigmasmith.rules import Rule, load_rules, validate_rule

__all__ = ["Rule", "UnsupportedRuleError", "load_rules", "rule_matches", "validate_rule"]
__version__ = "0.1.0"
