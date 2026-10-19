# Security policy

SigmaSmith processes YAML rule files and sample events with `yaml.safe_load` and never executes rule content. If you find a way to make the validator, matcher or compiler execute code, read files outside the rules directory, or misreport a result, email aman.s.732002@gmail.com with the subject `SigmaSmith security`. You will get a reply within 72 hours.

A rule that misses an attack is a detection gap, not a security issue; open a pull request with a failing positive case.
