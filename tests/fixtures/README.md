# Regression corpus

Each directory contains an `expected.json` contract. Legacy synthetic scenarios
are materialized into a temporary directory; a directory containing `fixture.jar`
is scanned directly. No fixture archive, class, script, or native file is executed.

The current scanner only exposes verdict, risk score, and findings. Capability and
obfuscation expectations are deliberately recorded now and reported as pending
assertions until the new `ScanReport` model is available.
