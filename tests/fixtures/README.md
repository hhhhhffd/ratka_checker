# Regression corpus

Each directory contains an `expected.json` contract for one safe, synthetic JAR.
`regression-scan` materializes the JAR into a temporary directory while running;
no fixture archive, class, script, or native file is executed.

The current scanner only exposes verdict, risk score, and findings. Capability and
obfuscation expectations are deliberately recorded now and reported as pending
assertions until the new `ScanReport` model is available.
