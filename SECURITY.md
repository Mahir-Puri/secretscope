# Security policy

SecretScope is a learning project that analyzes credentials and permissions. It
is not a hardened production security product. Please keep that in mind when
using it.

## Handling of secrets

The tool is designed so that a raw secret is used only long enough to compute a
redacted form and a SHA-256 fingerprint, after which the raw copy is wiped from
memory. Redacted values and short fingerprint prefixes are the only
credential-derived data that appear in output or logs. A fingerprint does not
make a leaked credential safe. If a real credential is ever exposed, rotate it.

## Reporting an issue

If you find a problem, please open an issue describing what you observed and how
to reproduce it. Do not include real credentials in a report. If you need to
show a detection, use a synthetic value like the documentation placeholder keys
used in this repository.

## Scope and limitations

The IAM analysis runs against synthetic, local fixtures. It models a small
subset of AWS authorization and is meant to demonstrate blast-radius reasoning,
not to replace a real IAM policy analyzer. See the README for the full list of
what is intentionally out of scope.
