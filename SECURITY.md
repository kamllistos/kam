# Security policy

kam is a security tool, so a flaw in it can hide a real risk. Thank you for reporting carefully.

## Reporting a vulnerability

**Please do not open a public issue.** Report privately through GitHub:
[Report a vulnerability](https://github.com/kamllistos/kam/security/advisories/new).

Include what you ran, what happened, and what you expected. For a missed finding, include a
minimal plan JSON or Terraform snippet with account IDs and names removed.

You can expect an acknowledgement within 7 days. Fixes are released as a new version, and
reporters are credited in the advisory unless they prefer otherwise.

## What counts

- kam reports **no** finding for a change that grants dangerous access (a false negative)
- kam crashes, hangs or behaves unsafely on crafted plan input
- anything in the release or install path (GitHub Action, Homebrew cask, binaries) that could
  let someone tamper with what users run

A harmless change being flagged (a false positive) is not a vulnerability. Please open a
[wrong result issue](https://github.com/kamllistos/kam/issues/new?template=wrong_result.yml) instead.

## Supported versions

Only the latest release receives fixes.
