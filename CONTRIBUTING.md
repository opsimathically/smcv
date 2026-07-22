# Contributing to SMCV

Read `AGENTS.md` and the active phase plan before making changes.

## Required local check

Run:

```sh
./scripts/check.sh
```

The check formats nothing and fails on formatting, lint, test, documentation,
dependency advisory/license, local-link, or obvious secret-pattern failures.
Use synthetic credentials and recovery material in every fixture.

Phase 5 operational checks also run with:

```sh
./scripts/operations-smoke.sh
./scripts/build-release.sh
./scripts/verify-release.sh dist/smcv-0.1.0-x86_64-unknown-linux-gnu.tar.gz
```

## Architecture

- `smcv-core` contains domain types and ports and has no HTTP or SQLite
  dependency.
- `smcv-crypto` contains reviewed cryptographic adapters.
- `smcv-storage` contains SQLite adapters and never owns authorization policy.
- `smcv-app` coordinates use cases across domain ports.
- `smcv-server` and `smcv-cli` are ingress binaries.

Dependency direction points inward. An ingress or persistence adapter cannot
bypass application authorization to decrypt protected values.
