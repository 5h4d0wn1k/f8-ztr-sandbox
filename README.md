> **⚠️ EDUCATIONAL USE ONLY — AUTHORIZED TESTING ONLY.**
> This project exists for education, research, and **defense of systems you own
> or hold explicit written authorization to assess**. Unauthorized use is
> prohibited and may be illegal. Read [ETHICS.md](ETHICS.md) and
> [SCOPE.md](SCOPE.md) before use. Use at your own risk; **AS IS**, no warranty.

# F8 — Zero-Trust Readiness Assessment Engine

![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)
![GitHub stars](https://img.shields.io/github/stars/5h4d0wn1k/f8-ztr-sandbox)
![Last commit](https://img.shields.io/github/last-commit/5h4d0wn1k/f8-ztr-sandbox)
![GitHub issues](https://img.shields.io/github/issues/5h4d0wn1k/f8-ztr-sandbox)

Deterministic, offline, standard-library-only **zero-trust assessment engine** that scores an organization's security posture against the four CISA Zero Trust Maturity Model pillars — Identity, Device, Network, Application — with per-control evidence grounding and PASS/PARTIAL/FAIL verdicts.

## Why

Zero-trust security is a maturity journey, not a checkbox. F8 turns posture review into an **evidence-driven readiness audit**: every control is scored against a grounding record, so a "PASS" means documented proof, not a claim. Built for authorized security assessments, academic research, and internal readiness tracking, the engine runs fully offline on Python's standard library and consumes only identity/resource fixtures you lawfully possess. It supports gap analysis for micro-segmentation, MFA, MDM pacing, and ZTNA — surfacing gate-blocking missing-required controls so remediation orders are explicit, measurable, and repeatable.

## Features

- **16 weighted controls across 4 CISA-aligned pillars** (Identity, Device, Network, Application) with `required`/`recommended` flags.
- **Evidence grounding** — each control carries a `control_id → status/evidence` record; missing evidence counts as unmet.
- **Verdicts & tiers** — `PASS`/`PARTIAL`/`FAIL` plus maturity tier (`TRADITIONAL`/`ADVANCED`/`INITIAL`/`NOT-READY`).
- **Missing-required list** — gate-blocking controls surfaced explicitly for remediation.
- **Embedded fixtures** — `modern` (best-in-class), `legacy` (flat/weak), `demo` (mid-tier), plus arbitrary `--bundle file.json`.
- **Gate-mode exit codes** — `0` clean run, `1` non-PASS under `--strict`, `2` config error.
- **Markdown or JSON reports** to `reports/` (gitignored).

## Quickstart

```bash
# Help
python3 firmware/ztr_sandbox.py --help

# Default demo run (scores the demo bundle, exits 0)
python3 firmware/ztr_sandbox.py

# Score a fixture and write a report
python3 firmware/ztr_sandbox.py --fixture legacy --report reports/legacy.json

# Gate mode against your own evidence bundle
python3 firmware/ztr_sandbox.py --bundle evidence.json --strict
```

Config lives in [`config.json`](config.json) (pillars, pass threshold). Reports are written as Markdown or JSON to `reports/`.

```bash
# Run the test suite
python3 -m unittest discover -s tests -v
```

## Project structure

```
f8-ztr-sandbox/
├── firmware/           # ztr_sandbox.py — the assessment engine (stdlib only)
├── tests/              # unittest suite (10 tests)
├── config.json         # pillars + pass threshold
├── ETHICS.md, SCOPE.md # authorized-use & scope rules
└── reports/            # generated reports (gitignored)
```

## Documentation

- [ETHICS.md](ETHICS.md) — authorized-use policy
- [SCOPE.md](SCOPE.md) — scope of assessment
- [SECURITY.md](SECURITY.md) — security policy
- [CONTRIBUTING.md](CONTRIBUTING.md) — contribution guide

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Read [ETHICS.md](ETHICS.md) and [SCOPE.md](SCOPE.md) before changing behavior.

## License

MIT. See [LICENSE](LICENSE).