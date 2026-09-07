# F8 — Zero-Trust Readiness Assessment Engine

A deterministic, offline, standard-library-only **assessment engine** that
scores an organization's security posture against the four Zero-Trust pillars
of the CISA Zero Trust Maturity Model — **Identity, Device, Network,
Application** — plus per-control **evidence fields** (grounding, not claims).

## Overview

- **Evidence-driven**: every control is evaluated against a bunded evidence
  record (`{control_id: {"status": 0|1, "evidence": "..."}}`). Controls with no
  evidence entry are counted as unmet and marked `(no evidence provided)`.
- **16 controls across 4 pillars** with required/recommended flags and weights:
  - Identity: MFA, centralized IAM, lifecycle automation, risk scoring
  - Device: MDM coverage, patching, attestation, endpoint telemetry
  - Network: micro-segmentation, encryption, east-west visibility, ZTNA
  - Application: allow-listing, secure SDLC, data classification/DLP,
    behavior monitoring
- **Verdicts**: `PASS` (all required controls met, ≥75%), `PARTIAL`, `FAIL`,
  and a maturity tier (`TRADITIONAL`/`ADVANCED`/`INITIAL`/`NOT-READY`).
- **Missing-required list**: gate-blocking controls surfaced explicitly.
- Embedded fixtures: `modern` (best-in-class), `legacy` (flat/weak), `demo`
  (mid-tier), plus arbitrary `--bundle file.json`.
- Clean exit codes: `0` successful run, `1` non-PASS verdict with `--strict`
  (gate mode), `2` config error. The default demo run always exits `0`.

## CLI

```bash
python3 firmware/ztr_sandbox.py --help
python3 firmware/ztr_sandbox.py
python3 firmware/ztr_sandbox.py --fixture legacy --report reports/legacy.json
python3 firmware/ztr_sandbox.py --bundle evidence.json --strict
```

Config lives in `config.json` (pillars, pass threshold). Reports to `reports/`
(Markdown or JSON), gitignored.

## Tests

```bash
python3 -m unittest discover -s tests -v
```

## IMPORTANT: Read before use.

Provided **exclusively** for authorized security research, academic study, and
readiness assessment of organizations you own or are authorized to assess. The
engine is evidence-scoring software; it performs no access, no probing, and no
collection — but the evidence you feed it must be lawfully obtained.

### Authorization Requirements

Only assess posture for organizations/infrastructure you own or have explicit
written authorization to analyze. Gathering or correlating control evidence
(e.g., from logs, IAM exports, or network inventories) always requires a lawful
basis and applicable permissions.

### Legal Framework

Unauthorized access to or interference with computer systems is governed by the
**Computer Fraud and Abuse Act (CFAA)** (18 U.S.C. § 1030), the **EU Directive
on Attacks Against Information Systems** (2013/40/EU), and equivalent
legislation in other jurisdictions. Penalties include imprisonment and
significant fines. Exporting or reusing third-party evidence may additionally
implicate data-protection and confidentiality obligations.

### Acceptable Use

- Self-assessment and internal readiness tracking
- Authorized security audits and posture reviews with signed scope
- Academic research on ZT maturity measurement (fixtures use fictional orgs)
- Education and training

### Prohibited Use

- Assessing third-party organizations without authorization
- Using evidence feeds to make claims about organizations you have no right to evaluate
- Publishing non-public posture findings about others
- Any use that violates applicable law, license, or NDA terms

### No Warranty

This software is provided "as is" without warranty of any kind. The authors
assume no liability for damages arising from use or misuse of this tool,
including incorrect readiness conclusions drawn from self-reported evidence.

### Responsible Disclosure

If your assessment surfaces serious control gaps that affect third parties,
share the finding privately with the affected organization's security team and
allow reasonable time for remediation before any public disclosure.

## Live Lab Test Plan

1. **Demo run** — `python3 firmware/ztr_sandbox.py` scores the `demo` bundle,
   prints pillar scores with evidence lines, and exits `0`.
2. **Best-in-class baseline** — `--fixture modern` yields verdict `PASS`,
   `missing_required == []`, and exit `0` (also under `--strict`).
3. **Weak baseline** — `--fixture legacy` yields verdict `FAIL`, lists
   `id_mfa` among missing required controls, and exits `1` under `--strict`.
4. **Evidence grounding** — inline evidence strings are echoed for every
   control (asserted by `test_evidence_present_in_output`).
5. **Zero-credit default** — a bundle with no evidence scores `0.0%`.
6. **Determinism** — identical bundles produce identical output.

## Metrics

| Metric | Definition |
|--------|-----------|
| Pillars | identity / device / network / application (16 weighted controls) |
| Overall score | weighted credit / total weight, 0–100% |
| Per-pillar score | same computation restricted to one pillar |
| Required controls | must be met; unmet required → NOT-READY |
| Verdict | PASS / PARTIAL / FAIL |
| Full evidence | each control carries a grounding `evidence` field |
| Exit codes | 0 successful demo, 1 non-PASS in --strict mode, 2 config error |

Verified offline: `modern` → 100%, PASS; `legacy` → FAIL with missing required
controls; uncovered controls get zero credit.

## License

MIT License