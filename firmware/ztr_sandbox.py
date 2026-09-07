#!/usr/bin/env python3
"""
F8 — Zero-Trust Readiness Assessment Engine.

Scores an organization's security posture against the four Zero-Trust pillars
of the CISA Zero Trust Maturity Model (Identity, Device, Network, Application —
plus Data), using an evidence bundle of controls, and returns per-pillar
scores, an overall readiness percentage, a maturity tier, and a PASS/PARTIAL/FAIL
verdict with evidence fields for every control.

The engine consumes *evidence*, not claims: each control carries grounding
(e.g. "MFA enforced org-wide via signed policy"), so the readiness verdict is
traceable. Deterministic and fully offline - standard library only.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

# --------------------------------------------------------------------------- #
# Pillar/control definitions (CISA ZTMM-aligned).
#   Each control: {id, name, weight, required (bool)}
# --------------------------------------------------------------------------- #
PILLARS = {
    "identity": {
        "label": "Identity",
        "controls": [
            {"id": "id_mfa", "name": "MFA enforced for all user access",
             "weight": 1.0, "required": True},
            {"id": "id_iam", "name": "Centralized IAM / least-privilege",
             "weight": 0.8, "required": True},
            {"id": "id_lifecycle", "name": "Leaver/mover lifecycle automated",
             "weight": 0.4, "required": False},
            {"id": "id_risk", "name": "Continuous authN risk scoring",
             "weight": 0.4, "required": False},
        ],
    },
    "device": {
        "label": "Device",
        "controls": [
            {"id": "dev_mdm", "name": "MDM/device inventory coverage",
             "weight": 1.0, "required": True},
            {"id": "dev_patch", "name": "Automated patching across fleet",
             "weight": 0.7, "required": True},
            {"id": "dev_attest", "name": "Device attestation before access",
             "weight": 0.5, "required": False},
            {"id": "dev_vuln", "name": "OS/app telemetry from endpoints",
             "weight": 0.4, "required": False},
        ],
    },
    "network": {
        "label": "Network",
        "controls": [
            {"id": "net_seg", "name": "Micro-segmentation / deny-by-default",
             "weight": 1.0, "required": True},
            {"id": "net_enc", "name": "Encrypted traffic everywhere",
             "weight": 0.7, "required": True},
            {"id": "net_eastwest", "name": "East-west traffic visibility",
             "weight": 0.5, "required": False},
            {"id": "net_access", "name": "Per-session network access (ZTNA)",
             "weight": 0.5, "required": False},
        ],
    },
    "application": {
        "label": "Application",
        "controls": [
            {"id": "app_allowlist", "name": "App allow-listing / no broad install",
             "weight": 1.0, "required": True},
            {"id": "app_sec", "name": "Secure SDLC with gates",
             "weight": 0.7, "required": True},
            {"id": "app_data", "name": "Data classification + DLP",
             "weight": 0.6, "required": False},
            {"id": "app_monitor", "name": "App-level behavioral monitoring",
             "weight": 0.4, "required": False},
        ],
    },
}

PILLAR_ORDER = ["identity", "device", "network", "application"]


# --------------------------------------------------------------------------- #
# Evidence bundles (synthetic; fictional orgs).
# --------------------------------------------------------------------------- #
EVIDENCE_MODERN = {
    "org": "acme-modern.example",
    "identity": {
        "id_mfa": {"status": 1, "evidence": "Org-wide MFA, policy signed"},
        "id_iam": {"status": 1, "evidence": "Central SSO + PAM"},
        "id_lifecycle": {"status": 1, "evidence": "Automated joiner/leaver"},
        "id_risk": {"status": 1, "evidence": "Continuous authN risk scoring"},
    },
    "device": {"dev_mdm": {"status": 1, "evidence": "MDM covers 100% fleet"},
               "dev_patch": {"status": 1, "evidence": "30-day patch SLA"},
               "dev_attest": {"status": 1, "evidence": "Attestation pre-access"},
               "dev_vuln": {"status": 1, "evidence": "EDR telemetry everywhere"}},
    "network": {"net_seg": {"status": 1,
                            "evidence": "Zero-trust segmentation live"},
                "net_enc": {"status": 1, "evidence": "TLS everywhere"},
                "net_eastwest": {"status": 1, "evidence": "Lateral visibility"},
                "net_access": {"status": 1, "evidence": "ZTNA per-session"}},
    "application": {"app_allowlist": {"status": 1,
                                      "evidence": "AppLocker allow policies"},
                    "app_sec": {"status": 1, "evidence": "Gated CI/CD SDLC"},
                    "app_data": {"status": 1, "evidence": "DLP + classification"},
                    "app_monitor": {"status": 1, "evidence": "App behavior monitoring"}},
}

EVIDENCE_LEGACY = {
    "org": "legacy-corp.example",
    "identity": {"id_mfa": {"status": 0, "evidence": "VPN-only MFA, no SSO"},
                 "id_iam": {"status": 0, "evidence": "Local admin accounts"}},
    "device": {"dev_mdm": {"status": 0, "evidence": "BYOD unmanaged"}},
    "network": {"net_seg": {"status": 0,
                            "evidence": "Flat VLAN, implicit trust"}},
    "application": {"app_allowlist": {"status": 0, "evidence": "Admins install anything"}},
}


def _default_evidence():
    # A mid-tier default demo bundle: some pillars met, some not.
    return {
        "org": "demo-org.example",
        "identity": {"id_mfa": {"status": 1, "evidence": "MFA on SaaS"},
                     "id_lifecycle": {"status": 1,
                                       "evidence": "Leaver offboarding weekly"}},
        "device": {"dev_mdm": {"status": 1, "evidence": "Forensic image"} },
        "network": {"net_enc": {"status": 1, "evidence": "Traffic encrypted"},
                    "net_eastwest": {"status": 0, "evidence": "IDS feeds raw"}},
        "application": {"app_allowlist": {"status": 0,
                                           "evidence": "Users install freely"}},
    }


# --------------------------------------------------------------------------- #
# Assessment engine.
# --------------------------------------------------------------------------- #
def assess(bundle, pillars=None):
    """Score one evidence bundle against the pillar/control model.

    Args:
      bundle: dict mapping pillar -> {control_id -> {status, evidence}}
      pillars: optional dict to override PILLARS (for tests).

    Returns dict with per-pillar score/evidence + overall verdict.
    """
    pillars = pillars or PILLARS
    per_pillar = []
    missing_required = []
    total_weight = 0.0
    total_credit = 0.0

    for key in PILLAR_ORDER:
        spec = pillars[key]
        evidence_block = bundle.get(key, {})
        p_w = 0.0
        p_credit = 0.0
        details = []
        for control in spec["controls"]:
            w = control["weight"]
            p_w += w
            total_weight += w
            rec = evidence_block.get(control["id"])
            if rec is None:
                # no evidence at all -> treated as not met, with a flag
                p_credit += 0.0
                details.append({"control": control["id"],
                                "name": control["name"], "status": 0,
                                "evidence": "(no evidence provided)"})
                if control["required"]:
                    missing_required.append(control["id"])
                continue
            status = 1 if rec.get("status") else 0
            p_credit += w * status
            total_credit += w * status
            details.append({"control": control["id"],
                            "name": control["name"], "status": status,
                            "evidence": rec.get("evidence", "")})
            if not status and control["required"]:
                missing_required.append(control["id"])
        per_pillar.append({
            "pillar": key,
            "label": spec["label"],
            "score": round(100 * p_credit / p_w, 1) if p_w else 0.0,
            "controls": details,
            "met": sum(1 for d in details if d["status"]),
            "total": len(details),
        })

    overall = round(100 * total_credit / total_weight, 1) if total_weight else 0.0
    if missing_required:
        tier = "NOT-READY"
        verdict = "FAIL"
    elif overall >= 75:
        tier = "INITIAL"
        verdict = "PASS"
    elif overall >= 50:
        tier = "ADVANCED"
        verdict = "PARTIAL"
    else:
        tier = "TRADITIONAL"
        verdict = "FAIL"

    return {
        "org": bundle.get("org", "?(unnamed)"),
        "overall": overall,
        "tier": tier,
        "verdict": verdict,
        "missing_required": sorted(set(missing_required)),
        "pillars": per_pillar,
        "control_total": int(total_weight),
    }


# --------------------------------------------------------------------------- #
# CLI / report.
# --------------------------------------------------------------------------- #
def main(argv=None):
    ap = argparse.ArgumentParser(
        prog="f8-ztr-sandbox",
        description="Zero-trust readiness assessment: score posture against "
                    "ZT pillars (identity/device/network/application) with "
                    "evidence fields.",
    )
    ap.add_argument("--bundle", default=None,
                    help="path to an evidence-bundle JSON (overrides demo bundle)")
    ap.add_argument("--fixture", choices=["modern", "legacy", "demo"],
                    default=None,
                    help="select an embedded evidence fixture to assess")
    ap.add_argument("--config", default="config.json")
    ap.add_argument("--report", default="reports/report.md")
    ap.add_argument("--strict", action="store_true",
                    help="exit 1 when the verdict is not PASS (gate mode)")
    ap.add_argument("--verbose", "-v", action="store_true")
    args = ap.parse_args(argv)

    cfg = {}
    cfg_path = Path(args.config)
    if cfg_path.exists():
        try:
            cfg = json.loads(cfg_path.read_text())
        except json.JSONDecodeError:
            print("[config] parse error in %s" % cfg_path, file=sys.stderr)
            return 2

    if args.bundle:
        bundle = json.loads(Path(args.bundle).read_text())
    elif args.fixture == "modern":
        bundle = EVIDENCE_MODERN
    elif args.fixture == "legacy":
        bundle = EVIDENCE_LEGACY
    else:
        bundle = _default_evidence()

    result = assess(bundle)

    banner = "=" * 62 + "\n  F8 - ZERO-TRUST READINESS ASSESSMENT\n" + "=" * 62
    lines = [banner,
             "  Organization : %s" % result["org"],
             "  Overall      : %.1f%%  [%s]  verdict %s" %
             (result["overall"], result["tier"], result["verdict"]),
             ""]
    for p in result["pillars"]:
        lines.append("  [%s] score=%.1f%%  (met %d/%d controls)"
                     % (p["label"].upper(), p["score"], p["met"], p["total"]))
        for c in p["controls"]:
            mark = "OK " if c["status"] else "-- "
            lines.append("    %s %-12s %s" % (mark, c["control"], c["name"]))
            lines.append("            evidence: %s" % c["evidence"])
    lines.append("")
    if result["missing_required"]:
        lines.append("  !! MISSING REQUIRED CONTROLS: %s"
                     % ", ".join(result["missing_required"]))
    else:
        lines.append("  all required controls present (evidence-backed)")
    text = "\n".join(lines)

    out = Path(args.report)
    out.parent.mkdir(parents=True, exist_ok=True)
    if args.report.endswith(".json"):
        out.write_text(json.dumps(result, indent=2))
    else:
        out.write_text(text)
    print(text)

    # 0 = successful run, 1 = not-PASS verdict (--strict only), 2 = config error.
    if result["verdict"] != "PASS" and args.strict:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())