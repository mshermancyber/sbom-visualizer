"""``sbom-scan`` — in-process CI gate that wraps the SAME logic the API uses.

Parses an SBOM, scans it (OSV + cve.org + NVD + KEV + EPSS, all cached), assesses it, and
emits text / json / sarif. No HTTP server is started — it calls ``parse_sbom``,
``scan_sbom`` and ``build_assessment`` directly.

Exit codes:
    0  PASS   — gate passed
    1  gate failed — verdict FAIL, or REVIEW when ``--fail-on`` includes ``review``, or any
                     matching ``--fail-on`` signal / denied license
    2  runtime error (bad input, parse failure, etc.)

Usage:
    sbom-scan <SBOM_PATH|-> [--policy strict|standard|lenient]
              [--fail-on kev,critical,high,review] [--license-deny GPL,AGPL]
              [--license-warn LGPL] [--format text|json|sarif] [--output FILE]
              [--no-nvd] [--no-epss] [-v|-vv|-q]
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys

from .logging_config import setup_logging
from .models import LicensePolicy
from .parsers import ParseError, parse_sbom
from .sarif import build_sarif
from .scanner import scan_sbom
from .scoring import build_assessment, classify_dependency_depth

# Map a --fail-on token to the assessment signal it gates on.
_SIGNAL_TOKENS = {"kev", "mal", "malicious", "critical", "high", "medium", "low", "review"}


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="sbom-scan",
        description="Scan an SBOM for vulnerabilities and gate CI on the result.",
    )
    p.add_argument("sbom", metavar="SBOM_PATH",
                   help="Path to an SBOM JSON file, or '-' to read stdin.")
    p.add_argument("--policy", choices=["strict", "standard", "lenient"], default="standard",
                   help="Gate policy (default: standard).")
    p.add_argument("--fail-on", default="",
                   help="Comma list of signals that force a non-zero exit: "
                        "kev,mal,critical,high,medium,low,review.")
    p.add_argument("--license-deny", default="",
                   help="Comma list of license patterns to DENY (e.g. GPL,AGPL).")
    p.add_argument("--license-warn", default="",
                   help="Comma list of license patterns to WARN on.")
    p.add_argument("--format", choices=["text", "json", "sarif"], default="text",
                   help="Output format (default: text).")
    p.add_argument("--output", "-o", default="-",
                   help="Write output to FILE instead of stdout.")
    p.add_argument("--no-nvd", action="store_true", help="Disable NVD enrichment.")
    p.add_argument("--no-epss", action="store_true", help="Disable EPSS overlay.")
    p.add_argument("-v", "--verbose", action="count", default=0,
                   help="-v INFO, -vv DEBUG logging to stderr.")
    p.add_argument("-q", "--quiet", action="store_true",
                   help="Suppress logging (ERROR only).")
    return p


def _split_csv(s: str) -> list[str]:
    return [x.strip() for x in (s or "").split(",") if x.strip()]


def _read_sbom_raw(path: str) -> object:
    if path == "-":
        data = sys.stdin.read()
    else:
        with open(path, "r", encoding="utf-8") as f:
            data = f.read()
    return json.loads(data)


def _apply_depth(sbom):
    depth_map = classify_dependency_depth(sbom)
    for i, c in enumerate(sbom.components):
        c.depth = depth_map.get(i, "unknown")
    return sbom


def _gate_exit_code(assessment, fail_on: list[str]) -> int:
    """0 PASS / 1 gate failed. ``fail-on`` maps signals → gate."""
    verdict = assessment.verdict
    tokens = {t.lower() for t in fail_on}

    # A FAIL verdict (incl. denied licenses, which fold into FAIL) always fails the gate.
    if verdict.status == "FAIL":
        return 1
    # REVIEW only fails the gate when explicitly requested.
    if verdict.status == "REVIEW" and "review" in tokens:
        return 1

    summary = assessment.summary
    signal_counts = {
        "kev": assessment.kevCount,
        "mal": assessment.maliciousCount,
        "malicious": assessment.maliciousCount,
        "critical": summary.CRITICAL,
        "high": summary.HIGH,
        "medium": summary.MEDIUM,
        "low": summary.LOW,
    }
    for tok in tokens:
        if tok == "review":
            continue
        if signal_counts.get(tok, 0) > 0:
            return 1
    # Any denied license also fails the gate.
    if any(v.rule == "deny" for v in assessment.licenseViolations):
        return 1
    return 0


def _text_report(assessment, findings, sbom) -> str:
    v = assessment.verdict
    s = assessment.summary
    r = assessment.risk
    lines: list[str] = []
    lines.append(f"VERDICT: {v.status}  (policy={v.policy})")
    if v.reasons:
        lines.append("  reasons: " + "; ".join(v.reasons))
    lines.append(f"Risk score: {r.score}/1000  grade {r.grade}  ({r.pct}%)")
    lines.append(
        f"Findings: {s.affected} affected component(s), {s.total} vuln(s)  "
        f"[CRIT {s.CRITICAL}  HIGH {s.HIGH}  MED {s.MEDIUM}  LOW {s.LOW}  "
        f"UNK {s.UNKNOWN}]"
    )
    lines.append(f"KEV: {assessment.kevCount}   Malicious: {assessment.maliciousCount}")
    if assessment.licenseViolations:
        deny = sum(1 for x in assessment.licenseViolations if x.rule == "deny")
        warn = sum(1 for x in assessment.licenseViolations if x.rule == "warn")
        lines.append(f"License: {deny} denied, {warn} flagged")
    if assessment.remediation:
        lines.append("")
        lines.append("Top remediations:")
        for item in assessment.remediation[:5]:
            kev = f", {item.kevCount} KEV" if item.kevCount else ""
            lines.append(
                f"  - {item.name} {item.currentVersion} -> {item.target}: "
                f"resolves {item.cvesResolved} CVE(s){kev} (risk -{item.riskRemoved})"
            )
    return "\n".join(lines) + "\n"


def _write(output: str, text: str) -> None:
    if output == "-":
        sys.stdout.write(text)
    else:
        with open(output, "w", encoding="utf-8") as f:
            f.write(text)


def _configure_logging(args) -> None:
    """Map -v/-vv/-q to LOG_LEVEL and (re)configure logging before the event loop starts."""
    if args.quiet:
        os.environ["LOG_LEVEL"] = "ERROR"
    elif args.verbose >= 2:
        os.environ["LOG_LEVEL"] = "DEBUG"
    elif args.verbose == 1:
        os.environ["LOG_LEVEL"] = "INFO"
    else:
        os.environ["LOG_LEVEL"] = "WARNING"
    setup_logging(force=True)


async def _run(args) -> int:
    try:
        raw = _read_sbom_raw(args.sbom)
    except (OSError, ValueError) as e:
        print(f"error: could not read SBOM: {e}", file=sys.stderr)
        return 2

    try:
        sbom, _extra = parse_sbom(raw)
    except (ParseError, ValueError, TypeError) as e:
        print(f"error: parse failure: {e}", file=sys.stderr)
        return 2

    _apply_depth(sbom)

    try:
        findings, summary, errors = await scan_sbom(
            sbom,
            kev=True,
            epss=not args.no_epss,
            mitre=True,
            nvd=not args.no_nvd,
        )
    except Exception as e:  # noqa: BLE001
        print(f"error: scan failure: {e}", file=sys.stderr)
        return 2

    license_policy = None
    deny = _split_csv(args.license_deny)
    warn = _split_csv(args.license_warn)
    if deny or warn:
        license_policy = LicensePolicy(deny=deny, warn=warn)

    assessment = build_assessment(sbom, findings, summary, policy=args.policy,
                                  license_policy=license_policy)

    if args.format == "json":
        out = json.dumps({
            "assessment": assessment.model_dump(),
            "findings": [f.model_dump() for f in findings],
            "errors": errors,
        }, indent=2)
        _write(args.output, out + "\n")
    elif args.format == "sarif":
        out = json.dumps(build_sarif(sbom, findings), indent=2)
        _write(args.output, out + "\n")
    else:
        _write(args.output, _text_report(assessment, findings, sbom))

    for err in errors:
        print(f"note: {err}", file=sys.stderr)

    return _gate_exit_code(assessment, _split_csv(args.fail_on))


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    _configure_logging(args)
    try:
        return asyncio.run(_run(args))
    except KeyboardInterrupt:
        return 2


if __name__ == "__main__":
    sys.exit(main())
