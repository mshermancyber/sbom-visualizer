"""Self-contained HTML report — port of the demo's buildHtmlReport.

Operates on the contract models (Sbom, findings, summary, assessment). Output is a single
static HTML document with inline styles, safe for download / "Save as PDF".
"""
from __future__ import annotations

import datetime
from urllib.parse import quote

from .models import Assessment, Finding, Sbom, Summary
from .scoring import cwe_name

_SEV_COLOR = {"CRITICAL": "#cc0000", "HIGH": "#e53935", "MEDIUM": "#f57c00",
              "LOW": "#f9a825", "NONE": "#388e3c", "UNKNOWN": "#388e3c"}
_VERDICT_BORDER = {"FAIL": "#cc0000", "REVIEW": "#f57c00", "PASS": "#388e3c"}
_VERDICT_BG = {"FAIL": "#fff0f0", "REVIEW": "#fff8ec", "PASS": "#f0fbf2"}
_VERDICT_ICON = {"FAIL": "&#10005;", "REVIEW": "!", "PASS": "&#10003;"}
_VERDICT_LABEL = {"FAIL": "FAIL — do not ship", "REVIEW": "REVIEW needed", "PASS": "PASS"}
_GRADE_COLOR = {"A": "#388e3c", "B": "#f57c00", "C": "#f57c00", "D": "#e53935", "F": "#e53935"}


def esc(s) -> str:
    return (str(s if s is not None else "")
            .replace("&", "&amp;").replace("<", "&lt;")
            .replace(">", "&gt;").replace('"', "&quot;"))


def _coverage_reasons(cov) -> str:
    parts = []
    if cov.oci:
        parts.append(f"{cov.oci} OCI image{'s' if cov.oci != 1 else ''}")
    if cov.devel:
        parts.append(f"{cov.devel} dev/pseudo-version")
    if cov.noId:
        parts.append(f"{cov.noId} with no name/PURL")
    if cov.other:
        parts.append(f"{cov.other} unqueryable")
    return ", ".join(parts)


def build_html_report(sbom: Sbom, findings: list[Finding], summary: Summary,
                      assessment: Assessment) -> str:
    ts = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    verdict = assessment.verdict
    cov = assessment.coverage
    risk = assessment.risk
    mal_count = assessment.maliciousCount
    kev_count = assessment.kevCount
    plan = assessment.remediation
    grade_color = _GRADE_COLOR.get(risk.grade, "#666")

    depth_by_idx = {f.componentIndex: sbom.components[f.componentIndex].depth
                    for f in findings if 0 <= f.componentIndex < len(sbom.components)}

    # Vuln rows
    vuln_rows = []
    for f in findings:
        if not (0 <= f.componentIndex < len(sbom.components)):
            continue
        c = sbom.components[f.componentIndex]
        dep = depth_by_idx.get(f.componentIndex)
        dep_html = (f'<br><span style="font-size:10px;color:#888">{esc(dep)}</span>'
                    if dep and dep != "unknown" else "")
        for v in f.vulns:
            sev = v.cvss.severity or "UNKNOWN"
            cve_html = (f'<br><strong>{esc(v.cveId)}</strong>'
                        if v.cveId and v.cveId != v.id else "")
            mal_html = ('<br><strong style="color:#cc0000">&#9760; MALICIOUS</strong>'
                        if v.malicious else "")
            fixed_html = (f'<strong style="color:#1a7f37">{esc(", ".join(v.fixed))}</strong>'
                          if v.fixed else "—")
            cwe_html = esc(", ".join(cwe_name(x) for x in v.cwes)) if v.cwes else "—"
            kev_html = '<strong style="color:#cc0000">&#9889; YES</strong>' if v.kev else "—"
            desc = esc(v.description[:180]) + ("…" if len(v.description) > 180 else "")
            vuln_rows.append(
                f'<tr><td><strong>{esc(c.name)}</strong><br>'
                f'<span style="font-size:11px;color:#666">{esc(c.version)}</span>{dep_html}</td>'
                f'<td><a href="https://osv.dev/vulnerability/{quote(v.id)}" target="_blank" '
                f'rel="noopener noreferrer"><strong>{esc(v.id)}</strong></a>{cve_html}{mal_html}</td>'
                f'<td><span style="font-weight:700;color:{_SEV_COLOR.get(sev, "#388e3c")}">{esc(sev)}</span></td>'
                f'<td>{fixed_html}</td>'
                f'<td style="font-size:11px">{cwe_html}</td>'
                f'<td>{kev_html}</td>'
                f'<td style="max-width:280px;font-size:12px">{desc}</td></tr>'
            )

    comp_rows = "".join(
        f'<tr><td>{esc(c.name)}</td><td>{esc(c.version)}</td><td>{esc(c.type)}</td>'
        f'<td style="font-size:11px">{esc(", ".join(c.licenses) or "—")}</td>'
        f'<td style="font-size:11px;word-break:break-all">{esc(c.purl or "—")}</td></tr>'
        for c in sbom.components[:200]
    )

    clean = summary.scanned - summary.affected

    verdict_html = (
        f'<div style="display:flex;align-items:center;gap:16px;border:3px solid '
        f'{_VERDICT_BORDER[verdict.status]};background:{_VERDICT_BG[verdict.status]};'
        f'border-radius:10px;padding:14px 20px;margin-bottom:20px">'
        f'<div style="font-size:30px;font-weight:900;color:{_VERDICT_BORDER[verdict.status]}">'
        f'{_VERDICT_ICON[verdict.status]}</div><div>'
        f'<div style="font-size:18px;font-weight:800;color:{_VERDICT_BORDER[verdict.status]}">'
        f'{_VERDICT_LABEL[verdict.status]}</div>'
        f'<div style="font-size:12px;color:#555;margin-top:2px">{esc(" · ".join(verdict.reasons))}</div>'
        f'</div></div>'
    )

    mal_html = (
        f'<div style="border:2px solid #cc0000;background:#fff0f0;border-radius:8px;'
        f'padding:12px 16px;margin-bottom:20px;color:#cc0000;font-weight:700">'
        f'&#9760; {mal_count} known-malicious package finding{"s" if mal_count != 1 else ""} '
        f'— remove immediately.</div>' if mal_count else ""
    )

    kev_block = (
        f'<div><div style="font-size:10px;text-transform:uppercase;letter-spacing:0.8px;'
        f'color:#999;margin-bottom:6px">CISA KEV</div>'
        f'<span style="font-size:28px;font-weight:700;color:#cc0000">&#9889; {kev_count}</span></div>'
        if kev_count else ""
    )

    risk_html = (
        f'<div style="display:flex;align-items:center;gap:20px;margin-bottom:24px;flex-wrap:wrap">'
        f'<div><div style="font-size:10px;text-transform:uppercase;letter-spacing:0.8px;'
        f'color:#999;margin-bottom:6px">Risk Grade</div>'
        f'<span class="grade-badge">{risk.grade}</span></div>'
        f'<div><div style="font-size:10px;text-transform:uppercase;letter-spacing:0.8px;'
        f'color:#999;margin-bottom:6px">Risk Score</div>'
        f'<span style="font-size:28px;font-weight:700;color:{grade_color}">{risk.score} / 1000</span></div>'
        f'{kev_block}</div>'
    )

    summary_cards = (
        f'<div class="scard"><div class="num">{len(sbom.components)}</div><div class="lbl">Components</div></div>'
        f'<div class="scard" style="border-color:#cc000040"><div class="num" style="color:#cc0000">{summary.CRITICAL}</div><div class="lbl">Critical</div></div>'
        f'<div class="scard" style="border-color:#e5393540"><div class="num" style="color:#e53935">{summary.HIGH}</div><div class="lbl">High</div></div>'
        f'<div class="scard" style="border-color:#f57c0040"><div class="num" style="color:#f57c00">{summary.MEDIUM}</div><div class="lbl">Medium</div></div>'
        f'<div class="scard" style="border-color:#f9a82540"><div class="num" style="color:#f9a825">{summary.LOW}</div><div class="lbl">Low</div></div>'
        f'<div class="scard" style="border-color:#38a16940"><div class="num" style="color:#388e3c">{clean}</div><div class="lbl">Clean</div></div>'
    )

    plan_html = ""
    if plan:
        rows = "".join(
            f'<tr><td>{i + 1}</td><td><strong>{esc(p.name)}</strong></td>'
            f'<td><span style="color:#999">{esc(p.currentVersion or "?")}</span> → '
            f'<strong style="color:#1a7f37">{esc(p.target)}</strong></td>'
            f'<td>{p.cvesResolved}</td>'
            f'<td>{"<strong style=\"color:#cc0000\">%d</strong>" % p.kevCount if p.kevCount else "—"}</td>'
            f'<td><strong style="color:#1a7f37">−{p.riskRemoved}</strong></td></tr>'
            for i, p in enumerate(plan[:10])
        )
        plan_html = (
            f'<h2>Remediation Plan — top {min(len(plan), 10)} of {len(plan)}</h2>'
            f'<table><thead><tr><th>#</th><th>Package</th><th>Upgrade</th>'
            f'<th>CVEs Resolved</th><th>KEV</th><th>Risk Removed</th></tr></thead>'
            f'<tbody>{rows}</tbody></table>'
        )

    cwe_html = ""
    if assessment.topCwes:
        rows = "".join(
            f'<tr><td>{esc(c.name)}</td>'
            f'<td><a href="https://cwe.mitre.org/data/definitions/{quote("".join(ch for ch in c.id if ch.isdigit()))}.html" '
            f'target="_blank" rel="noopener noreferrer">{esc(c.id)}</a></td><td>{c.count}</td></tr>'
            for c in assessment.topCwes
        )
        cwe_html = (
            f'<h2>Top Weaknesses (CWE)</h2><table><thead><tr><th>Weakness</th><th>CWE</th>'
            f'<th>Findings</th></tr></thead><tbody>{rows}</tbody></table>'
        )

    vuln_html = ""
    if vuln_rows:
        vuln_html = (
            f'<h2>Vulnerabilities ({len(vuln_rows)})</h2>'
            f'<table><thead><tr><th>Component</th><th>OSV / CVE ID</th><th>Severity</th>'
            f'<th>Fixed In</th><th>Weakness (CWE)</th><th>KEV</th><th>Description</th></tr></thead>'
            f'<tbody>{"".join(vuln_rows)}</tbody></table>'
        )

    cov_line = (
        f'{cov.queryable} of {cov.total} components scannable via OSV'
        + (f' — {cov.skipped} skipped ({esc(_coverage_reasons(cov))})'
           if cov.skipped else ' — full coverage')
    )

    more = " — first 200 shown" if len(sbom.components) > 200 else ""

    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><title>SBOM Report — {esc(sbom.name)}</title>
<style>
  body{{font-family:-apple-system,sans-serif;font-size:13px;color:#1a1a1a;max-width:1200px;margin:0 auto;padding:20px 24px}}
  h1{{font-size:22px;margin-bottom:4px}}h2{{font-size:16px;margin:24px 0 10px;padding-bottom:6px;border-bottom:2px solid #e0e0e0}}
  .meta{{color:#666;font-size:12px;margin-bottom:20px}}
  .summary{{display:grid;grid-template-columns:repeat(auto-fit,minmax(120px,1fr));gap:12px;margin-bottom:24px}}
  .scard{{border:1px solid #e0e0e0;border-radius:8px;padding:12px 16px;text-align:center}}
  .scard .num{{font-size:28px;font-weight:700;line-height:1.2}}
  .scard .lbl{{font-size:10px;text-transform:uppercase;letter-spacing:0.8px;color:#999;margin-top:4px}}
  .grade-badge{{display:inline-block;font-size:42px;font-weight:900;line-height:1;padding:10px 20px;border-radius:12px;border:3px solid;color:{grade_color};border-color:{grade_color};background:{grade_color}11}}
  table{{width:100%;border-collapse:collapse;font-size:12px;margin-top:8px}}
  th{{background:#f5f5f5;padding:8px 10px;text-align:left;font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:0.6px;color:#666;border-bottom:2px solid #e0e0e0}}
  td{{padding:7px 10px;border-bottom:1px solid #f0f0f0;vertical-align:top}}
  tr:hover td{{background:#fafafa}}
  a{{color:#1565c0;text-decoration:none}}a:hover{{text-decoration:underline}}
  @media print{{body{{padding:0}}h2{{page-break-after:avoid}}table{{page-break-inside:auto}}tr{{page-break-inside:avoid}}}}
</style></head><body>
<h1>SBOM Security Report</h1>
<div class="meta">
  <strong>{esc(sbom.name)}</strong>{(' v' + esc(sbom.version)) if sbom.version else ''} &nbsp;·&nbsp;
  Format: {esc(sbom.format.upper())} {esc(sbom.formatVersion)} &nbsp;·&nbsp;
  Generated: {ts}<br>
  Scan coverage: {cov_line}
</div>
{verdict_html}
{mal_html}
{risk_html}
<div class="summary">{summary_cards}</div>
{plan_html}
{cwe_html}
{vuln_html}
<h2>Components ({len(sbom.components)}{more})</h2>
<table><thead><tr><th>Name</th><th>Version</th><th>Type</th><th>Licenses</th><th>PURL</th></tr></thead>
<tbody>{comp_rows}</tbody></table>
<p style="margin-top:32px;font-size:11px;color:#999">Report generated by SBOM Visualizer · {ts} · OSV.dev vulnerability data</p>
</body></html>"""
