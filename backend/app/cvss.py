"""Local CVSS base-score calculators — exact port of the demo's cvss3Score / cvss2Score.

Reference: FIRST CVSS v3.1 specification section 7.1. The v3.1 Log4Shell vector
CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H must yield exactly 10.0.
"""
from __future__ import annotations

import math
import re
from typing import Optional

from cvss import CVSS4

_STRIP_PREFIX = re.compile(r"^CVSS:[^/]+/")


def parse_cvss_vector(vec: Optional[str]) -> Optional[dict[str, str]]:
    if not vec:
        return None
    parts: dict[str, str] = {}
    stripped = _STRIP_PREFIX.sub("", vec)
    for p in stripped.split("/"):
        idx = p.find(":")
        if idx > 0:
            parts[p[:idx]] = p[idx + 1:]
    return parts


def cvss3_score(vec: Optional[str]) -> Optional[float]:
    p = parse_cvss_vector(vec)
    if not p:
        return None

    AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}.get(p.get("AV"))
    AC = {"L": 0.77, "H": 0.44}.get(p.get("AC"))
    PR_U = {"N": 0.85, "L": 0.62, "H": 0.27}.get(p.get("PR"))   # scope unchanged
    PR_C = {"N": 0.85, "L": 0.68, "H": 0.50}.get(p.get("PR"))   # scope changed
    UI = {"N": 0.85, "R": 0.62}.get(p.get("UI"))
    S = p.get("S")  # U or C
    C = {"N": 0, "L": 0.22, "H": 0.56}.get(p.get("C"))
    I = {"N": 0, "L": 0.22, "H": 0.56}.get(p.get("I"))
    A = {"N": 0, "L": 0.22, "H": 0.56}.get(p.get("A"))

    if any(v is None for v in (AV, AC, UI, C, I, A)):
        return None
    PR = PR_C if S == "C" else PR_U
    if PR is None:
        return None

    isc_base = 1 - (1 - C) * (1 - I) * (1 - A)
    if S == "C":
        isc = 7.52 * (isc_base - 0.029) - 3.25 * math.pow(isc_base - 0.02, 15)
    else:
        isc = 6.42 * isc_base

    if isc <= 0:
        return 0.0
    exploitability = 8.22 * AV * AC * PR * UI
    if S == "C":
        base = min(1.08 * (isc + exploitability), 10)
    else:
        base = min(isc + exploitability, 10)

    # CVSS spec "round up" to 1 decimal.
    return math.ceil(base * 10) / 10


def cvss2_score(vec: Optional[str]) -> Optional[float]:
    p = parse_cvss_vector(vec)
    if not p:
        return None
    AV = {"N": 1.0, "A": 0.646, "L": 0.395}.get(p.get("AV"))
    AC = {"L": 0.71, "M": 0.61, "H": 0.35}.get(p.get("AC"))
    Au = {"N": 0.704, "S": 0.56, "M": 0.45}.get(p.get("Au"))
    C = {"N": 0, "P": 0.275, "C": 0.660}.get(p.get("C"))
    I = {"N": 0, "P": 0.275, "C": 0.660}.get(p.get("I"))
    A = {"N": 0, "P": 0.275, "C": 0.660}.get(p.get("A"))
    if any(v is None for v in (AV, AC, Au, C, I, A)):
        return None
    impact = 10.41 * (1 - (1 - C) * (1 - I) * (1 - A))
    exploitability = 20 * AV * AC * Au
    f_impact = 0 if impact == 0 else 1.176
    return round((0.6 * impact + 0.4 * exploitability - 1.5) * f_impact * 10) / 10


def cvss4_score(vector: Optional[str]) -> Optional[float]:
    """CVSS v4.0 base score via the maintained ``cvss`` library.

    Returns the base score rounded to one decimal (to match v3/v2), or
    ``None`` if the vector is missing or cannot be parsed.
    """
    if not vector:
        return None
    try:
        return round(CVSS4(vector).base_score * 10) / 10
    except Exception:
        return None


def score_to_severity4(score: Optional[float]) -> str:
    if score is None:
        return "UNKNOWN"
    if score == 0:
        return "NONE"
    if score < 4.0:
        return "LOW"
    if score < 7.0:
        return "MEDIUM"
    if score < 9.0:
        return "HIGH"
    return "CRITICAL"


def score_to_severity3(score: Optional[float]) -> str:
    if score is None:
        return "UNKNOWN"
    if score == 0:
        return "NONE"
    if score < 4.0:
        return "LOW"
    if score < 7.0:
        return "MEDIUM"
    if score < 9.0:
        return "HIGH"
    return "CRITICAL"


def score_to_severity2(score: Optional[float]) -> str:
    if score is None:
        return "UNKNOWN"
    if score < 4.0:
        return "LOW"
    if score < 7.0:
        return "MEDIUM"
    return "HIGH"


def _version_of(vec: str) -> Optional[str]:
    if vec.startswith("CVSS:3.1"):
        return "3.1"
    if vec.startswith("CVSS:3.0"):
        return "3.0"
    if vec.startswith("CVSS:4"):
        return "4.0"
    if vec.startswith("CVSS:2"):
        return "2.0"
    return None


def extract_osv_cvss(severity_arr: Optional[list]) -> dict:
    """Port of extractOsvCvss — pick the highest computable CVSS version.

    CVSS v4.0 vectors are now locally computable (via the ``cvss`` library) and
    take precedence over v3/v2 when present and scorable. A v4 vector that
    cannot be computed still must NOT shadow a computable v3/v2 entry.
    """
    if not severity_arr:
        return {"score": None, "severity": "UNKNOWN", "version": None, "vector": None}

    scored = []
    for s in severity_arr:
        if not isinstance(s, dict):
            continue
        vec = s.get("score") or ""
        stype = s.get("type")
        is_v4 = vec.startswith("CVSS:4") or (not vec.startswith("CVSS:") and stype == "CVSS_V4")
        is_v3 = vec.startswith("CVSS:3") or (not vec.startswith("CVSS:") and stype == "CVSS_V3")
        is_v2 = vec.startswith("CVSS:2") or (not vec.startswith("CVSS:") and stype == "CVSS_V2")
        if is_v4:
            sc = cvss4_score(vec)
            if sc is not None:
                scored.append({"score": sc, "severity": score_to_severity4(sc),
                               "version": _version_of(vec) or "4.0", "vector": vec})
        elif is_v3:
            sc = cvss3_score(vec)
            if sc is not None:
                scored.append({"score": sc, "severity": score_to_severity3(sc),
                               "version": _version_of(vec) or "3.1", "vector": vec})
        elif is_v2:
            sc = cvss2_score(vec)
            if sc is not None:
                scored.append({"score": sc, "severity": score_to_severity2(sc),
                               "version": _version_of(vec) or "2.0", "vector": vec})

    if scored:
        rank = {"4.0": 4, "3.1": 3, "3.0": 2, "2.0": 1}
        scored.sort(key=lambda x: rank.get(x["version"], 0), reverse=True)
        return scored[0]

    # Nothing computable — fall back to a v4 vector, else any.
    for s in severity_arr:
        if not isinstance(s, dict):
            continue
        sc = s.get("score") or ""
        if sc.startswith("CVSS:4") or s.get("type") == "CVSS_V4":
            return {"score": None, "severity": "UNKNOWN", "version": "4.0", "vector": s.get("score") or None}
    for s in severity_arr:
        if isinstance(s, dict) and s.get("score"):
            return {"score": None, "severity": "UNKNOWN",
                    "version": _version_of(s["score"]), "vector": s.get("score") or None}
    return {"score": None, "severity": "UNKNOWN", "version": None, "vector": None}
