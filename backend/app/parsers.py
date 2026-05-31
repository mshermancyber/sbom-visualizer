"""SBOM parsers — faithful port of detectFormat / parseCycloneDX / parseSPDX / parseSyft.

Produces the normalized internal Sbom shape from the API contract. Components carry the
contract field names (camelCase, e.g. ``bomRef``). Internal hashes / spdxId needed by the
scoring layer (NTIA, depth) are tracked separately and exposed via helper functions, so the
public Sbom stays clean while scoring still has access to the richer parse output.
"""
from __future__ import annotations

import json
from typing import Any

from .models import Component, Dependency, Sbom


class ParseError(ValueError):
    """Raised when an SBOM cannot be recognized or parsed."""


# ── Format detection ──────────────────────────────────────────
def detect_format(raw: dict) -> str:
    if raw.get("bomFormat") == "CycloneDX":
        return "cyclonedx"
    if raw.get("SPDXID") or raw.get("spdxVersion") or raw.get("packages"):
        return "spdx"
    if (raw.get("artifacts") and raw.get("source")) or (
        isinstance(raw.get("artifacts"), list) and raw.get("artifacts")
    ):
        return "syft"
    if isinstance(raw.get("artifacts"), list):
        return "syft"
    return "unknown"


# ── CycloneDX ─────────────────────────────────────────────────
def _norm_cdx_tools(tools: Any) -> list:
    if not tools:
        return []
    if isinstance(tools, list):
        return tools
    if isinstance(tools, dict):
        if isinstance(tools.get("components"), list):
            return tools["components"]
        if isinstance(tools.get("services"), list):
            return tools["services"]
    return []


def _parse_cdx_licenses(lics: Any) -> list[str]:
    if not lics:
        return []
    out = []
    for l in lics:
        if not isinstance(l, dict):
            continue
        lic = l.get("license") or {}
        val = lic.get("id") or lic.get("name") or l.get("expression") or ""
        if val:
            out.append(val)
    return out


def parse_cyclonedx(raw: dict) -> tuple[Sbom, list[dict]]:
    extra: list[dict] = []
    components: list[Component] = []
    for c in raw.get("components") or []:
        if not isinstance(c, dict):
            continue  # malformed entry (e.g. null/string in the components array)
        supplier = ""
        if isinstance(c.get("supplier"), dict):
            supplier = c["supplier"].get("name") or ""
        supplier = supplier or c.get("author") or ""
        comp = Component(
            name=c.get("name") or "",
            version=c.get("version") or "",
            type=c.get("type") or "library",
            purl=c.get("purl") or "",
            cpe=c.get("cpe") or "",
            description=c.get("description") or "",
            licenses=_parse_cdx_licenses(c.get("licenses")),
            supplier=supplier,
            bomRef=c.get("bom-ref") or "",
        )
        components.append(comp)
        extra.append({
            "hashes": c.get("hashes") or [],
            "spdxId": "",
            "bom_ref": c.get("bom-ref") or "",
            "distro": "",
        })

    deps = [
        Dependency(ref=d.get("ref", ""), deps=d.get("dependsOn") or [])
        for d in (raw.get("dependencies") or [])
        if isinstance(d, dict) and d.get("ref")
    ]

    meta = raw.get("metadata") or {}
    tools = _norm_cdx_tools(meta.get("tools"))
    tool_strs = [
        " ".join(x for x in [t.get("name"), t.get("version")] if x)
        for t in tools if isinstance(t, dict)
    ]
    tool_strs = [t for t in tool_strs if t]
    meta_comp = meta.get("component") or {}
    name = meta_comp.get("name") or (tools[0].get("name") if tools and isinstance(tools[0], dict) else "") or "CycloneDX SBOM"

    sbom = Sbom(
        format="cyclonedx",
        formatVersion=raw.get("specVersion") or "",
        name=name,
        version=meta_comp.get("version") or "",
        timestamp=meta.get("timestamp") or "",
        tools=tool_strs,
        serialNumber=raw.get("serialNumber") or "",
        components=components,
        dependencies=deps,
    )
    return sbom, extra


# ── SPDX ──────────────────────────────────────────────────────
def _extract_purl_spdx(p: dict) -> str:
    for r in p.get("externalRefs") or []:
        if not isinstance(r, dict):
            continue
        if r.get("referenceType") == "purl":
            return r.get("referenceLocator") or ""
    return ""


def _extract_cpe_spdx(p: dict) -> str:
    for r in p.get("externalRefs") or []:
        if not isinstance(r, dict):
            continue
        rt = r.get("referenceType") or ""
        if rt.startswith("cpe"):
            return r.get("referenceLocator") or ""
    return ""


def _guess_type_spdx(p: dict) -> str:
    purl = _extract_purl_spdx(p)
    if purl.startswith(("pkg:npm", "pkg:pypi", "pkg:gem", "pkg:maven", "pkg:cargo")):
        return "library"
    if purl.startswith(("pkg:deb", "pkg:rpm", "pkg:apk")):
        return "os"
    if purl.startswith(("pkg:docker", "pkg:oci")):
        return "container"
    return "library"


def _parse_spdx_licenses(p: dict) -> list[str]:
    lics: list[str] = []
    seen = set()

    def add(v):
        if v and v not in ("NOASSERTION", "NONE") and v not in seen:
            seen.add(v)
            lics.append(v)

    add(p.get("licenseConcluded"))
    add(p.get("licenseDeclared"))
    for l in p.get("licenseInfoFromFiles") or []:
        add(l)
    return lics


def parse_spdx(raw: dict) -> tuple[Sbom, list[dict]]:
    pkgs = raw.get("packages") or []
    ns = (raw.get("documentNamespace") or "").lower()
    creators = " ".join(((raw.get("creationInfo") or {}).get("creators") or [])).lower()

    def has(*words):
        return any(w in ns or w in creators for w in words)

    if has("arch"):
        spdx_distro = "Arch Linux"
    elif has("ubuntu"):
        spdx_distro = "Ubuntu"
    elif has("debian"):
        spdx_distro = "Debian"
    elif has("amazon"):
        spdx_distro = "Amazon Linux"
    elif has("fedora"):
        spdx_distro = "Fedora"
    elif has("alpine"):
        spdx_distro = "Alpine"
    elif has("suse"):
        spdx_distro = "openSUSE"
    else:
        spdx_distro = ""

    components: list[Component] = []
    extra: list[dict] = []
    for p in pkgs:
        if not isinstance(p, dict):
            continue  # malformed entry (e.g. null/string in the packages array)
        checksums = [
            {"alg": c.get("algorithm"), "content": c.get("checksumValue")}
            for c in (p.get("checksums") or [])
        ]
        comp = Component(
            name=p.get("name") or "",
            version=p.get("versionInfo") or "",
            type=_guess_type_spdx(p),
            purl=_extract_purl_spdx(p),
            cpe=_extract_cpe_spdx(p),
            description=p.get("description") or p.get("summary") or "",
            licenses=_parse_spdx_licenses(p),
            supplier=p.get("supplier") or p.get("originator") or "",
            bomRef=p.get("SPDXID") or "",
        )
        components.append(comp)
        extra.append({
            "hashes": checksums,
            "spdxId": p.get("SPDXID") or "",
            "bom_ref": "",
            "distro": spdx_distro,
        })

    # DEPENDS_ON relationships → dependency edges
    by_ref: dict[str, Dependency] = {}
    order: list[str] = []
    for r in raw.get("relationships") or []:
        if not isinstance(r, dict):
            continue
        if r.get("relationshipType") != "DEPENDS_ON":
            continue
        ref = r.get("spdxElementId")
        rel = r.get("relatedSpdxElement")
        if ref is None:
            continue
        if ref not in by_ref:
            by_ref[ref] = Dependency(ref=ref, deps=[])
            order.append(ref)
        by_ref[ref].deps.append(rel)
    deps = [by_ref[r] for r in order]

    creators_list = (raw.get("creationInfo") or {}).get("creators") or []
    tools = [c.replace("Tool: ", "", 1) if c.startswith("Tool: ") else c
             for c in creators_list]
    tools = [t for t in tools if t]

    sbom = Sbom(
        format="spdx",
        formatVersion=raw.get("spdxVersion") or "",
        name=raw.get("name") or "SPDX SBOM",
        version="",
        timestamp=(raw.get("creationInfo") or {}).get("created") or "",
        tools=tools,
        serialNumber=raw.get("documentNamespace") or "",
        distro=spdx_distro or None,
        components=components,
        dependencies=deps,
    )
    return sbom, extra


# ── Syft ──────────────────────────────────────────────────────
_SYFT_TYPE_MAP = {
    "npm": "library", "python": "library", "gem": "library", "java-archive": "library",
    "go-module": "library", "rust-crate": "library", "deb": "os", "rpm": "os",
    "apk": "os", "binary": "file", "conan": "library", "dart-pub": "library",
    "dotnet": "library", "haskell": "library", "hex": "library", "kotlin": "library",
    "lua": "library", "php-composer": "library", "portage": "os", "R-package": "library",
}


def _map_syft_type(t: Any) -> str:
    return _SYFT_TYPE_MAP.get(t, "library")


def parse_syft(raw: dict) -> tuple[Sbom, list[dict]]:
    artifacts = raw.get("artifacts") or []
    distro = raw.get("distro") or {}
    distro_name = distro.get("name") or distro.get("prettyName") or ""

    components: list[Component] = []
    extra: list[dict] = []
    for a in artifacts:
        if not isinstance(a, dict):
            continue  # malformed entry (e.g. null/string in the artifacts array)
        cpes = a.get("cpes") or []
        cpe = ""
        if cpes:
            first = cpes[0]
            cpe = first.get("cpe") if isinstance(first, dict) else first
            cpe = cpe or ""
        licenses = []
        for l in a.get("licenses") or []:
            licenses.append(l.get("value") if isinstance(l, dict) else l)
        licenses = [l for l in licenses if l]
        comp = Component(
            name=a.get("name") or "",
            version=a.get("version") or "",
            type=_map_syft_type(a.get("type")),
            purl=a.get("purl") or "",
            cpe=cpe,
            description="",
            licenses=licenses,
            supplier="",
            language=a.get("language") or "",
            bomRef=a.get("id") or a.get("purl") or a.get("name") or "",
        )
        components.append(comp)
        extra.append({
            "hashes": _syft_hashes(a),
            "spdxId": "",
            "bom_ref": "",
            "distro": distro_name,
            "syft_id": a.get("id") or "",
        })

    # artifactRelationships → dependency edges (child depends on parent)
    dep_map: dict[str, list[str]] = {}
    order: list[str] = []
    for r in raw.get("artifactRelationships") or []:
        if not isinstance(r, dict):
            continue
        if r.get("type") in ("dependency-of", "contains"):
            child = r.get("child")
            parent = r.get("parent")
            if child is None:
                continue
            if child not in dep_map:
                dep_map[child] = []
                order.append(child)
            dep_map[child].append(parent)
    deps = [Dependency(ref=ref, deps=dep_map[ref]) for ref in order]

    src = raw.get("source") or {}
    smeta = src.get("metadata") or {}
    starget = src.get("target") or {}
    name = (smeta.get("userInput") or smeta.get("imageID") or starget.get("userInput")
            or starget.get("imageID") or src.get("name") or "Syft SBOM")
    descriptor = raw.get("descriptor") or {}
    tool = ""
    if descriptor.get("name"):
        tool = f"{descriptor['name']} {descriptor.get('version', '')}".strip()

    sbom = Sbom(
        format="syft",
        formatVersion=(raw.get("schema") or {}).get("version") or "",
        name=name,
        version=smeta.get("manifestDigest") or smeta.get("imageDigest") or starget.get("imageDigest") or "",
        timestamp=descriptor.get("timestamp") or "",
        tools=[tool] if tool else [],
        serialNumber="",
        distro=(distro.get("prettyName") or distro.get("name") or "") or None,
        distroVersion=(distro.get("version") or "") or None,
        components=components,
        dependencies=deps,
    )
    return sbom, extra


def _syft_hashes(a: dict) -> list:
    meta = a.get("metadata") or {}
    files = meta.get("files") if isinstance(meta, dict) else None
    if files and isinstance(files, list) and isinstance(files[0], dict):
        digests = files[0].get("digests") or {}
        if isinstance(digests, dict):
            return [{"alg": k, "content": v} for k, v in digests.items()]
    return []


# ── Dispatch ──────────────────────────────────────────────────
def parse_sbom(raw: Any) -> tuple[Sbom, list[dict]]:
    """Parse raw SBOM JSON (dict or JSON string) into a normalized Sbom.

    Returns ``(sbom, extra)`` where ``extra[i]`` carries internal per-component fields
    (hashes, spdxId, distro) used by the scoring layer but kept off the public model.
    """
    if isinstance(raw, (str, bytes)):
        raw = json.loads(raw)
    if not isinstance(raw, dict):
        raise ParseError("SBOM must be a JSON object.")
    fmt = detect_format(raw)
    if fmt == "cyclonedx":
        return parse_cyclonedx(raw)
    if fmt == "spdx":
        return parse_spdx(raw)
    if fmt == "syft":
        return parse_syft(raw)
    raise ParseError("Unrecognized SBOM format. Expected CycloneDX, SPDX, or Syft JSON.")
