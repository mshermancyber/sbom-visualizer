import { describe, it, expect } from "vitest";
import {
  purlToRegistryUrl,
  safeUrl,
  escapeHtml,
  csvCell,
  csvRow,
  licClass,
  worstSeverity,
  sevRank,
  externalLink,
} from "./util";

describe("purlToRegistryUrl", () => {
  it("maps npm (with and without scope)", () => {
    expect(purlToRegistryUrl("pkg:npm/left-pad@1.3.0")).toBe(
      "https://www.npmjs.com/package/left-pad",
    );
    expect(purlToRegistryUrl("pkg:npm/%40babel/core@7.0.0")).toBe(
      "https://www.npmjs.com/package/@babel/core",
    );
  });
  it("maps pypi", () => {
    expect(purlToRegistryUrl("pkg:pypi/requests@2.31.0")).toBe(
      "https://pypi.org/project/requests/",
    );
  });
  it("maps maven (needs namespace)", () => {
    expect(purlToRegistryUrl("pkg:maven/org.apache/commons@1.0")).toBe(
      "https://central.sonatype.com/artifact/org.apache/commons",
    );
    expect(purlToRegistryUrl("pkg:maven/noNamespace@1.0")).toBe("");
  });
  it("maps cargo", () => {
    expect(purlToRegistryUrl("pkg:cargo/serde@1.0.0")).toBe(
      "https://crates.io/crates/serde",
    );
  });
  it("maps gem", () => {
    expect(purlToRegistryUrl("pkg:gem/rails@7.0.0")).toBe(
      "https://rubygems.org/gems/rails",
    );
  });
  it("maps nuget", () => {
    expect(purlToRegistryUrl("pkg:nuget/Newtonsoft.Json@13.0.1")).toBe(
      "https://www.nuget.org/packages/Newtonsoft.Json",
    );
  });
  it("maps golang", () => {
    expect(purlToRegistryUrl("pkg:golang/github.com/gin-gonic/gin@v1.9.0")).toBe(
      "https://pkg.go.dev/github.com/gin-gonic/gin",
    );
  });
  it("maps composer (needs namespace)", () => {
    expect(purlToRegistryUrl("pkg:composer/symfony/console@6.0")).toBe(
      "https://packagist.org/packages/symfony/console",
    );
    expect(purlToRegistryUrl("pkg:composer/justname@6.0")).toBe("");
  });
  it("returns '' for unknown type / bad input", () => {
    expect(purlToRegistryUrl("pkg:deb/debian/curl@7.0")).toBe("");
    expect(purlToRegistryUrl("not-a-purl")).toBe("");
    expect(purlToRegistryUrl("")).toBe("");
    expect(purlToRegistryUrl(null)).toBe("");
    expect(purlToRegistryUrl(undefined)).toBe("");
  });
  it("strips qualifiers and subpath", () => {
    expect(
      purlToRegistryUrl("pkg:npm/left-pad@1.3.0?arch=x64#sub/path"),
    ).toBe("https://www.npmjs.com/package/left-pad");
  });
});

describe("safeUrl", () => {
  it("allows http/https/mailto", () => {
    expect(safeUrl("http://example.com")).toBe("http://example.com");
    expect(safeUrl("https://example.com/x")).toBe("https://example.com/x");
    expect(safeUrl("mailto:a@b.com")).toBe("mailto:a@b.com");
  });
  it("blocks javascript: and data:", () => {
    expect(safeUrl("javascript:alert(1)")).toBe("");
    expect(safeUrl("data:text/html,<script>")).toBe("");
    expect(safeUrl("vbscript:msgbox(1)")).toBe("");
  });
  it("blocks empty/garbage", () => {
    expect(safeUrl("")).toBe("");
    expect(safeUrl("   ")).toBe("");
    expect(safeUrl(null)).toBe("");
  });
});

describe("externalLink", () => {
  it("renders a hardened anchor for safe URLs", () => {
    const html = externalLink("https://example.com", "click");
    expect(html).toContain('rel="noopener noreferrer"');
    expect(html).toContain('target="_blank"');
    expect(html).toContain('href="https://example.com"');
  });
  it("falls back to escaped text for unsafe URLs", () => {
    expect(externalLink("javascript:alert(1)", "x")).toBe("x");
  });
});

describe("escapeHtml", () => {
  it("escapes all dangerous characters", () => {
    expect(escapeHtml(`<script>"&'`)).toBe(
      "&lt;script&gt;&quot;&amp;&#39;",
    );
  });
  it("handles null/undefined as empty string", () => {
    expect(escapeHtml(null)).toBe("");
    expect(escapeHtml(undefined)).toBe("");
  });
  it("coerces numbers", () => {
    expect(escapeHtml(42)).toBe("42");
  });
});

describe("csvCell", () => {
  it("prefixes formula-injection leaders with a quote", () => {
    expect(csvCell("=SUM(A1)")).toBe("'=SUM(A1)");
    expect(csvCell("+1")).toBe("'+1");
    expect(csvCell("-1")).toBe("'-1");
    expect(csvCell("@cmd")).toBe("'@cmd");
  });
  it("doubles embedded quotes and wraps when needed", () => {
    expect(csvCell('he said "hi"')).toBe('"he said ""hi"""');
    expect(csvCell("a,b")).toBe('"a,b"');
    expect(csvCell("line\nbreak")).toBe('"line\nbreak"');
  });
  it("leaves plain values untouched", () => {
    expect(csvCell("plain")).toBe("plain");
    expect(csvCell(null)).toBe("");
  });
});

describe("csvRow", () => {
  it("joins escaped cells with commas", () => {
    expect(csvRow(["a", "b,c", "=x"])).toBe('a,"b,c",\'=x');
  });
});

describe("licClass", () => {
  it("classifies copyleft", () => {
    expect(licClass("GPL-3.0")).toBe("license-copyleft");
    expect(licClass("AGPL-3.0")).toBe("license-copyleft");
  });
  it("classifies permissive", () => {
    expect(licClass("MIT")).toBe("license-permissive");
    expect(licClass("Apache-2.0")).toBe("license-permissive");
  });
  it("classifies unknown/none", () => {
    expect(licClass("")).toBe("license-unknown");
    expect(licClass("NOASSERTION")).toBe("license-unknown");
  });
  it("falls back to generic tag", () => {
    expect(licClass("SomeWeirdLicense")).toBe("license-tag");
  });
});

describe("severity helpers", () => {
  it("ranks severities (lower = worse)", () => {
    expect(sevRank("CRITICAL")).toBeLessThan(sevRank("HIGH"));
    expect(sevRank("HIGH")).toBeLessThan(sevRank("LOW"));
  });
  it("picks the worst severity in a list", () => {
    expect(worstSeverity(["LOW", "CRITICAL", "MEDIUM"])).toBe("CRITICAL");
    expect(worstSeverity(["LOW", "MEDIUM"])).toBe("MEDIUM");
    expect(worstSeverity([])).toBe("UNKNOWN");
  });
});
