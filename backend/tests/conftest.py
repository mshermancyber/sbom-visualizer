"""Shared test fixtures — a small hand-authored CycloneDX 1.5 SBOM (offline)."""
import pytest

SAMPLE_CDX = {
    "bomFormat": "CycloneDX",
    "specVersion": "1.5",
    "serialNumber": "urn:uuid:1b2c3d4e-5f60-4a7b-8c9d-0e1f2a3b4c5d",
    "version": 1,
    "metadata": {
        "timestamp": "2024-11-02T14:30:00Z",
        "tools": {"components": [{"type": "application", "name": "syft", "version": "1.14.0"}]},
        "component": {
            "type": "application", "name": "acme-payment-service", "version": "2.3.0",
            "bom-ref": "acme-app", "purl": "pkg:generic/acme-payment-service@2.3.0",
            "supplier": {"name": "Acme Corp"},
        },
    },
    "components": [
        {"type": "library", "name": "log4j-core", "version": "2.14.1",
         "bom-ref": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
         "purl": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
         "supplier": {"name": "org.apache.logging.log4j"},
         "licenses": [{"license": {"id": "Apache-2.0"}}],
         "description": "Apache Log4j 2 core logging implementation",
         "hashes": [{"alg": "SHA-256", "content": "abc123"}]},
        {"type": "library", "name": "lodash", "version": "4.17.15", "bom-ref": "pkg:npm/lodash@4.17.15",
         "purl": "pkg:npm/lodash@4.17.15", "supplier": {"name": "lodash"},
         "licenses": [{"license": {"id": "MIT"}}]},
        {"type": "framework", "name": "express", "version": "4.17.1", "bom-ref": "pkg:npm/express@4.17.1",
         "purl": "pkg:npm/express@4.17.1", "supplier": {"name": "expressjs"},
         "licenses": [{"license": {"id": "MIT"}}]},
        {"type": "library", "name": "mysql-connector-java", "version": "8.0.11",
         "bom-ref": "pkg:maven/mysql/mysql-connector-java@8.0.11",
         "purl": "pkg:maven/mysql/mysql-connector-java@8.0.11", "supplier": {"name": "mysql"},
         "licenses": [{"license": {"id": "GPL-2.0"}}]},
        {"type": "library", "name": "internal-utils", "version": "1.0.0",
         "bom-ref": "pkg:npm/internal-utils@1.0.0", "purl": "pkg:npm/internal-utils@1.0.0",
         "supplier": {"name": "Acme Corp"}},
        {"type": "container", "name": "base-image", "version": "latest",
         "bom-ref": "img", "purl": "pkg:oci/base-image@sha256:deadbeef"},
    ],
    "dependencies": [
        {"ref": "acme-app", "dependsOn": [
            "pkg:npm/express@4.17.1",
            "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
            "pkg:maven/mysql/mysql-connector-java@8.0.11"]},
        {"ref": "pkg:npm/express@4.17.1", "dependsOn": ["pkg:npm/lodash@4.17.15"]},
        {"ref": "pkg:maven/mysql/mysql-connector-java@8.0.11",
         "dependsOn": ["pkg:npm/internal-utils@1.0.0"]},
    ],
}


@pytest.fixture
def sample_cdx():
    import copy
    return copy.deepcopy(SAMPLE_CDX)
