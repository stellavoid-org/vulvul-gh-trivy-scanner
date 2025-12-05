import json
from pathlib import Path

from vulvul_gh_trivy_scanner.get_vuls import parse_trivy_json


def _write_sample_trivy_json(path: Path):
    sample = {
        "Results": [
            {
                "Target": "poetry.lock",
                "Type": "poetry",
                "Packages": [
                    {
                        "ID": "pkg1@1.0.0",
                        "Name": "pkg1",
                        "Version": "1.0.0",
                        "DependsOn": ["dep1"],
                        "Identifier": {
                            "PURL": "pkg:pypi/pkg1@1.0.0",
                            "UID": "uid-1",
                        },
                    }
                ],
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "CVE-1",
                        "PkgID": "pkg1@1.0.0",
                        "PkgName": "pkg1",
                        "InstalledVersion": "1.0.0",
                        "FixedVersion": "1.1.0, 1.2.0",
                        "CVSS": {"ghsa": {"V3Score": 5.0, "V3Vector": "vec"}},
                        "CweIDs": ["CWE-1"],
                        "References": ["http://example.com"],
                        "Severity": "HIGH",
                        "SeveritySource": "ghsa",
                        "PrimaryURL": "http://advisory",
                        "PublishedDate": "2024-01-01T00:00:00Z",
                        "LastModifiedDate": "2024-02-01T00:00:00Z",
                        "Title": "Issue",
                        "Description": "desc",
                    }
                ],
            }
        ]
    }
    path.write_text(json.dumps(sample), encoding="utf-8")


def test_parse_trivy_json_reads_packages_and_vuls(tmp_path: Path):
    json_path = tmp_path / "trivy.json"
    _write_sample_trivy_json(json_path)

    vuls, packages = parse_trivy_json(json_path, branch="main", commit_hash="abc123")

    assert len(packages) == 1
    pkg = packages[0]
    assert pkg.id == "pkg1@1.0.0"
    assert pkg.purl == "pkg:pypi/pkg1@1.0.0"
    assert pkg.ecosystem == "pypi"
    assert pkg.manager == "poetry"
    assert pkg.path == "poetry.lock"
    assert pkg.depends_on_ids == ["dep1"]
    assert pkg.branch == "main"
    assert pkg.commit_hash == "abc123"

    assert len(vuls) == 1
    vul = vuls[0]
    assert vul.vulnerability_id == "CVE-1"
    assert vul.file_path == "poetry.lock"
    assert vul.pkg_id == "pkg1@1.0.0"
    assert vul.package is pkg
    assert vul.fixed_version == "1.1.0, 1.2.0"
    assert vul.cvss["ghsa"]["v3_score"] == 5.0
    assert vul.branch == "main"
    assert vul.commit_hash == "abc123"
