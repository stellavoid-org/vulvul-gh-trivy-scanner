from vulvul_gh_trivy_scanner.models_vuln import Package, Vul


def test_package_defaults_are_independent():
    p1 = Package()
    p2 = Package()

    p1.depends_on_ids.append("a")
    assert p2.depends_on_ids == []
    assert p1.name == ""
    assert p1.version == ""


def test_vul_defaults_and_links():
    vul = Vul(file_path="poetry.lock", vulnerability_id="CVE-1")

    vul.cwe_ids.append("CWE-1")
    another = Vul(file_path="poetry.lock", vulnerability_id="CVE-2")

    assert another.cwe_ids == []
    assert vul.file_path == "poetry.lock"
    assert vul.vulnerability_id == "CVE-1"
    assert vul.fixed_version is None
    assert vul.branch is None
