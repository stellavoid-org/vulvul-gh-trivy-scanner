from dataclasses import dataclass, field
from typing import Dict, List, Optional


@dataclass
class Package:
    # Trivy由来
    id: Optional[str] = None
    name: str = ""
    version: str = ""

    purl: Optional[str] = None
    uid: Optional[str] = None

    # 普遍情報
    ecosystem: Optional[str] = None
    manager: Optional[str] = None
    path: Optional[str] = None
    branch: Optional[str] = None
    commit_hash: Optional[str] = None

    depends_on_ids: List[str] = field(default_factory=list)


@dataclass
class Vul:
    # 検出されたファイル（Trivy Result.Target）
    file_path: str

    vulnerability_id: str

    title: Optional[str] = None
    description: Optional[str] = None

    severity: Optional[str] = None
    status: Optional[str] = None
    severity_source: Optional[str] = None
    primary_url: Optional[str] = None

    cwe_ids: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)

    cvss: Dict[str, Dict[str, float | str | None]] = field(default_factory=dict)

    published_date: Optional[str] = None
    last_modified_date: Optional[str] = None

    package: Optional[Package] = None
    pkg_id: Optional[str] = None
    pkg_name: Optional[str] = None
    installed_version: Optional[str] = None
    fixed_version: Optional[str] = None
    branch: Optional[str] = None
    commit_hash: Optional[str] = None

    raw: Optional[dict] = None
