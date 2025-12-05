from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

from .models_vuln import Package, Vul


@dataclass
class GHRepository:
    owner: str
    repo: str
    base_url: str = "https://github.com"
    api_base_url: str = "https://api.github.com"
    token: Optional[str] = None
    token_env_name: Optional[str] = None

    is_accessible: bool = False
    access_error: Optional[str] = None
    branches: List[str] = field(default_factory=list)

    work_dir: Optional[Path] = None
    out_dir: Optional[Path] = None

    vulnerabilities: List[Vul] = field(default_factory=list)
    packages: List[Package] = field(default_factory=list)

    def mark_accessible(self) -> None:
        self.is_accessible = True
        self.access_error = None

    def mark_inaccessible(self, reason: str) -> None:
        self.is_accessible = False
        self.access_error = reason
