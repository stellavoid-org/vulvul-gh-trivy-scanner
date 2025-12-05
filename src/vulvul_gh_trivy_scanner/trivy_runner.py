import subprocess
from pathlib import Path


def run_trivy_fs(target_dir: Path, output_json: Path) -> None:
    """
    Trivy FS スキャンを実行し、JSON を output_json に保存する。
    """
    output_json.parent.mkdir(parents=True, exist_ok=True)

    cmd = [
        "trivy",
        "fs",
        "--format",
        "json",
        "--output",
        str(output_json),
        "--list-all-pkgs",
        str(target_dir),
    ]
    subprocess.run(cmd, check=True)
