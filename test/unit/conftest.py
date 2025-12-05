import sys
from pathlib import Path

# Add repository-root/src to sys.path so tests can import vulvul_gh_trivy_scanner.* modules.
ROOT = Path(__file__).resolve().parents[2]
SRC_DIR = ROOT / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))
