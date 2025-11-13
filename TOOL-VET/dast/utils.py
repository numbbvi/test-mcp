import subprocess
import sys
from pathlib import Path
from typing import Optional


def clone_repository(git_url: str, destination: Path, depth: int = 1) -> Optional[Path]:
    """Git 저장소를 지정한 경로로 클론. file:// URL이나 로컬 경로도 지원."""
    # file:// URL이나 로컬 경로인 경우
    if git_url.startswith("file://") or Path(git_url).exists():
        source_path = Path(git_url.replace("file://", ""))
        if source_path.is_dir():
            import shutil
            shutil.copytree(source_path, destination, dirs_exist_ok=True)
            return destination
        return None
    
    # 일반 Git URL인 경우
    try:
        subprocess.run(
            ["git", "clone", *(["--depth", str(depth)] if depth else []), git_url, str(destination)],
            check=True,
            capture_output=True,
        )
        return destination
    except subprocess.CalledProcessError as exc:
        print("저장소 클론에 실패했습니다.", file=sys.stderr)
        if exc.stderr:
            print(exc.stderr.decode("utf-8", errors="ignore"), file=sys.stderr)
        return None


def extract_repo_name(git_url: str) -> str:
    """Git URL에서 저장소 이름을 추출합니다."""
    url = git_url.rstrip("/")
    if url.endswith(".git"):
        url = url[:-4]
    repo_name = url.split("/")[-1]
    return repo_name

