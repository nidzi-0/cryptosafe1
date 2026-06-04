from __future__ import annotations

import sys
from pathlib import Path


def main() -> int:
    project_root = Path(__file__).resolve().parent

    if str(project_root) not in sys.path:
        sys.path.insert(0, str(project_root))

    try:
        from src.main import main as app_main
    except Exception as exc:
        print(f"Failed to import application entry point: {exc}")
        return 1

    try:
        app_main()
        return 0
    except Exception as exc:
        print(f"Application failed to start: {exc}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())