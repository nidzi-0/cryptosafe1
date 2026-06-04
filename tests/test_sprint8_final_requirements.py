from pathlib import Path
import ast
import re


PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC_DIR = PROJECT_ROOT / "src"
TESTS_DIR = PROJECT_ROOT / "tests"


def test_sprint8_run_py_exists():
    path = PROJECT_ROOT / "run.py"

    assert path.exists()
    assert path.is_file()


def test_sprint8_requirements_txt_exists_and_contains_core_dependencies():
    path = PROJECT_ROOT / "requirements.txt"

    assert path.exists()

    text = path.read_text(encoding="utf-8").lower()

    required = [
        "cryptography",
        "argon2-cffi",
        "pytest",
        "pytest-cov",
        "pyinstaller",
    ]

    for dependency in required:
        assert dependency in text


def test_sprint8_requirements_are_pinned_with_versions():
    path = PROJECT_ROOT / "requirements.txt"
    lines = [
        line.strip()
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]

    unpinned = [
        line
        for line in lines
        if "==" not in line and not line.startswith("-")
    ]

    assert not unpinned, f"Dependencies must be pinned with versions: {unpinned}"


def test_sprint8_readme_exists():
    path = PROJECT_ROOT / "README.md"

    assert path.exists()
    assert path.is_file()


def test_sprint8_readme_contains_required_sections():
    path = PROJECT_ROOT / "README.md"
    text = path.read_text(encoding="utf-8").lower()

    required_phrases = [
        "cryptosafe manager",
        "installation",
        "run from source",
        "run tests",
        "build executable",
        "known limitations",
        "future work",
    ]

    missing = [phrase for phrase in required_phrases if phrase not in text]

    assert not missing, f"README.md missing sections: {missing}"


def test_sprint8_user_guide_exists():
    path = PROJECT_ROOT / "docs" / "user_guide.md"

    assert path.exists()
    assert path.is_file()


def test_sprint8_user_guide_contains_required_topics():
    path = PROJECT_ROOT / "docs" / "user_guide.md"
    text = path.read_text(encoding="utf-8").lower()

    required_topics = [
        "установка",
        "запуск",
        "мастер-пароль",
        "добавление записи",
        "редактирование",
        "удаление",
        "буфер обмена",
        "импорт",
        "экспорт",
    ]

    missing = [topic for topic in required_topics if topic not in text]

    assert not missing, f"user_guide.md missing topics: {missing}"


def test_sprint8_technical_summary_exists():
    path = PROJECT_ROOT / "docs" / "technical.md"

    assert path.exists()
    assert path.is_file()


def test_sprint8_technical_summary_contains_required_topics():
    path = PROJECT_ROOT / "docs" / "technical.md"
    text = path.read_text(encoding="utf-8").lower()

    required_topics = [
        "архитектура",
        "aes",
        "gcm",
        "argon2",
        "pbkdf2",
        "sqlite",
        "база данных",
        "audit",
        "clipboard",
        "security hardening",
    ]

    missing = [topic for topic in required_topics if topic not in text]

    assert not missing, f"technical.md missing topics: {missing}"


def test_sprint8_no_todo_or_fixme_in_src():
    forbidden = ["TODO", "FIXME"]

    offenders = []

    for path in SRC_DIR.rglob("*.py"):
        text = path.read_text(encoding="utf-8", errors="ignore")

        for marker in forbidden:
            if marker in text:
                offenders.append(f"{path}: contains {marker}")

    assert not offenders, "\n".join(offenders)


def test_sprint8_src_python_files_parse_without_syntax_errors():
    for path in SRC_DIR.rglob("*.py"):
        source = path.read_text(encoding="utf-8", errors="ignore")
        ast.parse(source, filename=str(path))


def test_sprint8_core_sprint_modules_exist():
    required_paths = [
        SRC_DIR / "core" / "crypto",
        SRC_DIR / "core" / "vault",
        SRC_DIR / "core" / "clipboard",
        SRC_DIR / "core" / "audit",
        SRC_DIR / "core" / "import_export",
        SRC_DIR / "core" / "security",
    ]

    for path in required_paths:
        assert path.exists(), f"Missing required module: {path}"


def test_sprint8_test_suite_contains_sprint_tests():
    sprint_tests = list(TESTS_DIR.glob("test_sprint*.py"))

    assert sprint_tests
    assert any("sprint3" in path.name for path in sprint_tests)
    assert any("sprint4" in path.name for path in sprint_tests)
    assert any("sprint5" in path.name for path in sprint_tests)
    assert any("sprint6" in path.name for path in sprint_tests)
    assert any("sprint7" in path.name for path in sprint_tests)


def test_sprint8_test_suite_covers_required_areas():
    test_files_text = "\n".join(
        path.read_text(encoding="utf-8", errors="ignore").lower()
        for path in TESTS_DIR.glob("test_*.py")
    )

    required_keywords = [
        "encrypt",
        "decrypt",
        "key",
        "entry",
        "clipboard",
        "import",
        "export",
    ]

    missing = [
        keyword
        for keyword in required_keywords
        if keyword not in test_files_text
    ]

    assert not missing, f"Test suite missing required areas: {missing}"


def test_sprint8_scripts_exist_for_report_and_packaging():
    required_scripts = [
        PROJECT_ROOT / "scripts" / "run_tests_with_report.ps1",
        PROJECT_ROOT / "scripts" / "build_exe.ps1",
    ]

    for path in required_scripts:
        assert path.exists(), f"Missing script: {path}"


def test_sprint8_pyinstaller_build_instruction_exists():
    readme = (PROJECT_ROOT / "README.md").read_text(encoding="utf-8").lower()

    assert "pyinstaller" in readme
    assert "cryptosafemanager" in readme
    assert "dist" in readme


def test_sprint8_report_directory_can_exist():
    report_dir = TESTS_DIR / "report"
    report_dir.mkdir(parents=True, exist_ok=True)

    assert report_dir.exists()
    assert report_dir.is_dir()