from pathlib import Path

OUTPUT_DIR = Path("output")
TEMP_DIR = OUTPUT_DIR / "temp"
REPOSITORIES_FILE = Path("test/repositories.txt")

GITHUB_PREFIXES = ('https://github.com/', 'http://github.com/')
GITHUB_DEPTH = 1
CLONE_RETRIES = 3

SUPPORTED_LANGUAGES = ["go", "ts"]
UNKNOWN_LANGUAGE = "unknown"

PROGRESS_PREPARE_START = 10
PROGRESS_DETECT_LANGS = 37
PROGRESS_SCAN_START = 40
PROGRESS_SCAN_END = 85
PROGRESS_FINALIZING = 95
PROGRESS_COMPLETE = 100

SEVERITY_CRITICAL = "critical"
SEVERITY_HIGH = "high"
SEVERITY_MEDIUM = "medium"
SEVERITY_LOW = "low"
SEVERITY_INFO = "info"

EXCLUDE_SEVERITIES = [SEVERITY_INFO]

LANGUAGE_EXTENSIONS = {
    "go": [".go"],
    "ts": [".ts", ".tsx", ".js", ".jsx"],
}

TEST_FILE_PATTERNS = [
    '_test.', '.test.', '.spec.', '/test/', '/tests/', 
    '/__tests__/', '/testdata/', 'test/', 'tests/'
]