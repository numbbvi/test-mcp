import re
import ast
import json
from pathlib import Path
from typing import List, Dict, Any, Optional
from dataclasses import dataclass

@dataclass
class Finding:
    rule_id: str
    severity: str
    message: str
    cwe: str
    file: str
    line: int
    column: int
    code_snippet: str
    pattern_type: str
    pattern: str
    confidence: float = 1.0

class CommonPatterns:
    SAFE_COMMENT_PATTERNS = [
        # TypeScript/JavaScript
        r'//\s*eslint-disable',
        r'//\s*@ts-ignore',
        # Go security suppression comments
        r'//nolint:gosec',
        r'//\s*nolint:gosec',
        r'//\s*nolint\s*:gosec',
        r'//\s*nolint:.*gosec',
        r'//#nosec',
        r'//\s*#nosec',
        r'//\s*#nosec\s+\w+',
        r'//\s*nosec',
        # General security comments
        r'//\s*safe',
        r'//\s*sanitized',
        r'//\s*trusted',
        r'//\s*validated',
        r'//\s*whitelisted',
        r'//\s*verified',
        r'//\s*controlled',
        # Block comments
        r'/\*\s*nosec\s*\*/',
        r'/\*\s*safe\s*\*/',
        r'/\*\s*security:\s*reviewed\s*\*/',
        r'/\*\s*nolint:gosec\s*\*/',
        r'/\*\s*#nosec\s*\*/',
    ]
    
    SHELL_METACHARACTERS = [
        ';', '&', '|', '||', '&&', '$(', '`', '$(',
        '>', '>>', '<', '\n', '\r\n', '2>&1', '2>',
    ]
    
    SHELL_FLAGS = ['-c', '/c', '/C', '-Command', '-EncodedCommand', '-File']
    
    SAFE_FILE_EXTENSIONS = ['.md', '.txt', '.json', '.log', '.tmp', '.dat', 
                           '.xml', '.yaml', '.yml', '.csv', '.ini', '.conf', '.git']
    
    CONFIDENCE_LEVELS = {
        'INFO': 0.1,
        'LOW': 0.3,
        'MEDIUM': 0.5,
        'HIGH': 0.7,
        'VERY_HIGH': 0.9,
        'CRITICAL': 1.0
    }
    
    @staticmethod
    def is_test_file(file_path: str, language: str = "all") -> bool:
        config = ConfigLoader.get_instance()
        test_patterns = config.get_test_file_patterns(language)
        return any(pattern in file_path for pattern in test_patterns)
    
    @staticmethod
    def has_safe_comment(line_content: str) -> bool:
        for pattern in CommonPatterns.SAFE_COMMENT_PATTERNS:
            if re.search(pattern, line_content, re.IGNORECASE):
                return True
        return False
    
    @staticmethod
    def is_safe_literal(value: str, language: str = "all") -> bool:
        config = ConfigLoader.get_instance()
        safe_keywords = config.get_safe_literals(language)
        if any(keyword in value for keyword in safe_keywords):
            return True
        
        safe_path_patterns = [
            r'README', r'LICENSE', r'CHANGELOG', r'CONTRIBUTING',
            r'\.md$', r'\.txt$', r'\.json$', r'\.yaml$', r'\.yml$',
            r'^docs/', r'^\.github/', r'^\.git/', r'^node_modules/',
            r'^dist/', r'^build/', r'^public/', r'^static/', r'^assets/'
        ]
        
        for pattern in safe_path_patterns:
            if re.search(pattern, value, re.IGNORECASE):
                return True
        
        return False
    
    @staticmethod
    def extract_base_var(var_name: str) -> str:
        if not var_name:
            return ""
        var_name = var_name.strip()
        if '.' in var_name:
            return var_name.split('.')[0].strip()
        return var_name
    
    @staticmethod
    def adjust_severity_down(severity: str, steps: int = 1) -> str:
        severity_levels = ["critical", "high", "medium", "low", "info"]
        try:
            current_index = severity_levels.index(severity.lower())
            new_index = min(current_index + steps, len(severity_levels) - 1)
            return severity_levels[new_index]
        except ValueError:
            return severity
    
    @staticmethod
    def adjust_severity_with_context(severity: str, context_type: str) -> tuple[str, float]:
        multiplier = 0.6
        if context_type == 'safe_var':
            multiplier = 0.5
        
        adjusted_severity = CommonPatterns.adjust_severity_down(severity, 1)
        return adjusted_severity, multiplier
    
    @staticmethod
    def is_arg_in_tainted_vars(arg: str, tainted_vars: set) -> bool:
        if arg in tainted_vars:
            return True
        base_var = CommonPatterns.extract_base_var(arg)
        return base_var in tainted_vars if base_var else False

class ConfigLoader:
    
    _instance: Optional['ConfigLoader'] = None
    _config: Dict[str, Any] = {}
    
    def __init__(self, config_path: Optional[str] = None):
        if ConfigLoader._instance is not None:
            return
        
        self.config_path = config_path or self._find_config_file()
        self._config = self._load_config()
        ConfigLoader._instance = self
    
    @classmethod
    def get_instance(cls, config_path: Optional[str] = None) -> 'ConfigLoader':
        if cls._instance is None:
            cls._instance = ConfigLoader(config_path)
        return cls._instance
    
    def _find_config_file(self) -> Path:
        current = Path(__file__).resolve().parent.parent.parent.parent
        for parent in [current] + list(current.parents):
            config_file = parent / "custom_config.json"
            if config_file.exists():
                return config_file
        return current / "custom_config.json"
    
    def _load_config(self) -> Dict[str, Any]:
        try:
            if self.config_path.exists():
                with open(self.config_path, 'r', encoding='utf-8') as f:
                    return json.load(f)
        except Exception as e:
            print(f"Warning: Could not load config file: {e}")
        return {}
    
    def get_whitelisted_domains(self, language: str = "all") -> List[str]:
        default_domains = ['localhost', '127.0.0.1', '0.0.0.0', '::1', 'example.com', 'example.org', 'example.net']
        try:
            patterns = self._config.get('patterns', {}).get('custom_patterns', {})
            if language in patterns:
                domains = patterns[language].get('whitelisted_domains', [])
                return default_domains + domains
            if 'all' in patterns:
                domains = patterns['all'].get('whitelisted_domains', [])
                return default_domains + domains
        except Exception:
            pass
        return default_domains
    
    def get_safe_url_patterns(self, language: str = "all") -> List[str]:
        default_patterns = [
            r'localhost:\d+',
            r'127\.0\.0\.1:\d+',
            r'example\.com',
            r'example\.org',
        ]
        try:
            patterns = self._config.get('patterns', {}).get('custom_patterns', {})
            if language in patterns:
                url_patterns = patterns[language].get('safe_urls', [])
                return default_patterns + url_patterns
            if 'all' in patterns:
                url_patterns = patterns['all'].get('safe_urls', [])
                return default_patterns + url_patterns
        except Exception:
            pass
        return default_patterns
    
    def get_safe_comment_patterns(self, language: str = "all") -> List[str]:
        try:
            patterns = self._config.get('patterns', {}).get('custom_patterns', {})
            if language in patterns:
                return patterns[language].get('safe_comments', [])
            if 'all' in patterns:
                return patterns['all'].get('safe_comments', [])
        except Exception:
            pass
        return []
    
    def get_exclude_dirs(self, language: str = "all") -> List[str]:
        default_dirs = {
            'go': ['vendor', 'node_modules', '__pycache__'],
            'typescript': ['node_modules', 'dist', 'build', '__pycache__'],
            'ts': ['node_modules', 'dist', 'build', '__pycache__'],
            'all': []
        }
        try:
            patterns = self._config.get('patterns', {}).get('custom_patterns', {})
            if language in patterns:
                dirs = patterns[language].get('exclude_dirs', [])
                return default_dirs.get(language, []) + dirs if dirs else default_dirs.get(language, [])
            if 'all' in patterns:
                dirs = patterns['all'].get('exclude_dirs', [])
                return default_dirs.get(language, []) + dirs if dirs else default_dirs.get(language, [])
        except Exception:
            pass
        return default_dirs.get(language, default_dirs.get('all', []))
    
    def get_test_file_patterns(self, language: str = "all") -> List[str]:
        default_patterns = [
            '_test.', '.test.', '.spec.', '/test/', '/tests/', '/__tests__/',
            '/testdata/', 'test/', 'tests/'
        ]
        try:
            patterns = self._config.get('patterns', {}).get('custom_patterns', {})
            if language in patterns:
                test_patterns = patterns[language].get('test_file_patterns', [])
                return default_patterns + test_patterns if test_patterns else default_patterns
            if 'all' in patterns:
                test_patterns = patterns['all'].get('test_file_patterns', [])
                return default_patterns + test_patterns if test_patterns else default_patterns
        except Exception:
            pass
        return default_patterns
    
    def get_safe_literals(self, language: str = "all") -> List[str]:
        default_literals = [
            'README', 'LICENSE', 'CHANGELOG', 'CONTRIBUTING',
            'package.json', 'tsconfig.json', 'node_modules',
            'dist/', 'build/', 'public/', 'static/', 'assets/'
        ]
        try:
            patterns = self._config.get('patterns', {}).get('custom_patterns', {})
            if language in patterns:
                literals = patterns[language].get('safe_literals', [])
                return default_literals + literals if literals else default_literals
            if 'all' in patterns:
                literals = patterns['all'].get('safe_literals', [])
                return default_literals + literals if literals else default_literals
        except Exception:
            pass
        return default_literals
    
    def reload(self):
        self._config = self._load_config()

class PatternMatcher:
    def __init__(self):
        self.pattern_modules = {}
        self.mcp_scanners = {}
        self._load_pattern_modules()
        self._load_mcp_scanners()
    
    def _load_pattern_modules(self):
        try:
            from scanner.analyzers.rules.go import GoASTAnalyzer
            self.pattern_modules['go'] = {
                'analyzer': GoASTAnalyzer()
            }
            print(" Go pattern module loaded successfully")
        except ImportError as e:
            print(f"Warning: Could not load Go pattern module: {e}")
        try:
            from scanner.analyzers.rules.typescript import TypeScriptASTAnalyzer
            self.pattern_modules['ts'] = {
                'analyzer': TypeScriptASTAnalyzer()
            }
            print(" TypeScript pattern module loaded successfully")
        except ImportError as e:
            print(f"Warning: Could not load TypeScript pattern module: {e}")
        if not self.pattern_modules:
            print("Warning: No pattern modules loaded successfully")
    
    def _load_mcp_scanners(self):
        try:
            from scanner.analyzers.common.mcp_scanner import create_mcp_scanner
            
            go_mcp_scanner = create_mcp_scanner('go')
            if go_mcp_scanner:
                self.mcp_scanners['go'] = go_mcp_scanner
                print(" Go MCP scanner loaded successfully")
            
            ts_mcp_scanner = create_mcp_scanner('typescript')
            if ts_mcp_scanner:
                self.mcp_scanners['ts'] = ts_mcp_scanner
                self.mcp_scanners['typescript'] = ts_mcp_scanner
                print(" TypeScript MCP scanner loaded successfully")
        except Exception as e:
            print(f"Warning: Could not load MCP scanners: {e}")

    def scan_file(self, file_path: Path, language: str) -> List[Finding]:
        findings = []
        
        try:
            # Language-specific patterns
            if language in self.pattern_modules:
                language_patterns = self.pattern_modules[language]
                if 'analyzer' in language_patterns:
                    analyzer = language_patterns['analyzer']
                    pattern_findings = analyzer.analyze_file(str(file_path))
                    findings.extend(pattern_findings)
                else:
                    content = file_path.read_text(encoding='utf-8', errors='ignore')
                    for pattern_type, pattern_instance in language_patterns.items():
                        pattern_findings = pattern_instance.scan(content, str(file_path))
                        findings.extend(pattern_findings)
            
            # MCP-specific detectors (language-independent)
            # Config Poisoning can work on any file without AST
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    lines = f.readlines()
            except:
                lines = []
            
            if lines:
                from scanner.analyzers.rules.mcp.config_poisoning import ConfigPoisoningDetector
                config_detector = ConfigPoisoningDetector()
                config_findings = config_detector.check(
                    calls=[],
                    tainted_vars=set(),
                    lines=lines,
                    file_path=str(file_path),
                    ast_result=None,
                    taint_result=None,
                    cfg=None
                )
                findings.extend(config_findings)
            
            # MCP scanners for AST-based detection (go/ts only)
            mcp_language = 'ts' if language in ['typescript', 'ts', 'javascript', 'js'] else language
            if mcp_language in self.mcp_scanners:
                mcp_scanner = self.mcp_scanners[mcp_language]
                mcp_findings = mcp_scanner.scan_file(str(file_path))
                findings.extend(mcp_findings)
                
        except Exception as e:
            print(f"Error scanning file {file_path}: {e}")
        return findings
    
    def scan_file_for_mcp(self, file_path: Path) -> List[Finding]:
        """
        Scan any file for MCP-specific vulnerabilities (language-independent).
        This is used to scan all files regardless of detected language.
        """
        findings = []
        
        try:
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    lines = f.readlines()
            except:
                lines = []
            
            if not lines:
                return findings
            
            # Config Poisoning - works on any file without AST
            from scanner.analyzers.rules.mcp.config_poisoning import ConfigPoisoningDetector
            config_detector = ConfigPoisoningDetector()
            config_findings = config_detector.check(
                calls=[],
                tainted_vars=set(),
                lines=lines,
                file_path=str(file_path),
                ast_result=None,
                taint_result=None,
                cfg=None
            )
            findings.extend(config_findings)
            
            # Try to detect language and use AST-based MCP scanners if available
            from scanner.analyzers.language import LanguageDetector
            detector = LanguageDetector()
            detected_lang = detector.detect_from_file(file_path)
            
            if detected_lang in ['go', 'typescript', 'ts', 'javascript', 'js']:
                mcp_language = 'ts' if detected_lang in ['typescript', 'ts', 'javascript', 'js'] else detected_lang
                if mcp_language in self.mcp_scanners:
                    mcp_scanner = self.mcp_scanners[mcp_language]
                    mcp_findings = mcp_scanner.scan_file(str(file_path))
                    findings.extend(mcp_findings)
                
        except Exception as e:
            print(f"Error scanning file {file_path} for MCP: {e}")
        
        return findings