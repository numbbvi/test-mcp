from __future__ import annotations
import json
import tempfile
import shutil
import time
import subprocess
from datetime import datetime
from zoneinfo import ZoneInfo
from pathlib import Path
from typing import Dict, List, Optional, Any
from rich.console import Console
from rich.progress import Progress, TaskID, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn, TimeRemainingColumn
from rich.logging import RichHandler
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich import box
from scanner.analyzers.language import LanguageDetector
from scanner.analyzers.common.scanner import PatternMatcher, Finding
from scanner.analyzers.common.constants import (
    GITHUB_PREFIXES, CLONE_RETRIES, SUPPORTED_LANGUAGES, 
    PROGRESS_PREPARE_START, PROGRESS_DETECT_LANGS, PROGRESS_SCAN_START,
    PROGRESS_SCAN_END, PROGRESS_FINALIZING, PROGRESS_COMPLETE,
    SEVERITY_INFO
)
from scanner.analyzers.common.utils import (
    is_github_repo, extract_repo_name, filter_findings_by_severity, count_findings_by_category
)


class RepositoryCloner:

    def __init__(self, work_dir: Path, progress_callback=None, logger=None):
        self.work_dir = work_dir
        self.progress_callback = progress_callback
        self.logger = logger
    
    def clone(self, github_url: str, max_retries: int = CLONE_RETRIES) -> Path:
        from scanner.analyzers.common.utils import normalize_github_url
        
        # Normalize GitHub URL to extract base URL and branch/commit
        base_url, branch_or_commit = normalize_github_url(github_url)
        repo_name = extract_repo_name(base_url)
        clone_path = self.work_dir / repo_name
        last_error = None
        
        for attempt in range(max_retries):
            try:
                if clone_path.exists():
                    shutil.rmtree(clone_path)
                
                self._log(f"Cloning repository: {base_url} (branch/commit: {branch_or_commit}) (attempt {attempt + 1}/{max_retries})")
                self._update_progress(26, f"Cloning {repo_name}... (attempt {attempt + 1})")
                
                # Check if branch_or_commit is a commit hash (7-40 hex chars)
                is_commit_hash = (
                    len(branch_or_commit) >= 7 and 
                    len(branch_or_commit) <= 40 and 
                    all(c in '0123456789abcdef' for c in branch_or_commit.lower())
                )
                
                # Build git clone command
                if is_commit_hash:
                    # For commit hash, we need more depth to fetch the commit
                    # Use --depth 50 to ensure we get enough history
                    clone_cmd = ['git', 'clone', '--progress', '--depth', '50', base_url, str(clone_path)]
                    process = subprocess.Popen(
                        clone_cmd,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.STDOUT,
                        text=True,
                        bufsize=1
                    )
                else:
                    # For branch name, use --depth 1 with --branch flag
                    clone_cmd = ['git', 'clone', '--progress', '--depth', '1', '--branch', branch_or_commit, base_url, str(clone_path)]
                    process = subprocess.Popen(
                        clone_cmd,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.STDOUT,
                        text=True,
                        bufsize=1
                    )
                
                output_lines = []
                for line in process.stdout:
                    output_lines.append(line)
                    if self.progress_callback:
                        if 'Receiving objects' in line or 'Resolving deltas' in line:
                            self.progress_callback.update(30, f"Downloading {repo_name}...")
                        elif 'Checking out files' in line:
                            self.progress_callback.update(34, f"Checking out {repo_name}...")
                
                return_code = process.wait()
                error_msg = ''.join(output_lines).strip()
                
                if return_code == 0:
                    # If branch_or_commit is a commit hash, checkout that commit
                    is_commit_hash = (
                        len(branch_or_commit) >= 7 and 
                        len(branch_or_commit) <= 40 and 
                        all(c in '0123456789abcdef' for c in branch_or_commit.lower())
                    )
                    if is_commit_hash:
                        checkout_process = subprocess.Popen(
                            ['git', 'checkout', branch_or_commit],
                            cwd=str(clone_path),
                            stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT,
                            text=True
                        )
                        checkout_output = checkout_process.stdout.read()
                        checkout_return_code = checkout_process.wait()
                        if checkout_return_code != 0:
                            self._log(f"Warning: Failed to checkout commit {branch_or_commit}: {checkout_output}")
                        else:
                            self._log(f"Checked out commit: {branch_or_commit}")
                    
                    self._update_progress(35, f"Repository cloned: {repo_name}")
                    self._log(f"Repository cloned to: {clone_path}")
                    return clone_path
                else:
                    if not error_msg:
                        error_msg = f"Git clone failed with exit code {return_code}"
                    last_error = error_msg
                    self._handle_clone_error(error_msg, github_url, attempt, max_retries)
                    
            except subprocess.CalledProcessError as e:
                last_error = str(e)
                if attempt < max_retries - 1:
                    self._retry_after_delay(attempt)
                else:
                    raise RuntimeError(f"Failed to clone after {max_retries} attempts: {last_error}")
            except Exception as e:
                last_error = str(e)
                if attempt < max_retries - 1:
                    self._retry_after_delay(attempt)
                else:
                    raise RuntimeError(f"Failed to clone after {max_retries} attempts: {last_error}")
        
        error_detail = f": {last_error}" if last_error else ""
        raise RuntimeError(f"Failed to clone repository after {max_retries} attempts{error_detail}")
    
    def _handle_clone_error(self, error_msg: str, github_url: str, attempt: int, max_retries: int):
        self._log(f"Git clone failed")
        self._log(f"Error details: {error_msg}")
        
        if 'Repository not found' in error_msg or 'not found' in error_msg.lower():
            raise RuntimeError(f"Repository not found: {github_url}. Please check the URL.")
        elif 'Permission denied' in error_msg or 'authentication failed' in error_msg.lower():
            raise RuntimeError(f"Authentication failed. The repository may be private: {github_url}")
        elif 'Could not resolve host' in error_msg:
            raise RuntimeError(f"Network error: Could not resolve host. Please check your internet connection.")
        
        if attempt < max_retries - 1:
            wait_time = (attempt + 1) * 2
            self._log(f"Retrying in {wait_time} seconds...")
            time.sleep(wait_time)
        else:
            raise subprocess.CalledProcessError(1, 'git clone', error_msg)
    
    def _retry_after_delay(self, attempt: int):
        wait_time = (attempt + 1) * 2
        self._log(f"Retrying in {wait_time} seconds...")
        time.sleep(wait_time)
    
    def _log(self, msg: str):
        if self.logger:
            self.logger(msg)
    
    def _update_progress(self, progress: int, msg: str):
        if self.progress_callback:
            self.progress_callback.update(progress, msg)


class ScanOrchestrator:
    
    def __init__(self, language_detector: LanguageDetector, pattern_matcher: PatternMatcher, 
                 console: Console, progress_callback=None, logger=None):
        self.language_detector = language_detector
        self.pattern_matcher = pattern_matcher
        self.console = console
        self.progress_callback = progress_callback
        self.logger = logger
    
    def scan_language_files_with_progress(self, repo_path: Path, language: str, 
                                         progress: Progress, task_id: TaskID, 
                                         lang_index: int, total_langs: int) -> tuple[List[Finding], int, int]:
        """
        Scan language files and return findings along with file statistics.
        
        Returns:
            tuple: (findings, total_files, scanned_files)
        """
        if language not in SUPPORTED_LANGUAGES:
            self._log(f"Unsupported language: {language} (skipping)")
            return [], 0, 0
        
        files = self._get_file_list(repo_path, language)
        total_files = len(files)
        self._log(f"[{language}] Found {total_files} files")
        
        if self.progress_callback and total_files > 0:
            base_progress = 40 + int((lang_index / total_langs) * 45)
            base_progress = min(84, base_progress)
            self.progress_callback.update(base_progress, f"Starting {language.upper()} scan ({total_files} files)")
        
        all_findings = []
        scanned_files = 0
        for i, file_path in enumerate(files):
            try:
                findings = self.pattern_matcher.scan_file(file_path, language)
                all_findings.extend(findings)
                scanned_files += 1
                
                if findings:
                    self.console.print(f" [yellow]{language.upper()}[/yellow] {file_path.name}: [red]{len(findings)} findings[/red]")
                    self._log(f"[{language}] {file_path.name}: {len(findings)} findings")
                else:
                    self.console.print(f" [yellow]{language.upper()}[/yellow] {file_path.name}: [green]No issues found[/green]")
                
                self._update_scan_progress(i, total_files, lang_index, total_langs, language, progress, task_id)
                    
            except Exception as e:
                self.console.print(f" [yellow]{language.upper()}[/yellow] {file_path.name}: [red]Error - {e}[/red]")
                self._log(f"[{language}] Error scanning {file_path}: {e}")
                # Error occurred but file was attempted to scan, so count it
                scanned_files += 1
        
        if lang_index == total_langs - 1:
            progress.update(task_id, completed=100)
        
        self._log(f"[{language}] Analysis completed - {len(all_findings)} total findings, {scanned_files}/{total_files} files scanned")
        return all_findings, total_files, scanned_files
    
    def _get_file_list(self, repo_path: Path, language: str) -> List[Path]:
        if repo_path.is_file():
            self._log(f"[{language}] Single file: {repo_path.name}")
            return [repo_path]
        else:
            return self.language_detector.get_file_list(repo_path, language)
    
    def _update_scan_progress(self, current: int, total: int, lang_index: int, 
                             total_langs: int, language: str, progress: Progress, task_id: TaskID):
        file_progress = (current + 1) / total if total else 1.0
        lang_progress = (lang_index + file_progress) / total_langs * 100
        progress.update(task_id, completed=lang_progress)
        
        if self.progress_callback:
            current_lang_progress = (current + 1) / total
            web_progress = 40 + int((lang_index + current_lang_progress) / total_langs * 45)
            web_progress = min(85, max(40, web_progress))
            self.progress_callback.update(web_progress, f"Scanning {language.upper()} ({current+1}/{total} files)")
    
    def _log(self, msg: str):
        if self.logger:
            self.logger(msg)


class ResultFormatter:
    
    def __init__(self, console: Console, language_detector: LanguageDetector):
        self.console = console
        self.language_detector = language_detector
    
    def finding_to_dict(self, finding: Finding) -> Dict[str, Any]:
        return {
            "rule_id": finding.rule_id,
            "severity": finding.severity,
            "message": finding.message,
            "cwe": finding.cwe,
            "file": finding.file,
            "line": finding.line,
            "column": finding.column,
            "code_snippet": finding.code_snippet,
            "pattern_type": finding.pattern_type,
            "pattern": finding.pattern,
            "confidence": finding.confidence
        }
    
    def generate_summary(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        if not findings:
            return {
                "total_findings": 0,
                "total_findings_excluding_info": 0,
                "mcp_findings": 0,
                "mcp_findings_excluding_info": 0,
                "general_findings": 0,
                "general_findings_excluding_info": 0,
                "by_severity": {},
                "by_rule": {},
                "by_language": {}
            }
        
        findings_excluding_info = filter_findings_by_severity(findings, [SEVERITY_INFO])
        
        mcp_findings = [f for f in findings if f.get("rule_id", "").startswith("mcp/")]
        general_findings = [f for f in findings if not f.get("rule_id", "").startswith("mcp/")]
        
        mcp_findings_excluding_info = filter_findings_by_severity(mcp_findings, [SEVERITY_INFO])
        general_findings_excluding_info = filter_findings_by_severity(general_findings, [SEVERITY_INFO])
        
        summary = {
            "total_findings": len(findings),
            "total_findings_excluding_info": len(findings_excluding_info),
            "mcp_findings": len(mcp_findings),
            "mcp_findings_excluding_info": len(mcp_findings_excluding_info),
            "general_findings": len(general_findings),
            "general_findings_excluding_info": len(general_findings_excluding_info),
            "by_severity": count_findings_by_category(findings, "severity"),
            "by_rule": count_findings_by_category(findings, "rule_id"),
            "by_language": count_findings_by_category(findings, "language")
        }
        
        return summary
    
    def display_scan_summary(self, findings: List[Dict[str, Any]], languages: List[str]):
        severity_stats = {}
        rule_stats = {}
        language_stats = {}
        
        for finding in findings:
            severity = finding.get("severity", "unknown")
            rule_id = finding.get("rule_id", "unknown")
            file_path = finding.get("file", "")

            lang = self.language_detector.detect_from_path(file_path)
            
            severity_stats[severity] = severity_stats.get(severity, 0) + 1
            rule_stats[rule_id] = rule_stats.get(rule_id, 0) + 1
            language_stats[lang] = language_stats.get(lang, 0) + 1
        
        table = Table(title="Security Scan Results Summary", box=box.ROUNDED)
        table.add_column("Category", style="cyan", no_wrap=True)
        table.add_column("Details", style="white")
        
        total_findings = len(findings)
        findings_excluding_info = filter_findings_by_severity(findings, [SEVERITY_INFO])
        total_findings_excluding_info = len(findings_excluding_info)
        
        if total_findings == 0:
            table.add_row("Total Findings", "[green]No security issues found![/green]")
        else:
            table.add_row("Total Findings", f"[red]{total_findings_excluding_info}[/red] security issues detected (excluding info)")
            if severity_stats.get("info", 0) > 0:
                table.add_row("Info Findings", f"[blue]{severity_stats.get('info', 0)}[/blue] info-level findings")
        
        if severity_stats:
            severity_text = " | ".join([
                f"[red]{severity.upper()}: {count}[/red]" if severity == 'high' 
                else f"[yellow]{severity.upper()}: {count}[/yellow]" if severity == 'medium'
                else f"[blue]{severity.upper()}: {count}[/blue]"
                for severity, count in sorted(severity_stats.items())
            ])
            table.add_row("By Severity", severity_text)
        
        if language_stats:
            lang_text = " | ".join([
                f"[cyan]{lang}: {count}[/cyan]" 
                for lang, count in sorted(language_stats.items())
            ])
            table.add_row("By Language", lang_text)
        
        if rule_stats:
            top_rules = sorted(rule_stats.items(), key=lambda x: x[1], reverse=True)[:5]
            rules_text = " | ".join([
                f"[magenta]{rule}: {count}[/magenta]"
                for rule, count in top_rules
            ])
            table.add_row("Top Rules", rules_text)
        
        self.console.print(Panel(table, title="Scan Summary", border_style="blue"))


class MCPScannerManager:
    
    def __init__(self, temp_dir: Optional[str] = None, verbose: bool = False):
        self.verbose = verbose
        self.work_dir = Path(temp_dir) if temp_dir else Path("output/temp")
        self.console = Console()

        self._cleanup_temp_dir()

        self.language_detector = LanguageDetector()
        self.pattern_matcher = PatternMatcher()
        self.progress_callback = None

        self.cloner = RepositoryCloner(self.work_dir, None, self.log_manager)
        self.orchestrator = ScanOrchestrator(
            self.language_detector, 
            self.pattern_matcher,
            self.console,
            None,
            self.log_manager
        )
        self.formatter = ResultFormatter(self.console, self.language_detector)
        
        self.log_manager(f"Manager initialized - work_dir: {self.work_dir}")
    
    def set_progress_callback(self, callback):
        self.progress_callback = callback
        self.cloner.progress_callback = callback
        self.orchestrator.progress_callback = callback
    
    def scan_repository_full(self, repo_path: str | Path) -> Dict[str, Any]:
        repo_path_str = str(repo_path)
        scan_start_time = time.time()
        # 한국 시간(KST, UTC+9)으로 변환
        kst = ZoneInfo('Asia/Seoul')
        scan_timestamp = datetime.now(kst).strftime("%Y-%m-%d %H:%M:%S")
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            "[progress.percentage]{task.percentage:>3.0f}%",
            TimeElapsedColumn(),
            TimeRemainingColumn(),
            console=self.console,
            expand=True,
        ) as progress:
            actual_repo_path = self._prepare_repository(repo_path_str, progress)
            
            # Count total files first (before language detection)
            total_files = self._count_total_files(actual_repo_path)
            self.log_manager(f"Total text files in repository: {total_files}")
            
            languages = self._detect_languages(actual_repo_path, progress)
            
            if not languages:
                scan_end_time = time.time()
                scan_duration = round(scan_end_time - scan_start_time, 2)
                return self._create_empty_result(repo_path_str, scan_duration, scan_timestamp)
            
            all_findings, lang_total_files, lang_scanned_files = self._scan_all_languages(actual_repo_path, languages, progress)
            
            # Scan all files for MCP-specific vulnerabilities (language-independent)
            mcp_findings, mcp_scanned_files = self._scan_all_files_for_mcp(actual_repo_path, progress)
            all_findings.extend(mcp_findings)
            
            # Calculate scanned files
            scanned_files = lang_scanned_files + mcp_scanned_files
            
            # Ensure scanned_files matches total_files if files were counted but not scanned
            if scanned_files == 0 and total_files > 0:
                # If no files were scanned but total_files > 0, set scanned_files to total_files
                # This happens when files exist but don't match scan patterns
                scanned_files = total_files
                self.log_manager(f"Warning: No files were scanned but {total_files} files were counted. Setting scanned_files to total_files.")
            
            # Ensure scanned_files doesn't exceed total_files
            if scanned_files > total_files:
                scanned_files = total_files
            
            self.log_manager(f"Final count: {total_files} total files, {scanned_files} scanned files (lang: {lang_scanned_files}, mcp: {mcp_scanned_files})")
            
            findings_dict = [self.formatter.finding_to_dict(f) for f in all_findings]
            
            # 파일 경로 정규화: 임시 경로를 저장소 내 상대 경로로 변환
            findings_dict = self._normalize_file_paths(findings_dict, actual_repo_path)
            
            self.formatter.display_scan_summary(findings_dict, languages)
        
        self._cleanup_if_cloned(repo_path_str, actual_repo_path)
        
        scan_end_time = time.time()
        scan_duration = round(scan_end_time - scan_start_time, 2)
        
        findings_excluding_info = filter_findings_by_severity(findings_dict, [SEVERITY_INFO])
        
        return {
            "scan_info": {
                "repository": repo_path_str,
                "languages": languages,
                "total_findings": len(findings_dict),
                "total_findings_excluding_info": len(findings_excluding_info),
                "scan_duration": scan_duration,
                "scan_timestamp": scan_timestamp,
            },
            "findings": findings_dict,
            "summary": self.formatter.generate_summary(findings_dict),
        }
    
    def _prepare_repository(self, repo_path_str: str, progress: Progress) -> Path:
        task_prepare = progress.add_task(" Preparing repository...", total=100)
        progress.update(task_prepare, completed=10)
        
        if self.progress_callback:
            self.progress_callback.update(20, "Preparing repository...")
        
        if is_github_repo(repo_path_str):
            self.log_manager(f"GitHub repository detected: {repo_path_str}")
            progress.update(task_prepare, description="Cloning GitHub repository...", completed=30)
            
            if self.progress_callback:
                self.progress_callback.update(22, "Starting clone...")
            
            actual_repo_path = self.cloner.clone(repo_path_str)
        else:
            actual_repo_path = Path(repo_path_str).resolve()
            if not actual_repo_path.exists():
                raise ValueError(f"Repository path does not exist: {actual_repo_path}")
            
            progress.update(task_prepare, description="Analyzing local repository...", completed=30)
            if self.progress_callback:
                self.progress_callback.update(25, "Analyzing local repository...")
        
        progress.update(task_prepare, completed=100)
        if self.progress_callback:
            self.progress_callback.update(36, "Repository ready")
        
        return actual_repo_path
    
    def _detect_languages(self, repo_path: Path, progress: Progress) -> List[str]:
        task_detect = progress.add_task("Detecting programming languages...", total=100)
        progress.update(task_detect, completed=20)
        
        if self.progress_callback:
            self.progress_callback.update(37, "Detecting languages...")
        
        self.log_manager(f"Starting repository analysis: {repo_path}")
        
        if repo_path.is_file():
            lang = self.language_detector.detect_from_file(repo_path)
            languages = [lang] if lang != 'unknown' else []
        else:
            languages = self.language_detector.detect(repo_path)
        
        progress.update(task_detect, completed=100)
        
        if self.progress_callback:
            self.progress_callback.update(39, f"Found: {', '.join(languages)}")
        
        if languages:
            self.log_manager(f"Detected languages: {', '.join(languages)}")
            self.console.print(f"\n [green]Detected languages:[/green] {', '.join(languages)}")
        else:
            self.log_manager("No supported languages detected (go/ts)")
            self.console.print("[red]No supported languages detected[/red]")
        
        return languages
    
    def _scan_all_languages(self, repo_path: Path, languages: List[str], progress: Progress) -> tuple[List[Finding], int, int]:
        """
        Scan all languages and return findings along with file statistics.
        
        Returns:
            tuple: (findings, total_files, scanned_files)
        """
        task_scan = progress.add_task("Scanning files for vulnerabilities...", total=100)
        all_findings = []
        total_files = 0
        scanned_files = 0
        scan_start_time = time.time()
        
        for i, lang in enumerate(languages):
            progress.update(task_scan, description=f"Scanning {lang.upper()} files...")
            
            if self.progress_callback:
                lang_progress = 40 + int((i / len(languages)) * 45)
                self.progress_callback.update(lang_progress, f"Starting {lang.upper()} scan...")
            
            lang_findings, lang_total_files, lang_scanned_files = self.orchestrator.scan_language_files_with_progress(
                repo_path, lang, progress, task_scan, i, len(languages)
            )
            all_findings.extend(lang_findings)
            total_files += lang_total_files
            scanned_files += lang_scanned_files
        
        scan_duration = time.time() - scan_start_time
        progress.update(task_scan, completed=100)
        
        if self.progress_callback:
            self.progress_callback.update(90, "Scan completed")
        
        self.log_manager(f"Scan completed in {scan_duration:.2f} seconds - {scanned_files}/{total_files} files scanned")
        
        return all_findings, total_files, scanned_files
    
    def _count_total_files(self, repo_path: Path) -> int:
        """
        Count all text files in the repository.
        
        Returns:
            int: Total number of text files
        """
        exclude_dirs = {
            '.git', 'node_modules', 'vendor', '__pycache__', '.venv', 
            'venv', 'dist', 'build', '.next', 'target', '.gradle',
            'output', 'temp', 'tmp', '.idea', '.vscode'
        }
        
        text_extensions = {
            '.json', '.js', '.ts', '.jsx', '.tsx', '.go', '.py', '.java',
            '.c', '.cpp', '.h', '.hpp', '.cs', '.rb', '.php', '.swift',
            '.kt', '.scala', '.rs', '.sh', '.bash', '.zsh', '.yaml', '.yml',
            '.toml', '.ini', '.conf', '.config', '.env', '.md', '.txt',
            '.xml', '.html', '.css', '.scss', '.less', '.vue', '.svelte',
            '.mjs', '.cjs', '.dart', '.lua', '.r', '.sql', '.pl', '.pm'
        }
        
        total_count = 0
        try:
            for file_path in repo_path.rglob('*'):
                if not file_path.is_file():
                    continue
                
                # Skip excluded directories
                if any(excluded in file_path.parts for excluded in exclude_dirs):
                    continue
                
                # Skip binary files (check extension or no extension)
                if file_path.suffix.lower() not in text_extensions and file_path.suffix:
                    continue
                
                # Skip very large files (> 1MB)
                try:
                    if file_path.stat().st_size > 1024 * 1024:
                        continue
                except:
                    continue
                
                total_count += 1
        except Exception as e:
            self.log_manager(f"Error counting total files: {e}")
        
        return total_count
    
    def _scan_all_files_for_mcp(self, repo_path: Path, progress: Progress) -> tuple[List[Finding], int]:
        """
        Scan all files in the repository for MCP-specific vulnerabilities.
        This is language-independent and focuses on MCP-specific issues like Config Poisoning.
        
        Returns:
            tuple: (findings, additional_files_scanned)
        """
        findings = []
        scanned_files = 0
        
        try:
            if self.progress_callback:
                self.progress_callback.update(85, "Scanning all files for MCP vulnerabilities...")
            
            # Exclude directories that should not be scanned
            exclude_dirs = {
                '.git', 'node_modules', 'vendor', '__pycache__', '.venv', 
                'venv', 'dist', 'build', '.next', 'target', '.gradle',
                'output', 'temp', 'tmp', '.idea', '.vscode'
            }
            
            # Get all text files (exclude binary files)
            text_extensions = {
                '.json', '.js', '.ts', '.jsx', '.tsx', '.go', '.py', '.java',
                '.c', '.cpp', '.h', '.hpp', '.cs', '.rb', '.php', '.swift',
                '.kt', '.scala', '.rs', '.sh', '.bash', '.zsh', '.yaml', '.yml',
                '.toml', '.ini', '.conf', '.config', '.env', '.md', '.txt',
                '.xml', '.html', '.css', '.scss', '.less', '.vue', '.svelte',
                '.mjs', '.cjs', '.dart', '.lua', '.r', '.sql', '.pl', '.pm'
            }
            
            scanned_paths = set()
            
            # First, mark files already scanned by language-specific scans
            for lang in ['go', 'typescript', 'ts', 'javascript', 'js']:
                if lang in ['typescript', 'ts', 'javascript', 'js']:
                    lang_extensions = ['.ts', '.tsx', '.js', '.jsx', '.mjs', '.cjs']
                elif lang == 'go':
                    lang_extensions = ['.go']
                else:
                    continue
                
                for ext in lang_extensions:
                    for file_path in repo_path.rglob(f'*{ext}'):
                        if file_path.is_file():
                            scanned_paths.add(file_path.resolve())
            
            # Scan all other text files for MCP vulnerabilities (excluding already scanned)
            for file_path in repo_path.rglob('*'):
                if not file_path.is_file():
                    continue
                
                # Skip if already scanned by language-specific scan
                if file_path.resolve() in scanned_paths:
                    continue
                
                # Skip excluded directories
                if any(excluded in file_path.parts for excluded in exclude_dirs):
                    continue
                
                # Skip binary files (check extension or no extension)
                if file_path.suffix.lower() not in text_extensions and file_path.suffix:
                    continue
                
                # Skip very large files (> 1MB)
                try:
                    if file_path.stat().st_size > 1024 * 1024:
                        continue
                except:
                    continue
                
                try:
                    mcp_findings = self.pattern_matcher.scan_file_for_mcp(file_path)
                    if mcp_findings:
                        findings.extend(mcp_findings)
                        self.log_manager(f"[MCP] {file_path.name}: {len(mcp_findings)} MCP findings")
                    scanned_files += 1
                except Exception as e:
                    self.log_manager(f"[MCP] Error scanning {file_path}: {e}")
                    # Count even if error occurred
                    scanned_files += 1
            
            self.log_manager(f"[MCP] Scanned {scanned_files} additional files for MCP vulnerabilities")
            
        except Exception as e:
            self.log_manager(f"[MCP] Error in MCP file scan: {e}")
        
        return findings, scanned_files
    
    def _create_empty_result(self, repo_path: str, scan_duration: float = 0.0, scan_timestamp: str = "") -> Dict[str, Any]:
        if not scan_timestamp:
            # 한국 시간(KST, UTC+9)으로 변환
            kst = ZoneInfo('Asia/Seoul')
            scan_timestamp = datetime.now(kst).strftime("%Y-%m-%d %H:%M:%S")
        return {
            "scan_info": {
                "repository": repo_path,
                "languages": [],
                "total_findings": 0,
                "total_findings_excluding_info": 0,
                "scan_duration": scan_duration,
                "scan_timestamp": scan_timestamp,
            },
            "findings": [],
            "summary": self.formatter.generate_summary([]),
        }
    
    def _cleanup_if_cloned(self, repo_path_str: str, actual_repo_path: Path):
        if is_github_repo(repo_path_str):
            try:
                if actual_repo_path.exists():
                    shutil.rmtree(actual_repo_path)
                    self.log_manager(f"Cleaned up cloned repository: {actual_repo_path}")
            except Exception as e:
                self.log_manager(f"Warning: Failed to cleanup cloned repository: {e}")
    
    def _cleanup_temp_dir(self):
        if self.work_dir.exists():
            try:
                shutil.rmtree(self.work_dir)
                self.log_manager(f"Cleaned up existing temp directory: {self.work_dir}")
            except Exception as e:
                self.log_manager(f"Warning: Failed to cleanup temp directory: {e}")
        self.work_dir.mkdir(parents=True, exist_ok=True)
    
    def _normalize_file_paths(self, findings: List[Dict[str, Any]], repo_path: Path) -> List[Dict[str, Any]]:
        """
        정규화 파일 경로: 임시 경로를 저장소 내 상대 경로로 변환
        
        Args:
            findings: Finding 딕셔너리 리스트
            repo_path: 저장소 루트 경로
            
        Returns:
            정규화된 Finding 딕셔너리 리스트
        """
        normalized_findings = []
        repo_name = repo_path.name
        
        for finding in findings:
            file_path = finding.get("file", "")
            if file_path:
                try:
                    # 절대 경로인 경우 저장소 경로를 기준으로 상대 경로 추출
                    if Path(file_path).is_absolute():
                        try:
                            file_path_obj = Path(file_path).resolve()
                            repo_path_resolved = repo_path.resolve()
                            if str(file_path_obj).startswith(str(repo_path_resolved)):
                                relative_path = file_path_obj.relative_to(repo_path_resolved)
                                normalized_path = str(relative_path).replace('\\', '/')
                                finding["file"] = normalized_path
                            else:
                                # 절대 경로지만 repo_path에 포함되지 않는 경우
                                # 임시 경로 패턴 확인
                                self._normalize_temp_path(finding, file_path, repo_name)
                        except (ValueError, Exception) as e:
                            # 상대 경로 변환 실패 시 임시 경로 패턴 확인
                            self._normalize_temp_path(finding, file_path, repo_name)
                    else:
                        # 상대 경로인 경우 임시 경로 패턴 확인
                        self._normalize_temp_path(finding, file_path, repo_name)
                except Exception as e:
                    self.log_manager(f"Warning: Failed to normalize file path '{file_path}': {e}")
            
            normalized_findings.append(finding)
        
        return normalized_findings
    
    def _normalize_temp_path(self, finding: Dict[str, Any], file_path: str, repo_name: str):
        """
        임시 경로 패턴을 제거하여 저장소 내 상대 경로로 변환
        
        Args:
            finding: Finding 딕셔너리
            file_path: 원본 파일 경로
            repo_name: 저장소 이름
        """
        # 임시 경로 패턴: output/temp/{repo_name}/... 또는 temp/{repo_name}/...
        temp_patterns = [
            f"output/temp/{repo_name}/",
            f"temp/{repo_name}/",
            f"output/temp/",
            f"temp/",
        ]
        
        for pattern in temp_patterns:
            if pattern in file_path:
                # 패턴 이후의 부분 추출
                normalized_path = file_path.split(pattern, 1)[-1]
                finding["file"] = normalized_path
                self.log_manager(f"Normalized file path: '{file_path}' -> '{normalized_path}'")
                return
    
    def log_manager(self, msg: str):
        if self.verbose:
            print(f"[LOG] {msg}")