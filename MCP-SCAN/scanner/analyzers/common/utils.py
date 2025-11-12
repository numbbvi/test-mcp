import re
from pathlib import Path
from typing import List, Dict, Any, Tuple

from scanner.analyzers.common.constants import GITHUB_PREFIXES


def is_github_repo(path: str) -> bool:
    """Check if path is a GitHub repository URL, including branch/commit hash paths."""
    # Check basic GitHub URL
    if any(path.startswith(prefix) for prefix in GITHUB_PREFIXES):
        return True
    
    # Check for GitHub URL with /tree/, /blob/, /commit/ paths
    github_url_pattern = r'https?://github\.com/[^/]+/[^/]+(/tree/|/blob/|/commit/)?'
    return bool(re.match(github_url_pattern, path))


def normalize_github_url(github_url: str) -> Tuple[str, str]:
    """
    Normalize GitHub URL to base repository URL and extract branch/commit.
    
    Returns:
        Tuple[str, str]: (base_repo_url, branch_or_commit)
        Example: ('https://github.com/user/repo', 'main') or ('https://github.com/user/repo', 'd7e6cf0')
    """
    # Remove trailing slash
    url = github_url.rstrip('/')
    
    # Pattern: https://github.com/owner/repo/tree/branch_or_commit
    tree_match = re.match(r'(https?://github\.com/[^/]+/[^/]+)/tree/([^/]+)', url)
    if tree_match:
        base_url = tree_match.group(1)
        branch_or_commit = tree_match.group(2)
        return base_url, branch_or_commit
    
    # Pattern: https://github.com/owner/repo/blob/branch_or_commit
    blob_match = re.match(r'(https?://github\.com/[^/]+/[^/]+)/blob/([^/]+)', url)
    if blob_match:
        base_url = blob_match.group(1)
        branch_or_commit = blob_match.group(2)
        return base_url, branch_or_commit
    
    # Pattern: https://github.com/owner/repo/commit/commit_hash
    commit_match = re.match(r'(https?://github\.com/[^/]+/[^/]+)/commit/([^/]+)', url)
    if commit_match:
        base_url = commit_match.group(1)
        commit_hash = commit_match.group(2)
        return base_url, commit_hash
    
    # Pattern: https://github.com/owner/repo (no branch/commit)
    base_match = re.match(r'(https?://github\.com/[^/]+/[^/]+)', url)
    if base_match:
        return base_match.group(1), 'main'
    
    # Return original URL if no match
    return url, 'main'


def extract_repo_name(repo_path: str) -> str:
    """Extract repository name from GitHub URL or local path."""
    if is_github_repo(repo_path):
        # Normalize URL to get base repo URL
        base_url, _ = normalize_github_url(repo_path)
        repo_name = base_url.rstrip('/').split('/')[-1]
        return repo_name[:-4] if repo_name.endswith('.git') else repo_name
    else:
        return Path(repo_path).name


def filter_findings_by_severity(findings: List[Dict[str, Any]], 
                                exclude_severities: List[str] = None) -> List[Dict[str, Any]]:
    if exclude_severities is None:
        exclude_severities = ['info']
    
    exclude_lower = [s.lower() for s in exclude_severities]
    return [f for f in findings if f.get("severity", "").lower() not in exclude_lower]


def count_findings_by_category(findings: List[Dict[str, Any]], 
                               category: str) -> Dict[str, int]:
    counts = {}
    for finding in findings:
        value = finding.get(category, "unknown")
        counts[value] = counts.get(value, 0) + 1
    return counts