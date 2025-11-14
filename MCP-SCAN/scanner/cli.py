#!/usr/bin/env python3
import argparse
import sys
import json
from datetime import datetime
from pathlib import Path
from rich import print
from scanner.runner.manager import MCPScannerManager
from scanner.ui.colors import make_console, build_gradient_text
from scanner.analyzers.common.utils import is_github_repo, filter_findings_by_severity
from scanner.analyzers.common.constants import SEVERITY_INFO, OUTPUT_DIR, TEMP_DIR

def print_banner():
    console = make_console()
    banner_text = (
        "\n"
        "   ██████╗  ██████╗ ███╗   ███╗████████╗ ██████╗  ██████╗ ██╗\n"
        "   ██╔══██╗██╔═══██╗████╗ ████║╚══██╔══╝██╔═══██╗██╔═══██╗██║\n"
        "   ██████╔╝██║   ██║██╔████╔██║   ██║   ██║   ██║██║   ██║██║\n"
        "   ██╔══██╗██║   ██║██║╚██╔╝██║   ██║   ██║   ██║██║   ██║██║\n"
        "   ██████╔╝╚██████╔╝██║ ╚═╝ ██║   ██║   ╚██████╔╝╚██████╔╝███████╗\n"
        "   ╚═════╝  ╚═════╝ ╚═╝     ╚═╝   ╚═╝    ╚═════╝  ╚═════╝ ╚══════╝\n"
        "   ███████╗ ██████╗ █████╗ ███╗   ██╗\n"
        "   ██╔════╝██╔════╝██╔══██╗████╗  ██║\n"
        "   ███████╗██║     ███████║██╔██╗ ██║\n"
        "   ╚════██║██║     ██╔══██║██║╚██╗██║\n"
        "   ███████║╚██████╗██║  ██║██║ ╚████║\n"
        "   ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝\n"
    )
    text = build_gradient_text(banner_text, start_hex="#6c5d53", end_hex="#dfd3c3", bold=True)
    console.print(text)

def main():
    print_banner()

    parser = argparse.ArgumentParser(
        description="MCP Server Scanner - Built by BOMTool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Examples:\n  bomtool-scan --path /path/to/local/repo\n  bomtool-scan --path https://github.com/user/repo\n",
    )

    parser.add_argument("--path", help="Local repository path or GitHub URL")
    parser.add_argument("--mcp-only", action="store_true", help="Scan only MCP servers (skip code analysis)")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose output")
    parser.add_argument("--output", help="Output file name (without extension, defaults to 'finding')")
    args = parser.parse_args()

    try:
        # output 디렉토리 확인 및 생성
        OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
        TEMP_DIR.mkdir(parents=True, exist_ok=True)
        
        manager = MCPScannerManager(temp_dir=str(TEMP_DIR), verbose=args.verbose)
        
        if args.mcp_only:
            print("[blue]Scanning MCP servers only...[/blue]")
            print("[yellow]MCP-only scanning not yet implemented[/yellow]")
            sys.exit(0)
        else:
            if not args.path:
                print("[red][!][/red] --path is required for full scan")
                sys.exit(1)
                
            is_github = is_github_repo(args.path)
            
            if is_github:
                print(f"[blue]GitHub repository detected:[/blue] {args.path}")
            else:
                workdir = Path(args.path).resolve()
                if not workdir.exists():
                    print(f"[red][!][/red] Path not found: {workdir}")
                    sys.exit(1)
            
            results = manager.scan_repository_full(args.path)
        
        # 출력 파일 이름 결정
        if args.output:
            output_name = args.output
        else:
            # 저장소 이름 자동 추출
            from scanner.analyzers.common.utils import extract_repo_name
            output_name = extract_repo_name(args.path)
        
        # 파일명에 특수문자 제거 및 안전한 이름으로 변환
        safe_output_name = "".join(c if c.isalnum() or c in ('-', '_') else '_' for c in output_name)
        
        out = OUTPUT_DIR / f"{safe_output_name}.json"
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(results, indent=2, ensure_ascii=False), encoding="utf-8")
        print(f"[green]Detailed results saved:[/green] {out.resolve()}")

    except Exception as e:
        print(f"[red][!][/red] Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()