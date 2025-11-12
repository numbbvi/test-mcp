from pathlib import Path
from typing import Dict, Any, List, Optional
import json
import subprocess

from scanner.analyzers.common.scanner import Finding
from scanner.analyzers.common.control_flow import ControlFlowGraph
from scanner.analyzers.common.taint_engine import TaintPropagationEngine

class LanguageAnalyzer:
    
    def __init__(self, language: str, parser_name: str):
        self.language = language
        self.parser_path = Path(__file__).parent.parent / "rules" / "parsers" / parser_name
        self.taint_analyzer = TaintPropagationEngine()
        self.detectors = []
    
    def analyze(self, file_path: str) -> List[Finding]:
        print(f"\nAnalyzing: {file_path}")
        
        ast_result = self._parse_ast(file_path)
        if not ast_result:
            return []
        
        cfg = self._build_cfg(ast_result)
        taint_result = self._analyze_taint(ast_result, cfg)
        findings = self._match_rules(ast_result, cfg, taint_result)
        
        print(f"Analysis complete: {len(findings)} findings")
        return findings
    
    def analyze_file(self, file_path: str):
        return self.analyze(file_path)
    
    def _parse_ast(self, file_path: str) -> Dict[str, Any]:
        print("  Step 1: Parsing AST...")
        
        ast_result = self._run_parser(self.parser_path, file_path, self.language)
        
        if ast_result:
            print(f"    AST parsed: {len(ast_result.get('functions', []))} functions, {len(ast_result.get('calls', []))} calls")
        
        return ast_result or {}
    
    def _build_cfg(self, ast_result: Dict[str, Any]) -> ControlFlowGraph:
        from scanner.analyzers.common.control_flow import ControlFlowEdge, NodeType, ControlFlowNode
        
        print("Building CFG...")
        
        cfg = ControlFlowGraph(ast_result.get('file_path', ''))
        
        func_nodes = []
        for func in ast_result.get('functions', []):
            cfg.add_function(func)
            func_name = func.get('name', 'anonymous')
            node_id = f"func_{func_name}_{func.get('line', 0)}"
            func_nodes.append((node_id, func.get('line', 0)))
        
        call_nodes = []
        for call in ast_result.get('calls', []):
            cfg.add_call(call)
            call_name = f"{call.get('package', '')}.{call.get('function', '')}" if call.get('package') else call.get('function', '')
            node_id = f"call_{call_name}_{call.get('line', 0)}"
            call_nodes.append((node_id, call.get('line', 0)))
        
        all_nodes = sorted(func_nodes + call_nodes, key=lambda x: x[1])
        if all_nodes:
            cfg.entry_node = all_nodes[0][0]
        
        sorted_nodes = sorted(func_nodes + call_nodes, key=lambda x: x[1])
        for i in range(len(sorted_nodes) - 1):
            from_node = sorted_nodes[i][0]
            to_node = sorted_nodes[i + 1][0]
            edge = ControlFlowEdge(
                from_node=from_node,
                to_node=to_node,
                edge_type="sequential"
            )
            cfg.add_edge(edge)
        
        if sorted_nodes:
            cfg.exit_nodes.add(sorted_nodes[-1][0])
        
        print(f"    CFG built: {len(cfg.nodes)} nodes, {len(cfg.edges)} edges, entry: {cfg.entry_node}")
        
        return cfg
    
    def _analyze_taint(self, ast_result: Dict[str, Any], cfg: ControlFlowGraph) -> Dict[str, Any]:
        print("Running taint analysis...")
        
        dataflow_result = {
            'data_flows': ast_result.get('data_flows', [])
        }
        
        taint_result = self.taint_analyzer.analyze(ast_result, cfg, dataflow_result)
        
        all_tainted = set(taint_result.get('all_tainted', []))
        print(f"    Found {len(all_tainted)} tainted variables")
        
        return taint_result
    
    def _match_rules(self, ast_result: Dict[str, Any], cfg: ControlFlowGraph, 
                     taint_result: Dict[str, Any]) -> List[Finding]:
        print("Matching vulnerability rules...")
        
        findings = []
        all_tainted = set(taint_result.get('all_tainted', []))
        
        tainted_sample = list(all_tainted)[:10]
        print(f"    Tainted variables sample: {tainted_sample}")
        
        try:
            with open(ast_result.get('file_path', ''), 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
        except:
            lines = []
        
        calls = ast_result.get('calls', [])
        file_path = ast_result.get('file_path', '')
        
        for detector in self.detectors:
            detector_findings = detector.check(calls, all_tainted, lines, file_path, ast_result, taint_result, cfg)
            findings.extend(detector_findings)
            
            detector_name = detector.__class__.__name__.replace('Detector', '')
            if detector_findings:
                print(f"    Found {len(detector_findings)} {detector_name} vulnerabilities")
        
        return findings
    
    def register_detector(self, detector):
        self.detectors.append(detector)
    
    def _run_parser(self, parser_path: Path, file_path: str, language: str) -> Optional[Dict[str, Any]]:
        try:
            if language == 'go':
                cmd = [str(parser_path), file_path]
            elif language in ['typescript', 'javascript']:
                cmd = ['node', str(parser_path), file_path]
            else:
                print(f"Unsupported language: {language}")
                return None
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode != 0:
                print(f"Error running {language} parser: {result.stderr}")
                return None
            
            return json.loads(result.stdout)
            
        except subprocess.TimeoutExpired:
            print(f"{language} parser timeout for {file_path}")
            return None
        except json.JSONDecodeError as e:
            print(f"Failed to parse {language} parser output: {e}")
            return None
        except Exception as e:
            print(f"Error running {language} parser: {e}")
            return None


def create_typescript_analyzer():
    from scanner.analyzers.rules.typescript.command_injection import CommandInjectionDetector
    from scanner.analyzers.rules.typescript.path_traversal import PathTraversalDetector
    from scanner.analyzers.rules.typescript.server_side_request_forgery import SSRFDetector
    
    analyzer = LanguageAnalyzer('typescript', 'ts_parser.js')
    
    analyzer.register_detector(CommandInjectionDetector())
    analyzer.register_detector(PathTraversalDetector())
    analyzer.register_detector(SSRFDetector())
    
    return analyzer


def create_go_analyzer():
    from scanner.analyzers.rules.go.command_injection import CommandInjectionDetector
    from scanner.analyzers.rules.go.path_traversal import PathTraversalDetector
    from scanner.analyzers.rules.go.server_side_request_forgery import SSRFDetector
    
    analyzer = LanguageAnalyzer('go', 'go_parser')
    
    analyzer.register_detector(CommandInjectionDetector())
    analyzer.register_detector(PathTraversalDetector())
    analyzer.register_detector(SSRFDetector())
    
    return analyzer