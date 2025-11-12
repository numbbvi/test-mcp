from pathlib import Path
from typing import Dict, Any, List, Optional
import json
import subprocess

from scanner.analyzers.common.scanner import Finding
from scanner.analyzers.common.control_flow import ControlFlowGraph
from scanner.analyzers.common.taint_engine import TaintPropagationEngine
from scanner.analyzers.rules.mcp import (
    ToxicFlowDetector,
    ToolPoisoningDetector,
    ToolNameSpoofingDetector,
    ToolShadowingDetector,
    ConfigPoisoningDetector
)


class MCPScanner:
    
    def __init__(self, language: str, parser_name: str):
        self.language = language
        self.parser_path = Path(__file__).parent.parent / "rules" / "parsers" / parser_name
        self.taint_analyzer = TaintPropagationEngine()
        self.detectors = []
        self._register_detectors()
    
    def _register_detectors(self):
        self.detectors.append(ToxicFlowDetector())
        self.detectors.append(ToolPoisoningDetector())
        self.detectors.append(ToolNameSpoofingDetector())
        self.detectors.append(ToolShadowingDetector())
        self.detectors.append(ConfigPoisoningDetector())
    
    def scan_file(self, file_path: str) -> List[Finding]:
        findings = []
        
        ast_result = self._parse_ast(file_path)
        if not ast_result:
            return findings
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
        except:
            lines = []
        
        calls = ast_result.get('calls', [])
        
        cfg = self._build_cfg(ast_result)
        
        dataflow_result = {
            'data_flows': ast_result.get('data_flows', [])
        }
        taint_result = self.taint_analyzer.analyze(ast_result, cfg, dataflow_result)
        
        all_tainted = set(taint_result.get('all_tainted', []))
        
        for detector in self.detectors:
            try:
                detector_findings = detector.check(
                    calls, 
                    all_tainted,
                    lines, 
                    file_path, 
                    ast_result, 
                    taint_result, 
                    cfg=cfg
                )
                findings.extend(detector_findings)
            except Exception as e:
                print(f"Error in {detector.__class__.__name__}: {e}")
        
        return findings
    
    def _parse_ast(self, file_path: str) -> Dict[str, Any]:
        try:
            if self.language == 'go':
                cmd = [str(self.parser_path), file_path]
            elif self.language in ['typescript', 'javascript']:
                cmd = ['node', str(self.parser_path), file_path]
            else:
                return {}
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode != 0:
                return {}
            
            return json.loads(result.stdout)
            
        except Exception as e:
            return {}
    
    def _build_cfg(self, ast_result: Dict[str, Any]) -> ControlFlowGraph:
        from scanner.analyzers.common.control_flow import ControlFlowEdge, NodeType, ControlFlowNode
        
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


def create_mcp_scanner(language: str) -> Optional[MCPScanner]:
    if language == 'go':
        return MCPScanner('go', 'go_parser')
    elif language in ['typescript', 'ts', 'javascript', 'js']:
        return MCPScanner('typescript', 'ts_parser.js')
    return None