from __future__ import annotations
import json
from pathlib import Path
from typing import Dict, List, Set, Optional, Any, Tuple
from dataclasses import dataclass
from enum import Enum

class NodeType(Enum):
    START = "start"
    END = "end"
    ASSIGNMENT = "assignment"
    CONDITION = "condition"
    LOOP = "loop"
    FUNCTION_CALL = "function_call"
    RETURN = "return"
    BRANCH = "branch"

@dataclass
class ControlFlowNode:
    id: str
    node_type: NodeType
    line: int
    column: int
    code: str
    taint_sources: Set[str] = None
    taint_sinks: Set[str] = None
    
    def __post_init__(self):
        if self.taint_sources is None:
            self.taint_sources = set()
        if self.taint_sinks is None:
            self.taint_sinks = set()

@dataclass
class ControlFlowEdge:
    from_node: str
    to_node: str
    edge_type: str
    condition: Optional[str] = None

class ControlFlowGraph:
    
    def __init__(self, file_path: str):
        self.file_path = file_path
        self.nodes: Dict[str, ControlFlowNode] = {}
        self.edges: List[ControlFlowEdge] = []
        self.entry_node: Optional[str] = None
        self.exit_nodes: Set[str] = set()
        self.functions: Dict[str, Any] = {}
        self.variable_states: Dict[str, Dict[str, Set[str]]] = {}
        
    def add_node(self, node: ControlFlowNode):
        self.nodes[node.id] = node
        
    def add_edge(self, edge: ControlFlowEdge):
        self.edges.append(edge)
    
    def add_function(self, func: Dict):
        func_name = func.get('name', 'anonymous')
        self.functions[func_name] = func
        
        node_id = f"func_{func_name}_{func.get('line', 0)}"
        node = ControlFlowNode(
            id=node_id,
            node_type=NodeType.FUNCTION_CALL,
            line=func.get('line', 0),
            column=func.get('column', 0),
            code=func_name
        )
        self.add_node(node)
    
    def add_call(self, call: Dict):
        call_name = f"{call.get('package', '')}.{call.get('function', '')}" if call.get('package') else call.get('function', '')
        node_id = f"call_{call_name}_{call.get('line', 0)}"
        
        node = ControlFlowNode(
            id=node_id,
            node_type=NodeType.FUNCTION_CALL,
            line=call.get('line', 0),
            column=call.get('column', 0),
            code=call_name
        )
        self.add_node(node)
        
    def get_successors(self, node_id: str) -> List[str]:
        successors = []
        for edge in self.edges:
            if edge.from_node == node_id:
                successors.append(edge.to_node)
        return successors
        
    def get_predecessors(self, node_id: str) -> List[str]:
        predecessors = []
        for edge in self.edges:
            if edge.to_node == node_id:
                predecessors.append(edge.from_node)
        return predecessors
        
    def get_all_paths(self, start: str, end: str, max_depth: int = 50) -> List[List[str]]:
        paths = []
        visited = set()
        
        def dfs(current: str, path: List[str], depth: int):
            if depth > max_depth or current in visited:
                return
                
            path.append(current)
            visited.add(current)
            
            if current == end:
                paths.append(path.copy())
            else:
                for successor in self.get_successors(current):
                    dfs(successor, path, depth + 1)
                    
            path.pop()
            visited.remove(current)
            
        dfs(start, [], 0)
        return paths
    
    def get_all_paths_from_entry(self, max_depth: int = 100) -> List[List[str]]:
        if not self.entry_node:
            return []
        
        all_paths = []
        
        def dfs(current: str, path: List[str], visited: Set[str], depth: int):
            if depth > max_depth:
                return
            
            path.append(current)
            visited.add(current)
            
            successors = self.get_successors(current)
            
            if not successors or current in self.exit_nodes:
                all_paths.append(path.copy())
            else:
                for successor in successors:
                    if successor not in visited:
                        dfs(successor, path, visited.copy(), depth + 1)
            
            path.pop()
        
        dfs(self.entry_node, [], set(), 0)
        return all_paths
    
    def get_edge_condition(self, from_node: str, to_node: str) -> Optional[str]:
        for edge in self.edges:
            if edge.from_node == from_node and edge.to_node == to_node:
                return edge.condition
        return None