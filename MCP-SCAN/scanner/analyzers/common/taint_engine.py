from typing import Dict, Set, Any, List, Tuple, Optional

class TaintPropagationEngine:
    
    def __init__(self):
        self.enable_control_flow_sensitive = True
        self.enable_path_sensitive = True
    
    def analyze(self, ast_result: Dict[str, Any], cfg: Any, dataflow_result: Dict[str, Any]) -> Dict[str, Any]:
        print("  Step 4: Analyzing taint propagation...")
        
        initial_tainted = self._collect_initial_sources(ast_result)
        print(f"    Found {len(initial_tainted)} initial taint sources")
        
        flow_graph = self._build_flow_graph(ast_result)
        print(f"    Built data flow graph: {len(flow_graph)} nodes")
        
        range_vars = self._collect_range_vars(flow_graph, ast_result)
        initial_tainted = initial_tainted | range_vars
        if range_vars:
            print(f"    Added {len(range_vars)} range loop variables as potentially tainted")
        
        propagated = self._propagate_recursive(initial_tainted, flow_graph)
        print(f"    Propagated to {len(propagated)} total variables")
        
        func_call_tainted = self._propagate_through_calls(ast_result, propagated)
        print(f"    Function calls added {len(func_call_tainted - propagated)} variables")
        
        all_tainted = propagated | func_call_tainted
        
        if self.enable_control_flow_sensitive and cfg and hasattr(cfg, 'nodes'):
            cf_tainted = self._analyze_control_flow_sensitive(ast_result, cfg, initial_tainted, flow_graph)
            all_tainted = all_tainted | cf_tainted
            print(f"    Control-flow sensitive analysis added {len(cf_tainted - all_tainted)} variables")
        
        path_sensitive_results = {}
        if self.enable_path_sensitive and cfg and hasattr(cfg, 'get_all_paths_from_entry'):
            path_sensitive_results = self._analyze_path_sensitive(ast_result, cfg, initial_tainted, flow_graph)
            print(f"    Path-sensitive analysis found {len(path_sensitive_results)} unique paths")
        
        print(f"    Total tainted variables: {len(all_tainted)}")
        
        return {
            'initial_tainted': list(initial_tainted),
            'propagated_tainted': list(propagated),
            'func_call_tainted': list(func_call_tainted),
            'all_tainted': list(all_tainted),
            'path_sensitive_results': path_sensitive_results
        }
    
    def _collect_initial_sources(self, ast_result: Dict[str, Any]) -> Set[str]:
        tainted = set()
        
        for source in ast_result.get('taint_sources', []):
            var_name = source.get('var_name', '')
            if var_name:
                tainted.add(var_name)
                
        return tainted
    
    def _build_flow_graph(self, ast_result: Dict[str, Any]) -> Dict[str, Set[str]]:
        flow_graph = {}
        
        for flow in ast_result.get('data_flows', []):
            from_var = flow.get('from', '')
            to_var = flow.get('to', '')
            
            from_var = self._extract_var_name(from_var)
            to_var = self._extract_var_name(to_var)
            
            if from_var and to_var:
                if from_var not in flow_graph:
                    flow_graph[from_var] = set()
                flow_graph[from_var].add(to_var)
        
        return flow_graph
    
    def _collect_range_vars(self, flow_graph: Dict[str, Set[str]], ast_result: Dict[str, Any]) -> Set[str]:
        range_vars = set()
        
        for flow in ast_result.get('data_flows', []):
            if flow.get('flow_type') == 'range_loop':
                to_var = self._extract_var_name(flow.get('to', ''))
                if to_var:
                    range_vars.add(to_var)
        
        return range_vars
    
    def _propagate_recursive(self, sources: Set[str], graph: Dict[str, Set[str]]) -> Set[str]:
        tainted = set(sources)
        worklist = list(sources)
        
        while worklist:
            current = worklist.pop(0)
            
            if current in graph:
                for target in graph[current]:
                    if target not in tainted:
                        tainted.add(target)
                        worklist.append(target)
        
        return tainted
    
    def _propagate_through_calls(self, ast_result: Dict[str, Any], tainted_vars: Set[str]) -> Set[str]:
        extended_tainted = set(tainted_vars)
        
        func_defs = {}
        for func in ast_result.get('functions', []):
            func_name = func.get('name', '')
            if func_name:
                func_defs[func_name] = func
        
        for call in ast_result.get('calls', []):
            func_name = call.get('function', '')
            args = call.get('args', [])
            
            tainted_args = []
            for i, arg in enumerate(args):
                if isinstance(arg, str) and arg.startswith('"') and arg.endswith('"'):
                    continue
                
                arg_var = self._extract_var_name(arg)
                if arg_var and arg_var in tainted_vars:
                    tainted_args.append(i)
            
            if tainted_args and func_name in func_defs:
                func_def = func_defs[func_name]
                params = func_def.get('params', [])
                
                for arg_idx in tainted_args:
                    if arg_idx < len(params):
                        param_name = params[arg_idx].get('name', '')
                        if param_name:
                            extended_tainted.add(param_name)
        
        return extended_tainted
    
    def _extract_var_name(self, expr: str) -> str:
        if not expr:
            return ''
        
        if '()' in expr:
            return ''
        
        expr = expr.strip()
        
        return expr
    
    def _analyze_control_flow_sensitive(self, ast_result: Dict[str, Any], cfg: Any, 
                                       initial_tainted: Set[str], flow_graph: Dict[str, Set[str]]) -> Set[str]:
        cf_tainted = set(initial_tainted)
        
        node_taint_states: Dict[str, Set[str]] = {}
        
        if not cfg.entry_node:
            return cf_tainted
        
        worklist = [cfg.entry_node]
        visited = set()
        
        while worklist:
            current_node_id = worklist.pop(0)
            
            if current_node_id in visited:
                continue
            visited.add(current_node_id)
            
            if current_node_id not in node_taint_states:
                predecessors = cfg.get_predecessors(current_node_id)
                if predecessors:
                    merged_taint = set()
                    for pred in predecessors:
                        if pred in node_taint_states:
                            merged_taint = merged_taint | node_taint_states[pred]
                    node_taint_states[current_node_id] = merged_taint.copy()
                else:
                    node_taint_states[current_node_id] = set(initial_tainted)
            
            current_taint = node_taint_states[current_node_id]
            
            for from_var, to_vars in flow_graph.items():
                if from_var in current_taint:
                    for to_var in to_vars:
                        current_taint.add(to_var)
                        cf_tainted.add(to_var)
            
            successors = cfg.get_successors(current_node_id)
            for succ in successors:
                if succ not in node_taint_states:
                    node_taint_states[succ] = current_taint.copy()
                else:
                    node_taint_states[succ] = node_taint_states[succ] | current_taint
                
                if succ not in visited:
                    worklist.append(succ)
        
        return cf_tainted
    
    def _analyze_path_sensitive(self, ast_result: Dict[str, Any], cfg: Any,
                                initial_tainted: Set[str], flow_graph: Dict[str, Set[str]]) -> Dict[str, Set[str]]:
        path_results = {}
        
        all_paths = cfg.get_all_paths_from_entry(max_depth=100)
        
        if not all_paths:
            return path_results
        
        print(f"      Analyzing {len(all_paths)} execution paths...")
        
        for path_idx, path in enumerate(all_paths[:50]):
            path_id = f"path_{path_idx}"
            path_tainted = set(initial_tainted)
            
            for node_id in path:
                node = cfg.nodes.get(node_id)
                if not node:
                    continue
                
                for from_var, to_vars in flow_graph.items():
                    if from_var in path_tainted:
                        for to_var in to_vars:
                            path_tainted.add(to_var)
                
                if node.taint_sources:
                    for source in node.taint_sources:
                        path_tainted.add(source)
            
            path_results[path_id] = path_tainted
        
        return path_results