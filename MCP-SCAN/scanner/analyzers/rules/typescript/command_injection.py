import re
from typing import List, Dict, Set, Any
from scanner.analyzers.common.scanner import Finding, CommonPatterns
from scanner.analyzers.common.base_detector import BaseDetector

class CommandInjectionDetector(BaseDetector):
    def __init__(self, language: str = "typescript"):
        super().__init__()
        self.language = language
        self.exec_sinks = [
            ('child_process', 'exec'), ('', 'exec'),
            ('child_process', 'execSync'), ('', 'execSync'),
            ('child_process', 'spawn'), ('', 'spawn'),
            ('child_process', 'spawnSync'), ('', 'spawnSync'),
            ('child_process', 'execFile'), ('', 'execFile'),
            ('child_process', 'execFileSync'), ('', 'execFileSync'),
            ('child_process', 'fork'), ('', 'fork'),
        ]
        self.third_party_sinks = [
            ('shelljs', 'exec'),
            ('shelljs', 'ShellString.exec'),
            ('execa', 'command'),
            ('execa', 'commandSync'),
            ('execa', 'shell'),
            ('execa', 'shellSync'),
            ('execa', ''),
            ('cross-spawn', 'spawn'),
            ('cross-spawn', 'sync'),
            ('npm-run', 'exec'),
            ('npm-run', 'execSync'),
            ('npm-run', 'spawn'),
            ('npm-run', 'spawnSync'),
            ('cmd-shim', 'cmdShim'),
            ('cmd-shim', 'cmdShimIfExists'),
        ]
        # Note: wrapper_sinks are user-defined functions that might wrap dangerous functions
        # We should check their actual implementation rather than hardcoding them
        # These are kept for backward compatibility but should be verified dynamically
        self.wrapper_sinks = [
            # Removed hardcoded wrapper sinks - they should be detected by analyzing function definitions
        ]
        self.code_exec_sinks = [
            ('eval', ''),
            ('Function', ''),
            ('vm', 'runInContext'),
            ('vm', 'runInNewContext'),
            ('vm', 'runInThisContext'),
            ('vm', 'Script'),
            ('vm2', 'run'),
            ('vm2', 'NodeVM'),
        ]
        self.dynamic_load_sinks = [
            ('', 'require'),
            ('', 'import'),
            ('module', '_load'),
            ('module', 'createRequire'),
        ]
        self.dangerous_sinks = (
            self.exec_sinks + 
            self.third_party_sinks +
            self.wrapper_sinks +
            self.code_exec_sinks +
            self.dynamic_load_sinks
        )
        self.shell_patterns = [
            'sh', 'bash', 'zsh', 'ksh', 'csh', 'tcsh', 'fish', 'dash',
            '/bin/sh', '/bin/bash', '/bin/zsh', '/bin/ksh', '/bin/dash',
            '/usr/bin/sh', '/usr/bin/bash', '/usr/bin/zsh',
            '/usr/local/bin/bash', '/usr/local/bin/zsh',
            'cmd', 'cmd.exe', 'command.com',
            'powershell', 'powershell.exe', 'pwsh', 'pwsh.exe',
            'conhost.exe', 'wscript', 'cscript',
        ]
        self.shell_flags = ['-c', '/c', '/C', '-Command', '-EncodedCommand', '-File']
        self.shell_metacharacters = [
            ';', '&', '|', '||', '&&', '$(', '`', '$(',
            '>', '>>', '<', '\n', '\r\n', '2>&1', '2>',
        ]
        self.sanitization_functions = [
            'escape', 'escapeShellArg', 'escapeShellCmd', 'sanitize',
            'validate', 'validateInput', 'clean', 'filter',
            'stripTags', 'removeSpecialChars', 'whitelistFilter',
            'shellEscape', 'quote', 'shellescape',
        ]
        self.safe_comment_patterns = [
            r'//\s*eslint-disable',
            r'//\s*@ts-ignore',
            r'//\s*safe',
            r'//\s*sanitized',
            r'//\s*trusted',
            r'//\s*validated',
            r'//\s*whitelisted',
            r'/\*\s*security:\s*reviewed\s*\*/',
        ]
        self.safe_comment_patterns_compiled = [re.compile(p, re.IGNORECASE) for p in self.safe_comment_patterns]
        self.whitelist_patterns = [
            r'allowedCommands\.includes',
            r'commandWhitelist\.has',
            r'SAFE_COMMANDS\.indexOf',
            r'if\s*\(.*===.*\)',
        ]
        self.whitelist_patterns_compiled = [re.compile(p) for p in self.whitelist_patterns]
        self.safe_commands = [
            'node', 'npm', 'yarn', 'pnpm', 'git', 'echo', 'pwd', 'ls', 'dir',
            'whoami', 'which', 'where', 'type', 'cat', 'head', 'tail',
            'grep', 'find', 'wc', 'date', 'uname', 'hostname',
            'tsc', 'ts-node', 'esbuild', 'webpack', 'rollup', 'vite',
            'jest', 'mocha', 'cypress', 'playwright', 'vitest',
            'eslint', 'prettier', 'husky', 'lint-staged',
            'docker', 'docker-compose', 'kubectl', 'helm',
            'aws', 'gcloud', 'az', 'terraform',
            'mkdir', 'rmdir', 'cp', 'mv', 'rm', 'chmod', 'chown',
            'curl', 'wget', 'tar', 'zip', 'unzip', 'gzip', 'gunzip',
        ]
    
    def get_name(self) -> str:
        return "command-injection"
    
    def get_cwe(self) -> str:
        return "CWE-78"
    
    def get_rule_id(self, language: str = None) -> str:
        lang = language or self.language
        return f"{lang}/command-injection"
    
    def is_dangerous_sink(self, pkg: str, fn: str) -> bool:
        if pkg:
            return (pkg, fn) in self.dangerous_sinks
        else:
            # Only built-in dangerous functions are considered dangerous by default
            # User-defined functions like execPromise should be checked dynamically
            return fn in ['eval', 'Function', 'exec', 'execSync', 'spawn', 'spawnSync', 
                         'execFile', 'execFileSync', 'fork', 'require', 'import', 'execa',
                         'command', 'commandSync', 'shell', 'shellSync']
    
    def get_sink_severity(self, pkg: str, fn: str) -> str:
        if (pkg, fn) in self.code_exec_sinks or fn == 'eval' or fn == 'Function':
            return "critical"
        if (pkg, fn) in self.exec_sinks or (pkg, fn) in self.third_party_sinks:
            return "high"
        # wrapper_sinks are now checked dynamically - severity determined by actual implementation
        if (pkg, fn) in self.dynamic_load_sinks or fn == 'require' or fn == 'import':
            return "medium"
        return "high"
    
    def check(self, calls: List[Dict], tainted_vars: Set[str], 
              lines: List[str], file_path: str, ast_result: Dict[str, Any] = None, 
              taint_result: Dict[str, Any] = None, cfg: Any = None) -> List[Finding]:
        findings = []
        
        if not ast_result:
            return findings
        
        data_flows = ast_result.get('data_flows', [])
        taint_sources = {s.get('var_name') for s in ast_result.get('taint_sources', [])}
        
        if taint_result:
            all_tainted = set(taint_result.get('all_tainted', []))
        else:
            all_tainted = set()
            taint_result = {'all_tainted': [], 'initial_tainted': []}
        
        for call in calls:
            pkg = call.get('package', '')
            fn = call.get('function', '')
            line = call.get('line', 0)
            line_content = lines[line-1] if 0 < line <= len(lines) else ""
            
            # Check if this is a known dangerous function
            is_shell_exec = False
            if (pkg == 'child_process' and fn in ['exec', 'execSync']):
                is_shell_exec = True
            elif not pkg and fn in ['exec', 'execSync']:
                # Only built-in exec/execSync without package are considered dangerous
                is_shell_exec = True
            
            # For user-defined functions (like execPromise), check if they actually call dangerous functions
            is_user_defined_wrapper = False
            if not pkg and fn in ['execAsync', 'execPromise', 'runCommand', 'executeCommand', 
                                 'runScript', 'executeScript', 'systemCommand', 'shellCommand']:
                # Check if this function is defined in the current file and calls dangerous functions
                is_user_defined_wrapper = self._is_user_defined_wrapper_function(
                    fn, ast_result, file_path, lines
                )
            
            if (is_shell_exec or is_user_defined_wrapper) and fn:
                args = call.get('args', [])
                
                # Check if function is called with array arguments (safe)
                is_array_arg = False
                if args and len(args) > 0:
                    first_arg = args[0].strip()
                    # Check if first argument is an array
                    if first_arg.startswith('[') or first_arg.startswith('Array'):
                        is_array_arg = True
                    # Check in line content for array syntax
                    if not is_array_arg and '[' in line_content:
                        array_pattern = rf'{re.escape(fn)}\s*\(\s*\['
                        if re.search(array_pattern, line_content, re.IGNORECASE):
                            is_array_arg = True
                
                # If called with array arguments, it's likely safe (spawn-like)
                if is_array_arg and is_user_defined_wrapper:
                    # Skip - array arguments are safe
                    continue
                
                template_content = None
                
                if args and len(args) > 0:
                    first_arg = args[0].strip()
                    if first_arg.startswith('`') and first_arg.endswith('`'):
                        template_content = first_arg[1:-1]
                    elif '`' in first_arg:
                        template_match = re.search(r'`([^`]+)`', first_arg)
                        if template_match:
                            template_content = template_match.group(1)
                
                if not template_content:
                    fn_pattern = re.escape(fn)
                    template_literal_pattern = rf'{fn_pattern}\s*\(\s*`([^`]+)`'
                    template_match = re.search(template_literal_pattern, line_content, re.IGNORECASE)
                    if template_match:
                        template_content = template_match.group(1)
                
                if not template_content and '`' in line_content:
                    lines_to_check = []
                    start_line = max(0, line - 5)
                    end_line = min(len(lines), line + 5)
                    for i in range(start_line, end_line):
                        if i < len(lines):
                            lines_to_check.append(lines[i])
                    
                    full_context = ''.join(lines_to_check)
                    fn_pattern = re.escape(fn)
                    template_literal_pattern = rf'{fn_pattern}\s*\([^`]*`([^`]+)`'
                    template_match = re.search(template_literal_pattern, full_context, re.DOTALL | re.IGNORECASE)
                    if template_match:
                        template_content = template_match.group(1)
                
                if template_content:
                    template_vars = re.findall(r'\$\{([^}]+)\}', template_content)
                    
                    context_start = max(0, line - 10)
                    context_end = min(len(lines), line + 1)
                    context_lines = lines[context_start:context_end]
                    
                    has_user_input = False
                    unsafe_vars = []
                    
                    for var_expr in template_vars:
                        var_clean = var_expr.strip()
                        
                        var_is_safe = False
                        
                        for ctx_line in context_lines:
                            if re.search(rf'const\s+{re.escape(var_clean)}\s*=', ctx_line, re.IGNORECASE) or \
                               re.search(rf'let\s+{re.escape(var_clean)}\s*=', ctx_line, re.IGNORECASE) or \
                               re.search(rf'var\s+{re.escape(var_clean)}\s*=', ctx_line, re.IGNORECASE):
                                
                                if re.search(r'===?\s*[\'"][^\'"]+[\'"]\s*\?\s*[\'"][^\'"]+[\'"]\s*:\s*[\'"][^\'"]+[\'"]', ctx_line):
                                    var_is_safe = True
                                    break
                                
                                if 'writeToTempFile' in ctx_line or 'writeFile' in ctx_line:
                                    var_is_safe = True
                                    break
                                
                                if '.split(' in ctx_line and '.pop()' in ctx_line:
                                    var_is_safe = True
                                    break
                                
                                if re.search(rf'{re.escape(var_clean)}\s*[:=]\s*[\'"][^\'"]+[\'"]', ctx_line):
                                    var_is_safe = True
                                    break
                        
                        if var_is_safe:
                            continue
                        
                        if var_clean in all_tainted:
                            has_user_input = True
                            unsafe_vars.append(var_clean)
                            continue
                        
                        if var_clean in taint_sources:
                            has_user_input = True
                            unsafe_vars.append(var_clean)
                            continue
                        
                        for taint_source in taint_sources:
                            if taint_source.endswith('.') and var_clean.startswith(taint_source):
                                has_user_input = True
                                unsafe_vars.append(var_clean)
                                break
                            if var_clean.startswith(taint_source + '.'):
                                has_user_input = True
                                unsafe_vars.append(var_clean)
                                break
                        
                        if has_user_input:
                            break
                        
                        for flow in data_flows:
                            to_var = flow.get('to', '').strip()
                            if to_var == var_clean:
                                from_var = flow.get('from', '').strip()
                                if from_var in taint_sources or from_var in all_tainted:
                                    has_user_input = True
                                    unsafe_vars.append(var_clean)
                                    break
                            if has_user_input:
                                break
                        
                        if has_user_input:
                            break
                        
                        common_taint_patterns = [
                            'args.', 'req.', 'request.', 'input.', 'user.', 
                            'param.', 'query.', 'body.', 'data.', 'payload.',
                            'params.', 'queryParams.', 'routeParams.', 'formData.'
                        ]
                        for pattern in common_taint_patterns:
                            if var_clean.startswith(pattern):
                                has_user_input = True
                                unsafe_vars.append(var_clean)
                                break
                        
                        if has_user_input:
                            break
                    
                    if has_user_input and unsafe_vars:
                        # 단순 치환만 사용하는지 확인 (쉘 특수문자/공백/주입을 막지 못함)
                        has_insufficient_sanitization = False
                        simple_replace_patterns = [
                            r'\.replace\s*\(',
                            r'\.replaceAll\s*\(',
                            r'\.replace\s*\([^,]+,\s*[\'"]',
                            r'\.replaceAll\s*\([^,]+,\s*[\'"]',
                        ]
                        
                        # 컨텍스트에서 단순 치환만 사용하는지 확인
                        for ctx_line in context_lines:
                            for var_name in unsafe_vars:
                                if var_name in ctx_line:
                                    # 단순 replace/replaceAll만 있는지 확인
                                    has_replace = any(re.search(p, ctx_line) for p in simple_replace_patterns)
                                    # 적절한 sanitization 함수가 없는지 확인
                                    has_proper_sanitization = any(
                                        sanitize_fn in ctx_line 
                                        for sanitize_fn in ['escape', 'escapeShellArg', 'escapeShellCmd', 
                                                           'shellEscape', 'quote', 'shellescape',
                                                           'spawn', 'execFile', 'execFileSync']
                                    )
                                    # 쉘 특수문자 검사가 없는지 확인
                                    metachar_patterns = [
                                        r'metachar',
                                        r'special.*char',
                                        r'shell.*char',
                                        r'dangerous.*char',
                                        r'[;&|`$<>]',
                                        r'shell.*escape',
                                        r'escape.*shell',
                                    ]
                                    has_metachar_check = any(
                                        re.search(pattern, ctx_line, re.IGNORECASE) 
                                        for pattern in metachar_patterns
                                    )
                                    
                                    if has_replace and not has_proper_sanitization and not has_metachar_check:
                                        has_insufficient_sanitization = True
                                        break
                            if has_insufficient_sanitization:
                                break
                        
                        language = self.language
                        unsafe_vars_str = ', '.join(unsafe_vars[:3])
                        
                        # execPromise 같은 사용자 정의 래퍼 함수인지 확인 (실제 정의를 확인)
                        is_wrapper = is_user_defined_wrapper
                        
                        if has_insufficient_sanitization:
                            if is_wrapper:
                                if pkg:
                                    message = f"[CRITICAL] Command injection in {pkg}.{fn}() - External-controlled value ({unsafe_vars_str}) combined via string template and passed to shell command - Simple replacement only cannot prevent shell special characters/spaces/injection - Use proper shell escaping (e.g., spawn with array args, execFile, or shellEscape)"
                                else:
                                    message = f"[CRITICAL] Command injection in {fn}() - External-controlled value ({unsafe_vars_str}) combined via string template and passed to shell command - Simple replacement only cannot prevent shell special characters/spaces/injection - Use proper shell escaping (e.g., spawn with array args, execFile, or shellEscape)"
                            else:
                                if pkg:
                                    message = f"[CRITICAL] Command injection in {pkg}.{fn}() - External-controlled value ({unsafe_vars_str}) in template literal passed to shell command - Simple replacement only cannot prevent shell special characters/spaces/injection - Shell metacharacters may be interpreted, allowing arbitrary command execution"
                                else:
                                    message = f"[CRITICAL] Command injection in {fn}() - External-controlled value ({unsafe_vars_str}) in template literal passed to shell command - Simple replacement only cannot prevent shell special characters/spaces/injection - Shell metacharacters may be interpreted, allowing arbitrary command execution"
                        else:
                            if is_wrapper:
                                if pkg:
                                    message = f"[CRITICAL] Command injection in {pkg}.{fn}() - External-controlled value ({unsafe_vars_str}) combined via string template and passed to shell command - Shell metacharacters may be interpreted, allowing arbitrary command execution"
                                else:
                                    message = f"[CRITICAL] Command injection in {fn}() - External-controlled value ({unsafe_vars_str}) combined via string template and passed to shell command - Shell metacharacters may be interpreted, allowing arbitrary command execution"
                            else:
                                if pkg:
                                    message = f"[CRITICAL] Command injection in {pkg}.{fn}() - Unvalidated user input ({unsafe_vars_str}) in template literal passed to shell command - Shell metacharacters may be interpreted, allowing arbitrary command execution"
                                else:
                                    message = f"[CRITICAL] Command injection in {fn}() - Unvalidated user input ({unsafe_vars_str}) in template literal passed to shell command - Shell metacharacters may be interpreted, allowing arbitrary command execution"
                        
                        snippet_lines = []
                        start_snippet = max(0, line - 3)
                        end_snippet = min(len(lines), line + 3)
                        
                        for i in range(start_snippet, end_snippet):
                            if i < len(lines):
                                snippet_lines.append(lines[i].rstrip())
                        
                        code_snippet = self._normalize_indent('\n'.join(snippet_lines))
                        
                        findings.append(Finding(
                            rule_id=self.get_rule_id(language),
                            severity="critical",
                            message=message,
                            cwe=self.get_cwe(),
                            file=file_path,
                            line=line,
                            column=call.get('column', 0),
                            code_snippet=code_snippet,
                            pattern_type="template_literal_injection" if not has_insufficient_sanitization else "insufficient_sanitization_injection",
                            pattern=f"{pkg}.{fn}" if pkg else fn,
                            confidence=0.95 if has_insufficient_sanitization else 0.9
                        ))
                        continue
                
                if not template_content and '+' in line_content:
                    fn_pattern = re.escape(fn)
                    string_concat_pattern = rf'{fn_pattern}\s*\(\s*([^)]+)'
                    concat_match = re.search(string_concat_pattern, line_content, re.IGNORECASE)
                    if concat_match:
                        concat_content = concat_match.group(1)
                        if '+' in concat_content:
                            var_pattern = r'\b([a-zA-Z_$][a-zA-Z0-9_$.]*)\b'
                            vars_in_concat = re.findall(var_pattern, concat_content)
                            
                            context_start = max(0, line - 10)
                            context_end = min(len(lines), line + 1)
                            context_lines = lines[context_start:context_end]
                            
                            has_user_input = False
                            unsafe_vars = []
                            
                            for var_name in vars_in_concat:
                                if var_name in ['exec', 'execSync', 'execAsync', 'spawn', 'shell']:
                                    continue
                                
                                var_is_safe = False
                                
                                for ctx_line in context_lines:
                                    if re.search(rf'const\s+{re.escape(var_name)}\s*=', ctx_line, re.IGNORECASE) or \
                                       re.search(rf'let\s+{re.escape(var_name)}\s*=', ctx_line, re.IGNORECASE) or \
                                       re.search(rf'var\s+{re.escape(var_name)}\s*=', ctx_line, re.IGNORECASE):
                                        
                                        if re.search(r'===?\s*[\'"][^\'"]+[\'"]\s*\?\s*[\'"][^\'"]+[\'"]\s*:\s*[\'"][^\'"]+[\'"]', ctx_line):
                                            var_is_safe = True
                                            break
                                        
                                        if 'writeToTempFile' in ctx_line or 'writeFile' in ctx_line:
                                            var_is_safe = True
                                            break
                                        
                                        if '.split(' in ctx_line and '.pop()' in ctx_line:
                                            var_is_safe = True
                                            break
                                        
                                        if re.search(rf'{re.escape(var_name)}\s*[:=]\s*[\'"][^\'"]+[\'"]', ctx_line):
                                            var_is_safe = True
                                            break
                                
                                if var_is_safe:
                                    continue
                                
                                if var_name in all_tainted:
                                    has_user_input = True
                                    unsafe_vars.append(var_name)
                                    continue
                                
                                if var_name in taint_sources:
                                    has_user_input = True
                                    unsafe_vars.append(var_name)
                                    continue
                                
                                for taint_source in taint_sources:
                                    if taint_source.endswith('.') and var_name.startswith(taint_source):
                                        has_user_input = True
                                        unsafe_vars.append(var_name)
                                        break
                                    if var_name.startswith(taint_source + '.'):
                                        has_user_input = True
                                        unsafe_vars.append(var_name)
                                        break
                                
                                if has_user_input:
                                    break
                                
                                for flow in data_flows:
                                    to_var = flow.get('to', '').strip()
                                    if to_var == var_name:
                                        from_var = flow.get('from', '').strip()
                                        if from_var in taint_sources or from_var in all_tainted:
                                            has_user_input = True
                                            unsafe_vars.append(var_name)
                                            break
                                    if has_user_input:
                                        break
                                
                                if has_user_input:
                                    break
                                
                                common_taint_patterns = [
                                    'args.', 'req.', 'request.', 'input.', 'user.', 
                                    'param.', 'query.', 'body.', 'data.', 'payload.',
                                    'params.', 'queryParams.', 'routeParams.', 'formData.'
                                ]
                                for pattern in common_taint_patterns:
                                    if var_name.startswith(pattern):
                                        has_user_input = True
                                        unsafe_vars.append(var_name)
                                        break
                                
                                if has_user_input:
                                    break
                            
                            if has_user_input and unsafe_vars:
                                # 단순 치환만 사용하는지 확인 (쉘 특수문자/공백/주입을 막지 못함)
                                has_insufficient_sanitization = False
                                simple_replace_patterns = [
                                    r'\.replace\s*\(',
                                    r'\.replaceAll\s*\(',
                                    r'\.replace\s*\([^,]+,\s*[\'"]',
                                    r'\.replaceAll\s*\([^,]+,\s*[\'"]',
                                ]
                                
                                # 컨텍스트에서 단순 치환만 사용하는지 확인
                                for ctx_line in context_lines:
                                    for var_name in unsafe_vars:
                                        if var_name in ctx_line:
                                            # 단순 replace/replaceAll만 있는지 확인
                                            has_replace = any(re.search(p, ctx_line) for p in simple_replace_patterns)
                                            # 적절한 sanitization 함수가 없는지 확인
                                            has_proper_sanitization = any(
                                                sanitize_fn in ctx_line 
                                                for sanitize_fn in ['escape', 'escapeShellArg', 'escapeShellCmd', 
                                                                   'shellEscape', 'quote', 'shellescape',
                                                                   'spawn', 'execFile', 'execFileSync']
                                            )
                                            # 쉘 특수문자 검사가 없는지 확인
                                            metachar_patterns = [
                                                r'metachar',
                                                r'special.*char',
                                                r'shell.*char',
                                                r'dangerous.*char',
                                                r'[;&|`$<>]',
                                                r'shell.*escape',
                                                r'escape.*shell',
                                            ]
                                            has_metachar_check = any(
                                                re.search(pattern, ctx_line, re.IGNORECASE) 
                                                for pattern in metachar_patterns
                                            )
                                            
                                            if has_replace and not has_proper_sanitization and not has_metachar_check:
                                                has_insufficient_sanitization = True
                                                break
                                    if has_insufficient_sanitization:
                                        break
                                
                                language = self.language
                                unsafe_vars_str = ', '.join(unsafe_vars[:3])
                                
                                # execPromise 같은 사용자 정의 래퍼 함수인지 확인 (실제 정의를 확인)
                                # Check if this is a user-defined wrapper function
                                is_user_defined_wrapper_concat = False
                                if not pkg and fn in ['execAsync', 'execPromise', 'runCommand', 'executeCommand', 
                                                     'runScript', 'executeScript', 'systemCommand', 'shellCommand']:
                                    is_user_defined_wrapper_concat = self._is_user_defined_wrapper_function(
                                        fn, ast_result, file_path, lines
                                    )
                                is_wrapper = is_user_defined_wrapper_concat
                                
                                if has_insufficient_sanitization:
                                    if is_wrapper:
                                        if pkg:
                                            message = f"[CRITICAL] Command injection in {pkg}.{fn}() - External-controlled value ({unsafe_vars_str}) combined via string concatenation and passed to shell command - Simple replacement only cannot prevent shell special characters/spaces/injection - Use proper shell escaping (e.g., spawn with array args, execFile, or shellEscape)"
                                        else:
                                            message = f"[CRITICAL] Command injection in {fn}() - External-controlled value ({unsafe_vars_str}) combined via string concatenation and passed to shell command - Simple replacement only cannot prevent shell special characters/spaces/injection - Use proper shell escaping (e.g., spawn with array args, execFile, or shellEscape)"
                                    else:
                                        if pkg:
                                            message = f"[CRITICAL] Command injection in {pkg}.{fn}() - External-controlled value ({unsafe_vars_str}) in string concatenation passed to shell command - Simple replacement only cannot prevent shell special characters/spaces/injection - Shell metacharacters may be interpreted, allowing arbitrary command execution"
                                        else:
                                            message = f"[CRITICAL] Command injection in {fn}() - External-controlled value ({unsafe_vars_str}) in string concatenation passed to shell command - Simple replacement only cannot prevent shell special characters/spaces/injection - Shell metacharacters may be interpreted, allowing arbitrary command execution"
                                else:
                                    if is_wrapper:
                                        if pkg:
                                            message = f"[CRITICAL] Command injection in {pkg}.{fn}() - External-controlled value ({unsafe_vars_str}) combined via string concatenation and passed to shell command - Shell metacharacters may be interpreted, allowing arbitrary command execution"
                                        else:
                                            message = f"[CRITICAL] Command injection in {fn}() - External-controlled value ({unsafe_vars_str}) combined via string concatenation and passed to shell command - Shell metacharacters may be interpreted, allowing arbitrary command execution"
                                    else:
                                        if pkg:
                                            message = f"[CRITICAL] Command injection in {pkg}.{fn}() - Unvalidated user input ({unsafe_vars_str}) in string concatenation passed to shell command - Shell metacharacters may be interpreted, allowing arbitrary command execution"
                                        else:
                                            message = f"[CRITICAL] Command injection in {fn}() - Unvalidated user input ({unsafe_vars_str}) in string concatenation passed to shell command - Shell metacharacters may be interpreted, allowing arbitrary command execution"
                                
                                snippet_lines = []
                                start_snippet = max(0, line - 3)
                                end_snippet = min(len(lines), line + 3)
                                
                                for i in range(start_snippet, end_snippet):
                                    if i < len(lines):
                                        snippet_lines.append(lines[i].rstrip())
                                
                                code_snippet = self._normalize_indent('\n'.join(snippet_lines))
                                
                                findings.append(Finding(
                                    rule_id=self.get_rule_id(language),
                                    severity="critical",
                                    message=message,
                                    cwe=self.get_cwe(),
                                    file=file_path,
                                    line=line,
                                    column=call.get('column', 0),
                                    code_snippet=code_snippet,
                                    pattern_type="string_concatenation_injection" if not has_insufficient_sanitization else "insufficient_sanitization_injection",
                                    pattern=f"{pkg}.{fn}" if pkg else fn,
                                    confidence=0.95 if has_insufficient_sanitization else 0.9
                                ))
                                continue
        
        base_findings = super().check(calls, tainted_vars, lines, file_path, ast_result, taint_result, cfg)
        findings.extend(base_findings)
        
        return findings
    
    def is_safe_usage(self, call: Dict, line_content: str, args: List[str], 
                     file_path: str, lines: List[str]) -> bool:
        return self._is_safe_usage(line_content, args, file_path)
    
    def analyze_data_flow(self, ast_result: Dict[str, Any], 
                         taint_result: Dict[str, Any]) -> List[Dict]:
        return []
    
    def build_finding_message(self, call: Dict, severity: str, 
                             base_var: str = None, data_flow_finding: Dict = None) -> str:
        pkg = call.get('package', '')
        fn = call.get('function', '')
        
        if data_flow_finding:
            return data_flow_finding['message']
        
        sink_category = self._get_sink_category(pkg, fn)
        
        if base_var:
            if sink_category == 'code_eval':
                return f"Code Injection: User input '{base_var}' in {fn}() - Arbitrary code execution"
            elif sink_category == 'exec':
                return f"Command injection: User input '{base_var}' in {pkg}.{fn}() if pkg else {fn}() - verify input sanitization"
            else:
                return f"Command injection: User input '{base_var}' in {pkg}.{fn}() if pkg else {fn}() - verify input sanitization"
        
        return f"Command injection: {pkg}.{fn}() if pkg else {fn}() - verify input sanitization"
    
    def _get_sink_category(self, pkg: str, fn: str) -> str:
        if pkg:
            if (pkg, fn) in self.code_exec_sinks:
                return 'code_eval'
            elif (pkg, fn) in self.exec_sinks:
                return 'exec'
            elif (pkg, fn) in self.third_party_sinks:
                return 'third_party'
            # wrapper_sinks are now checked dynamically - skip hardcoded check
            elif False:  # Removed wrapper_sinks hardcoded check
                return 'wrapper'
            elif (pkg, fn) in self.dynamic_load_sinks:
                return 'dynamic_load'
        else:
            if fn in ['eval', 'Function']:
                return 'code_eval'
            elif fn in ['exec', 'execSync', 'spawn', 'spawnSync', 'execFile', 'execFileSync', 'fork']:
                return 'exec'
            elif fn in ['execAsync', 'execPromise', 'runCommand', 'executeCommand', 'runScript', 'executeScript', 'systemCommand', 'shellCommand']:
                return 'wrapper'
            elif fn in ['require', 'import']:
                return 'dynamic_load'
            elif fn in ['execa', 'command', 'commandSync', 'shell', 'shellSync']:
                return 'third_party'
        return 'exec'
    
    def _is_user_defined_wrapper_function(self, fn_name: str, ast_result: Dict[str, Any], 
                                          file_path: str, lines: List[str]) -> bool:
        """
        Check if a function is user-defined and actually wraps dangerous functions.
        Returns True only if the function definition exists, calls dangerous functions,
        AND is not a safe wrapper (e.g., using spawn with array args, execFile, etc.).
        
        This method:
        1. Finds the function definition
        2. Checks if it calls dangerous functions (exec, execSync, spawn, etc.)
        3. Checks if it's a safe wrapper (spawn with array args, execFile, shellEscape, etc.)
        4. Checks argument types (array vs string)
        """
        if not ast_result:
            return False
        
        # Find function definition
        functions = ast_result.get('functions', [])
        func_def = None
        for func in functions:
            if func.get('name', '') == fn_name:
                func_def = func
                break
        
        if not func_def:
            # Function not found in AST - might be from another file or library
            # For common wrapper names like execPromise, we should still check the call site
            # But we can't verify if it's safe, so we'll be conservative and check it
            common_wrapper_names = ['execPromise', 'execAsync', 'runCommand', 'executeCommand',
                                  'runScript', 'executeScript', 'systemCommand', 'shellCommand']
            if fn_name in common_wrapper_names:
                # Common wrapper name - check it at call site
                return True
            return False
        
        func_line = func_def.get('line', 0)
        if func_line == 0:
            return False
        
        # Find the start of function body (after function declaration line)
        start_line_idx = func_line - 1  # Convert to 0-based index
        if start_line_idx >= len(lines):
            return False
        
        # Find the end of function body by looking for closing brace or next function
        brace_count = 0
        in_function = False
        end_line_idx = start_line_idx
        
        # Look for function declaration line
        for i in range(start_line_idx, min(len(lines), start_line_idx + 200)):
            line = lines[i]
            
            # Check if we're inside the function body
            if '{' in line:
                brace_count += line.count('{')
                in_function = True
            if '}' in line:
                brace_count -= line.count('}')
                if in_function and brace_count == 0:
                    # Found end of function
                    end_line_idx = i + 1
                    break
            
            # Also check for next function definition
            if i > start_line_idx and in_function:
                next_func_pattern = r'^\s*(?:async\s+)?(?:function|const|let|var)\s+\w+\s*[=:]?\s*(?:async\s*)?\s*\(|^\s*export\s+(?:async\s+)?function'
                if re.search(next_func_pattern, line):
                    # Found next function, end of current function
                    end_line_idx = i
                    break
        
        # If we didn't find the end, use a reasonable limit
        if end_line_idx == start_line_idx:
            end_line_idx = min(len(lines), start_line_idx + 100)
        
        # Extract function body
        body_lines = lines[start_line_idx:end_line_idx]
        body_content = '\n'.join(body_lines)
        
        # Check if function body contains calls to dangerous functions
        dangerous_patterns = [
            r'child_process\.(exec|execSync)',
            r'require\s*\([^)]*child_process[^)]*\)\.exec',
            r'require\s*\([^)]*child_process[^)]*\)\.execSync',
            r'import.*child_process.*exec',
            r'\.exec\s*\(',
            r'\.execSync\s*\(',
            # Only match standalone exec/execSync if they're likely from child_process
            r'(?:^|\s)(?:exec|execSync)\s*\(',
        ]
        
        # Check for dangerous exec/execSync calls (shell string-based)
        has_dangerous_call = False
        for pattern in dangerous_patterns:
            if re.search(pattern, body_content, re.IGNORECASE):
                has_dangerous_call = True
                break
        
        if not has_dangerous_call:
            # No dangerous calls found - might be safe or use safe methods
            return False
        
        # Check if it's a safe wrapper (spawn with array args, execFile, shellEscape, etc.)
        safe_patterns = [
            # spawn with array arguments (safe)
            r'spawn\s*\([^,]*,\s*\[',  # spawn(command, [args])
            r'\.spawn\s*\([^,]*,\s*\[',  # cp.spawn(command, [args])
            r'child_process\.spawn\s*\([^,]*,\s*\[',
            # execFile (safe - doesn't use shell)
            r'execFile\s*\(',
            r'\.execFile\s*\(',
            r'child_process\.execFile',
            # execFileSync (safe)
            r'execFileSync\s*\(',
            r'\.execFileSync\s*\(',
            r'child_process\.execFileSync',
            # shellEscape functions (safe)
            r'shellEscape\s*\(',
            r'escapeShellArg\s*\(',
            r'escapeShellCmd\s*\(',
            r'quote\s*\(',
            r'shellescape\s*\(',
            # Using spawn with options object (likely safe)
            r'spawn\s*\([^,]*,\s*[^,]*,\s*\{[^}]*shell\s*:\s*false',
            r'\.spawn\s*\([^,]*,\s*[^,]*,\s*\{[^}]*shell\s*:\s*false',
        ]
        
        # Check if safe patterns are used
        has_safe_pattern = False
        for pattern in safe_patterns:
            if re.search(pattern, body_content, re.IGNORECASE):
                has_safe_pattern = True
                break
        
        # If it has dangerous calls but also has safe patterns, check more carefully
        if has_safe_pattern:
            # Check if spawn is used with array arguments (safe)
            spawn_array_pattern = r'spawn\s*\([^,]*,\s*\[[^\]]+\]'
            if re.search(spawn_array_pattern, body_content, re.IGNORECASE):
                # spawn with array args is safe - don't report as dangerous
                return False
        
        # Check function parameters to see if they accept array or string
        func_params = func_def.get('params', [])
        has_array_param = False
        for param in func_params:
            param_type = param.get('type', '')
            if '[]' in param_type or 'Array' in param_type or 'string[]' in param_type:
                has_array_param = True
                break
        
        # If function accepts array parameter and uses spawn with array, it's likely safe
        if has_array_param and has_safe_pattern:
            return False
        
        # If we have dangerous calls and no safe patterns, it's a dangerous wrapper
        return True
    
    def _is_safe_usage(self, line_content: str, args: List[str], file_path: str) -> bool:
        if '.test.' in file_path or '.spec.' in file_path or '/test/' in file_path or '/__tests__/' in file_path:
            return True
        for pattern in self.safe_comment_patterns_compiled:
            if pattern.search(line_content):
                return True
        for sanitize_fn in self.sanitization_functions:
            if sanitize_fn in line_content:
                return True
        for pattern in self.whitelist_patterns_compiled:
            if pattern.search(line_content):
                return True
        
        if args and len(args) > 0:
            first_arg = args[0].strip('"`\'')
            safe_node_modules = [
                'path', 'fs', 'crypto', 'util', 'url', 'http', 'https', 
                'os', 'stream', 'events', 'net', 'tls', 'dns',
                'child_process', 'cluster', 'worker_threads', 'perf_hooks',
                'async_hooks', 'timers', 'buffer', 'querystring', 'punycode',
                'module', 'assert', 'console', 'process', 'zlib', 'readline',
                'v8', 'vm', 'domain', 'string_decoder', 'inspector', 'trace_events'
            ]
            if first_arg in safe_node_modules or first_arg.startswith('node:'):
                return True
            
            if first_arg in self.safe_commands:
                return True
            if args[0].startswith('"') and '${' not in args[0] and '$(' not in args[0]:
                has_metachar = any(meta in args[0] for meta in self.shell_metacharacters)
                if not has_metachar:
                    return True
        if 'spawn(' in line_content and '[' in line_content:
            if 'shell:' not in line_content and 'shell :' not in line_content:
                return True
        
        script_patterns = [
            r'/scripts/',
            r'devcheck\.ts',
            r'devdocs\.ts',
            r'build\.ts',
            r'deploy\.ts',
            r'validate.*\.ts',
            r'fetch.*\.ts',
        ]
        
        for pattern in script_patterns:
            if re.search(pattern, file_path):
                return True
        
        if 'execa(' in line_content and 'args' in line_content:
            return True
        
        if 'spawn(' in line_content and 'args' in line_content:
            return True
        
        return False