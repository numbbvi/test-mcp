from scanner.analyzers.common.ast_analyzer import create_typescript_analyzer

class TypeScriptASTAnalyzer:
    def __new__(cls):
        return create_typescript_analyzer()

__all__ = ['TypeScriptASTAnalyzer']