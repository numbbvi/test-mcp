from scanner.analyzers.common.ast_analyzer import create_go_analyzer

class GoASTAnalyzer:
    def __new__(cls):
        return create_go_analyzer()

__all__ = ['GoASTAnalyzer']