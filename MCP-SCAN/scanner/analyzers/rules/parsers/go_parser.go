package main

import (
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

func NewGoParser() *GoParser {
	sourcePatterns := []string{
		".*\\.ReadFile",
		".*\\.ReadAll",
		".*\\.ReadDir",
		".*\\.Query\\(\\)",
		".*\\.FormValue",
		".*\\.PostFormValue",
		".*\\.Header\\.Get",
		".*\\.Cookie",
		".*\\.Getenv",
		".*\\.Scan",
		".*\\.Unmarshal",
		".*\\.Decode",
	}

	sinkPatterns := []string{
		".*\\.Command",
		".*\\.Exec",
		".*\\.StartProcess",
		".*\\.Open",
		".*\\.Create",
		".*\\.OpenFile",
		".*\\.WriteFile",
		".*\\.Printf",
		".*\\.Print",
		".*\\.Execute",
		".*\\.NewRequest",
	}

	sourceRegexes := make([]*regexp.Regexp, len(sourcePatterns))
	for i, pattern := range sourcePatterns {
		sourceRegexes[i] = regexp.MustCompile(pattern)
	}

	sinkRegexes := make([]*regexp.Regexp, len(sinkPatterns))
	for i, pattern := range sinkPatterns {
		sinkRegexes[i] = regexp.MustCompile(pattern)
	}

	return &GoParser{
		sourceRegexes: sourceRegexes,
		sinkRegexes:   sinkRegexes,
	}
}

func (p *GoParser) ParseFile(filePath string) *ASTData {
	fset := token.NewFileSet()
	node, err := parser.ParseFile(fset, filePath, nil, parser.ParseComments)

	astData := newASTData(filePath)

	if err != nil {
		astData.Error = err.Error()
		return astData
	}

	p.parseAST(node, fset, astData)
	return astData
}

func (p *GoParser) parseAST(node ast.Node, fset *token.FileSet, astData *ASTData) {
	ast.Inspect(node, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.FuncDecl:
			p.parseFunction(x, fset, astData)
		case *ast.FuncLit:
			p.parseFunctionLiteral(x, fset, astData)
		case *ast.CallExpr:
			p.parseCall(x, fset, astData)
		case *ast.AssignStmt:
			p.parseAssignment(x, fset, astData)
		case *ast.ImportSpec:
			p.parseImport(x, fset, astData)
		case *ast.GenDecl:
			p.parseDeclaration(x, fset, astData)
		case *ast.RangeStmt:
			p.parseRangeStatement(x, fset, astData)
		}
		return true
	})
}

func (p *GoParser) parseFunction(fn *ast.FuncDecl, fset *token.FileSet, astData *ASTData) {
	if fn.Name == nil {
		return
	}

	funcName := fn.Name.Name
	pos := fset.Position(fn.Pos())
	params := p.collectParams(fn.Type.Params)

	p.recordFunction(astData, funcName, pos, params, "function")
}

func (p *GoParser) parseFunctionLiteral(fn *ast.FuncLit, fset *token.FileSet, astData *ASTData) {
	pos := fset.Position(fn.Pos())
	funcName := fmt.Sprintf("anonymous_%d_%d", pos.Line, pos.Column)
	params := p.collectParams(fn.Type.Params)

	p.recordFunction(astData, funcName, pos, params, "function_literal")
}

func (p *GoParser) parseCall(call *ast.CallExpr, fset *token.FileSet, astData *ASTData) {
	funcName := p.getCallString(call.Fun)
	pos := fset.Position(call.Pos())

	isTaintSource := p.isTaintSource(funcName)
	isTaintSink := p.isTaintSink(funcName)

	pkg, fn := p.splitCall(funcName)

	args := []string{}
	for _, arg := range call.Args {
		argStr := p.getExprString(arg)
		if argStr != "" {
			args = append(args, argStr)
		}
	}

	astData.Calls = append(astData.Calls, Call{
		Package:       pkg,
		Function:      fn,
		Args:          args,
		Line:          pos.Line,
		Column:        pos.Column,
		IsTaintSource: isTaintSource,
		IsTaintSink:   isTaintSink,
	})

	if isTaintSource {
		varName := p.extractVarName(call)
		if varName != "" {
			astData.TaintSources = append(astData.TaintSources, TaintSource{
				VarName: varName,
				Source:  funcName,
				Line:    pos.Line,
				Column:  pos.Column,
			})
		}
	}

	for i, arg := range call.Args {
		argName := p.getExprString(arg)
		if argName != "" && !strings.Contains(argName, "()") {
			paramTarget := fmt.Sprintf("%s_param_%d", funcName, i)
			p.addDataFlow(astData, argName, paramTarget, pos, "function_argument")
		}
	}
}

func (p *GoParser) parseAssignment(assign *ast.AssignStmt, fset *token.FileSet, astData *ASTData) {
	pos := fset.Position(assign.Pos())

	for i, lhs := range assign.Lhs {
		if rhs := i < len(assign.Rhs); rhs {
			rhsExpr := assign.Rhs[i]
			lhsStr := p.getExprString(lhs)
			rhsStr := p.getExprString(rhsExpr)

			if lhsStr != "" && rhsStr != "" {
				p.addDataFlow(astData, rhsStr, lhsStr, pos, "assignment")
				p.handleCallTaint(rhsExpr, lhsStr, pos, astData)
				p.handleCompositeTaint(rhsExpr, lhsStr, pos, astData)
				p.handlePointerFlows(lhs, rhsExpr, lhsStr, rhsStr, pos, astData)

				p.analyzeAdvancedDataFlow(lhs, rhsExpr, lhsStr, rhsStr, pos, astData, fset)
			}
		}
	}
}

func (p *GoParser) parseImport(imp *ast.ImportSpec, fset *token.FileSet, astData *ASTData) {
	pos := fset.Position(imp.Pos())
	modulePath := ""

	if imp.Path != nil {
		modulePath = strings.Trim(imp.Path.Value, "\"")
	}

	astData.Imports = append(astData.Imports, Import{
		Module: modulePath,
		Line:   pos.Line,
		Column: pos.Column,
	})
}

func (p *GoParser) parseDeclaration(decl *ast.GenDecl, fset *token.FileSet, astData *ASTData) {
	pos := fset.Position(decl.Pos())

	for _, spec := range decl.Specs {
		switch s := spec.(type) {
		case *ast.TypeSpec:
			if s.Name != nil {
				astData.Exports = append(astData.Exports, Export{
					Name:   s.Name.Name,
					Line:   pos.Line,
					Column: pos.Column,
				})
			}
		case *ast.ValueSpec:
			for _, name := range s.Names {
				astData.Vars = append(astData.Vars, Variable{
					Name: name.Name,
					Line: pos.Line,
					Type: p.getTypeString(s.Type),
				})
			}
		}
	}
}

func (p *GoParser) parseRangeStatement(rangeStmt *ast.RangeStmt, fset *token.FileSet, astData *ASTData) {
	pos := fset.Position(rangeStmt.Pos())

	var rangeVar string
	if rangeStmt.Value != nil {
		if ident, ok := rangeStmt.Value.(*ast.Ident); ok {
			rangeVar = ident.Name
		}
	} else if rangeStmt.Key != nil {
		if ident, ok := rangeStmt.Key.(*ast.Ident); ok {
			rangeVar = ident.Name
		}
	}

	rangedExpr := p.getExprString(rangeStmt.X)

	if rangeVar != "" && rangedExpr != "" {
		p.addDataFlow(astData, rangedExpr, rangeVar, pos, "range_loop")
	}
}

// 헬퍼 함수들 (go_utils.go에서 이동)
func (p *GoParser) collectParams(fieldList *ast.FieldList) []Param {
	var params []Param
	if fieldList == nil {
		return params
	}

	for _, param := range fieldList.List {
		for _, name := range param.Names {
			paramType := ""
			if param.Type != nil {
				paramType = p.getTypeString(param.Type)
			}
			params = append(params, Param{
				Name: name.Name,
				Type: paramType,
			})
		}
	}

	return params
}

func (p *GoParser) recordFunction(astData *ASTData, name string, pos token.Position, params []Param, funcType string) {
	astData.Functions = append(astData.Functions, Function{
		Name:   name,
		Line:   pos.Line,
		Column: pos.Column,
		Type:   funcType,
		Params: params,
	})
}

func (p *GoParser) splitCall(funcName string) (pkg, fn string) {
	if idx := strings.LastIndex(funcName, "."); idx >= 0 {
		return funcName[:idx], funcName[idx+1:]
	}
	return "", funcName
}

func (p *GoParser) addDataFlow(astData *ASTData, from, to string, pos token.Position, flowType string) {
	astData.DataFlows = append(astData.DataFlows, DataFlow{
		From:     from,
		To:       to,
		Line:     pos.Line,
		Column:   pos.Column,
		FlowType: flowType,
	})
}

func (p *GoParser) handleCallTaint(rhsExpr ast.Expr, lhsStr string, pos token.Position, astData *ASTData) {
	if callExpr, ok := rhsExpr.(*ast.CallExpr); ok {
		funcName := p.getCallString(callExpr.Fun)
		if p.isTaintSource(funcName) {
			astData.TaintSources = append(astData.TaintSources, TaintSource{
				VarName: lhsStr,
				Source:  funcName,
				Line:    pos.Line,
				Column:  pos.Column,
			})
		}
	}
}

func (p *GoParser) handleCompositeTaint(rhsExpr ast.Expr, lhsStr string, pos token.Position, astData *ASTData) {
	if compLit, ok := rhsExpr.(*ast.CompositeLit); ok {
		for _, elt := range compLit.Elts {
			if callExpr, ok := elt.(*ast.CallExpr); ok {
				funcName := p.getCallString(callExpr.Fun)
				if p.isTaintSource(funcName) {
					astData.TaintSources = append(astData.TaintSources, TaintSource{
						VarName: lhsStr,
						Source:  funcName + " (in composite)",
						Line:    pos.Line,
						Column:  pos.Column,
					})
				}
			}
		}
	}
}

func (p *GoParser) handlePointerFlows(lhs ast.Expr, rhsExpr ast.Expr, lhsStr, rhsStr string, pos token.Position, astData *ASTData) {
	if starExpr, ok := rhsExpr.(*ast.StarExpr); ok {
		ptrName := p.getExprString(starExpr.X)
		if ptrName != "" && !strings.Contains(ptrName, "*") {
			p.addDataFlow(astData, ptrName, lhsStr, pos, "pointer_deref")
		}
	}

	if starExpr, ok := lhs.(*ast.StarExpr); ok {
		ptrName := p.getExprString(starExpr.X)
		if ptrName != "" && rhsStr != "" {
			p.addDataFlow(astData, rhsStr, ptrName, pos, "pointer_assign")
		}
	}
}

func (p *GoParser) getExprString(expr ast.Expr) string {
	switch x := expr.(type) {
	case *ast.Ident:
		return x.Name
	case *ast.SelectorExpr:
		return p.getExprString(x.X) + "." + x.Sel.Name
	case *ast.CallExpr:
		return p.getExprString(x.Fun) + "()"
	case *ast.StarExpr:
		return "*" + p.getExprString(x.X)
	case *ast.UnaryExpr:
		if x.Op == token.AND {
			return "&" + p.getExprString(x.X)
		}
		return p.getExprString(x.X)
	case *ast.BasicLit:
		return x.Value
	default:
		return ""
	}
}

func (p *GoParser) getCallString(expr ast.Expr) string {
	return p.getExprString(expr)
}

func (p *GoParser) getTypeString(expr ast.Expr) string {
	switch x := expr.(type) {
	case *ast.Ident:
		return x.Name
	case *ast.SelectorExpr:
		return p.getExprString(x.X) + "." + x.Sel.Name
	case *ast.ArrayType:
		return "[]" + p.getTypeString(x.Elt)
	case *ast.MapType:
		return "map[" + p.getTypeString(x.Key) + "]" + p.getTypeString(x.Value)
	case *ast.StarExpr:
		return "*" + p.getTypeString(x.X)
	default:
		return ""
	}
}

func (p *GoParser) isTaintSource(funcName string) bool {
	for _, regex := range p.sourceRegexes {
		if regex.MatchString(funcName) {
			return true
		}
	}
	return false
}

func (p *GoParser) isTaintSink(funcName string) bool {
	for _, regex := range p.sinkRegexes {
		if regex.MatchString(funcName) {
			return true
		}
	}
	return false
}

func (p *GoParser) extractVarName(call *ast.CallExpr) string {
	if len(call.Args) > 0 {
		return p.getExprString(call.Args[0])
	}
	return ""
}

func (p *GoParser) analyzeAdvancedDataFlow(lhs ast.Expr, rhsExpr ast.Expr, lhsStr, rhsStr string, pos token.Position, astData *ASTData, fset *token.FileSet) {
	p.analyzeFunctionChain(rhsExpr, lhsStr, pos, astData, fset)

	p.analyzeConditionalAssignment(lhs, rhsExpr, lhsStr, rhsStr, pos, astData, fset)

	p.analyzeStructFieldAssignment(lhs, rhsExpr, lhsStr, rhsStr, pos, astData, fset)

	p.analyzeCollectionAssignment(lhs, rhsExpr, lhsStr, rhsStr, pos, astData, fset)
}

func (p *GoParser) analyzeFunctionChain(expr ast.Expr, targetVar string, pos token.Position, astData *ASTData, fset *token.FileSet) {
	if callExpr, ok := expr.(*ast.CallExpr); ok {
		if selectorExpr, ok := callExpr.Fun.(*ast.SelectorExpr); ok {
			chain := p.buildFunctionChain(selectorExpr, fset)
			if len(chain) > 1 {
				p.addDataFlow(astData, chain[0], targetVar, pos, "function_chain")
				for i := 1; i < len(chain); i++ {
					p.addDataFlow(astData, chain[i-1], chain[i], pos, "chain_link")
				}
			}
		}
	}
}

func (p *GoParser) buildFunctionChain(expr ast.Expr, fset *token.FileSet) []string {
	var chain []string

	if selectorExpr, ok := expr.(*ast.SelectorExpr); ok {
		if parentChain := p.buildFunctionChain(selectorExpr.X, fset); len(parentChain) > 0 {
			chain = append(chain, parentChain...)
		}
		chain = append(chain, selectorExpr.Sel.Name)
	} else if ident, ok := expr.(*ast.Ident); ok {
		chain = append(chain, ident.Name)
	}

	return chain
}

func (p *GoParser) analyzeConditionalAssignment(lhs ast.Expr, rhsExpr ast.Expr, lhsStr, rhsStr string, pos token.Position, astData *ASTData, fset *token.FileSet) {

	if binaryExpr, ok := rhsExpr.(*ast.BinaryExpr); ok {
		if binaryExpr.Op == token.ADD || binaryExpr.Op == token.SUB {
			p.extractVariablesFromExpression(binaryExpr, lhsStr, pos, astData, fset)
		}
	}
}

func (p *GoParser) traverseBlockForAssignments(block *ast.BlockStmt, targetVar string, pos token.Position, astData *ASTData, fset *token.FileSet) {
	if block == nil {
		return
	}

	for _, stmt := range block.List {
		if assignStmt, ok := stmt.(*ast.AssignStmt); ok {
			for i, lhs := range assignStmt.Lhs {
				if i < len(assignStmt.Rhs) {
					lhsStr := p.getExprString(lhs)
					rhsStr := p.getExprString(assignStmt.Rhs[i])
					if lhsStr == targetVar && rhsStr != "" {
						p.addDataFlow(astData, rhsStr, targetVar, pos, "conditional_assignment")
					}
				}
			}
		}
	}
}

func (p *GoParser) analyzeStructFieldAssignment(lhs ast.Expr, rhsExpr ast.Expr, lhsStr, rhsStr string, pos token.Position, astData *ASTData, fset *token.FileSet) {
	if selectorExpr, ok := lhs.(*ast.SelectorExpr); ok {
		objName := p.getExprString(selectorExpr.X)
		fieldName := selectorExpr.Sel.Name
		fullFieldName := fmt.Sprintf("%s.%s", objName, fieldName)

		p.addDataFlow(astData, rhsStr, fullFieldName, pos, "struct_field_assignment")

		p.addDataFlow(astData, rhsStr, objName, pos, "struct_modification")
	}
}

func (p *GoParser) analyzeCollectionAssignment(lhs ast.Expr, rhsExpr ast.Expr, lhsStr, rhsStr string, pos token.Position, astData *ASTData, fset *token.FileSet) {
	if indexExpr, ok := lhs.(*ast.IndexExpr); ok {
		collectionName := p.getExprString(indexExpr.X)
		indexName := p.getExprString(indexExpr.Index)

		p.addDataFlow(astData, rhsStr, collectionName, pos, "collection_assignment")
		p.addDataFlow(astData, indexName, collectionName, pos, "index_influence")
	}
}

func (p *GoParser) extractVariablesFromExpression(expr ast.Expr, targetVar string, pos token.Position, astData *ASTData, fset *token.FileSet) {
	switch x := expr.(type) {
	case *ast.BinaryExpr:
		p.extractVariablesFromExpression(x.X, targetVar, pos, astData, fset)
		p.extractVariablesFromExpression(x.Y, targetVar, pos, astData, fset)
	case *ast.Ident:
		p.addDataFlow(astData, x.Name, targetVar, pos, "expression_variable")
	case *ast.SelectorExpr:
		selectorStr := p.getExprString(x)
		p.addDataFlow(astData, selectorStr, targetVar, pos, "expression_selector")
	}
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "Usage: %s <file_path>\n", filepath.Base(os.Args[0]))
		os.Exit(1)
	}

	filePath := os.Args[1]
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		fmt.Fprintf(os.Stderr, "File not found: %s\n", filePath)
		os.Exit(1)
	}

	parser := NewGoParser()
	astData := parser.ParseFile(filePath)

	jsonData, err := json.MarshalIndent(astData, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error marshaling JSON: %v\n", err)
		os.Exit(1)
	}

	fmt.Println(string(jsonData))
}
