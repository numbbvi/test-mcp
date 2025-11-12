package main

import "regexp"

type ASTData struct {
	FilePath     string        `json:"file_path"`
	Functions    []Function    `json:"functions"`
	Calls        []Call        `json:"calls"`
	Vars         []Variable    `json:"vars"`
	TaintSources []TaintSource `json:"taint_sources"`
	DataFlows    []DataFlow    `json:"data_flows"`
	Imports      []Import      `json:"imports"`
	Exports      []Export      `json:"exports"`
	Error        string        `json:"error,omitempty"`
}

type Function struct {
	Name   string  `json:"name"`
	Line   int     `json:"line"`
	Column int     `json:"column"`
	Type   string  `json:"type"`
	Params []Param `json:"params"`
}

type Param struct {
	Name string `json:"name"`
	Type string `json:"type"`
}

type Call struct {
	Package       string   `json:"package"`
	Function      string   `json:"function"`
	Args          []string `json:"args"`
	Line          int      `json:"line"`
	Column        int      `json:"column"`
	IsTaintSource bool     `json:"is_taint_source"`
	IsTaintSink   bool     `json:"is_taint_sink"`
}

type Variable struct {
	Name string `json:"name"`
	Line int    `json:"line"`
	Type string `json:"type"`
}

type TaintSource struct {
	VarName string `json:"var_name"`
	Source  string `json:"source"`
	Line    int    `json:"line"`
	Column  int    `json:"column"`
}

type DataFlow struct {
	From     string `json:"from"`
	To       string `json:"to"`
	Line     int    `json:"line"`
	Column   int    `json:"column"`
	FlowType string `json:"flow_type"`
}

type Import struct {
	Module string `json:"module"`
	Line   int    `json:"line"`
	Column int    `json:"column"`
}

type Export struct {
	Name   string `json:"name"`
	Line   int    `json:"line"`
	Column int    `json:"column"`
}

type GoParser struct {
	sourceRegexes []*regexp.Regexp
	sinkRegexes   []*regexp.Regexp
}

func newASTData(filePath string) *ASTData {
	return &ASTData{
		FilePath:     filePath,
		Functions:    []Function{},
		Calls:        []Call{},
		Vars:         []Variable{},
		TaintSources: []TaintSource{},
		DataFlows:    []DataFlow{},
		Imports:      []Import{},
		Exports:      []Export{},
	}
}
