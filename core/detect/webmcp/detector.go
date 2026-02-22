package webmcp

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"

	"github.com/Clyra-AI/wrkr/core/detect"
	"github.com/Clyra-AI/wrkr/core/detect/mcpgateway"
	"github.com/Clyra-AI/wrkr/core/model"
	"github.com/dop251/goja/ast"
	"github.com/dop251/goja/parser"
	"golang.org/x/net/html"
)

const detectorID = "webmcp"

type Detector struct{}

func New() Detector { return Detector{} }

func (Detector) ID() string { return detectorID }

type declaration struct {
	name   string
	method string
	rel    string
}

func (Detector) Detect(_ context.Context, scope detect.Scope, _ detect.Options) ([]model.Finding, error) {
	info, err := os.Stat(scope.Root)
	if err != nil || !info.IsDir() {
		return nil, nil
	}

	policy, _, policyErr := mcpgateway.LoadPolicy(scope.Root)
	if policyErr != nil {
		return nil, policyErr
	}

	files, err := detect.WalkFiles(scope.Root)
	if err != nil {
		return nil, err
	}

	parseErrors := make([]model.Finding, 0)
	declSet := map[string]declaration{}
	for _, rel := range files {
		lower := strings.ToLower(rel)
		ext := strings.ToLower(filepath.Ext(lower))

		if lower == ".well-known/webmcp" ||
			lower == ".well-known/webmcp.json" ||
			lower == ".well-known/webmcp.yaml" ||
			lower == ".well-known/webmcp.yml" ||
			strings.HasSuffix(lower, "/.well-known/webmcp") ||
			strings.HasSuffix(lower, "/.well-known/webmcp.json") ||
			strings.HasSuffix(lower, "/.well-known/webmcp.yaml") ||
			strings.HasSuffix(lower, "/.well-known/webmcp.yml") {
			item := declaration{name: "webmcp", method: "route_file", rel: rel}
			declSet[declarationKey(item)] = item
		}

		switch ext {
		case ".html", ".htm":
			names, parseErr := parseHTMLDeclarations(scope.Root, rel)
			if parseErr != nil {
				parseErrors = append(parseErrors, model.Finding{
					FindingType: "parse_error",
					Severity:    model.SeverityMedium,
					ToolType:    "webmcp",
					Location:    rel,
					Repo:        scope.Repo,
					Org:         fallbackOrg(scope.Org),
					Detector:    detectorID,
					ParseError:  parseErr,
				})
				continue
			}
			for _, name := range names {
				item := declaration{name: name, method: "declarative_html", rel: rel}
				declSet[declarationKey(item)] = item
			}
		case ".js", ".mjs", ".cjs":
			names, parseErr := parseJSDeclarations(scope.Root, rel)
			if parseErr != nil {
				parseErrors = append(parseErrors, model.Finding{
					FindingType: "parse_error",
					Severity:    model.SeverityMedium,
					ToolType:    "webmcp",
					Location:    rel,
					Repo:        scope.Repo,
					Org:         fallbackOrg(scope.Org),
					Detector:    detectorID,
					ParseError:  parseErr,
				})
				continue
			}
			for _, name := range names {
				item := declaration{name: name, method: "imperative_js", rel: rel}
				declSet[declarationKey(item)] = item
			}
		}

		if couldContainRoutes(ext) {
			contains, containsErr := containsWebMCPRoute(scope.Root, rel)
			if containsErr != nil {
				return nil, containsErr
			}
			if contains {
				item := declaration{name: "webmcp", method: "route_declaration", rel: rel}
				declSet[declarationKey(item)] = item
			}
		}
	}

	decls := make([]declaration, 0, len(declSet))
	for _, item := range declSet {
		decls = append(decls, item)
	}
	sort.Slice(decls, func(i, j int) bool {
		if decls[i].method != decls[j].method {
			return decls[i].method < decls[j].method
		}
		if decls[i].name != decls[j].name {
			return decls[i].name < decls[j].name
		}
		return decls[i].rel < decls[j].rel
	})

	findings := make([]model.Finding, 0, len(parseErrors)+len(decls))
	findings = append(findings, parseErrors...)
	for _, item := range decls {
		posture := mcpgateway.EvaluateCoverage(policy, item.name)
		severity := model.SeverityLow
		if posture.Coverage == mcpgateway.CoverageUnprotected {
			severity = model.SeverityHigh
		} else if posture.Coverage == mcpgateway.CoverageUnknown {
			severity = model.SeverityMedium
		}

		findings = append(findings, model.Finding{
			FindingType: "webmcp_declaration",
			Severity:    severity,
			ToolType:    "webmcp",
			Location:    item.rel,
			Repo:        scope.Repo,
			Org:         fallbackOrg(scope.Org),
			Detector:    detectorID,
			Evidence: []model.Evidence{
				{Key: "declaration_method", Value: item.method},
				{Key: "declaration_name", Value: item.name},
				{Key: "coverage", Value: posture.Coverage},
				{Key: "policy_posture", Value: posture.PolicyPosture},
				{Key: "default_behavior", Value: posture.DefaultAction},
				{Key: "reason_code", Value: posture.ReasonCode},
			},
			Remediation: "Keep WebMCP discovery static-only and configure explicit gateway controls for each declaration.",
		})
	}

	model.SortFindings(findings)
	return findings, nil
}

func parseHTMLDeclarations(root, rel string) ([]string, *model.ParseError) {
	path := filepath.Join(root, filepath.FromSlash(rel))
	payload, err := os.ReadFile(path) // #nosec G304 -- detector reads repository content selected by user.
	if err != nil {
		return nil, &model.ParseError{Kind: "file_read_error", Format: "html", Path: rel, Detector: detectorID, Message: err.Error()}
	}
	doc, parseErr := html.Parse(bytes.NewReader(payload))
	if parseErr != nil {
		return nil, &model.ParseError{Kind: "parse_error", Format: "html", Path: rel, Detector: detectorID, Message: parseErr.Error()}
	}
	set := map[string]struct{}{}
	var walk func(*html.Node)
	walk = func(node *html.Node) {
		if node == nil {
			return
		}
		if node.Type == html.ElementNode {
			for _, attr := range node.Attr {
				if !strings.EqualFold(attr.Key, "tool-name") {
					continue
				}
				name := strings.ToLower(strings.TrimSpace(attr.Val))
				if name != "" {
					set[name] = struct{}{}
				}
			}
		}
		for child := node.FirstChild; child != nil; child = child.NextSibling {
			walk(child)
		}
	}
	walk(doc)
	return sortedSet(set), nil
}

func parseJSDeclarations(root, rel string) ([]string, *model.ParseError) {
	path := filepath.Join(root, filepath.FromSlash(rel))
	payload, err := os.ReadFile(path) // #nosec G304 -- detector reads repository content selected by user.
	if err != nil {
		return nil, &model.ParseError{Kind: "file_read_error", Format: "javascript", Path: rel, Detector: detectorID, Message: err.Error()}
	}
	program, parseErr := parser.ParseFile(nil, rel, payload, 0)
	if parseErr != nil {
		return nil, &model.ParseError{Kind: "parse_error", Format: "javascript", Path: rel, Detector: detectorID, Message: parseErr.Error()}
	}
	set := map[string]struct{}{}
	walkAST(program, func(node any) {
		call, ok := node.(*ast.CallExpression)
		if !ok {
			return
		}
		if !isModelContextRegistration(call.Callee) {
			return
		}
		name := firstStringArgument(call.ArgumentList)
		if name == "" {
			name = "webmcp"
		}
		set[name] = struct{}{}
	})
	return sortedSet(set), nil
}

func walkAST(node any, visit func(any)) {
	if node == nil {
		return
	}
	visit(node)

	rv := reflect.ValueOf(node)
	walkValue(rv, visit)
}

func walkValue(value reflect.Value, visit func(any)) {
	if !value.IsValid() {
		return
	}
	switch value.Kind() {
	case reflect.Interface, reflect.Pointer:
		if value.IsNil() {
			return
		}
		walkValue(value.Elem(), visit)
	case reflect.Struct:
		for i := 0; i < value.NumField(); i++ {
			field := value.Field(i)
			if !field.IsValid() {
				continue
			}
			if field.CanInterface() {
				visit(field.Interface())
			}
			walkValue(field, visit)
		}
	case reflect.Slice, reflect.Array:
		for i := 0; i < value.Len(); i++ {
			item := value.Index(i)
			if item.CanInterface() {
				visit(item.Interface())
			}
			walkValue(item, visit)
		}
	}
}

func isModelContextRegistration(expr ast.Expression) bool {
	chain := memberChain(expr)
	if len(chain) < 3 {
		return false
	}
	if chain[0] != "navigator" || chain[1] != "modelcontext" {
		return false
	}
	last := chain[len(chain)-1]
	return last == "registertool" || last == "register"
}

func memberChain(expr ast.Expression) []string {
	switch typed := expr.(type) {
	case *ast.DotExpression:
		left := memberChain(typed.Left)
		return append(left, strings.ToLower(typed.Identifier.Name.String()))
	case *ast.BracketExpression:
		left := memberChain(typed.Left)
		name := expressionString(typed.Member)
		if name == "" {
			return nil
		}
		return append(left, strings.ToLower(name))
	case *ast.Optional:
		return memberChain(typed.Expression)
	case *ast.OptionalChain:
		return memberChain(typed.Expression)
	case *ast.Identifier:
		return []string{strings.ToLower(typed.Name.String())}
	default:
		return nil
	}
}

func firstStringArgument(args []ast.Expression) string {
	if len(args) == 0 {
		return ""
	}
	return strings.ToLower(strings.TrimSpace(expressionString(args[0])))
}

func expressionString(expr ast.Expression) string {
	switch typed := expr.(type) {
	case *ast.StringLiteral:
		return typed.Value.String()
	case *ast.Identifier:
		return typed.Name.String()
	default:
		return ""
	}
}

func containsWebMCPRoute(root, rel string) (bool, error) {
	path := filepath.Join(root, filepath.FromSlash(rel))
	payload, err := os.ReadFile(path) // #nosec G304 -- detector reads repository files selected by user.
	if err != nil {
		return false, err
	}
	if bytes.Contains(payload, []byte("/.well-known/webmcp")) {
		return true, nil
	}
	return false, nil
}

func declarationKey(item declaration) string {
	return item.method + "|" + item.name + "|" + item.rel
}

func sortedSet(set map[string]struct{}) []string {
	out := make([]string, 0, len(set))
	for item := range set {
		out = append(out, item)
	}
	sort.Strings(out)
	return out
}

func couldContainRoutes(ext string) bool {
	switch ext {
	case ".go", ".js", ".mjs", ".cjs", ".ts", ".tsx", ".py", ".rb", ".php", ".java", ".kt", ".rs":
		return true
	default:
		return false
	}
}

func fallbackOrg(org string) string {
	if strings.TrimSpace(org) == "" {
		return "local"
	}
	return strings.TrimSpace(org)
}
