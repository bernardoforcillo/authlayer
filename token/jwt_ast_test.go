package token

import (
	"go/ast"
	"go/parser"
	gotoken "go/token"
	"testing"
)

// TestSignatureComparisonUsesHmacEqual pins a source-level property that no
// black-box test can: that Parse's signature check is literally a call to
// hmac.Equal, the constant-time comparison, rather than some functionally
// identical but variable-time stand-in such as ==. hmac.Equal and == accept
// and reject exactly the same inputs — the only difference between them is
// how long they take to do it, and a unit test observes outcomes, not
// wall-clock timing, so no assertion over Parse's return value can tell
// them apart. This test instead parses jwt.go's AST and inspects the
// comparison's source form directly, which is the one place the difference
// is actually visible.
//
// It fails if that call is replaced by anything else (including ==) and
// fails if it is deleted outright. It intentionally does not attempt to
// measure timing — see the comment at the comparison site in jwt.go for why
// hmac.Equal must stay.
func TestSignatureComparisonUsesHmacEqual(t *testing.T) {
	fset := gotoken.NewFileSet()
	file, err := parser.ParseFile(fset, "jwt.go", nil, 0)
	if err != nil {
		t.Fatalf("parse jwt.go: %v", err)
	}

	var parseFn *ast.FuncDecl
	for _, decl := range file.Decls {
		if fn, ok := decl.(*ast.FuncDecl); ok && fn.Name.Name == "Parse" {
			parseFn = fn
			break
		}
	}
	if parseFn == nil {
		t.Fatal("jwt.go: no func Parse found — this test needs updating to match")
	}

	// Find the `if <cond> { verified = true ... }` statement inside Parse
	// and require <cond> to be exactly a call to hmac.Equal(...).
	var ifFound, usesHmacEqual bool
	ast.Inspect(parseFn.Body, func(n ast.Node) bool {
		ifStmt, ok := n.(*ast.IfStmt)
		if !ok || !setsIdentTrue(ifStmt.Body, "verified") {
			return true
		}
		ifFound = true

		call, ok := ifStmt.Cond.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		pkgIdent, ok := sel.X.(*ast.Ident)
		if ok && pkgIdent.Name == "hmac" && sel.Sel.Name == "Equal" {
			usesHmacEqual = true
		}
		return true
	})

	if !ifFound {
		t.Fatal("jwt.go: no `if ... { verified = true }` found inside Parse — " +
			"the signature-verification structure changed; update this test to match")
	}
	if !usesHmacEqual {
		t.Fatal("jwt.go: Parse's verified-signature condition is not a direct call to hmac.Equal — " +
			"this must be a constant-time comparison; see the comment at the comparison site")
	}
}

// setsIdentTrue reports whether body contains a top-level `name = true`
// assignment.
func setsIdentTrue(body *ast.BlockStmt, name string) bool {
	for _, stmt := range body.List {
		assign, ok := stmt.(*ast.AssignStmt)
		if !ok || len(assign.Lhs) != 1 || len(assign.Rhs) != 1 {
			continue
		}
		lhs, ok := assign.Lhs[0].(*ast.Ident)
		if !ok || lhs.Name != name {
			continue
		}
		rhs, ok := assign.Rhs[0].(*ast.Ident)
		if ok && rhs.Name == "true" {
			return true
		}
	}
	return false
}
