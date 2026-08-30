// Command verify extracts every Go code block from the Mintlify pages under
// docs/ and compiles and runs it, so no sample can drift from the library it
// documents.
//
//	go run ./docs/_verify          # verify every page
//	go run ./docs/_verify -keep    # leave the generated programs in place
//	go run ./docs/_verify -v       # print each program's stdout
//
// It lives under an underscore-prefixed directory so the "./..." patterns the
// project gate uses (go build, go vet, go test) never see it, and it writes the
// programs it generates into a dot-prefixed directory for the same reason.
// gofmt does descend into both, so both stay formatted.
//
// # Markers
//
// Every ```go fence in docs/ MUST be preceded by an MDX comment naming what to
// do with it. An unmarked Go fence is a failure, not a silent skip: the point
// of the harness is that "which samples ran" has an exhaustive answer.
//
//	{/* verify:program */}      a complete Go file — compiled and run alone
//	{/* verify:import */}       an import block, merged into the page program
//	{/* verify:decl */}         top-level declarations, appended to it
//	{/* verify:main */}         statements, appended to that program's main()
//	{/* verify:skip reason */}  not executed; the reason is reported verbatim
//
// A program marker may pin its own complete standard output inline:
//
//	{/* verify:program stdout="true false" */}
//
// The import/decl/main blocks on one page are assembled, in source order, into
// a single program — so a page's snippets continue each other exactly as a
// reader reads them. A page-level
//
//	{/* verify:stdout "first line\nsecond line" */}
//
// pins that program's complete standard output, which is how a sample whose
// printed value IS the documented claim gets checked rather than merely run.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// block is one fenced Go sample and the marker that governs it.
type block struct {
	page string
	line int
	mode string // program, import, decl, main, skip
	note string // a skip's reason
	body string
}

// page is one .mdx file's samples.
type page struct {
	path   string
	blocks []block
	stdout string // expected stdout for the assembled program
	hasExp bool
}

// result is one compiled-and-run program.
type result struct {
	name   string
	page   string
	lines  []int
	ok     bool
	detail string
	stdout string
}

var (
	markerRe = regexp.MustCompile(`^\s*\{/\*\s*verify:(program|import|decl|main|skip|stdout)\b\s*(.*?)\s*\*/\}\s*$`)
	fenceRe  = regexp.MustCompile("^(\\s*)(```+)\\s*([A-Za-z0-9_+-]*)(.*)$")
)

func main() {
	var (
		keep    = flag.Bool("keep", false, "keep the generated programs")
		verbose = flag.Bool("v", false, "print each program's stdout")
		root    = flag.String("root", "docs", "directory of .mdx pages")
	)
	flag.Parse()

	repo, err := os.Getwd()
	if err != nil {
		fail(err)
	}

	navProblems, err := checkNavigation(*root)
	if err != nil {
		fail(err)
	}

	pages, err := collect(*root)
	if err != nil {
		fail(err)
	}
	if len(pages) == 0 {
		fail(fmt.Errorf("no .mdx pages under %s", *root))
	}

	work := filepath.Join(repo, ".docsverify")
	if err := os.RemoveAll(work); err != nil {
		fail(err)
	}
	if err := os.MkdirAll(work, 0o750); err != nil {
		fail(err)
	}
	if !*keep {
		defer func() { _ = os.RemoveAll(work) }()
	}

	var results []result
	var skipped []block
	unmarked := 0

	for _, p := range pages {
		var imports, decls, mains []block
		for _, b := range p.blocks {
			switch b.mode {
			case "program":
				want, hasWant, err := inlineStdout(b)
				if err != nil {
					fail(err)
				}
				results = append(results, run(repo, work, programName(p.path, b.line),
					p.path, []int{b.line}, b.body, want, hasWant))
			case "import":
				imports = append(imports, b)
			case "decl":
				decls = append(decls, b)
			case "main":
				mains = append(mains, b)
			case "skip":
				skipped = append(skipped, b)
			default:
				unmarked++
				results = append(results, result{
					name:   fmt.Sprintf("%s:%d", p.path, b.line),
					page:   p.path,
					lines:  []int{b.line},
					detail: "UNMARKED go fence — add a {/* verify:... */} marker above it",
				})
			}
		}
		if len(imports)+len(decls)+len(mains) == 0 {
			continue
		}
		src, lines := assemble(imports, decls, mains)
		results = append(results, run(repo, work, programName(p.path, 0),
			p.path, lines, src, p.stdout, p.hasExp))
	}

	sort.Slice(results, func(i, j int) bool { return results[i].name < results[j].name })

	failures := 0
	fmt.Printf("%-54s %s\n", "PROGRAM", "RESULT")
	fmt.Println(strings.Repeat("-", 78))
	for _, r := range results {
		status := "ok"
		if !r.ok {
			status = "FAIL"
			failures++
		}
		fmt.Printf("%-54s %s\n", r.name, status)
		switch {
		case !r.ok:
			fmt.Printf("    page %s (blocks at %v)\n", r.page, r.lines)
			for _, l := range strings.Split(strings.TrimRight(r.detail, "\n"), "\n") {
				fmt.Printf("    | %s\n", l)
			}
		case *verbose && strings.TrimSpace(r.stdout) != "":
			for _, l := range strings.Split(strings.TrimRight(r.stdout, "\n"), "\n") {
				fmt.Printf("    | %s\n", l)
			}
		}
	}

	fmt.Println()
	if len(skipped) > 0 {
		fmt.Println("NOT EXECUTED (declared, with a reason):")
		for _, b := range skipped {
			reason := b.note
			if reason == "" {
				reason = "(no reason given — that is itself a failure)"
				failures++
			}
			fmt.Printf("  %s:%d  %s\n", b.page, b.line, reason)
		}
		fmt.Println()
	}

	for _, p := range navProblems {
		fmt.Println("navigation:", p)
		failures++
	}

	fmt.Printf("%d programs, %d failed, %d Go blocks not executed, %d unmarked\n",
		len(results), failures, len(skipped), unmarked)
	if failures > 0 {
		os.Exit(1)
	}
}

// checkNavigation reconciles docs.json's navigation with the pages on disk:
// every referenced page must exist, and every page must be reachable. Neither
// is enforced by Mintlify's JSON Schema, and both are silent 404s if wrong.
func checkNavigation(root string) ([]string, error) {
	raw, err := os.ReadFile(filepath.Join(root, "docs.json")) //nolint:gosec // fixed path
	if err != nil {
		return nil, err
	}
	var cfg struct {
		Navigation any `json:"navigation"`
	}
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return nil, fmt.Errorf("docs.json: %w", err)
	}

	referenced := map[string]bool{}
	var walk func(node any, inPages bool)
	walk = func(node any, inPages bool) {
		switch n := node.(type) {
		case string:
			if inPages {
				referenced[n] = true
			}
		case []any:
			for _, c := range n {
				walk(c, inPages)
			}
		case map[string]any:
			for k, v := range n {
				switch k {
				case "pages":
					walk(v, true)
				case "groups", "tabs", "anchors", "dropdowns",
					"versions", "languages", "products", "menu", "global":
					walk(v, false)
				}
			}
		}
	}
	walk(cfg.Navigation, false)

	var problems []string
	for page := range referenced {
		if _, err := os.Stat(filepath.Join(root, page+".mdx")); err != nil {
			problems = append(problems, "references "+page+", which is not a file")
		}
	}
	err = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		name := d.Name()
		if d.IsDir() {
			if path != root && (strings.HasPrefix(name, "_") || strings.HasPrefix(name, ".")) {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(name, ".mdx") {
			return nil
		}
		rel, rerr := filepath.Rel(root, path)
		if rerr != nil {
			return rerr
		}
		slug := strings.TrimSuffix(filepath.ToSlash(rel), ".mdx")
		if !referenced[slug] {
			problems = append(problems, slug+" is on disk but unreachable from the navigation")
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Strings(problems)
	return problems, nil
}

// inlineStdout reads the optional stdout="..." attribute off a program marker.
func inlineStdout(b block) (string, bool, error) {
	rest := strings.TrimSpace(b.note)
	if !strings.HasPrefix(rest, "stdout=") {
		return "", false, nil
	}
	s, err := strconv.Unquote(strings.TrimPrefix(rest, "stdout="))
	if err != nil {
		return "", false, fmt.Errorf("%s:%d: verify:program stdout= wants a quoted string: %w",
			b.page, b.line, err)
	}
	return s, true, nil
}

// collect reads every .mdx page under root and pulls out its Go fences.
func collect(root string) ([]page, error) {
	var pages []page
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".mdx") {
			return nil
		}
		p, err := parse(path)
		if err != nil {
			return err
		}
		if len(p.blocks) > 0 {
			pages = append(pages, p)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(pages, func(i, j int) bool { return pages[i].path < pages[j].path })
	return pages, nil
}

// parse scans one page for Go fences and the markers that precede them.
func parse(path string) (page, error) {
	raw, err := os.ReadFile(path) //nolint:gosec // paths come from the docs tree
	if err != nil {
		return page{}, err
	}
	p := page{path: filepath.ToSlash(path)}
	lines := strings.Split(strings.ReplaceAll(string(raw), "\r\n", "\n"), "\n")

	var mode, note string
	for i := 0; i < len(lines); i++ {
		line := lines[i]

		if m := markerRe.FindStringSubmatch(line); m != nil {
			if m[1] == "stdout" {
				s, uerr := strconv.Unquote(strings.TrimSpace(m[2]))
				if uerr != nil {
					return page{}, fmt.Errorf("%s:%d: verify:stdout wants a quoted string: %w",
						p.path, i+1, uerr)
				}
				p.stdout, p.hasExp = s, true
				continue
			}
			mode, note = m[1], m[2]
			continue
		}
		// A marker that does not parse would silently do nothing, which is
		// worse than doing the wrong thing: the check it was meant to apply
		// would just never run. Refuse it.
		if strings.Contains(line, "verify:") && strings.Contains(line, "{/*") {
			return page{}, fmt.Errorf("%s:%d: malformed verify marker: %s",
				p.path, i+1, strings.TrimSpace(line))
		}

		f := fenceRe.FindStringSubmatch(line)
		if f == nil {
			if strings.TrimSpace(line) != "" {
				// A marker governs only the fence that follows it directly.
				mode, note = "", ""
			}
			continue
		}
		indent, ticks, lang := f[1], f[2], f[3]
		start := i + 1
		var body []string
		for i++; i < len(lines); i++ {
			t := strings.TrimSpace(lines[i])
			if strings.HasPrefix(t, ticks) && strings.Trim(t, "`") == "" {
				break
			}
			body = append(body, strings.TrimPrefix(lines[i], indent))
		}
		if lang == "go" {
			p.blocks = append(p.blocks, block{
				page: p.path,
				line: start,
				mode: mode,
				note: note,
				body: strings.Join(body, "\n"),
			})
		}
		mode, note = "", ""
	}
	return p, nil
}

// assemble folds a page's import, decl and main blocks into one program.
func assemble(imports, decls, mains []block) (string, []int) {
	var lines []int
	var b strings.Builder
	b.WriteString("package main\n\n")
	for _, blk := range imports {
		b.WriteString(blk.body)
		b.WriteString("\n\n")
		lines = append(lines, blk.line)
	}
	for _, blk := range decls {
		b.WriteString(blk.body)
		b.WriteString("\n\n")
		lines = append(lines, blk.line)
	}
	b.WriteString("func main() {\n")
	for _, blk := range mains {
		for _, l := range strings.Split(blk.body, "\n") {
			if l == "" {
				b.WriteString("\n")
				continue
			}
			b.WriteString("\t" + l + "\n")
		}
		b.WriteString("\n")
		lines = append(lines, blk.line)
	}
	b.WriteString("}\n")
	return b.String(), lines
}

// run writes a program into the work tree, compiles and executes it, and
// checks its output against want when the page pinned one.
func run(repo, work, name, pg string, lines []int, src, want string, hasWant bool) result {
	r := result{name: name, page: pg, lines: lines}
	dir := filepath.Join(work, name)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		r.detail = err.Error()
		return r
	}
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte(src), 0o600); err != nil {
		r.detail = err.Error()
		return r
	}

	cmd := exec.Command("go", "run", "./.docsverify/"+name)
	cmd.Dir = repo
	out, err := cmd.CombinedOutput()
	r.stdout = string(out)
	if err != nil {
		r.detail = numbered(src) + "\n--- go run ---\n" + string(out) + err.Error()
		return r
	}
	if hasWant {
		got := strings.TrimSpace(strings.ReplaceAll(string(out), "\r\n", "\n"))
		if got != strings.TrimSpace(want) {
			r.detail = fmt.Sprintf("stdout mismatch\n  want: %q\n  got:  %q", want, got)
			return r
		}
	}
	r.ok = true
	return r
}

// numbered renders a failing program with line numbers, so a compile error's
// position points at something the reader can see.
func numbered(src string) string {
	var b strings.Builder
	for i, l := range strings.Split(src, "\n") {
		fmt.Fprintf(&b, "%4d| %s\n", i+1, l)
	}
	return b.String()
}

// programName turns a page path into a directory name unique per program.
func programName(path string, line int) string {
	s := strings.TrimSuffix(filepath.ToSlash(path), ".mdx")
	s = strings.TrimPrefix(s, "docs/")
	s = strings.NewReplacer("/", "_", "-", "_", ".", "_").Replace(s)
	if line > 0 {
		return fmt.Sprintf("p_%s_l%d", s, line)
	}
	return "p_" + s
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "verify:", err)
	os.Exit(1)
}
