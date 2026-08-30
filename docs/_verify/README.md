# docs/_verify

Extracts every Go code block from the Mintlify pages under `docs/` and compiles
and runs it, and reconciles `docs.json`'s navigation with the pages on disk.

```sh
go run ./docs/_verify        # from the repository root
go run ./docs/_verify -v     # also print each program's stdout
go run ./docs/_verify -keep  # leave the generated programs in .docsverify/
```

The directory is underscore-prefixed so `go build ./...`, `go vet ./...` and
`go test ./...` never see it, and the programs it generates go into the
dot-prefixed `.docsverify/` for the same reason. `gofmt` descends into both, so
both stay formatted.

Every ```` ```go ```` fence in `docs/` must carry an MDX marker on the line
above it. An unmarked one fails the run — "which samples ran" has to have an
exhaustive answer.

| Marker | Meaning |
|---|---|
| `{/* verify:program */}` | a complete Go file, compiled and run on its own |
| `{/* verify:program stdout="…" */}` | the same, with its complete stdout pinned |
| `{/* verify:import */}` | an import block, merged into the page's program |
| `{/* verify:decl */}` | top-level declarations, appended to that program |
| `{/* verify:main */}` | statements, appended to that program's `main()` |
| `{/* verify:skip reason */}` | not executed; the reason is reported verbatim |
| `{/* verify:stdout "…" */}` | pins the assembled page program's stdout |

A page's `import`/`decl`/`main` blocks are assembled in source order into one
program, so its snippets continue each other exactly as a reader reads them.

It also reconciles `docs.json` with the tree in three directions, all of which
Mintlify's JSON Schema leaves unchecked and all of which render as a live link
to a 404:

- every page the navigation references exists on disk;
- every page on disk is reachable from the navigation;
- every absolute internal link and `href` resolves to a page, and every
  `#anchor` to a heading on it.

Mintlify does not document its heading slugifier, so anchor matching accepts
both the "drop the apostrophe" and the "treat it as a separator" conventions.
Headings linked to by anchor avoid punctuation for that reason.
