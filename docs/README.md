# authlayer documentation

A [Mintlify](https://mintlify.com) site. `docs.json` is the configuration; every
page is an `.mdx` file beside it, and the navigation in `docs.json` is the only
place page order is declared.

## Run it locally

Needs Node 20.17+. The CLI package is `mint` (not the legacy `mintlify`, which
conflicts with it).

```sh
npm i -g mint
cd docs
mint dev            # http://localhost:3000
mint validate       # strict; exits non-zero on warnings
mint broken-links
```

## Every Go sample here is executed

Not by Mintlify — by a harness in this repository, from the repository root:

```sh
go run ./docs/_verify        # compile and run every sample; check docs.json and links
go run ./docs/_verify -v     # also print each program's stdout
```

It assembles each page's Go blocks into one program, runs it, and compares its
output against the value the page pins. A Go fence with no `{/* verify:... */}`
marker fails the run rather than being skipped silently. See
[`_verify/README.md`](_verify/README.md) for the markers and for what else it
checks.
