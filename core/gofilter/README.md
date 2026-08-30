# core/gofilter — vendored copy of `github.com/kor44/gofilter`

This directory is a **vendored copy**, not original LancarSec code.

| | |
| --- | --- |
| Upstream | <https://github.com/kor44/gofilter> |
| Upstream commit | `75787865c72c` (2017-11-11T11:51:39Z) |
| Go pseudo-version | `v0.0.0-20171111115139-75787865c72c` |
| Module checksum | `h1:i5aYIjSbOchkIWw9rm+k/+rA0GDKHuBjobr/D3jcZdY=` (signed entry #5640065 in sum.golang.org) |
| Upstream licence | MIT — see `LICENSE` in this directory |
| Vendored on | 2026-08-30 |
| Third-party dependencies | none — stdlib only (`bytes`, `errors`, `fmt`, `net`, `regexp`, `strconv`, `strings`) |

## Why it is vendored

This package is the firewall rule DSL engine — the most load-bearing dependency in
the product. Upstream is an untagged 2017 commit on a personal repository with no
`go.mod`, no releases, and no maintenance since. A silently disappearing or
force-pushed upstream would take the firewall with it. Vendoring pins the code,
makes it reviewable in-tree, and lets later waves patch it directly.

## Licence compatibility

MIT is a permissive licence and is **compatible with GPL v2**: MIT-licensed code
may be incorporated into a GPL v2 work, and the combined work is distributed under
GPL v2. The only obligation is that the MIT copyright notice and permission notice
travel with the copies — that is what `core/gofilter/LICENSE` is for. Do not delete
it, and do not relicense the files in this directory. The top-level `LICENSE`
(GNU GPL v2) continues to govern LancarSec as a whole.

## What was changed from upstream

Three things. None affects runtime behaviour.

1. **Line endings normalised to LF.** Upstream ships `filter_info.go`, `lexer.rl`,
   `parser.y` and `README.md` with CRLF; the rest with LF. This repo is LF-only
   (see `.gitattributes`). `filter_info.go` was reported by `gofmt -l` purely
   because of the CRLF.
2. **`lexer.go` line 458 reflowed by `gofmt`.** Upstream has
   `{ /*lexer.ts++; lexer.te--;*/ token_kind = token_UNPARSED` on one line;
   gofmt splits the statement onto its own line. Cosmetic only, but it is a
   deviation and it is why `diff` against upstream is not empty for this file.

Everything else is byte-identical to upstream after CRLF stripping. Verified
per-file with `diff <(tr -d '
' < $GOMODCACHE/.../<f>) core/gofilter/<f>`:
`filter_main.go`, `filter_info.go`, `nodes.go`, `parser.go`, `filter_test.go`
and `LICENSE` are 0 diff lines; `lexer.go` is 5 (the reflow above).

Re-run that check after any edit here. If you intend to modify this package —
for example to fix the reachable panic recorded below — record the change in
this list so the provenance stays auditable.

## Known defect carried over from upstream

`parser.go` compiles a `matches` operand with `regexp.Compile(val.(string))`,
an unchecked type assertion. Any `matches` rule whose right-hand side is not a
quoted string panics:

    ip.src matches 1.2.3.4          panic: interface {} is net.IP, not string
    ip.asn matches 1234             panic: interface {} is int, not string
    http.user_agent matches ff:ee   panic: interface {} is []uint8, not string
    proxy.attack matches true       panic: interface {} is bool, not string

`NewFilter` does not recover. Both call sites — `config.buildDomain` at startup
and `core/server/monitor.go` on live reload — are therefore one config typo away
from killing the proxy. Not fixed here: wave 2 does not change behaviour. Fix it
in a later wave, either with a comma-ok assertion in the vendored parser or a
recover at both call sites.

## Regenerating the parser and lexer

`lexer.go` and `parser.go` are machine-generated from `lexer.rl` and `parser.y`.
The `//go:generate` directives in `filter_main.go` are **stale**: `go tool yacc`
was removed from the Go distribution in Go 1.8. Do not run `go generate ./...`
against this directory. The current equivalents are:

```sh
ragel -Z lexer.rl                    # -> lexer.go   (Ragel 6.x)
go run golang.org/x/tools/cmd/goyacc@latest -o parser.go -p filter parser.y
```

After regenerating, re-apply changes 2 and 3 above, or `gofmt -w` and re-check
`go vet`.

## Filter syntax (from the upstream README)

A Go implementation of the Wireshark display filter, over `Message`
(`map[string]interface{}`).

Comparison: `eq`/`==`, `ne`/`!=`, `gt`/`>`, `lt`/`<`, `ge`/`>=`, `le`/`<=`.
Search: `contains`, `matches` (Go RE2 regexp).
Logical: `and`/`&&`, `or`/`||`, `not`/`!`.
A bare field name tests for the field's presence.

Not implemented upstream: `upper()`/`lower()`, the slice operator
(`eth.src[0:3]`), and `bitwise_and`/`&`.

## Known quirks — measured, not inferred (2026-08-30)

These are upstream behaviours preserved as-is. They are documented here so a
later wave can fix them deliberately rather than discover them in production.

1. **`or` binds tighter than `and`.** `parser.y` declares `%left token_TEST_AND`
   before `%left token_TEST_OR`, and in yacc later declarations have *higher*
   precedence. So `a and b or c` parses as `a and (b or c)`, the opposite of
   Wireshark and of every other boolean language. Verified:
   `a == false and b == true or c == true` with `a=false, b=true, c=true`
   returns `false`. Existing rules in `config.json` were written against this
   behaviour — changing it is a breaking change, not a bugfix.
2. **`matches` panics on a non-string operand.** In `parser.go` case 13 the
   parser does `val.(string)` on the value returned by
   `checkFieldNameVsTypeValue`, which is only a `string` for `FT_STRING`/`FT_BYTES`
   fields whose literal is neither a quoted string nor colon-hex. All four of
   these panic rather than returning an error:
   - `http.user_agent matches ff:ee` → `interface {} is []uint8, not string`
   - `ip.asn matches 1234` → `interface {} is int, not string`
   - `ip.src matches 1.2.3.4` → `interface {} is net.IP, not string`
   - `proxy.attack matches true` → `interface {} is bool, not string`
   `NewFilter` has no `recover()`, so a typo in a rule panics the caller.
   In LancarSec that is `config.buildDomain` (startup) and
   `server.ReloadConfig` (`core/server/monitor.go:456`, live reload).
3. **`[]byte`-valued fields never match string comparisons.** `applyRange`
   matches `[]uint8` before the `default` arm, so a `[]byte` field value is
   iterated byte-by-byte and each `byte` is compared against a `string`.
   Harmless today: every field LancarSec registers holds a `string`, `int`,
   `bool` or `net.IP`.
4. **No complexity limit on regexes compiled from rule text.** Bounded in
   practice only by Go's `regexp/syntax` (max repeat 1000, program-size cap) and
   by RE2's linear-time matching — there is no catastrophic backtracking.
   `(a+)+$` and 40 nested `(a|aa)` alternations compile instantly and match a
   5 KB input in 0.5 ms and 6.3 ms respectively.
5. **`RegisterField` is not goroutine-safe** — it writes three package-level maps
   with no mutex. Safe today because the only caller is
   `core/firewall/filter.go`'s `init()`. Never call it after startup.

The parser itself is table-driven goyacc, **not** recursive descent, so deeply
nested input cannot blow the goroutine stack: 200 000 nested parentheses parse in
16 ms using 19 MB, growing linearly. `filterMaxDepth` is 200 but the generated
code grows the stack past it rather than erroring.
