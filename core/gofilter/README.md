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

Three things. The first two are cosmetic; the third is a deliberate behaviour
change and is the only place this package diverges from upstream semantics.

1. **Line endings normalised to LF.** Upstream ships `filter_info.go`, `lexer.rl`,
   `parser.y` and `README.md` with CRLF; the rest with LF. This repo is LF-only
   (see `.gitattributes`). `filter_info.go` was reported by `gofmt -l` purely
   because of the CRLF.
2. **`lexer.go` line 458 reflowed by `gofmt`.** Upstream has
   `{ /*lexer.ts++; lexer.te--;*/ token_kind = token_UNPARSED` on one line;
   gofmt splits the statement onto its own line. Cosmetic only, but it is a
   deviation and it is why `diff` against upstream is not empty for this file.
3. **The `matches` operand assertion is comma-ok (wave 4).** Upstream's
   `predicate: token_FIELD token_TEST_MATCHES token_UNPARSED` action compiles
   the pattern with `regexp.Compile(val.(string))`, an unchecked assertion on
   whatever `checkFieldNameVsTypeValue` returned. That value is only a `string`
   for an `FT_STRING`/`FT_BYTES` field whose literal parsed as neither a quoted
   string nor colon-hex — so `net.IP`, `int`, `bool` and `[]byte` operands all
   panicked, and `NewFilter` has no `recover()`. LancarSec replaces it with

   ```go
   pattern, isString := val.(string)
   if !isString {
       str := fmt.Sprintf("Field \"%s\" can not be used with \"matches\": the pattern must be a string, but \"%s\" was parsed as %T.", …)
       filterlex.Error(str)
       return 1
   }
   r_expr, err := regexp.Compile(pattern)
   ```

   so a bad operand is an ordinary parse error naming the field and the type the
   operand actually produced, and `NewFilter` returns `(nil, error)` as it does
   for every other malformed rule. **This is applied to both `parser.go` and
   `parser.y`**, so regenerating the parser from the yacc grammar reproduces the
   fix instead of silently reverting it. Covered by `matches_test.go`.

Everything else is byte-identical to upstream after CRLF stripping. Verified
per-file with `diff <(tr -d '
' < $GOMODCACHE/.../<f>) core/gofilter/<f>`:
`filter_main.go`, `filter_info.go`, `nodes.go`, `filter_test.go` and `LICENSE`
are 0 diff lines; `lexer.go` is 5 (the reflow in change 2); `parser.go` and
`parser.y` carry change 3 and nothing else. `matches_test.go` is LancarSec's
own file and has no upstream counterpart.

Re-run that check after any edit here. If you intend to modify this package,
record the change in the numbered list above so the provenance stays auditable.

## The `matches` panic — fixed in wave 4

Recorded here because it is the reason this package needed to be patchable
in-tree, and because the fix is the one intentional semantic deviation in the
list above.

`parser.go` used to compile a `matches` operand with
`regexp.Compile(val.(string))`, an unchecked type assertion. Any `matches` rule
whose right-hand side did not parse to a string panicked:

    ip.src matches 1.2.3.4          panic: interface {} is net.IP, not string
    ip.asn matches 1234             panic: interface {} is int, not string
    http.user_agent matches ff:ee   panic: interface {} is []uint8, not string
    proxy.attack matches true       panic: interface {} is bool, not string

`NewFilter` does not recover, and both call sites — `config.buildDomain` at
startup and `core/server/monitor.go` on live reload — were therefore one config
typo away from killing the proxy. Wave 4 fixed it in the parser (change 3
above), which is the right layer: a bare `recover()` at the two call sites would
have turned the crash into a silently half-applied reload rather than a named
error. The same four rules now produce, for example:

    Field "ip.asn" can not be used with "matches": the pattern must be a string,
    but "1234" was parsed as int.

## Regenerating the parser and lexer

`lexer.go` and `parser.go` are machine-generated from `lexer.rl` and `parser.y`.
The `//go:generate` directives in `filter_main.go` are **stale**: `go tool yacc`
was removed from the Go distribution in Go 1.8. Do not run `go generate ./...`
against this directory. The current equivalents are:

```sh
ragel -Z lexer.rl                    # -> lexer.go   (Ragel 6.x)
go run golang.org/x/tools/cmd/goyacc@latest -o parser.go -p filter parser.y
```

After regenerating, re-apply change 2 above (or `gofmt -w`) and re-check
`go vet`. Change 3 lives in `parser.y` as well, so a regenerated `parser.go`
carries it automatically — but run `go test ./core/gofilter/` afterwards:
`matches_test.go` is what proves it survived the round trip.

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

These are upstream behaviours, documented here so a later wave can fix them
deliberately rather than discover them in production. All are preserved as-is
except number 2, which wave 4 changed on purpose.

1. **`or` binds tighter than `and`.** `parser.y` declares `%left token_TEST_AND`
   before `%left token_TEST_OR`, and in yacc later declarations have *higher*
   precedence. So `a and b or c` parses as `a and (b or c)`, the opposite of
   Wireshark and of every other boolean language. Verified:
   `a == false and b == true or c == true` with `a=false, b=true, c=true`
   returns `false`. Existing rules in `config.json` were written against this
   behaviour — changing it is a breaking change, not a bugfix.
2. ~~**`matches` panics on a non-string operand.**~~ **Fixed in wave 4** — see
   change 3 in "What was changed from upstream" and the section above. Upstream
   `parser.go` case 13 did `val.(string)` on the value returned by
   `checkFieldNameVsTypeValue`, which is only a `string` for `FT_STRING`/`FT_BYTES`
   fields whose literal is neither a quoted string nor colon-hex, so all four of
   `http.user_agent matches ff:ee`, `ip.asn matches 1234`,
   `ip.src matches 1.2.3.4` and `proxy.attack matches true` panicked out of
   `NewFilter` and took the caller with them — `config.buildDomain` at startup
   and `server.ReloadConfig` on live reload. They now return a parse error
   naming the field and the operand's real type. This entry stays in the list
   because it is the one quirk LancarSec chose to diverge on; the rest below are
   still preserved as-is.
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

## Do not run modernize or gofmt sweeps over this directory

`modernize -fix ./...` rewrites this package (56 lines in `nodes.go` alone) and
destroys the provenance the fidelity check above depends on. Exclude
`core/gofilter/` from any repo-wide automated rewrite, and re-run the per-file
diff against `$GOMODCACHE` if you suspect one has run.
