# Middleware benchmark baseline (wave 3)

Committed by wave 3 so wave 7 (hot-path concurrency rewrite) and wave 8 (upstream
transport) have something to diff against. **Do not edit the numbers.** Re-run the
command below on the same machine after a wave lands and append a new section.

## How to reproduce

```
go test ./core/server/ -run '^$' -bench BenchmarkMiddleware -benchmem -count 5 -cpu 1,4,16
```

Benchmark source: `core/server/middleware_bench_test.go`.

## Machine

| | |
| --- | --- |
| Date | 2026-08-31 |
| Commit | `8f1f26c` (wave 2 head; `Middleware` is still byte-for-byte upstream) |
| Go | go1.25.14 windows/amd64, GOAMD64=v1 |
| OS | Windows 11 Pro 26100 |
| CPU | AMD Ryzen 7 5700X, 8 cores / 16 threads |
| Load | interactive desktop, not an isolated bench box - see "Reading these numbers" |

## Medians (n=5)

| Benchmark | -cpu 1 | -cpu 4 | -cpu 16 | B/op | allocs/op |
| --- | ---: | ---: | ---: | ---: | ---: |
| MiddlewareHotPath | 11559 ns | 10250 ns | 11522 ns | 34945 | 31 |
| MiddlewareHotPathParallel | 9542 ns | 10146 ns | 7652 ns | 34943 | 31 |
| **MiddlewareDecisionPath** | **386.1 ns** | 369.7 ns | 358.9 ns | 80 | 4 |
| **MiddlewareDecisionPathParallel** | **386.9 ns** | 897.1 ns | **1022 ns** | 80 | 4 |
| MiddlewareChallengeStage1 | 1086 ns | 1093 ns | 1058 ns | 528 | 10 |
| MiddlewareChallengeStage1Parallel | 1079 ns | 1773 ns | 1788 ns | 528 | 10 |
| MiddlewareHarnessBaseline | 31.6 ns | 31.0 ns | 31.6 ns | 0 | 0 |

## What these say

**The global mutex inverts scaling, and the effect is now measured on this repo.**
`MiddlewareDecisionPathParallel` - the R2 ip-ratelimit path, which touches nothing
but `firewall.Mutex` and two maps - goes from **386.9 ns/op uncontended to 1022 ns/op
at 16 threads, 2.6x SLOWER with 16x the cores**. The serial twin
(`MiddlewareDecisionPath`) is flat at ~360-390 ns across the same `-cpu` values, so
this is contention, not GC or scheduling. The audit's figure was the same shape
(43.7 ns/op at 1 -> 90.9 ns/op at 16, 2.08x); the absolute values differ because
that measurement did not include a full `Middleware` call.

Every request takes `firewall.Mutex` three or four times, twice for **writing**:

| Site | Lock |
| --- | --- |
| `middleware.go:40-42` domain lookup | RLock |
| `middleware.go:76-81` counter read (origin mode) | RLock |
| `middleware.go:88-100` sliding-window + TotalRequests | **Lock** |
| `middleware.go:129-131` unknown-fingerprint window | **Lock** (unknown fingerprints only) |
| `middleware.go:216-218` challenge-failure window | **Lock** (challenged requests only) |
| `middleware.go:306-320` access log + BypassedRequests | **Lock** (bypassed requests only) |

`MiddlewareChallengeStage1Parallel` shows the same inversion at 1079 -> 1788 ns/op
(1.66x) because a challenged request takes the write lock twice.

**The hot path does NOT show the inversion, and that is not good news.** At
34945 B/op it is dominated by allocation, and allocation parallelises. The 32 KiB
of that is `httputil.ReverseProxy` allocating a fresh copy buffer per response
because no `BufferPool` is configured (`core/config/init.go:126-130`,
`core/server/monitor.go:467-471`). Fix that in wave 8 and the hot path will start
showing the wave 7 lock behaviour too - so re-baseline between the two waves rather
than comparing a post-8 hot path against this line.

**Targets for wave 7.** `MiddlewareDecisionPathParallel` and
`MiddlewareChallengeStage1Parallel` at `-cpu 16` must come DOWN, and must not
exceed their own `-cpu 1` number. Anything else is a failed rewrite, however good
the single-thread figure looks.

## Reading these numbers

- **Serial vs parallel is not comparable.** `-cpu N` on a serial benchmark only
  changes GOMAXPROCS (i.e. GC parallelism); `RunParallel` actually runs N workers.
  Compare serial-to-serial and parallel-to-parallel.
- **Absolute values are machine- and load-specific.** This was measured on an
  interactive desktop; `MiddlewareHotPath` at `-cpu 1` ranged 8670-12531 ns across
  the five runs. The low-allocation benchmarks are tight (`DecisionPath` 381.5-394.2)
  and are the ones to trust. Ratios within one run are far more meaningful than
  absolute numbers across machines.
- The upstream backend is an **in-process stub RoundTripper**, not a socket, so
  no TCP or kernel time is included.
- The response writer discards output, so response serialisation is excluded.
- Each goroutine reuses one `*http.Request` and resets the four identity headers
  `Middleware` adds; `MiddlewareHarnessBaseline` (31.6 ns/op) is that reset, and is
  included in every other number above.
- `MiddlewareHotPath*` trims `DomainsData[...].LastLogs` every 4096 iterations,
  because `utils.AddLogs` appends unboundedly with no monitor goroutine running.
  That is ~1/4096 of a mutex round trip, i.e. noise.

## Raw output

```
goos: windows
goarch: amd64
pkg: github.com/azferius/lancarsec/core/server
cpu: AMD Ryzen 7 5700X 8-Core Processor             
BenchmarkMiddlewareHotPath                       	  130932	      9110 ns/op	   34943 B/op	      31 allocs/op
BenchmarkMiddlewareHotPath                       	  154408	      8670 ns/op	   34941 B/op	      31 allocs/op
BenchmarkMiddlewareHotPath                       	   99640	     12531 ns/op	   34948 B/op	      31 allocs/op
BenchmarkMiddlewareHotPath                       	  116718	     12000 ns/op	   34945 B/op	      31 allocs/op
BenchmarkMiddlewareHotPath                       	   99396	     11559 ns/op	   34948 B/op	      31 allocs/op
BenchmarkMiddlewareHotPath-4                     	  112795	     10250 ns/op	   34951 B/op	      31 allocs/op
BenchmarkMiddlewareHotPath-4                     	  104707	     10720 ns/op	   34952 B/op	      31 allocs/op
BenchmarkMiddlewareHotPath-4                     	  122479	     10601 ns/op	   34950 B/op	      31 allocs/op
BenchmarkMiddlewareHotPath-4                     	  109377	     10245 ns/op	   34952 B/op	      31 allocs/op
BenchmarkMiddlewareHotPath-4                     	  130836	     10061 ns/op	   34949 B/op	      31 allocs/op
BenchmarkMiddlewareHotPath-16                    	  117795	     11123 ns/op	   34975 B/op	      31 allocs/op
BenchmarkMiddlewareHotPath-16                    	  113317	     12272 ns/op	   34976 B/op	      31 allocs/op
BenchmarkMiddlewareHotPath-16                    	  113602	     10788 ns/op	   34976 B/op	      31 allocs/op
BenchmarkMiddlewareHotPath-16                    	  105936	     11781 ns/op	   34972 B/op	      31 allocs/op
BenchmarkMiddlewareHotPath-16                    	  106876	     11522 ns/op	   34975 B/op	      31 allocs/op
BenchmarkMiddlewareHotPathParallel               	  134439	      9327 ns/op	   34943 B/op	      31 allocs/op
BenchmarkMiddlewareHotPathParallel               	  144655	      9848 ns/op	   34942 B/op	      31 allocs/op
BenchmarkMiddlewareHotPathParallel               	  126007	      9542 ns/op	   34943 B/op	      31 allocs/op
BenchmarkMiddlewareHotPathParallel               	  127278	      9135 ns/op	   34943 B/op	      31 allocs/op
BenchmarkMiddlewareHotPathParallel               	  136214	     10912 ns/op	   34943 B/op	      31 allocs/op
BenchmarkMiddlewareHotPathParallel-4             	  111182	     10147 ns/op	   35003 B/op	      31 allocs/op
BenchmarkMiddlewareHotPathParallel-4             	  108855	     10211 ns/op	   35005 B/op	      31 allocs/op
BenchmarkMiddlewareHotPathParallel-4             	  116586	     10036 ns/op	   35000 B/op	      31 allocs/op
BenchmarkMiddlewareHotPathParallel-4             	  120478	     10146 ns/op	   34998 B/op	      31 allocs/op
BenchmarkMiddlewareHotPathParallel-4             	  107188	      9983 ns/op	   35006 B/op	      31 allocs/op
BenchmarkMiddlewareHotPathParallel-16            	  138384	      7652 ns/op	   35187 B/op	      31 allocs/op
BenchmarkMiddlewareHotPathParallel-16            	  137044	      7866 ns/op	   35190 B/op	      31 allocs/op
BenchmarkMiddlewareHotPathParallel-16            	  137433	      7720 ns/op	   35189 B/op	      31 allocs/op
BenchmarkMiddlewareHotPathParallel-16            	  167959	      7267 ns/op	   35140 B/op	      31 allocs/op
BenchmarkMiddlewareHotPathParallel-16            	  172783	      7143 ns/op	   35134 B/op	      31 allocs/op
BenchmarkMiddlewareDecisionPath                  	 2956171	       394.2 ns/op	      80 B/op	       4 allocs/op
BenchmarkMiddlewareDecisionPath                  	 3090476	       391.1 ns/op	      80 B/op	       4 allocs/op
BenchmarkMiddlewareDecisionPath                  	 3091948	       386.1 ns/op	      80 B/op	       4 allocs/op
BenchmarkMiddlewareDecisionPath                  	 2938156	       383.4 ns/op	      80 B/op	       4 allocs/op
BenchmarkMiddlewareDecisionPath                  	 3075232	       381.5 ns/op	      80 B/op	       4 allocs/op
BenchmarkMiddlewareDecisionPath-4                	 3104642	       369.7 ns/op	      80 B/op	       4 allocs/op
BenchmarkMiddlewareDecisionPath-4                	 2882061	       379.4 ns/op	      80 B/op	       4 allocs/op
BenchmarkMiddlewareDecisionPath-4                	 3208714	       379.4 ns/op	      80 B/op	       4 allocs/op
BenchmarkMiddlewareDecisionPath-4                	 3383552	       362.5 ns/op	      80 B/op	       4 allocs/op
BenchmarkMiddlewareDecisionPath-4                	 3263503	       366.6 ns/op	      80 B/op	       4 allocs/op
BenchmarkMiddlewareDecisionPath-16               	 3331340	       366.9 ns/op	      80 B/op	       4 allocs/op
BenchmarkMiddlewareDecisionPath-16               	 3441217	       358.9 ns/op	      80 B/op	       4 allocs/op
BenchmarkMiddlewareDecisionPath-16               	 3198258	       370.0 ns/op	      80 B/op	       4 allocs/op
BenchmarkMiddlewareDecisionPath-16               	 3523484	       354.9 ns/op	      80 B/op	       4 allocs/op
BenchmarkMiddlewareDecisionPath-16               	 3374624	       357.1 ns/op	      80 B/op	       4 allocs/op
BenchmarkMiddlewareDecisionPathParallel          	 3546464	       407.8 ns/op	      80 B/op	       4 allocs/op
BenchmarkMiddlewareDecisionPathParallel          	 3138175	       386.9 ns/op	      80 B/op	       4 allocs/op
BenchmarkMiddlewareDecisionPathParallel          	 3114402	       410.1 ns/op	      80 B/op	       4 allocs/op
BenchmarkMiddlewareDecisionPathParallel          	 3026108	       386.7 ns/op	      80 B/op	       4 allocs/op
BenchmarkMiddlewareDecisionPathParallel          	 3183106	       386.9 ns/op	      80 B/op	       4 allocs/op
BenchmarkMiddlewareDecisionPathParallel-4        	 1358265	       887.6 ns/op	      80 B/op	       4 allocs/op
BenchmarkMiddlewareDecisionPathParallel-4        	 1361278	       883.5 ns/op	      80 B/op	       4 allocs/op
BenchmarkMiddlewareDecisionPathParallel-4        	 1342292	       897.1 ns/op	      80 B/op	       4 allocs/op
BenchmarkMiddlewareDecisionPathParallel-4        	 1319500	       912.2 ns/op	      80 B/op	       4 allocs/op
BenchmarkMiddlewareDecisionPathParallel-4        	 1276530	       918.6 ns/op	      80 B/op	       4 allocs/op
BenchmarkMiddlewareDecisionPathParallel-16       	 1000000	      1022 ns/op	      80 B/op	       4 allocs/op
BenchmarkMiddlewareDecisionPathParallel-16       	 1000000	      1014 ns/op	      80 B/op	       4 allocs/op
BenchmarkMiddlewareDecisionPathParallel-16       	 1000000	      1002 ns/op	      80 B/op	       4 allocs/op
BenchmarkMiddlewareDecisionPathParallel-16       	 1000000	      1025 ns/op	      80 B/op	       4 allocs/op
BenchmarkMiddlewareDecisionPathParallel-16       	 1000000	      1025 ns/op	      80 B/op	       4 allocs/op
BenchmarkMiddlewareChallengeStage1               	 1000000	      1119 ns/op	     528 B/op	      10 allocs/op
BenchmarkMiddlewareChallengeStage1               	 1066543	      1086 ns/op	     528 B/op	      10 allocs/op
BenchmarkMiddlewareChallengeStage1               	 1000000	      1096 ns/op	     528 B/op	      10 allocs/op
BenchmarkMiddlewareChallengeStage1               	 1000000	      1080 ns/op	     528 B/op	      10 allocs/op
BenchmarkMiddlewareChallengeStage1               	 1000000	      1058 ns/op	     528 B/op	      10 allocs/op
BenchmarkMiddlewareChallengeStage1-4             	 1000000	      1085 ns/op	     528 B/op	      10 allocs/op
BenchmarkMiddlewareChallengeStage1-4             	 1000000	      1018 ns/op	     528 B/op	      10 allocs/op
BenchmarkMiddlewareChallengeStage1-4             	 1000000	      1100 ns/op	     528 B/op	      10 allocs/op
BenchmarkMiddlewareChallengeStage1-4             	 1000000	      1105 ns/op	     528 B/op	      10 allocs/op
BenchmarkMiddlewareChallengeStage1-4             	 1000000	      1093 ns/op	     528 B/op	      10 allocs/op
BenchmarkMiddlewareChallengeStage1-16            	 1000000	      1072 ns/op	     528 B/op	      10 allocs/op
BenchmarkMiddlewareChallengeStage1-16            	 1000000	      1058 ns/op	     528 B/op	      10 allocs/op
BenchmarkMiddlewareChallengeStage1-16            	 1000000	      1023 ns/op	     528 B/op	      10 allocs/op
BenchmarkMiddlewareChallengeStage1-16            	  970873	      1108 ns/op	     528 B/op	      10 allocs/op
BenchmarkMiddlewareChallengeStage1-16            	 1000000	      1050 ns/op	     528 B/op	      10 allocs/op
BenchmarkMiddlewareChallengeStage1Parallel       	 1000000	      1226 ns/op	     528 B/op	      10 allocs/op
BenchmarkMiddlewareChallengeStage1Parallel       	 1000000	      1028 ns/op	     528 B/op	      10 allocs/op
BenchmarkMiddlewareChallengeStage1Parallel       	 1000000	      1048 ns/op	     528 B/op	      10 allocs/op
BenchmarkMiddlewareChallengeStage1Parallel       	 1000000	      1079 ns/op	     528 B/op	      10 allocs/op
BenchmarkMiddlewareChallengeStage1Parallel       	 1000000	      1100 ns/op	     528 B/op	      10 allocs/op
BenchmarkMiddlewareChallengeStage1Parallel-4     	  685365	      1727 ns/op	     528 B/op	      10 allocs/op
BenchmarkMiddlewareChallengeStage1Parallel-4     	  677620	      1798 ns/op	     528 B/op	      10 allocs/op
BenchmarkMiddlewareChallengeStage1Parallel-4     	  675812	      1852 ns/op	     528 B/op	      10 allocs/op
BenchmarkMiddlewareChallengeStage1Parallel-4     	  671820	      1764 ns/op	     528 B/op	      10 allocs/op
BenchmarkMiddlewareChallengeStage1Parallel-4     	  692691	      1773 ns/op	     528 B/op	      10 allocs/op
BenchmarkMiddlewareChallengeStage1Parallel-16    	  684919	      1774 ns/op	     528 B/op	      10 allocs/op
BenchmarkMiddlewareChallengeStage1Parallel-16    	  677082	      1788 ns/op	     528 B/op	      10 allocs/op
BenchmarkMiddlewareChallengeStage1Parallel-16    	  667430	      1819 ns/op	     528 B/op	      10 allocs/op
BenchmarkMiddlewareChallengeStage1Parallel-16    	  697698	      1749 ns/op	     528 B/op	      10 allocs/op
BenchmarkMiddlewareChallengeStage1Parallel-16    	  664860	      1799 ns/op	     528 B/op	      10 allocs/op
BenchmarkMiddlewareHarnessBaseline               	35465394	        30.98 ns/op	       0 B/op	       0 allocs/op
BenchmarkMiddlewareHarnessBaseline               	38752179	        31.49 ns/op	       0 B/op	       0 allocs/op
BenchmarkMiddlewareHarnessBaseline               	38393856	        31.62 ns/op	       0 B/op	       0 allocs/op
BenchmarkMiddlewareHarnessBaseline               	36971424	        32.16 ns/op	       0 B/op	       0 allocs/op
BenchmarkMiddlewareHarnessBaseline               	39619912	        37.73 ns/op	       0 B/op	       0 allocs/op
BenchmarkMiddlewareHarnessBaseline-4             	30784306	        33.06 ns/op	       0 B/op	       0 allocs/op
BenchmarkMiddlewareHarnessBaseline-4             	37552220	        31.42 ns/op	       0 B/op	       0 allocs/op
BenchmarkMiddlewareHarnessBaseline-4             	39590240	        31.03 ns/op	       0 B/op	       0 allocs/op
BenchmarkMiddlewareHarnessBaseline-4             	41250153	        30.83 ns/op	       0 B/op	       0 allocs/op
BenchmarkMiddlewareHarnessBaseline-4             	39786478	        30.41 ns/op	       0 B/op	       0 allocs/op
BenchmarkMiddlewareHarnessBaseline-16            	38546042	        31.47 ns/op	       0 B/op	       0 allocs/op
BenchmarkMiddlewareHarnessBaseline-16            	40006267	        31.69 ns/op	       0 B/op	       0 allocs/op
BenchmarkMiddlewareHarnessBaseline-16            	39356520	        30.71 ns/op	       0 B/op	       0 allocs/op
BenchmarkMiddlewareHarnessBaseline-16            	39611150	        31.87 ns/op	       0 B/op	       0 allocs/op
BenchmarkMiddlewareHarnessBaseline-16            	38193448	        31.65 ns/op	       0 B/op	       0 allocs/op
```
