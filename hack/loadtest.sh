#!/bin/sh
#
# loadtest.sh -- end-to-end throughput / latency / memory measurement against a
# running LancarSec.
#
# This measures what a Go benchmark cannot: the whole path from a real socket,
# through net/http, through Middleware's decision logic, through
# httputil.ReverseProxy, to a backend and back. Report is req/s, p99 latency and
# peak resident memory of the LancarSec process during the run.
#
# Requires a load generator: vegeta (preferred) or hey. Neither is vendored;
# the script detects what is installed and tells you how to install one if not.
#
# Works from Git Bash on Windows and from Linux. POSIX sh, no bashisms.
#
# See hack/README.md for the full run sequence and for what the numbers should
# look like today.

set -eu

PROG=loadtest.sh

# ---------------------------------------------------------------- defaults ---

URL=http://127.0.0.1/bench
HOST=bench.local
CLIENT_IP=203.0.113.10
DURATION=30
CONNS=50
RATE=0 # 0 == as fast as the workers can go (vegeta only)
PROC_NAME=lancarsec
PROC_PID=""
MEASURE_RSS=1
SAMPLE_INTERVAL=1
OUTDIR=./hack-results
GENERATOR=""

usage() {
	cat <<EOF
Usage: $PROG [options]

  -u URL        target URL                        (default $URL)
  -H HOST       Host header sent to LancarSec     (default $HOST)
  -i IP         Cf-Connecting-Ip header value     (default $CLIENT_IP)
  -d SECONDS    attack duration in seconds        (default $DURATION)
  -c N          concurrent workers / connections  (default $CONNS)
  -r RATE       requests/sec, 0 = unthrottled     (default $RATE)
  -p PID        LancarSec process id to sample    (default: auto-detect)
  -n NAME       process name for auto-detect      (default $PROC_NAME)
  -g GENERATOR  force 'vegeta' or 'hey'           (default: auto-detect)
  -o DIR        output directory                  (default $OUTDIR)
  -R            do not measure RSS (skip the peak-memory column)
  -h            this help

On Windows, -p must be a Windows PID (the one tasklist prints), not the MSYS
job id that Git Bash reports for a background job.
EOF
}

while [ $# -gt 0 ]; do
	case $1 in
	-u) URL=${2:?-u needs a value}; shift 2 ;;
	-H) HOST=${2:?-H needs a value}; shift 2 ;;
	-i) CLIENT_IP=${2:?-i needs a value}; shift 2 ;;
	-d) DURATION=${2:?-d needs a value}; shift 2 ;;
	-c) CONNS=${2:?-c needs a value}; shift 2 ;;
	-r) RATE=${2:?-r needs a value}; shift 2 ;;
	-p) PROC_PID=${2:?-p needs a value}; shift 2 ;;
	-n) PROC_NAME=${2:?-n needs a value}; shift 2 ;;
	-g) GENERATOR=${2:?-g needs a value}; shift 2 ;;
	-o) OUTDIR=${2:?-o needs a value}; shift 2 ;;
	-R) MEASURE_RSS=0; shift ;;
	-h) usage; exit 0 ;;
	*) printf '%s: unknown option: %s\n\n' "$PROG" "$1" >&2; usage >&2; exit 2 ;;
	esac
done

# ----------------------------------------------------------------- helpers ---

die() {
	printf '%s: error: %s\n' "$PROG" "$*" >&2
	exit 1
}

note() {
	printf '%s: %s\n' "$PROG" "$*" >&2
}

need() {
	command -v "$1" >/dev/null 2>&1 || die "required command not found: $1"
}

case "$(uname -s 2>/dev/null || echo unknown)" in
MINGW* | MSYS* | CYGWIN*) OS_KIND=windows ;;
*) OS_KIND=unix ;;
esac

PS_EXE=""
if [ "$OS_KIND" = windows ]; then
	if command -v powershell >/dev/null 2>&1; then
		PS_EXE=powershell
	elif command -v pwsh >/dev/null 2>&1; then
		PS_EXE=pwsh
	fi
fi

# rss_kb PID -- prints resident set size in KiB, or nothing if unavailable.
rss_kb() {
	_pid=$1
	if [ "$OS_KIND" = windows ]; then
		if [ -n "$PS_EXE" ]; then
			"$PS_EXE" -NoProfile -NonInteractive -Command \
				"\$p = Get-Process -Id $_pid -ErrorAction SilentlyContinue; if (\$p) { [int](\$p.WorkingSet64 / 1024) }" \
				2>/dev/null | tr -d '\r\n '
		else
			# "lancarsec.exe","1234","Console","1","17,272 K"
			tasklist //FI "PID eq $_pid" //NH //FO CSV 2>/dev/null |
				sed -n 's/.*,"\([0-9.,][0-9.,]*\) K"[[:space:]]*$/\1/p' |
				tr -d '.,' | head -1
		fi
	elif [ -r "/proc/$_pid/status" ]; then
		awk '/^VmRSS:/ { print $2; exit }' "/proc/$_pid/status"
	else
		ps -o rss= -p "$_pid" 2>/dev/null | tr -d ' '
	fi
}

# detect_pid NAME -- best-effort process id lookup.
detect_pid() {
	_name=$1
	if [ "$OS_KIND" = windows ]; then
		tasklist //FI "IMAGENAME eq ${_name}.exe" //NH //FO CSV 2>/dev/null |
			sed -n 's/^"[^"]*","\([0-9][0-9]*\)".*/\1/p' | head -1
	elif command -v pgrep >/dev/null 2>&1; then
		pgrep -x "$_name" 2>/dev/null | head -1
	fi
}

# --------------------------------------------------------------- preflight ---

need curl
need awk
need sed

case $DURATION in
'' | *[!0-9]*) die "-d must be a whole number of seconds, got '$DURATION'" ;;
esac
[ "$DURATION" -gt 0 ] || die "-d must be greater than zero"
case $CONNS in
'' | *[!0-9]*) die "-c must be a whole number, got '$CONNS'" ;;
esac
[ "$CONNS" -gt 0 ] || die "-c must be greater than zero"
case $RATE in
'' | *[!0-9]*) die "-r must be a whole number, got '$RATE'" ;;
esac

if [ -z "$GENERATOR" ]; then
	if command -v vegeta >/dev/null 2>&1; then
		GENERATOR=vegeta
	elif command -v hey >/dev/null 2>&1; then
		GENERATOR=hey
	else
		cat >&2 <<'EOF'
loadtest.sh: error: no load generator found. Install one of:

  vegeta (preferred -- exact rate control and real percentiles):
      go install github.com/tsenart/vegeta/v12@latest
      brew install vegeta
      # or a release binary from https://github.com/tsenart/vegeta/releases

  hey:
      go install github.com/rakyll/hey@latest
      brew install hey

Then re-run. Both must be on PATH; on Windows make sure %USERPROFILE%\go\bin
is on PATH so Git Bash can see them.
EOF
		exit 1
	fi
fi
command -v "$GENERATOR" >/dev/null 2>&1 || die "requested generator '$GENERATOR' is not on PATH"

mkdir -p "$OUTDIR"
STAMP=$(date +%Y%m%d-%H%M%S)
RUNDIR=$OUTDIR/loadtest-$STAMP
mkdir -p "$RUNDIR"

note "target      $URL (Host: $HOST)"
note "generator   $GENERATOR"
note "duration    ${DURATION}s, workers $CONNS, rate $RATE"
note "output      $RUNDIR"

# One real request before we commit to a full run. A harness that spends 30
# seconds hammering a 404 and then reports a beautiful throughput number is
# worse than no harness at all.
PRE_CODE=$(curl -s -o "$RUNDIR/preflight.body" -w '%{http_code}' --max-time 10 \
	-H "Host: $HOST" -H "Cf-Connecting-Ip: $CLIENT_IP" "$URL") ||
	die "preflight request to $URL failed -- is LancarSec running and listening on :80?"

case $PRE_CODE in
200) : ;;
302)
	die "preflight got HTTP 302: LancarSec is challenging this path (stage 1
       cookie redirect) instead of proxying it. Throughput measured here would
       be the challenge path, not the proxy path. Point -u at a path whitelisted
       by a firewall rule with action \"0\" -- hack/config.test.json ships one
       for /bench."
	;;
404)
	die "preflight got HTTP 404: LancarSec has no domain configured for
       Host: $HOST. Check the 'name' field in the config the proxy loaded."
	;;
*) die "preflight got HTTP $PRE_CODE, expected 200. Body saved to $RUNDIR/preflight.body" ;;
esac

if ! grep -q 'X-Stub-Origin\|lancarsec-stub-origin' "$RUNDIR/preflight.body" 2>/dev/null; then
	note "warning: response body does not look like hack/stuborigin output;"
	note "         the number below may be describing your real backend."
fi

# ------------------------------------------------------------- rss sampler ---

RSS_FILE=$RUNDIR/rss.txt
STOPFLAG=$RUNDIR/.sampling
SAMPLER_PID=""

if [ "$MEASURE_RSS" -eq 1 ]; then
	if [ -z "$PROC_PID" ]; then
		PROC_PID=$(detect_pid "$PROC_NAME" || true)
	fi
	[ -n "$PROC_PID" ] ||
		die "could not find the LancarSec process. Pass -p PID, or -R to skip
       the memory measurement."
	FIRST=$(rss_kb "$PROC_PID")
	[ -n "$FIRST" ] ||
		die "could not read RSS for pid $PROC_PID. Pass -R to skip the memory
       measurement, or check that the pid is a live process."
	note "sampling RSS of pid $PROC_PID every ${SAMPLE_INTERVAL}s (start ${FIRST} KiB)"
fi

start_sampler() {
	[ "$MEASURE_RSS" -eq 1 ] || return 0
	: >"$RSS_FILE"
	: >"$STOPFLAG"
	(
		_t0=$(date +%s)
		while [ -e "$STOPFLAG" ]; do
			_kb=$(rss_kb "$PROC_PID")
			if [ -n "$_kb" ]; then
				printf '%s %s\n' "$(($(date +%s) - _t0))" "$_kb" >>"$RSS_FILE"
			fi
			sleep "$SAMPLE_INTERVAL"
		done
	) &
	SAMPLER_PID=$!
}

stop_sampler() {
	[ -n "$SAMPLER_PID" ] || return 0
	rm -f "$STOPFLAG"
	wait "$SAMPLER_PID" 2>/dev/null || true
	SAMPLER_PID=""
}

cleanup() {
	rm -f "$STOPFLAG" 2>/dev/null || true
	if [ -n "$SAMPLER_PID" ]; then
		kill "$SAMPLER_PID" 2>/dev/null || true
	fi
}
trap cleanup EXIT INT TERM

# ------------------------------------------------------------------ attack ---

REPORT=$RUNDIR/report.txt
start_sampler

case $GENERATOR in
vegeta)
	TARGETS=$RUNDIR/target.txt
	{
		printf 'GET %s\n' "$URL"
		printf 'Host: %s\n' "$HOST"
		printf 'Cf-Connecting-Ip: %s\n' "$CLIENT_IP"
	} >"$TARGETS"

	vegeta attack \
		-targets="$TARGETS" \
		-duration="${DURATION}s" \
		-rate="$RATE" \
		-max-workers="$CONNS" \
		-timeout=10s \
		-keepalive \
		-output="$RUNDIR/results.bin" ||
		die "vegeta attack failed"

	vegeta report -type=text "$RUNDIR/results.bin" >"$REPORT" ||
		die "vegeta report failed"
	;;
hey)
	# hey silently ignores a Host header passed via -H; the Host header must go
	# through the dedicated -host flag or every request 404s at the proxy.
	if [ "$RATE" -gt 0 ]; then
		HEY_Q=$((RATE / CONNS))
		[ "$HEY_Q" -gt 0 ] || HEY_Q=1
		hey -z "${DURATION}s" -c "$CONNS" -q "$HEY_Q" \
			-host "$HOST" -H "Cf-Connecting-Ip: $CLIENT_IP" \
			"$URL" >"$REPORT" 2>&1 || die "hey failed (see $REPORT)"
	else
		hey -z "${DURATION}s" -c "$CONNS" \
			-host "$HOST" -H "Cf-Connecting-Ip: $CLIENT_IP" \
			"$URL" >"$REPORT" 2>&1 || die "hey failed (see $REPORT)"
	fi
	;;
*) die "unsupported generator: $GENERATOR" ;;
esac

stop_sampler

# ------------------------------------------------------------------ report ---

# vegeta's report lines carry their own column headers, and the set of
# percentiles has changed between vegeta releases. Rather than assume a fixed
# column, find "99" in the bracketed header and take the value at that index.
parse_vegeta() {
	awk -v want="$2" -v field="$3" '
		index($0, want) == 1 {
			head = $0; sub(/^[^[]*\[/, "", head); sub(/\].*$/, "", head)
			vals = $0; sub(/^[^]]*\][ \t]*/, "", vals)
			nh = split(head, H, /[ ,]+/)
			nv = split(vals, V, /[ ,]+/)
			for (i = 1; i <= nh && i <= nv; i++) {
				if (H[i] == field) { print V[i]; exit }
			}
		}
	' "$1"
}

RPS=""
P99=""
SUCCESS=""

case $GENERATOR in
vegeta)
	RPS=$(parse_vegeta "$REPORT" "Requests" "rate")
	P99=$(parse_vegeta "$REPORT" "Latencies" "99")
	SUCCESS=$(awk '/^Success/ { print $NF; exit }' "$REPORT")
	;;
hey)
	RPS=$(awk '/Requests\/sec:/ { print $2; exit }' "$REPORT")
	# hey's own report template prints "99%%" (a literal double percent); match
	# either form so we survive a future hey that fixes it.
	P99=$(awk '/[ \t]99%%? in/ { print $3 "s"; exit }' "$REPORT")
	SUCCESS=$(awk '/\[200\]/ { print $2; exit }' "$REPORT")
	;;
esac

[ -n "$RPS" ] || die "could not parse a request rate out of $REPORT"
[ -n "$P99" ] || die "could not parse a p99 latency out of $REPORT"

RSS_START=NA
RSS_PEAK=NA
RSS_END=NA
if [ "$MEASURE_RSS" -eq 1 ] && [ -s "$RSS_FILE" ]; then
	RSS_START=$(awk 'NR==1 { print $2; exit }' "$RSS_FILE")
	RSS_END=$(awk '{ last = $2 } END { print last }' "$RSS_FILE")
	RSS_PEAK=$(awk 'BEGIN { m = 0 } { if ($2 > m) m = $2 } END { print m }' "$RSS_FILE")
elif [ "$MEASURE_RSS" -eq 1 ]; then
	note "warning: no RSS samples were collected (process gone? sampler blocked?)"
fi

CSV=$OUTDIR/loadtest.csv
if [ ! -f "$CSV" ]; then
	echo "timestamp,generator,url,host,duration_s,workers,rate,req_per_s,p99,success,rss_start_kib,rss_peak_kib,rss_end_kib" >"$CSV"
fi
printf '%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s\n' \
	"$STAMP" "$GENERATOR" "$URL" "$HOST" "$DURATION" "$CONNS" "$RATE" \
	"$RPS" "$P99" "${SUCCESS:-NA}" "$RSS_START" "$RSS_PEAK" "$RSS_END" >>"$CSV"

cat <<EOF

=============================== loadtest.sh ===============================
 generator        $GENERATOR
 target           $URL   (Host: $HOST)
 duration         ${DURATION}s   workers $CONNS   rate ${RATE:-0}
---------------------------------------------------------------------------
 throughput       $RPS req/s
 p99 latency      $P99
 success          ${SUCCESS:-unknown}
 RSS start        $RSS_START KiB
 RSS peak         $RSS_PEAK KiB
 RSS end          $RSS_END KiB
---------------------------------------------------------------------------
 full report      $REPORT
 rss samples      $RSS_FILE
 appended to      $CSV
===========================================================================
EOF
