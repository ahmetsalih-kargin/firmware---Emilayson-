#!/bin/bash

if [ $# -ne 4 ]; then
    echo "$0: Usage: ./analyses_all.sh [iid] [brand] [target address] [sql ip]"
    exit 1
fi

set -e
set -u

if [ -e ./firmae.config ]; then
    source ./firmae.config
elif [ -e ../firmae.config ]; then
    source ../firmae.config
else
    echo "Error: Could not find 'firmae.config'!"
    exit 1
fi

IID="${1}"
BRAND="${2}"
TARGET="${3}"
PSQL_IP="${4}"
WORK_DIR="$(get_scratch "${IID}")"
LOG_DIR="${WORK_DIR}/analysis_log"
EXPLOIT_DIR="$LOG_DIR/exploits"

mkdir -p "$LOG_DIR"
mkdir -p "$EXPLOIT_DIR"

# One "<step> <exit code>" line per step, so a failed step can be told apart
# (the `result` file below is written unconditionally).
: > "$LOG_DIR/steps"
record_step() {
    echo "$1 $2" >> "$LOG_DIR/steps"
    if [ "$2" -ne 0 ]; then
        echo "[!] step '$1' exited with status $2"
    fi
}

sleep 10

echo '[*] FirmAE web server initializer'
echo "${BRAND}, ${TARGET}, ${IID}"
rc=0
if [ -n "${FIRMAE_BROWSER_USER:-}" ]; then
    # headless Chrome as an unprivileged user, sandbox on (SECURITY.md S11; browser_user.sh)
    source "$(dirname -- "$0")/browser_user.sh"
    trap browser_cleanup EXIT
    if browser_prepare "$FIRMAE_BROWSER_USER"; then
        browser_userns_warning
        { time browser_as ./initializer.py "$BRAND" "$TARGET" > "$LOG_DIR/initializer_log" 2>&1 ; } 2> "$LOG_DIR/initializer_time" || rc=$?
    else
        rc=$?
    fi
    browser_cleanup
else
    { time ./initializer.py "$BRAND" "$TARGET" > "$LOG_DIR/initializer_log" 2>&1 ; } 2> "$LOG_DIR/initializer_time" || rc=$?
fi
record_step initializer "$rc"
rc=0
{ time ./nmap.sh "$IID" "$TARGET" > "$LOG_DIR/nmap_log" 2>&1 ; } 2> "$LOG_DIR/nmap_time" || rc=$?
record_step nmap "$rc"

echo '[*] fuzzer'
rc=0
{ time ./fuzzer/fuzzer.py ci "$BRAND" "$IID" "$TARGET" "$WORK_DIR" "$LOG_DIR" > "$LOG_DIR/fuzzer_log_ci" ; } 2> "$LOG_DIR/fuzzer_ci_time" || rc=$?
record_step fuzzer_ci "$rc"
rc=0
{ time ./fuzzer/fuzzer.py bof "$BRAND" "$IID" "$TARGET" "$WORK_DIR" "$LOG_DIR" > "$LOG_DIR/fuzzer_log_bof" ; } 2> "$LOG_DIR/fuzzer_bof_time" || rc=$?
record_step fuzzer_bof "$rc"

# TODO: re-run web server after fuzzer.
echo '[*] rsf'
if [ -f routersploit/rsf.py ]; then
    rc=0
    # subshell: a failing cd/rsf must not stop the script or change its directory
    (cd routersploit && timeout --preserve-status --signal SIGINT 600 ./rsf.py "$TARGET" > "$LOG_DIR/rsf" 2>&1) || rc=$?
else
    echo "[!] routersploit/rsf.py not found (empty git submodule?), skipping rsf"
    echo "routersploit/rsf.py not found, rsf skipped" > "$LOG_DIR/rsf"
    rc=127
fi
record_step rsf "$rc"
echo '[*] analyzer finished'
echo true > "${LOG_DIR}/result"
