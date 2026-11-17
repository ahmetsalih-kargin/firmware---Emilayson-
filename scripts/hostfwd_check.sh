#!/bin/bash
# Web check of a user-network (DHCP mode) emulation, used by
# scripts/run_mode.sh. Source it after firmae.config (needs qemu_pids,
# CHECK_TIMEOUT). firmae/hostfwd.py is its Python twin, used by check_emulation
# (via firmae/check.py); equivalence is pinned by tests/unit/test_check_py.py.
#
# QEMU forwards the guest's ports to loopback ports that makeNetwork.py chose
# and recorded in scratch/<IID>/hostfwd, one "<tcp|udp> <guest port> <host
# port>" per line. Those host ports are not reserved: another program (another
# image's QEMU, any local server) can hold one, in which case run.sh refuses to
# start QEMU -- and a plain `curl 127.0.0.1:<port>` would then report that
# other program as this firmware's web UI. So an answer counts only while this
# image's QEMU runs and if the listening socket belongs to it.

# Same range as HOSTFWD_PORT_MIN/MAX in scripts/makeNetwork.py; host ports
# outside it are refused.
HOSTFWD_PORT_MIN=10000
HOSTFWD_PORT_MAX=19999
HOSTFWD_MAX_BYTES=4096
HOSTFWD_MAX_LINES=64

# read_hostfwd <file>: set HOSTFWD_HTTP / HOSTFWD_HTTPS to the host ports of
# guest tcp/80 and tcp/443. Any malformed, out-of-range or duplicate line,
# a symlink, a non-regular or oversized file rejects the whole file (return 1,
# both empty): the check then probes nothing and reports web=false.
read_hostfwd () {
    local FILE=${1} CONTENT LINE N=0 PROTO GUEST HOST
    HOSTFWD_HTTP=""
    HOSTFWD_HTTPS=""
    if [ -L "${FILE}" ] || [ ! -f "${FILE}" ]; then
        return 1
    fi
    CONTENT=`head -c $((HOSTFWD_MAX_BYTES + 1)) -- "${FILE}" 2>/dev/null | tr -d '\000'` || return 1
    if [ ${#CONTENT} -gt ${HOSTFWD_MAX_BYTES} ]; then
        return 1
    fi
    while IFS= read -r LINE; do
        N=$((N + 1))
        if [ ${N} -gt ${HOSTFWD_MAX_LINES} ] || ! [[ "${LINE}" =~ ^(tcp|udp)\ ([0-9]{1,5})\ ([0-9]{1,5})$ ]]; then
            HOSTFWD_HTTP=""; HOSTFWD_HTTPS=""
            return 1
        fi
        PROTO=${BASH_REMATCH[1]}
        GUEST=$((10#${BASH_REMATCH[2]}))
        HOST=$((10#${BASH_REMATCH[3]}))
        if [ ${GUEST} -lt 1 ] || [ ${GUEST} -gt 65535 ] \
           || [ ${HOST} -lt ${HOSTFWD_PORT_MIN} ] || [ ${HOST} -gt ${HOSTFWD_PORT_MAX} ]; then
            HOSTFWD_HTTP=""; HOSTFWD_HTTPS=""
            return 1
        fi
        [ "${PROTO}" = tcp ] || continue
        if [ ${GUEST} -eq 80 ]; then
            [ -z "${HOSTFWD_HTTP}" ] || { HOSTFWD_HTTP=""; HOSTFWD_HTTPS=""; return 1; }
            HOSTFWD_HTTP=${HOST}
        elif [ ${GUEST} -eq 443 ]; then
            [ -z "${HOSTFWD_HTTPS}" ] || { HOSTFWD_HTTP=""; HOSTFWD_HTTPS=""; return 1; }
            HOSTFWD_HTTPS=${HOST}
        fi
    done <<< "${CONTENT}"
    return 0
}

# pid_running <PID>: the process exists and is not a zombie (an exited child
# that nobody has waited for yet still answers `kill -0`).
pid_running () {
    local STAT
    [[ "${1}" =~ ^[0-9]+$ ]] || return 1
    STAT=`cat "/proc/${1}/stat" 2>/dev/null` || return 1
    STAT=${STAT##*) }
    [ -n "${STAT}" ] && [[ "${STAT:0:1}" != [ZX] ]]
}

# hostfwd_emulation_state <IID> [<run.sh PID>]: "running" (this image's QEMU
# runs), "starting" (not yet, but run.sh -- or, without a PID, possibly a
# run.sh started next to us -- is still there) or "dead" (run.sh is gone and
# no QEMU of this image runs: e.g. its pre-check found a host port taken).
hostfwd_emulation_state () {
    if [ -n "`qemu_pids "${1}"`" ]; then
        echo running
    elif [ -z "${2:-}" ] || pid_running "${2}"; then
        echo starting
    else
        echo dead
    fi
}

# hostfwd_owned_by_qemu <IID> <host port>: every TCP listener on <port> belongs
# to a QEMU process of this image (`ss -p`; root sees every owner). No ss, no
# listener or an owner we cannot see counts as "not ours": we would rather
# report web=false for a real emulation than web=true for another program.
hostfwd_owned_by_qemu () {
    local IID=${1} PORT=${2} OUT QEMU PIDS PID LINE
    if ! command -v ss > /dev/null 2>&1; then
        echo "[!] hostfwd: 'ss' not found; cannot tell who listens on 127.0.0.1:${PORT} (web=false)" >&2
        return 1
    fi
    OUT=`ss -Htlnp "sport = :${PORT}" 2>/dev/null` || OUT=""
    if [ -z "${OUT}" ]; then
        echo "[!] hostfwd: no listener found on port ${PORT} (web=false)" >&2
        return 1
    fi
    QEMU=" `qemu_pids "${IID}" | tr '\n' ' '`"
    while IFS= read -r LINE; do
        PIDS=`grep -o 'pid=[0-9]*' <<< "${LINE}" | cut -d= -f2 || true`
        if [ -z "${PIDS}" ]; then
            echo "[!] hostfwd: owner of port ${PORT} unknown (web=false)" >&2
            return 1
        fi
        for PID in ${PIDS}; do
            if [[ "${QEMU}" != *" ${PID} "* ]]; then
                echo "[!] hostfwd: port ${PORT} belongs to PID ${PID}, not to the QEMU of image ${IID} (web=false)" >&2
                return 1
            fi
        done
    done <<< "${OUT}"
    return 0
}

# check_hostfwd <IID> <http host port|""> <https host port|""> [<run.sh PID>]:
# like check_network (same CHECK_TIMEOUT, same output "<IP|None> <ping> <web>
# <ping time> <web time>"), but probes only http://127.0.0.1:<port> and
# https://127.0.0.1:<port> of the forwarded guest ports -- never the host's own
# port 80/443 -- and never pings: ICMP is not forwarded by the user network,
# and pinging 127.0.0.1 only shows that the host is up. "ping" is reported
# true exactly when the guest answered through the forward (the only proof
# that its network is reachable from the host), with the web time as its time.
# Probes only while this image's QEMU runs, stops at once when the emulation
# is gone, and accepts an answer only from a port that QEMU listens on.
# Diagnostics go to stderr; stdout carries the result line only.
check_hostfwd () {
    local IID=${1} HTTP=${2} HTTPS=${3} RUN_PID=${4:-} START_TIME CURRENT_TIME t_start t_end
    local WEB=false WTIME=-1 STATE PORT
    if [ -z "${HTTP}" ] && [ -z "${HTTPS}" ]; then
        echo "None false false -1 -1"
        return 0
    fi
    sleep 10
    START_TIME=$(date +%s | bc)
    CURRENT_TIME=${START_TIME}
    t_start=$(date +%s.%N)
    while [ ${CURRENT_TIME} -le $((START_TIME + CHECK_TIMEOUT)) ]; do
        STATE=`hostfwd_emulation_state "${IID}" "${RUN_PID}"`
        if [ "${STATE}" = dead ]; then
            echo "[!] hostfwd: the emulation of image ${IID} is not running (run.sh ended, no QEMU); web=false" >&2
            break
        fi
        PORT=""
        if [ "${STATE}" = running ]; then
            if [ -n "${HTTP}" ] && curl --noproxy '*' --max-time 2 --output /dev/null --silent "http://127.0.0.1:${HTTP}"; then
                PORT=${HTTP}
            elif [ -n "${HTTPS}" ] && curl --noproxy '*' --max-time 2 --output /dev/null --silent "https://127.0.0.1:${HTTPS}"; then
                PORT=${HTTPS}
            fi
        fi
        if [ -n "${PORT}" ]; then
            t_end=$(date +%s.%N)
            # the answer counts only if it came from this image's QEMU
            if hostfwd_owned_by_qemu "${IID}" "${PORT}"; then
                WTIME=$(echo "$t_end - $t_start" | bc)
                WEB=true
            fi
            break
        fi
        sleep 1
        CURRENT_TIME=$(date +%s | bc)
    done
    if ${WEB}; then
        echo "127.0.0.1 true true ${WTIME} ${WTIME}"
    else
        echo "None false false -1 -1"
    fi
}

# is_user_network <work dir>: the image runs in DHCP / user-network mode
# (makeNetwork.py wrote "true" to isDhcp; same test as check_emulation.sh).
is_user_network () {
    grep -sq true "${1}/isDhcp"
}
