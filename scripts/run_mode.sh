#!/bin/bash
# The terminal-bound modes of run.sh -- analyze, debug, run, boot -- unchanged
# apart from taking their inputs as arguments (they used to be variables of the
# enclosing script). Called by firmae/pipeline.py after the emulation is ready;
# it stays shell because these modes are interactive (debug.py, telnet) and run
# in the user's terminal process group, so Ctrl-C reaches them as before.
#
# usage: run_mode.sh <mode> <IID> <ARCH> <BRAND> <IP> <WEB_RESULT> <PING_RESULT> <PSQL_IP>

set -e
set -u

if [ $# -ne 8 ]; then
    echo "usage: $0 <mode> <IID> <ARCH> <BRAND> <IP> <WEB_RESULT> <PING_RESULT> <PSQL_IP>"
    exit 2
fi
OPTION=${1}
IID=${2}
ARCH=${3}
BRAND=${4}
IP=${5}
WEB_RESULT=${6}
PING_RESULT=${7}
PSQL_IP=${8}

if [ -e ./firmae.config ]; then
    source ./firmae.config
else
    echo "Error: Could not find 'firmae.config'!"
    exit 1
fi

WORK_DIR=`get_scratch "${IID}"`

# DHCP / user-network images (makeNetwork.py wrote "true" to isDhcp, the same
# test as check_emulation.sh): the guest is reachable only through the
# loopback ports recorded in ${WORK_DIR}/hostfwd, and "ip" is 127.0.0.1 --
# the HOST. Tools that take that address as their target (check_network,
# analyses_all.sh, debug.py) would probe and attack the host's own services,
# as root. Exit codes as in firmae/errors.py (ExitCode).
EXIT_UNREACHABLE=50
EXIT_ANALYSIS=60
USER_NET=false
if grep -sq true "${WORK_DIR}/isDhcp"; then
    USER_NET=true
fi

# background helpers must not outlive us (SIGTERM from the pipeline, Ctrl-C)
trap 'kill $(jobs -p) 2>/dev/null || true' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP

# Values are quoted throughout: BRAND and IP may be empty, and an unquoted empty
# argument disappears (check_network then got no IP, analyses_all.sh shifted
# arguments). The results are compared, not executed: `($WEB_RESULT)` with an
# empty value ran an empty subshell, i.e. counted as true.
if [ "${OPTION}" = "analyze" ]; then
    # ================================
    # analyze firmware (check vulnerability)
    # ================================
    if ${USER_NET}; then
        echo -e "[\033[31m-\033[0m] Analysis is not supported for DHCP/user-network images:" \
                "the tools would target 127.0.0.1, i.e. the host's own services (the guest is" \
                "reachable only through the ports in ${WORK_DIR}/hostfwd)" >&2
        exit ${EXIT_ANALYSIS}
    fi
    if [ "${WEB_RESULT}" = true ]; then
        echo "[*] Waiting web service..."
        "${WORK_DIR}/run_analyze.sh" &
        EMU_PID=$!
        IP=`cat "${WORK_DIR}/ip"`
        check_network "${IP}" false

        echo -e "[\033[32m+\033[0m] start pentest!"
        cd analyses
        ./analyses_all.sh "${IID}" "${BRAND}" "${IP}" "${PSQL_IP}"
        cd -

        sync
        # only this image's QEMU; then let run_analyze.sh tear its network down
        stop_qemu "${IID}"
        wait_for_exit "${EMU_PID}" 30
    else
        echo -e "[\033[31m-\033[0m] Web unreachable"
    fi

elif [ "${OPTION}" = "debug" ]; then
    # ================================
    # run debug mode.
    # ================================
    if ${USER_NET}; then
        # PING_RESULT means "web answered through the forward" for these
        # images; "Network unreachable" would be the wrong reason
        echo -e "[\033[31m-\033[0m] Debug mode is not supported for DHCP/user-network images:" \
                "QEMU's user network does not forward the debug shell ports (31337-31339) or" \
                "gdbserver, and their address 127.0.0.1 is the host. Use 'run' mode instead." >&2
        exit ${EXIT_UNREACHABLE}
    fi
    if [ "${PING_RESULT}" = true ]; then
        echo -e "[\033[32m+\033[0m] Run debug!"
        while [ ! -f "./scratch/${IID}/run_debug.sh" ];
        do
            echo "Wait until emulation was finished"
            sleep 30
        done
        IP=`cat "${WORK_DIR}/ip"`
        "./scratch/${IID}/run_debug.sh" &
        EMU_PID=$!
        check_network "${IP}" true

        sleep 10
        ./debug.py "${IID}"

        sync
        stop_qemu "${IID}"
        wait_for_exit "${EMU_PID}" 30
    else
        echo -e "[\033[31m-\033[0m] Network unreachable"
    fi
elif [ "${OPTION}" = "run" ]; then
    # ================================
    # just run mode
    # ================================
    if ${USER_NET}; then
        # only the forwarded loopback ports of this image's QEMU, never the
        # host's own 127.0.0.1:80 (scripts/hostfwd_check.sh)
        (
            if ! source "$(dirname "${BASH_SOURCE[0]}")/hostfwd_check.sh"; then
                echo "[!] scripts/hostfwd_check.sh not found: no web check"
            elif read_hostfwd "${WORK_DIR}/hostfwd"; then
                check_hostfwd "${IID}" "${HOSTFWD_HTTP}" "${HOSTFWD_HTTPS}"
            else
                echo "[!] ${WORK_DIR}/hostfwd is missing or invalid: no web check"
            fi
        ) &
    else
        # IP is empty when the network was not reachable: check_network returns at once
        check_network "${IP}" false &
    fi
    "${WORK_DIR}/run.sh"
elif [ "${OPTION}" = "boot" ]; then
    # ================================
    # boot debug mode
    # ================================
    BOOT_KERNEL_PATH=`get_boot_kernel "${ARCH}" true`
    BOOT_KERNEL=./binaries/`basename "${BOOT_KERNEL_PATH}"`
    echo -e "[\033[32m+\033[0m] Connect with gdb-multiarch -q ${BOOT_KERNEL} -ex='target remote:1234'"
    "${WORK_DIR}/run_boot.sh"
fi
