#!/bin/bash
#
# The final emulation of one image: what scratch/<IID>/run.sh does (and its
# links run_debug.sh, run_analyze.sh, run_boot.sh).
#
#     emulate.sh <run.sh as invoked> <IID> <FirmAE root: . | .. | ../..>
#
# Started only by the run.sh wrapper that scripts/makeNetwork.py writes. It
# passes its own $0 unresolved (the mode is its basename: "debug", "analyze"
# and "boot" anywhere in it, as before), the image ID and the directory in
# which it found firmae.config. The wrapper execs this script, so the PID that
# check_emulation.sh / run_mode.sh started stays the PID of the emulation.
#
# This is the former run.sh template, unchanged in what it runs. Everything
# that depends on the image -- architecture, init, network type, TAP devices
# and VLANs, the QEMU NICs, the user-network port forwards -- comes from
# scratch/<IID>/emulation.conf (format: EMULATION_FILE in makeNetwork.py).
# Those values derive from the guest's serial log and this script runs as
# root, so the file is never sourced or eval'd: every line must match a fixed
# record grammar built from explicit character lists (no locale-dependent
# ranges or classes), numbers are compared only after they matched digits,
# and every value is expanded quoted. A file that does not parse stops the
# emulation before anything is touched.

set -e
set -u

if [ $# -ne 3 ]; then
    echo "Usage: emulate.sh <run.sh path> <IID> <FirmAE root>  (started by scratch/<IID>/run.sh)" >&2
    exit 1
fi
INVOKED=${1}
IID=${2}
FIRMAE_ROOT=${3}

EMU_D='0123456789'
EMU_NZ='123456789'
EMU_AN="${EMU_D}ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
EMU_NUM="(0|[${EMU_NZ}][${EMU_D}]{0,9})"

if ! [[ "${IID}" =~ ^${EMU_NUM}$ ]] || [ "${IID}" -gt 2147483647 ]; then
    echo "Error: invalid image ID '${IID}'" >&2
    exit 1
fi
case "${FIRMAE_ROOT}" in
    .|..|../..) ;;
    *) echo "Error: invalid FirmAE root '${FIRMAE_ROOT}'" >&2; exit 1;;
esac
# the same file the old script sourced (./firmae.config, ../firmae.config or
# ../../firmae.config, relative to the current directory)
source "${FIRMAE_ROOT}/firmae.config"

RUN_MODE=`basename "${INVOKED}"`
WORK_DIR=`get_scratch ${IID}`

# ---------------------------------------------------------------------------
# scratch/<IID>/emulation.conf
# ---------------------------------------------------------------------------

EMU_FILE=${WORK_DIR}/emulation.conf
EMU_MAX_LINE=4096       # EMULATION_MAX_LINE in makeNetwork.py
EMU_MAX_LINES=256       # EMULATION_MAX_LINES
EMU_IFNAME="[${EMU_AN}][${EMU_AN}_.:-]{0,14}"
EMU_RE_LINE="^([ABCDEFGHIJKLMNOPQRSTUVWXYZ_]{1,32})=(.*)\$"
EMU_RE_IFNAME_OR_EMPTY="^(${EMU_IFNAME})?\$"
EMU_RE_INIT="^(rd)?init=/[${EMU_AN}_./-]+\$"
EMU_RE_NET="^([${EMU_D}.]{7,15}) ([${EMU_D}.]{7,15}) (-|${EMU_NUM})\$"
EMU_RE_NIC_NUM="^(tap|socket) ${EMU_NUM}\$"
EMU_RE_HOSTFWD="^(tcp|udp) ${EMU_NUM} ${EMU_NUM}\$"
EMU_RE_IPV4="^([${EMU_D}]{1,3})\\.([${EMU_D}]{1,3})\\.([${EMU_D}]{1,3})\\.([${EMU_D}]{1,3})\$"
EMU_RE_OCTET="^(0|[${EMU_NZ}][${EMU_D}]{0,2})\$"

emu_die () {
    echo "Error: ${EMU_FILE}: ${1}; not starting the emulation (re-run makeNetwork.py)" >&2
    exit 1
}

# emu_ipv4 <value>: dotted quad, every octet 0..255 without leading zeros
emu_ipv4 () {
    local o
    [[ "${1}" =~ ${EMU_RE_IPV4} ]] || return 1
    for o in "${BASH_REMATCH[@]:1:4}"; do
        [[ "${o}" =~ ${EMU_RE_OCTET} ]] || return 1
        [ "${o}" -le 255 ] || return 1
    done
    return 0
}

# emu_guest_ipv4 <value>: emu_ipv4, and an address the host may put on a TAP
# device, route and probe -- isGuestIpv4 in makeNetwork.py, usable_guest_ip in
# firmae/check.py: not 0.0.0.0/8, loopback 127/8, link-local 169.254/16,
# multicast 224/4, reserved 240/4 or the broadcast 255.255.255.255
emu_guest_ipv4 () {
    local o1 o2
    emu_ipv4 "${1}" || return 1
    # again: emu_ipv4's octet checks overwrote BASH_REMATCH (no leading zeros
    # any more, so the octets compare as decimal numbers)
    [[ "${1}" =~ ${EMU_RE_IPV4} ]] || return 1
    o1=${BASH_REMATCH[1]}; o2=${BASH_REMATCH[2]}
    [ "${o1}" -ne 0 ] && [ "${o1}" -ne 127 ] && [ "${o1}" -lt 224 ] || return 1
    [ "${o1}" -ne 169 ] || [ "${o2}" -ne 254 ] || return 1
    return 0
}

EMU_SEEN=" "
EMU_FORMAT=""
EMU_ARCH=""
EMU_ENDIAN=""
NETWORK_TYPE=""
NET_BRIDGE=""
NET_INTERFACE=""
QEMU_INIT=""
GEN_FIRMAE_NET=""
NET_HOSTIP=()
NET_GUESTIP=()
NET_VLAN=()
NIC_KIND=()
NIC_ARG=()
HOSTFWD_PROTO=()
HOSTFWD_GUEST=()
HOSTFWD_HOST=()

emu_record () {        # emu_record <line number> <key> <value>
    local n=${1} key=${2} value=${3} a b c
    case "${key}" in
        FORMAT|IID|ARCH|ENDIAN|NETWORK_TYPE|NET_BRIDGE|NET_INTERFACE|QEMU_INIT|GEN_FIRMAE_NET)
            case "${EMU_SEEN}" in *" ${key} "*) emu_die "${key} given twice";; esac
            EMU_SEEN="${EMU_SEEN}${key} ";;
    esac
    case "${key}" in
        FORMAT)
            [ "${value}" = 1 ] || emu_die "unknown format '${value}'"
            EMU_FORMAT=${value};;
        IID)
            [ "${value}" = "${IID}" ] || emu_die "it is for image '${value}', not ${IID}";;
        ARCH)
            case "${value}" in arm|mips) EMU_ARCH=${value};; *) emu_die "line ${n}: invalid ARCH";; esac;;
        ENDIAN)
            case "${value}" in el|eb) EMU_ENDIAN=${value};; *) emu_die "line ${n}: invalid ENDIAN";; esac;;
        NETWORK_TYPE)
            case "${value}" in
                None|normal|reload|bridge|bridgereload|default) NETWORK_TYPE=${value};;
                *) emu_die "line ${n}: invalid NETWORK_TYPE";;
            esac;;
        NET_BRIDGE)
            [[ "${value}" =~ ${EMU_RE_IFNAME_OR_EMPTY} ]] || emu_die "line ${n}: invalid NET_BRIDGE"
            NET_BRIDGE=${value};;
        NET_INTERFACE)
            [[ "${value}" =~ ${EMU_RE_IFNAME_OR_EMPTY} ]] || emu_die "line ${n}: invalid NET_INTERFACE"
            NET_INTERFACE=${value};;
        QEMU_INIT)
            [[ "${value}" =~ ${EMU_RE_INIT} ]] || emu_die "line ${n}: invalid QEMU_INIT"
            QEMU_INIT=${value};;
        GEN_FIRMAE_NET)
            case "${value}" in true|false) GEN_FIRMAE_NET=${value};; *) emu_die "line ${n}: invalid GEN_FIRMAE_NET";; esac;;
        NET)
            [[ "${value}" =~ ${EMU_RE_NET} ]] || emu_die "line ${n}: invalid NET"
            a=${BASH_REMATCH[1]}; b=${BASH_REMATCH[2]}; c=${BASH_REMATCH[3]}
            emu_ipv4 "${a}" && emu_ipv4 "${b}" || emu_die "line ${n}: invalid address in NET"
            emu_guest_ipv4 "${a}" && emu_guest_ipv4 "${b}" ||
                emu_die "line ${n}: NET address is loopback, 0/8, link-local, multicast, reserved or broadcast"
            if [ "${c}" = - ]; then
                c=""
            elif [ "${c}" -gt 4094 ]; then
                emu_die "line ${n}: invalid VLAN id"
            fi
            [ ${#NET_HOSTIP[@]} -lt 4 ] || emu_die "more than 4 NET records"
            NET_HOSTIP+=("${a}"); NET_GUESTIP+=("${b}"); NET_VLAN+=("${c}");;
        NIC)
            [ ${#NIC_KIND[@]} -lt 4 ] || emu_die "more than 4 NIC records"
            if [ "${value}" = user ] || [ "${value}" = "user fwd" ]; then
                NIC_KIND+=(user); NIC_ARG+=("${value#user}")
            elif [[ "${value}" =~ ${EMU_RE_NIC_NUM} ]]; then
                a=${BASH_REMATCH[1]}; b=${BASH_REMATCH[2]}
                if [ "${a}" = socket ] && { [ "${b}" -lt 20000 ] || [ "${b}" -gt 59999 ]; }; then
                    emu_die "line ${n}: invalid placeholder port"
                fi
                NIC_KIND+=("${a}"); NIC_ARG+=("${b}")
            else
                emu_die "line ${n}: invalid NIC"
            fi;;
        HOSTFWD)
            [[ "${value}" =~ ${EMU_RE_HOSTFWD} ]] || emu_die "line ${n}: invalid HOSTFWD"
            a=${BASH_REMATCH[1]}; b=${BASH_REMATCH[2]}; c=${BASH_REMATCH[3]}
            { [ "${b}" -ge 1 ] && [ "${b}" -le 65535 ] && [ "${c}" -ge 10000 ] && [ "${c}" -le 19999 ]; } ||
                emu_die "line ${n}: HOSTFWD port out of range"
            case " ${HOSTFWD_HOST[*]-} " in *" ${c} "*) emu_die "host port ${c} forwarded twice";; esac
            [ ${#HOSTFWD_PROTO[@]} -lt 34 ] || emu_die "too many HOSTFWD records"
            HOSTFWD_PROTO+=("${a}"); HOSTFWD_GUEST+=("${b}"); HOSTFWD_HOST+=("${c}");;
        *)
            emu_die "line ${n}: unknown record ${key}";;
    esac
}

read_emulation () {
    local line n=0 i key fwd=0
    if [ -L "${EMU_FILE}" ] || [ ! -f "${EMU_FILE}" ]; then
        emu_die "missing, or not a regular file"
    fi
    while IFS= read -r -n "${EMU_MAX_LINE}" line || [ -n "${line}" ]; do
        n=$((n + 1))
        [ "${n}" -le "${EMU_MAX_LINES}" ] || emu_die "more than ${EMU_MAX_LINES} lines"
        [ "${#line}" -lt "${EMU_MAX_LINE}" ] || emu_die "line ${n} is too long"
        case "${line}" in '#'*) continue;; esac
        [[ "${line}" =~ ${EMU_RE_LINE} ]] || emu_die "line ${n} is not a KEY=value record"
        emu_record "${n}" "${BASH_REMATCH[1]}" "${BASH_REMATCH[2]}"
    done < "${EMU_FILE}"

    for key in FORMAT IID ARCH ENDIAN NETWORK_TYPE NET_BRIDGE NET_INTERFACE QEMU_INIT GEN_FIRMAE_NET; do
        case "${EMU_SEEN}" in *" ${key} "*) ;; *) emu_die "no ${key} record";; esac
    done
    case "${EMU_ARCH}${EMU_ENDIAN}" in
        armel|mipsel|mipseb) ;;
        *) emu_die "unsupported architecture ${EMU_ARCH}${EMU_ENDIAN}";;
    esac
    # a guest address that is also a host-side TAP address: probes and the
    # route to the guest would reach the host itself (checkEmulation in makeNetwork.py)
    for (( i=0; i<${#NET_GUESTIP[@]}; i++ )); do
        case " ${NET_HOSTIP[*]} " in
            *" ${NET_GUESTIP[i]} "*) emu_die "guest address ${NET_GUESTIP[i]} is also a host address";;
        esac
    done
    [ ${#NIC_KIND[@]} -ge 1 ] || emu_die "no NIC record"
    for (( i=0; i<${#NIC_KIND[@]}; i++ )); do
        if [ "${NIC_KIND[i]}" = tap ] && [ "${NIC_ARG[i]}" -ge ${#NET_HOSTIP[@]} ]; then
            emu_die "NIC ${i} uses a network that has no NET record"
        fi
        if [ "${NIC_KIND[i]}" = user ] && [ "${NIC_ARG[i]}" = " fwd" ]; then
            fwd=$((fwd + 1))
        fi
    done
    if [ ${#HOSTFWD_PROTO[@]} -gt 0 ]; then
        [ "${fwd}" -eq 1 ] || emu_die "HOSTFWD records need exactly one 'NIC=user fwd'"
    else
        [ "${fwd}" -eq 0 ] || emu_die "'NIC=user fwd' without HOSTFWD records"
    fi
}

read_emulation
ARCHEND=${EMU_ARCH}${EMU_ENDIAN}

# ---------------------------------------------------------------------------
# the emulation (former run.sh template)
# ---------------------------------------------------------------------------

IMAGE=`get_fs ${IID}`
# (get_kernel has one argument; the old template passed a second one,
# "true" for mips in debug mode, that get_kernel never read)
KERNEL=`get_kernel ${ARCHEND}`

if [[ "${RUN_MODE}" == *analyze* ]]; then
    QEMU_DEBUG="user_debug=31 firmadyne.syscall=32"
else
    QEMU_DEBUG="user_debug=0 firmadyne.syscall=1"
fi

if [[ "${RUN_MODE}" == *boot* ]]; then
    QEMU_BOOT=(-s -S)
else
    QEMU_BOOT=()
fi

QEMU=`get_qemu ${ARCHEND}`
QEMU_MACHINE=`get_qemu_machine ${ARCHEND}`
QEMU_ROOTFS=`get_qemu_disk ${ARCHEND}`

# Clean up on every exit path -- normal end, error (set -e), Ctrl-C, SIGTERM:
# stop QEMU, release the image's mount and loop device, and remove the network
# interfaces, even if start_net failed half-way.
# monitor and serial sockets: private directory of this image (was predictable
# /tmp names; the monitor gives code execution with QEMU's privileges)
mkdir -p "${WORK_DIR}/run"
chmod 0700 "${WORK_DIR}/run"
rm -f "${WORK_DIR}"/run/*.sock

# TAP device and host-side device (the VLAN on it, if any) of network j; set
# by start_net as it goes. stop_net leaves out an argument that is not set
# yet, as the unquoted ${TAPDEV_j} of the old script expanded to nothing.
TAPDEV=()
HOSTNETDEV=()

start_net () {
    local j
    for (( j=0; j<${#NET_HOSTIP[@]}; j++ )); do
        TAPDEV[j]=tap${IID}_${j}
        HOSTNETDEV[j]=${TAPDEV[j]}
        echo "Creating TAP device ${TAPDEV[j]}..."
        sudo tunctl -t "${TAPDEV[j]}" -u "${USER}"

        if [ -n "${NET_VLAN[j]}" ]; then
            echo "Initializing VLAN..."
            HOSTNETDEV[j]=${TAPDEV[j]}.${NET_VLAN[j]}
            sudo ip link add link "${TAPDEV[j]}" name "${HOSTNETDEV[j]}" type vlan id "${NET_VLAN[j]}"
            if [ "${GEN_FIRMAE_NET}" = true ]; then
                sudo ip link set "${TAPDEV[j]}" up
            else
                sudo ip link set "${HOSTNETDEV[j]}" up
            fi
        fi

        echo "Bringing up TAP device..."
        sudo ip link set "${HOSTNETDEV[j]}" up
        sudo ip addr add "${NET_HOSTIP[j]}/24" dev "${HOSTNETDEV[j]}"

        if [ "${GEN_FIRMAE_NET}" != true ]; then
            echo "Adding route to ${NET_GUESTIP[j]}..."
            sudo ip route add "${NET_GUESTIP[j]}" via "${NET_GUESTIP[j]}" dev "${HOSTNETDEV[j]}"
        fi
    done
}

QEMU_PID=""
IMAGE_ATTACHED=false
NET_STARTED=false
stop_net () {
    local j
    for (( j=0; j<${#NET_HOSTIP[@]}; j++ )); do
        echo "Bringing down TAP device..."
        sudo ip link set ${TAPDEV[j]:+"${TAPDEV[j]}"} down
        if [ -n "${NET_VLAN[j]}" ]; then
            echo "Removing VLAN..."
            sudo ip link delete ${HOSTNETDEV[j]:+"${HOSTNETDEV[j]}"}
        fi
        echo "Deleting TAP device ${TAPDEV[j]:-}..."
        sudo tunctl -d ${TAPDEV[j]:+"${TAPDEV[j]}"}
    done
}
cleanup () {
    local rc=$?
    trap - EXIT INT TERM HUP
    set +eu
    if [ -n "${QEMU_PID}" ]; then
        kill ${QEMU_PID} 2>/dev/null
        wait_for_exit ${QEMU_PID} ${QEMU_STOP_GRACE}
    fi
    if mountpoint -q "${WORK_DIR}/image"; then
        umount "${WORK_DIR}/image"
    fi
    if ${IMAGE_ATTACHED}; then
        del_partition "${DEVICE:0:$((${#DEVICE}-2))}"
    fi
    if ${NET_STARTED}; then
        stop_net
        unisolate_guest_network ${IID}
    fi
    echo "Done!"
    exit ${rc}
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP

DEVICE=`add_partition "${WORK_DIR}/image.raw"`
IMAGE_ATTACHED=true
mount_partition "${DEVICE}" "${WORK_DIR}/image" > /dev/null

# The guest wrote this file system during earlier runs and the writes below run
# as root on the host: refuse a symlinked /firmadyne and any target that is not
# a regular file (a symlink, FIFO or device node would redirect the write).
GUEST_DIR=${WORK_DIR}/image/firmadyne
if [ -L "${GUEST_DIR}" ] || [ ! -d "${GUEST_DIR}" ]; then
    echo "Error: ${GUEST_DIR} is not a plain directory" >&2
    exit 1
fi
for GUEST_FILE in network_type net_bridge net_interface debug.sh; do
    GUEST_FILE=${GUEST_DIR}/${GUEST_FILE}
    if [ -L "${GUEST_FILE}" ] || { [ -e "${GUEST_FILE}" ] && [ ! -f "${GUEST_FILE}" ]; }; then
        echo "Error: ${GUEST_FILE} is not a regular file" >&2
        exit 1
    fi
done

echo "${NETWORK_TYPE}" > "${WORK_DIR}/image/firmadyne/network_type"
echo "${NET_BRIDGE}" > "${WORK_DIR}/image/firmadyne/net_bridge"
echo "${NET_INTERFACE}" > "${WORK_DIR}/image/firmadyne/net_interface"

echo "#!/firmadyne/sh" > "${WORK_DIR}/image/firmadyne/debug.sh"
if [[ "${RUN_MODE}" == *debug* ]]; then
    echo "while (true); do /firmadyne/busybox nc -lp 31337 -e /firmadyne/sh; done &" >> "${WORK_DIR}/image/firmadyne/debug.sh"
    echo "/firmadyne/busybox telnetd -p 31338 -l /firmadyne/sh" >> "${WORK_DIR}/image/firmadyne/debug.sh"
fi
chmod a+x "${WORK_DIR}/image/firmadyne/debug.sh"

sleep 1
sync
umount "${WORK_DIR}/image" > /dev/null
del_partition "${DEVICE:0:$((${#DEVICE}-2))}"
IMAGE_ATTACHED=false

NET_STARTED=true
start_net

# the guest must not open connections to the host or be routed anywhere
# (rules removed again by cleanup(); see isolate_guest_network in firmae.config)
isolate_guest_network ${IID}

# user network: these loopback ports were free when makeNetwork.py chose them
# (scratch/<IID>/hostfwd); stop with a clear error if one has been taken since,
# QEMU would refuse the hostfwd rule anyway
for (( i=0; i<${#HOSTFWD_PROTO[@]}; i++ )); do
    [ "${HOSTFWD_PROTO[i]}" = tcp ] || continue
    HOSTFWD_PORT=${HOSTFWD_HOST[i]}
    if (exec 3<>"/dev/tcp/127.0.0.1/${HOSTFWD_PORT}") 2>/dev/null; then
        echo "Error: host port 127.0.0.1:${HOSTFWD_PORT} (hostfwd) is in use; re-run makeNetwork.py to choose other ports" >&2
        exit 1
    fi
done

# QEMU command line
if [ "${EMU_ARCH}" = arm ]; then
    NIC_DEVICE=virtio-net-device
    QEMU_DISK=(-drive "if=none,file=${IMAGE},format=raw,id=rootfs" -device virtio-blk-device,drive=rootfs)
else
    NIC_DEVICE=e1000
    QEMU_DISK=(-drive "if=ide,format=raw,file=${IMAGE}")
fi
QEMU_NETWORK=()
for (( i=0; i<${#NIC_KIND[@]}; i++ )); do
    QEMU_NETWORK+=(-device "${NIC_DEVICE},netdev=net${i}" -netdev)
    case "${NIC_KIND[i]}" in
        socket)
            QEMU_NETWORK+=("socket,id=net${i},listen=127.0.0.1:${NIC_ARG[i]}");;
        tap)
            QEMU_NETWORK+=("tap,id=net${i},ifname=${TAPDEV[${NIC_ARG[i]}]},script=no");;
        user)
            # restrict=on: no way out for the guest; forwards on loopback only
            NETDEV="user,id=net${i},restrict=on"
            if [ "${NIC_ARG[i]}" = " fwd" ]; then
                for (( k=0; k<${#HOSTFWD_PROTO[@]}; k++ )); do
                    NETDEV="${NETDEV},hostfwd=${HOSTFWD_PROTO[k]}:127.0.0.1:${HOSTFWD_HOST[k]}-:${HOSTFWD_GUEST[k]}"
                done
            fi
            QEMU_NETWORK+=("${NETDEV}");;
    esac
done

# QEMU runs in the background and we `wait` for it: bash does not run traps
# while a foreground command is running, so Ctrl-C/SIGTERM reach cleanup()
# immediately. Its exit status does not matter (was: `| true`).
echo -n "Starting emulation of firmware... "
QEMU_ARGS=(${QEMU_BOOT[@]+"${QEMU_BOOT[@]}"} -m 1024 -M "${QEMU_MACHINE}" -kernel "${KERNEL}"
    "${QEMU_DISK[@]}" -append "root=${QEMU_ROOTFS} console=ttyS0 nandsim.parts=64,64,64,64,64,64,64,64,64,64 ${QEMU_INIT} rw debug ignore_loglevel print-fatal-signals=1 FIRMAE_NET=${FIRMAE_NET} FIRMAE_NVRAM=${FIRMAE_NVRAM} FIRMAE_KERNEL=${FIRMAE_KERNEL} FIRMAE_ETC=${FIRMAE_ETC} ${QEMU_DEBUG}"
    -serial "file:${WORK_DIR}/qemu.final.serial.log"
    -serial "unix:${WORK_DIR}/run/serial1.sock,server,nowait"
    -monitor "unix:${WORK_DIR}/run/monitor.sock,server,nowait"
    -display none
    "${QEMU_NETWORK[@]}")
if [ "${EMU_ARCH}" = arm ]; then
    QEMU_AUDIO_DRV=none "${QEMU}" "${QEMU_ARGS[@]}" &
else
    "${QEMU}" "${QEMU_ARGS[@]}" &
fi
QEMU_PID=$!
wait ${QEMU_PID} || true
QEMU_PID=""
