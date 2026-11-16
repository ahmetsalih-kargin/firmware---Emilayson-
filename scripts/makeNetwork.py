#!/usr/bin/env python3

import sys
import getopt
import re
import struct
import socket
import stat
import os
import time
import subprocess

try:  # run as ./scripts/makeNetwork.py
    from imagepath import resolve_in_root
    from procgroup import raise_on_sigterm, run_with_timeout
except ImportError:  # imported as scripts.makeNetwork (tests)
    from scripts.imagepath import resolve_in_root
    from scripts.procgroup import raise_on_sigterm, run_with_timeout

debug = 0
SCRATCHDIR = ""
SCRIPTDIR = ""

# ---------------------------------------------------------------------------
# Untrusted input. The serial log and the image are written by the emulated
# firmware, and run.sh (generated from them) runs as root on the host. Every
# value that reaches QEMUCMDTEMPLATE is checked against a whitelist, once when
# it is parsed (bad records are skipped) and again in qemuCmd() (bad values
# raise), so no log line can become shell code.
# ---------------------------------------------------------------------------

# Linux interface names: at most IFNAMSIZ-1 = 15 bytes. ':' is kept for alias
# labels (eth0:1); none of these characters is special inside "..." in bash.
# The first one must be alphanumeric, so "eth0.1".split(".")[0] (buildConfig)
# is never empty and no name looks like a command-line option.
# \Z, not $: "$" also matches before a trailing newline, so "eth0\n" was accepted.
IFNAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,14}\Z")
MAC_RE = re.compile(r"^[0-9a-f]{2}(:[0-9a-f]{2}){5}\Z")
IPV4_RE = re.compile(r"^(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])"
                     r"(\.(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])){3}\Z")
QEMU_INIT_RE = re.compile(r"^(rd)?init=/[A-Za-z0-9_./-]+\Z")
NETWORK_TYPES = ("None", "normal", "reload", "bridge", "bridgereload", "default")
MAX_VLAN_ID = 4094
MAX_U32 = 0xFFFFFFFF
# The guest can make the serial log (and its init script) arbitrarily large.
MAX_READ = 64 * 1024 * 1024
# QEMU attaches at most 4 NICs (interfaceNum in qemuNetworkConfig); more
# networks would only create unused TAP devices and ip.N files.
MAX_NETWORKS = 4
MAX_INTERFACES = 64     # parsed "interface with address" records, before filtering
MAX_FORWARD_PORTS = 32  # extra hostfwd rules besides 80/443 (user network)
INFER_DEFAULT_TIMEOUT = 600   # seconds for scripts/inferDefault.py
MAX_WARNINGS = 5        # per parser call, so a flood of bad lines cannot flood the log


class UnsafeValue(ValueError):
    """A firmware-controlled value that must not reach run.sh."""


class UnsafeImagePath(Exception):
    """A path in the (guest-written) image that the host must not write through."""


def isIfname(name):
    return isinstance(name, str) and IFNAME_RE.match(name) is not None


def isIpv4(ip):
    return isinstance(ip, str) and IPV4_RE.match(ip) is not None


def _isInt(v, lo, hi):
    return isinstance(v, int) and not isinstance(v, bool) and lo <= v <= hi


def _decodeIfname(raw):
    """bytes from the log -> interface name, or None if it is not a safe one."""
    try:
        name = raw.decode("ascii")
    except UnicodeDecodeError:
        return None
    return name if isIfname(name) else None


def _hexU32(raw):
    """Hex digits from the log -> int, or None if it does not fit 32 bits
    (struct.pack used to raise on those and abort makeNetwork)."""
    if len(raw.lstrip(b"0")) > 8:
        return None
    return int(raw, 16)


def _reportSkipped(kind, skipped):
    for line in skipped[:MAX_WARNINGS]:
        print("[!] Warning: skipped invalid %s record: %r" % (kind, line[:120]))
    if len(skipped) > MAX_WARNINGS:
        print("[!] Warning: skipped %d more invalid %s records"
              % (len(skipped) - MAX_WARNINGS, kind))


def readLimited(path, limit=MAX_READ):
    """Read at most `limit` bytes of a guest-written log. Beyond the limit the
    rest is dropped, cut at the last complete line (a cut-off line could yield
    a truncated interface name)."""
    with open(path, "rb") as f:
        data = f.read(limit + 1)
    if len(data) > limit:
        print("[!] Warning: %s is larger than %d bytes; only the first %d are parsed"
              % (path, limit, limit))
        data = data[:limit]
        data = data[:data.rfind(b"\n") + 1]
    return data


# ---------------------------------------------------------------------------
# Writing into the image after the guest has run. A symlink planted by the
# guest (/firmadyne -> /etc, /firmadyne/preInit.sh -> /root/.bashrc, a device
# node, ...) must never redirect a host root write.
# ---------------------------------------------------------------------------

def imageFile(imageRoot, relPath, expected=None):
    """Host path of image file `relPath` that is safe to open: every directory
    on the way is resolved inside the image (resolve_in_root), the file itself
    is not a symlink and, if present, is a regular file. `expected` (a path an
    earlier call returned) additionally requires that the guest has not changed
    the directories in between. Raises UnsafeImagePath otherwise."""
    path = resolve_in_root(imageRoot, relPath, follow_final=False)
    if expected is not None and path != expected:
        raise UnsafeImagePath("%s now resolves to %s (was %s)" % (relPath, path, expected))
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        return path
    if not stat.S_ISREG(st.st_mode):
        raise UnsafeImagePath("%s is not a regular file" % path)
    return path


def firmadyneFile(targetDir, name):
    """/firmadyne/<name> of the image. FirmAE created that directory itself, so
    any symlink on the way means the guest tampered with it: refuse."""
    root = os.path.realpath(targetDir + "/image")
    path = imageFile(root, "/firmadyne/" + name)
    if path != os.path.join(root, "firmadyne", name):
        raise UnsafeImagePath("/firmadyne/%s is redirected to %s" % (name, path))
    return path


def openImageFile(path, mode):
    """open() that does not follow a symlink in the last component (checked
    before, but O_NOFOLLOW keeps it so) and does not block on a FIFO."""
    flags = {"rb": os.O_RDONLY, "ab": os.O_WRONLY | os.O_APPEND | os.O_CREAT,
             "wb": os.O_WRONLY | os.O_TRUNC | os.O_CREAT}[mode]
    fd = os.open(path, flags | os.O_NOFOLLOW | os.O_NONBLOCK, 0o644)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise UnsafeImagePath("%s is not a regular file" % path)
        os.set_blocking(fd, True)
        return os.fdopen(fd, mode)
    except BaseException:
        os.close(fd)
        raise

QEMUCMDTEMPLATE = """#!/bin/bash

set -e
set -u

ARCHEND=%(ARCHEND)s
IID=%(IID)i

if [ -e ./firmae.config ]; then
    source ./firmae.config
elif [ -e ../firmae.config ]; then
    source ../firmae.config
elif [ -e ../../firmae.config ]; then
    source ../../firmae.config
else
    echo "Error: Could not find 'firmae.config'!"
    exit 1
fi

RUN_MODE=`basename ${0}`

IMAGE=`get_fs ${IID}`
if (echo ${ARCHEND} | grep -q "mips" && echo ${RUN_MODE} | grep -q "debug"); then
    KERNEL=`get_kernel ${ARCHEND} true`
else
    KERNEL=`get_kernel ${ARCHEND} false`
fi

if (echo ${RUN_MODE} | grep -q "analyze"); then
    QEMU_DEBUG="user_debug=31 firmadyne.syscall=32"
else
    QEMU_DEBUG="user_debug=0 firmadyne.syscall=1"
fi

if (echo ${RUN_MODE} | grep -q "boot"); then
    QEMU_BOOT="-s -S"
else
    QEMU_BOOT=""
fi

QEMU=`get_qemu ${ARCHEND}`
QEMU_MACHINE=`get_qemu_machine ${ARCHEND}`
QEMU_ROOTFS=`get_qemu_disk ${ARCHEND}`
WORK_DIR=`get_scratch ${IID}`

# Clean up on every exit path -- normal end, error (set -e), Ctrl-C, SIGTERM:
# stop QEMU, release the image's mount and loop device, and remove the network
# interfaces, even if START_NET failed half-way.
# monitor and serial sockets: private directory of this image (was predictable
# /tmp names; the monitor gives code execution with QEMU's privileges)
mkdir -p ${WORK_DIR}/run
chmod 0700 ${WORK_DIR}/run
rm -f ${WORK_DIR}/run/*.sock

QEMU_PID=""
IMAGE_ATTACHED=false
NET_STARTED=false
stop_net () {
    true
%(STOP_NET)s
}
cleanup () {
    local rc=$?
    trap - EXIT INT TERM HUP
    set +eu
    if [ -n "${QEMU_PID}" ]; then
        kill ${QEMU_PID} 2>/dev/null
        wait_for_exit ${QEMU_PID} ${QEMU_STOP_GRACE}
    fi
    if mountpoint -q ${WORK_DIR}/image; then
        umount ${WORK_DIR}/image
    fi
    if ${IMAGE_ATTACHED}; then
        del_partition ${DEVICE:0:$((${#DEVICE}-2))}
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
mount_partition ${DEVICE} ${WORK_DIR}/image > /dev/null

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

echo "%(NETWORK_TYPE)s" > ${WORK_DIR}/image/firmadyne/network_type
echo "%(NET_BRIDGE)s" > ${WORK_DIR}/image/firmadyne/net_bridge
echo "%(NET_INTERFACE)s" > ${WORK_DIR}/image/firmadyne/net_interface

echo "#!/firmadyne/sh" > ${WORK_DIR}/image/firmadyne/debug.sh
if (echo ${RUN_MODE} | grep -q "debug"); then
    echo "while (true); do /firmadyne/busybox nc -lp 31337 -e /firmadyne/sh; done &" >> ${WORK_DIR}/image/firmadyne/debug.sh
    echo "/firmadyne/busybox telnetd -p 31338 -l /firmadyne/sh" >> ${WORK_DIR}/image/firmadyne/debug.sh
fi
chmod a+x ${WORK_DIR}/image/firmadyne/debug.sh

sleep 1
sync
umount ${WORK_DIR}/image > /dev/null
del_partition ${DEVICE:0:$((${#DEVICE}-2))}
IMAGE_ATTACHED=false

NET_STARTED=true
%(START_NET)s

# the guest must not open connections to the host or be routed anywhere
# (rules removed again by cleanup(); see isolate_guest_network in firmae.config)
isolate_guest_network ${IID}

# QEMU runs in the background and we `wait` for it: bash does not run traps
# while a foreground command is running, so Ctrl-C/SIGTERM reach cleanup()
# immediately. Its exit status does not matter (was: `| true`).
echo -n "Starting emulation of firmware... "
%(QEMU_ENV_VARS)s ${QEMU} ${QEMU_BOOT} -m 1024 -M ${QEMU_MACHINE} -kernel ${KERNEL} \\
    %(QEMU_DISK)s -append "root=${QEMU_ROOTFS} console=ttyS0 nandsim.parts=64,64,64,64,64,64,64,64,64,64 %(QEMU_INIT)s rw debug ignore_loglevel print-fatal-signals=1 FIRMAE_NET=${FIRMAE_NET} FIRMAE_NVRAM=${FIRMAE_NVRAM} FIRMAE_KERNEL=${FIRMAE_KERNEL} FIRMAE_ETC=${FIRMAE_ETC} ${QEMU_DEBUG}" \\
    -serial file:${WORK_DIR}/qemu.final.serial.log \\
    -serial unix:${WORK_DIR}/run/serial1.sock,server,nowait \\
    -monitor unix:${WORK_DIR}/run/monitor.sock,server,nowait \\
    -display none \\
    %(QEMU_NETWORK)s &
QEMU_PID=$!
wait ${QEMU_PID} || true
QEMU_PID=""
"""


def mountImage(targetDir):
    loopFile = (
        subprocess.check_output(
            ["bash", "-c", 'source firmae.config && add_partition "$1"', "_",
             "%s/image.raw" % targetDir]
        )
        .decode()
        .strip()
    )
    # A failed mount used to be ignored (os.system), and the following writes
    # then went to the empty mount-point directory on the host.
    # The partition node can still be settling right after add_partition; retry
    # briefly before giving up.
    # nodev,nosuid: device nodes and setuid files the guest put into the image
    # have no effect on the host while it is mounted here.
    for attempt in range(5):
        res = subprocess.run(["mount", "-o", "nodev,nosuid", loopFile, "%s/image" % targetDir],
                             stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        if res.returncode == 0:
            break
        time.sleep(1)
    else:
        sys.stderr.write(res.stderr.decode(errors="replace"))
        raise subprocess.CalledProcessError(res.returncode, res.args)
    time.sleep(1)
    return loopFile


def umountImage(targetDir, loopFile):
    subprocess.run(["umount", "%s/image" % targetDir], stdout=subprocess.DEVNULL, check=True)
    subprocess.check_output(
        ["bash", "-c", 'source firmae.config && del_partition "$1"', "_",
         loopFile.rsplit("p", 1)[0]]
    )


def checkVariable(key):
    if os.environ[key] == "true":
        return True
    else:
        return False


def stripTimestamps(data):
    lines = data.split(b"\n")
    # throw out the timestamps
    prog = re.compile(rb"^\[[^\]]*\] firmadyne: ")
    lines = [prog.sub(b"", l) for l in lines]
    return lines


def findMacChanges(data, endianness):
    lines = stripTimestamps(data)
    candidates = filter(lambda l: l.startswith(b"ioctl_SIOCSIFHWADDR"), lines)
    if debug:
        print("Mac Changes %r" % candidates)

    result = []
    if endianness == "eb":
        fmt = ">I"
    elif endianness == "el":
        fmt = "<I"
    prog = re.compile(
        rb"^ioctl_SIOCSIFHWADDR\[[^\]]+\]: dev:([^ ]+) mac:0x([0-9a-f]+) 0x([0-9a-f]+)"
    )
    skipped = []
    for c in candidates:
        g = prog.match(c)
        if g:
            (iface, mac0, mac1) = g.groups()
            iface = _decodeIfname(iface)
            mac0, mac1 = _hexU32(mac0), _hexU32(mac1)
            if iface is None or mac0 is None or mac1 is None:
                skipped.append(c)
                continue
            m0 = struct.pack(fmt, mac0)[2:]
            m1 = struct.pack(fmt, mac1)
            mac = "%02x:%02x:%02x:%02x:%02x:%02x" % struct.unpack("BBBBBB", m0 + m1)
            result.append((iface, mac))
    _reportSkipped("MAC change", skipped)
    return result


def findPorts(data, endianness):
    lines = stripTimestamps(data)
    candidates = filter(
        lambda l: l.startswith(b"inet_bind"), lines
    )  # logs for the inconfig process
    result = []
    if endianness == "eb":
        fmt = ">I"
    elif endianness == "el":
        fmt = "<I"
    prog = re.compile(
        rb"^inet_bind\[[^\]]+\]: proto:SOCK_(DGRAM|STREAM), ip:port: 0x([0-9a-f]+):([0-9]+)"
    )
    portSet = {}
    skipped = []
    for c in candidates:
        g = prog.match(c)
        if g:
            (proto, addr, port) = g.groups()
            proto = "tcp" if proto == b"STREAM" else "udp"
            addr = _hexU32(addr)
            # length check first: int() refuses very long decimal strings
            port = int(port) if len(port) <= 5 else None
            if addr is None or port is None or not 1 <= port <= 65535:
                skipped.append(c)
                continue
            addr = socket.inet_ntoa(struct.pack(fmt, addr))
            if port not in portSet:
                result.append((proto, addr, port))
                portSet[port] = True
    _reportSkipped("inet_bind", skipped)
    return result


# Get the netwokr interfaces in the router, except 127.0.0.1
def findNonLoInterfaces(data, endianness):
    lines = stripTimestamps(data)
    candidates = filter(
        lambda l: l.startswith(b"__inet_insert_ifa"), lines
    )  # logs for the inconfig process
    if debug:
        print("Candidate ifaces: %r" % candidates)
    result = []
    if endianness == "eb":
        fmt = ">I"
    elif endianness == "el":
        fmt = "<I"
    prog = re.compile(rb"^__inet_insert_ifa\[[^\]]+\]: device:([^ ]+) ifa:0x([0-9a-f]+)")
    skipped = []
    for c in candidates:
        g = prog.match(c)
        if g:
            (iface, addr) = g.groups()
            iface = _decodeIfname(iface)
            addr = _hexU32(addr)
            if iface is None or addr is None:
                skipped.append(c)
                continue
            addr = socket.inet_ntoa(struct.pack(fmt, addr))
            if addr != "127.0.0.1" and addr != "0.0.0.0":
                if len(result) >= MAX_INTERFACES:
                    print("[!] Warning: more than %d interfaces with an address; "
                          "ignoring the rest" % MAX_INTERFACES)
                    break
                result.append((iface, addr))
    _reportSkipped("interface address", skipped)
    return result


def findIfacesForBridge(data, brif):
    lines = stripTimestamps(data)
    result = []
    candidates = filter(
        lambda l: l.startswith(b"br_dev_ioctl") or l.startswith(b"br_add_if"), lines
    )
    # re.escape: the name is data, not a pattern ("br(" used to raise re.error)
    progs = [
        re.compile(p % re.escape(brif.encode()))
        for p in [
            rb"^br_dev_ioctl\[[^\]]+\]: br:%s dev:(.*)",
            rb"^br_add_if\[[^\]]+\]: br:%s dev:(.*)",
        ]
    ]
    skipped = []
    for c in candidates:
        for p in progs:
            g = p.match(c)
            if g:
                iface = g.group(1)
                try:
                    iface = iface.decode("utf-8")
                except UnicodeDecodeError:
                    skipped.append(c)
                    continue
                # we only add it if the interface is not the bridge itself
                # there are images that call brctl addif br0 br0 (e.g., 5152)
                if iface != brif:
                    if not isIfname(iface.strip()):
                        skipped.append(c)
                        continue
                    result.append(iface.strip())
    _reportSkipped("bridge member", skipped)
    return result


def findVlanInfoForDev(data, dev):
    lines = stripTimestamps(data)
    results = []
    candidates = filter(lambda l: l.startswith(b"register_vlan_dev"), lines)
    prog = re.compile(
        rb"register_vlan_dev\[[^\]]+\]: dev:%s vlan_id:([0-9]+)" % re.escape(dev.encode())
    )
    skipped = []
    for c in candidates:
        g = prog.match(c)
        if g:
            vid = g.group(1)
            # length check first: int() refuses very long decimal strings
            if len(vid) > 4 or int(vid) > MAX_VLAN_ID:
                skipped.append(c)
                continue
            results.append(int(vid))
    _reportSkipped("VLAN", skipped)
    return results


def ifaceNo(dev):
    g = re.match(r"[^0-9]+([0-9]+)", dev)
    return int(g.group(1)) if g else -1


def isDhcpIp(ip):
    # normal dhcp client ip
    if ip.startswith("10.0.2."):
        return True
    # netgear armel R6900 series
    elif ip.endswith(".190"):
        return True
    return False


def placeholderPort(iid, i):
    """Loopback port of placeholder NIC i of image iid. One range of 4 ports per
    image, so parallel emulations do not collide (was the fixed 2000-2003 on all
    interfaces). Same formula as SOCK_BASE in scripts/run.<arch>.sh."""
    return 20000 + (int(iid) % 10000) * 4 + i


def forwardPorts(ports, warn=False):
    """Ports for extra hostfwd rules: no 80/443 (always forwarded), only valid
    ports, one rule per (proto, port), at most MAX_FORWARD_PORTS. The guest
    controls the list; unbounded it would make one huge QEMU argument."""
    result = []
    seen = set()
    for (proto, _addr, port) in ports:
        if port in (80, 443) or not 1 <= port <= 65535 or (proto, port) in seen:
            continue
        if len(result) >= MAX_FORWARD_PORTS:
            if warn:
                print("[!] Warning: more than %d ports to forward; ignoring the rest"
                      % MAX_FORWARD_PORTS)
            break
        seen.add((proto, port))
        result.append((proto, port))
    return result


def qemuArchNetworkConfig(i, tap_num, arch, n, isUserNetwork, ports, iid=0):
    if arch == "arm":
        device = "virtio-net-device"
    else:
        device = "e1000"

    if not n:
        return (
            "-device %(DEVICE)s,netdev=net%(I)i -netdev socket,id=net%(I)i,listen=127.0.0.1:%(PORT)i"
            % {"DEVICE": device, "I": i, "PORT": placeholderPort(iid, i)}
        )
    else:
        (ip, dev, vlan, mac, brif) = n
        vlan_id = vlan if vlan else i
        mac_str = "" if not mac else ",macaddr=%s" % mac
        if isUserNetwork:  # user network dhcp server
            # TODO: get port list (inet_bind)
            # TODO: maybe need reverse ping checker
            # portfwd = ",hostfwd=udp::67-:67"
            # portfwd += ",hostfwd=udp::68-:68" # icmp port cannot foward
            # restrict=on: the guest cannot reach the host or the outside world
            # (explicit hostfwd rules are not affected); forwards listen on
            # loopback only, so the emulated web UI is not exposed to the LAN
            portfwd = "restrict=on,hostfwd=tcp:127.0.0.1:80-:80,hostfwd=tcp:127.0.0.1:443-:443,"
            for (proto, port) in forwardPorts(ports):
                portfwd += "hostfwd=%(TYPE)s:127.0.0.1:%(PORT)i-:%(PORT)i," % {
                    "TYPE": proto,
                    "PORT": port,
                }

            return (
                "-device %(DEVICE)s,netdev=net%(I)i -netdev user,id=net%(I)i,%(FWD)s"
                % {"DEVICE": device, "I": i, "FWD": portfwd[:-1]}
            )
        else:
            return (
                "-device %(DEVICE)s,netdev=net%(I)i -netdev tap,id=net%(I)i,ifname=${TAPDEV_%(TAP_NUM)i},script=no"
                % {"I": i, "DEVICE": device, "TAP_NUM": tap_num}
            )


def qemuNetworkConfig(arch, network, isUserNetwork, ports, iid=0):
    output = []
    assigned = []
    interfaceNum = 4
    if arch == "arm" and checkVariable("FIRMAE_NET"):
        interfaceNum = 1

    if isUserNetwork:
        forwardPorts(ports, warn=True)      # only to report a truncation once

    for i in range(0, interfaceNum):
        for j, n in enumerate(network):
            # need to connect the jth emulated network interface to the corresponding host interface
            if i == ifaceNo(n[1]):
                output.append(
                    qemuArchNetworkConfig(i, j, arch, n, isUserNetwork, ports, iid)
                )
                assigned.append(n)
                break

        # otherwise, put placeholder socket connection
        if len(output) <= i:
            output.append(qemuArchNetworkConfig(i, i, arch, None, isUserNetwork, ports, iid))

    # find unassigned interfaces
    for j, n in enumerate(network[:interfaceNum]):
        if n not in assigned:
            # guess assignment
            print("Warning: Unmatched interface: %s" % (n,))
            output[j] = qemuArchNetworkConfig(j, j, arch, n, isUserNetwork, ports, iid)
            assigned.append(n)

    return " ".join(output)


def buildConfig(brif, iface, vlans, macs):
    # there should be only one ip
    ip = brif[1]
    br = brif[0]

    # strip vlanid from interface name (e.g., eth2.2 -> eth2)
    dev = iface.split(".")[0]

    # check whether there is a different mac set
    mac = None
    d = dict(macs)
    if br in d:
        mac = d[br]
    elif dev in d:
        mac = d[dev]

    vlan_id = None
    if len(vlans):
        vlan_id = vlans[0]

    return (ip, dev, vlan_id, mac, br)


def convertToHostIp(ip):
    tups = [int(x) for x in ip.split(".")]
    if tups[3] > 1:  # sometimes it can has 0 asus FW_RT_AC3100_300438432738
        tups[3] -= 1
    else:
        tups[3] += 1
    return ".".join([str(x) for x in tups])


# iterating the networks
def startNetwork(network):
    template_1 = """
TAPDEV_%(I)i=tap${IID}_%(I)i
HOSTNETDEV_%(I)i=${TAPDEV_%(I)i}
echo "Creating TAP device ${TAPDEV_%(I)i}..."
sudo tunctl -t ${TAPDEV_%(I)i} -u ${USER}
"""

    if checkVariable("FIRMAE_NET"):
        template_vlan = """
echo "Initializing VLAN..."
HOSTNETDEV_%(I)i=${TAPDEV_%(I)i}.%(VLANID)i
sudo ip link add link ${TAPDEV_%(I)i} name ${HOSTNETDEV_%(I)i} type vlan id %(VLANID)i
sudo ip link set ${TAPDEV_%(I)i} up
"""

        template_2 = """
echo "Bringing up TAP device..."
sudo ip link set ${HOSTNETDEV_%(I)i} up
sudo ip addr add %(HOSTIP)s/24 dev ${HOSTNETDEV_%(I)i}
"""
    else:
        template_vlan = """
echo "Initializing VLAN..."
HOSTNETDEV_%(I)i=${TAPDEV_%(I)i}.%(VLANID)i
sudo ip link add link ${TAPDEV_%(I)i} name ${HOSTNETDEV_%(I)i} type vlan id %(VLANID)i
sudo ip link set ${HOSTNETDEV_%(I)i} up
"""

        template_2 = """
echo "Bringing up TAP device..."
sudo ip link set ${HOSTNETDEV_%(I)i} up
sudo ip addr add %(HOSTIP)s/24 dev ${HOSTNETDEV_%(I)i}

echo "Adding route to %(GUESTIP)s..."
sudo ip route add %(GUESTIP)s via %(GUESTIP)s dev ${HOSTNETDEV_%(I)i}
"""

    output = []
    for i, (ip, dev, vlan, mac, brif) in enumerate(network):
        output.append(template_1 % {"I": i})
        if vlan != None:
            output.append(template_vlan % {"I": i, "VLANID": vlan})
        output.append(
            template_2 % {"I": i, "HOSTIP": convertToHostIp(ip), "GUESTIP": ip}
        )
    return "\n".join(output)


def stopNetwork(network):
    template_1 = """
echo "Bringing down TAP device..."
sudo ip link set ${TAPDEV_%(I)i} down
"""

    template_vlan = """
echo "Removing VLAN..."
sudo ip link delete ${HOSTNETDEV_%(I)i}
"""

    template_2 = """
echo "Deleting TAP device ${TAPDEV_%(I)i}..."
sudo tunctl -d ${TAPDEV_%(I)i}
"""

    output = []
    for i, (ip, dev, vlan, mac, brif) in enumerate(network):
        output.append(template_1 % {"I": i})
        if vlan != None:
            output.append(template_vlan % {"I": i})
        output.append(template_2 % {"I": i})
    return "\n".join(output)


def checkQemuCmdInputs(iid, network, ports, network_type, qemuInitValue):
    """Second line of defence: the parsers already drop bad records, but nothing
    unchecked may ever be formatted into the root shell script."""
    def bad(what, value):
        raise UnsafeValue("refusing to put %s %r into run.sh" % (what, value))

    if not _isInt(iid, 0, 2**31 - 1):
        bad("IID", iid)
    if network_type not in NETWORK_TYPES:
        bad("network type", network_type)
    if not isinstance(qemuInitValue, str) or not QEMU_INIT_RE.match(qemuInitValue):
        bad("init", qemuInitValue)
    if len(network) > MAX_NETWORKS:
        bad("number of networks", len(network))
    for n in network:
        if not isinstance(n, tuple) or len(n) != 5:
            bad("network entry", n)
        (ip, dev, vlan, mac, brif) = n
        if not isIpv4(ip):
            bad("IP address", ip)
        if not isIfname(dev):
            bad("interface name", dev)
        if not isIfname(brif):
            bad("bridge name", brif)
        if vlan is not None and not _isInt(vlan, 0, MAX_VLAN_ID):
            bad("VLAN id", vlan)
        if mac is not None and not (isinstance(mac, str) and MAC_RE.match(mac)):
            bad("MAC address", mac)
    for p in ports:
        if not isinstance(p, tuple) or len(p) != 3:
            bad("port entry", p)
        (proto, addr, port) = p
        if proto not in ("tcp", "udp") or not isIpv4(addr) or not _isInt(port, 1, 65535):
            bad("port", p)


def qemuCmd(
    iid, network, ports, network_type, arch, endianness, qemuInitValue, isUserNetwork
):
    network_bridge = ""
    network_iface = ""
    if arch == "mips":
        qemuEnvVars = ""
        qemuDisk = "-drive if=ide,format=raw,file=${IMAGE}"
        if endianness != "eb" and endianness != "el":
            raise Exception("You didn't specify a valid endianness")
    elif arch == "arm":
        qemuDisk = "-drive if=none,file=${IMAGE},format=raw,id=rootfs -device virtio-blk-device,drive=rootfs"
        if endianness == "el":
            qemuEnvVars = "QEMU_AUDIO_DRV=none"
        elif endianness == "eb":
            raise Exception("armeb currently not supported")
        else:
            raise Exception("You didn't specify a valid endianness")
    else:
        raise Exception("Unsupported architecture")

    checkQemuCmdInputs(iid, network, ports, network_type, qemuInitValue)

    for (ip, dev, vlan, mac, brif) in network:
        network_bridge = brif
        network_iface = dev
        break

    return QEMUCMDTEMPLATE % {
        "IID": iid,
        "NETWORK_TYPE": network_type,
        "NET_BRIDGE": network_bridge,
        "NET_INTERFACE": network_iface,
        "START_NET": startNetwork(network),
        "STOP_NET": stopNetwork(network),
        "ARCHEND": arch + endianness,
        "QEMU_DISK": qemuDisk,
        "QEMU_INIT": qemuInitValue,
        "QEMU_NETWORK": qemuNetworkConfig(arch, network, isUserNetwork, ports, iid),
        "QEMU_ENV_VARS": qemuEnvVars,
    }


def getNetworkList(data, ifacesWithIps, macChanges):
    global debug
    networkList = []
    deviceHasBridge = False
    for iwi in ifacesWithIps:
        if iwi[0] == "lo":  # skip local network
            continue
        # find all interfaces that are bridged with that interface
        brifs = findIfacesForBridge(data, iwi[0])
        if debug:
            print("brifs for %s %r" % (iwi[0], brifs))
        for dev in brifs:
            # find vlan_ids for all interfaces in the bridge
            vlans = findVlanInfoForDev(data, dev)
            # create a config for each tuple
            config = buildConfig(iwi, dev, vlans, macChanges)
            if config not in networkList:
                networkList.append(config)
                deviceHasBridge = True

        # if there is no bridge just add the interface
        if not brifs and not deviceHasBridge:
            vlans = findVlanInfoForDev(data, iwi[0])
            config = buildConfig(iwi, iwi[0], vlans, macChanges)
            if config not in networkList:
                networkList.append(config)

    if checkVariable("FIRMAE_NET"):
        return networkList
    else:
        ips = set()
        pruned_network = []
        for n in networkList:
            if n[0] not in ips:
                ips.add(n[0])
                pruned_network.append(n)
            else:
                if debug:
                    print("duplicate ip address for interface: ", n)
        return pruned_network


def readWithException(filePath, limit=MAX_READ):
    """Contents of an image file as bytes, byte for byte: they are written back
    later. (This used to decode line by line and silently drop lines that were
    not UTF-8, so the restored init script lost them.) A missing file reads as
    b"" as before; a file larger than `limit` raises UnsafeImagePath, since a
    truncated copy could not be restored."""
    try:
        f = openImageFile(filePath, "rb")
    except FileNotFoundError:
        return b""
    with f:
        data = f.read(limit + 1)
    if len(data) > limit:
        raise UnsafeImagePath("%s is larger than %d bytes" % (filePath, limit))
    return data


def inferNetwork(iid, arch, endianness, init):
    global SCRIPTDIR
    global SCRATCHDIR
    TIMEOUT = int(os.environ["TIMEOUT"])
    targetDir = SCRATCHDIR + "/" + str(iid)

    loopFile = mountImage(targetDir)

    # `init` comes from the firmware; resolve it inside the image (chroot
    # semantics) so neither `file` nor the append below can reach host files
    # through a symlink planted in the image (SECURITY.md S5). The last
    # component is not followed: `file -b` reports symlinks as such and those
    # take the preInit.sh branch below, as before.
    #
    # Policy for unsafe paths (the image has been written by the guest once an
    # earlier init candidate ran): a redirected /firmadyne file means FirmAE's
    # own files were tampered with -> UnsafeImagePath, makeNetwork stops. An
    # init script that is not a regular file (or is huge) is a property of this
    # candidate only -> it is skipped (None) and the next candidate is tried.
    try:
        initPath = resolve_in_root(targetDir + "/image", init, follow_final=False)
        fileType = (
            subprocess.check_output(["file", "-b", initPath])
            .decode()
            .strip()
        )
        print("[*] Infer test: %s (%s)" % (init, fileType))

        with openImageFile(firmadyneFile(targetDir, "network_type"), "wb") as out:
            out.write(b"None")

        qemuInitValue = "rdinit=/firmadyne/preInit.sh"
        if os.path.exists(targetDir + "/service"):
            with open(targetDir + "/service") as f:
                webService = f.read().strip()
        else:
            webService = None
        print("[*] web service: %s" % webService)
        # targetFile: (path inside the image, host path) of the file whose
        # original content targetData is written back by process()
        targetFile = None
        targetData = None
        out = None
        if not init.endswith("preInit.sh"):  # rcS, preinit
            if (
                fileType.find("ELF") == -1 and fileType.find("symbolic link") == -1
            ):  # maybe script
                try:
                    path = imageFile(targetDir + "/image", init, expected=initPath)
                    targetData = readWithException(path)
                    out = openImageFile(path, "ab")
                except (UnsafeImagePath, ValueError, OSError) as e:
                    print("[!] Warning: skipping init %s: %s" % (init, e))
                    return None
                targetFile = (init, path)
            # netgear R6200
            elif fileType.find("ELF") != -1 or fileType.find("symbolic link") != -1:
                qemuInitValue = qemuInitValue[2:]  # remove 'rd'
                path = firmadyneFile(targetDir, "preInit.sh")
                targetFile = ("/firmadyne/preInit.sh", path)
                targetData = readWithException(path)
                out = openImageFile(path, "ab")
                out.write((init + " &\n").encode("utf-8", "surrogateescape"))
        else:  # preInit.sh
            out = openImageFile(firmadyneFile(targetDir, "preInit.sh"), "ab")

        if out:
            out.write(b"\n/firmadyne/network.sh &\n")
            if webService:
                out.write(b"/firmadyne/run_service.sh &\n")
            out.write(b"/firmadyne/debug.sh\n")
            # trendnet TEW-828DRU_1.0.7.2, etc...
            out.write(b"/firmadyne/busybox sleep 36000\n")
            out.close()
    finally:
        umountImage(targetDir, loopFile)

    print("Running firmware %d: terminating after %d secs..." % (iid, TIMEOUT))

    # Initial emulation in its own process group: after TIMEOUT seconds the
    # group gets SIGINT (as with the old `timeout --signal SIGINT`), SIGKILL 15 s
    # later if it is still there; on Ctrl-C/SIGTERM the group is stopped before
    # we exit. stdout is discarded, stderr goes to makeNetwork.log, as before.
    rc, timedOut = run_with_timeout(
        ["%s/run.%s.sh" % (SCRIPTDIR, arch + endianness), str(iid), qemuInitValue],
        TIMEOUT, stdout=subprocess.DEVNULL)
    print("[*] initial emulation ended (%s, exit %s)" % ("timeout" if timedOut else "exited", rc))

    loopFile = mountImage(targetDir)
    try:
        # inferDefault.py copies into /firmadyne/: a symlinked directory or a
        # (dangling) symlink nvram_files would make that copy land on the host
        if not os.path.exists(firmadyneFile(targetDir, "nvram_files")):
            print("Infer NVRAM default file!\n")
            # Optional improvement: a hang or failure here must not fail the
            # stage. The whole process group is stopped (inferDefault runs `file`).
            _, timedOut = run_with_timeout(
                ["%s/inferDefault.py" % SCRIPTDIR, str(iid)], INFER_DEFAULT_TIMEOUT)
            if timedOut:
                print("[!] Warning: inferDefault.py timed out after %d s; "
                      "continuing without NVRAM default files" % INFER_DEFAULT_TIMEOUT)
    finally:
        umountImage(targetDir, loopFile)

    data = readLimited("%s/qemu.initial.serial.log" % targetDir)

    ports = findPorts(data, endianness)

    # find interfaces with non loopback ip addresses
    ifacesWithIps = findNonLoInterfaces(data, endianness)
    # find changes of mac addresses for devices
    macChanges = findMacChanges(data, endianness)
    print("[*] Interfaces: %r" % ifacesWithIps)

    networkList = getNetworkList(data, ifacesWithIps, macChanges)
    return qemuInitValue, networkList, targetFile, targetData, ports


def checkNetwork(networkList):
    filterNetworkList = []
    devList = ["eth0", "eth1", "eth2", "eth3"]
    result = "None"

    if checkVariable("FIRMAE_NET"):
        devs = [dev for (ip, dev, vlan, mac, brif) in networkList]
        devs = set(devs)
        ips = [ip for (ip, dev, vlan, mac, brif) in networkList]
        ips = set(ips)
        # check "ethX" and bridge interfaces
        # bridge interface can be named guest-lan1, br0
        # wnr2000v4-V1.0.0.70.zip - mipseb
        # [('192.168.1.1', 'br0', None, None, 'br0'), ('10.0.2.15', 'eth0', None, None, 'br1')]
        # R6900
        # [('192.168.1.1', 'br0', None, None, 'br0'), ('20.45.150.190', 'eth0', None, None, 'eth0')]
        if (
            len(devs) > 1
            and any([dev.startswith("eth") for dev in devs])
            and any([not dev.startswith("eth") for dev in devs])
        ):
            print("[*] Check router")
            # remove dhcp ip address
            networkList = [
                network for network in networkList if not network[1].startswith("eth")
            ]
        # linksys FW_LAPAC1200_LAPAC1750_1.1.03.000
        # [('192.168.1.252', 'eth0', None, None, 'br0'), ('10.0.2.15', 'eth0', None, None, 'br0')]
        elif (
            len(ips) > 1
            and any([ip.startswith("10.0.2.") for ip in ips])
            and any([not ip.startswith("10.0.2.") for ip in ips])
        ):
            print("[*] Check router")
            # remove dhcp ip address
            networkList = [
                network
                for network in networkList
                if not network[0].startswith("10.0.2.")
            ]

        # br and eth
        if networkList:
            vlanNetworkList = [
                network
                for network in networkList
                if not network[0].endswith(".0.0.0")
                and network[1].startswith("eth")
                and network[2] != None
            ]
            ethNetworkList = [
                network
                for network in networkList
                if not network[0].endswith(".0.0.0") and network[1].startswith("eth")
            ]
            invalidEthNetworkList = [
                network
                for network in networkList
                if network[0].endswith(".0.0.0") and network[1].startswith("eth")
            ]
            brNetworkList = [
                network
                for network in networkList
                if not network[0].endswith(".0.0.0")
                and not network[1].startswith("eth")
            ]
            invalidBrNetworkList = [
                network
                for network in networkList
                if network[0].endswith(".0.0.0") and not network[1].startswith("eth")
            ]
            if vlanNetworkList:
                print("has vlan ethernet")
                filterNetworkList = vlanNetworkList
                result = "normal"
            elif ethNetworkList:
                print("has ethernet")
                filterNetworkList = ethNetworkList
                result = "normal"
            elif invalidEthNetworkList:
                print("has ethernet and invalid IP")
                for (ip, dev, vlan, mac, brif) in invalidEthNetworkList:
                    filterNetworkList.append(("192.168.0.1", dev, vlan, mac, brif))
                result = "reload"
            elif brNetworkList:
                print("only has bridge interface")
                for (ip, dev, vlan, mac, brif) in brNetworkList:
                    if devList:
                        dev = devList.pop(0)
                        filterNetworkList.append((ip, dev, vlan, mac, brif))
                result = "bridge"
            elif invalidBrNetworkList:
                print("only has bridge interface and invalid IP")
                for (ip, dev, vlan, mac, brif) in invalidBrNetworkList:
                    if devList:
                        dev = devList.pop(0)
                        filterNetworkList.append(("192.168.0.1", dev, vlan, mac, brif))
                result = "bridgereload"

        else:
            print("[*] no network interface: bring up default network")
            filterNetworkList.append(("192.168.0.1", "eth0", None, None, "br0"))
            result = "default"
    else:  # if checkVariable("FIRMAE_NET"):
        filterNetworkList = networkList

    return filterNetworkList, result  # (network_type)


def readWebFlag(path):
    """True if the file written by check_emulation.sh says "true"."""
    try:
        with open(path) as f:
            return f.read().strip() == "true"
    except FileNotFoundError:
        return False


def process(iid, arch, endianness, makeQemuCmd=False, outfile=None):
    success = False

    global SCRIPTDIR
    global SCRATCHDIR

    with open(SCRATCHDIR + "/" + str(iid) + "/init") as f:
        inits = f.read().split("\n")[:-1]
    for init in inits:
        with open(SCRATCHDIR + "/" + str(iid) + "/current_init", "w") as out:
            out.write(init)
        inferred = inferNetwork(iid, arch, endianness, init)
        if inferred is None:  # unusable init candidate (see inferNetwork)
            continue
        qemuInitValue, networkList, targetFile, targetData, ports = inferred

        print("[*] ports: %r" % ports)
        # check network interfaces and add script in the file system
        # return the fixed network interface
        print("[*] networkInfo: %r" % networkList)
        filterNetworkList, network_type = checkNetwork(networkList)

        print("[*] filter network info: %r" % filterNetworkList)

        # filter ip
        # some firmware uses multiple network interfaces for one bridge
        # netgear WNDR3400v2-V1.0.0.54_1.0.82.zip - check only one IP
        # asus FW_RT_AC87U_300438250702
        # [('192.168.1.1', 'eth0', None, None), ('169.254.39.3', 'eth1', None, None), ('169.254.39.1', 'eth2', None, None), ('169.254.39.166', 'eth3', None, None)]

        if len(filterNetworkList) > MAX_NETWORKS:
            print("[!] Warning: %d networks found; only the first %d are used"
                  % (len(filterNetworkList), MAX_NETWORKS))
            filterNetworkList = filterNetworkList[:MAX_NETWORKS]

        if filterNetworkList:
            ips = [ip for (ip, dev, vlan, mac, brif) in filterNetworkList]
            ips = set(ips)
            with open(SCRATCHDIR + "/" + str(iid) + "/ip_num", "w") as out:
                out.write(str(len(ips)))

            for idx, ip in enumerate(ips):
                with open(SCRATCHDIR + "/" + str(iid) + "/ip." + str(idx), "w") as out:
                    out.write(str(ip))

            isUserNetwork = any(isDhcpIp(ip) for ip in ips)
            with open(SCRATCHDIR + "/" + str(iid) + "/isDhcp", "w") as out:
                if isUserNetwork:
                    out.write("true")
                else:
                    out.write("false")

            qemuCommandLine = qemuCmd(
                iid,
                filterNetworkList,
                ports,
                network_type,
                arch,
                endianness,
                qemuInitValue,
                isUserNetwork,
            )

            with open(outfile, "w") as out:
                out.write(qemuCommandLine)
            os.chmod(
                outfile,
                stat.S_IRWXU
                | stat.S_IRGRP
                | stat.S_IXGRP
                | stat.S_IROTH
                | stat.S_IXOTH,
            )

            # not os.system(): that ignores SIGINT while it waits
            subprocess.call(["./scripts/check_emulation.sh", str(iid), arch + endianness])

            if readWebFlag(SCRATCHDIR + "/" + str(iid) + "/web"):
                success = True
                break

        # restore infer network data
        # targetFile is None when init is preInit.sh; an empty original is not
        # written back (as before)
        if targetFile and targetData:
            targetDir = SCRATCHDIR + "/" + str(iid)
            loopFile = mountImage(targetDir)
            try:
                # the guest ran in between: re-check that the path still leads
                # to the same regular file inside the image
                (relPath, hostPath) = targetFile
                path = imageFile(targetDir + "/image", relPath, expected=hostPath)
                with openImageFile(path, "wb") as out:
                    out.write(targetData)
            except (UnsafeImagePath, ValueError) as e:
                print("[!] Warning: not restoring %s: %s" % (relPath, e))
            finally:
                umountImage(targetDir, loopFile)

    return success


def archEnd(value):
    arch = None
    end = None

    tmp = value.lower()
    if tmp.startswith("mips"):
        arch = "mips"
    elif tmp.startswith("arm"):
        arch = "arm"
    if tmp.endswith("el"):
        end = "el"
    elif tmp.endswith("eb"):
        end = "eb"
    return (arch, end)


def getWorkDir():
    if os.path.isfile("./firmae.config"):
        return os.getcwd()
    elif os.path.isfile("../firmae.config"):
        path = os.getcwd()
        return path[: path.rfind("/")]
    else:
        return None


def main():
    makeQemuCmd = False
    iid = None
    outfile = None
    arch = None
    endianness = None
    workDir = getWorkDir()
    if not workDir:
        raise Exception("Can't find firmae.config file")

    global SCRATCHDIR
    global SCRIPTDIR
    SCRATCHDIR = workDir + "/scratch"
    SCRIPTDIR = workDir + "/scripts"
    (opts, argv) = getopt.getopt(sys.argv[1:], "i:a:oqd")
    for (k, v) in opts:
        if k == "-d":
            global debug
            debug += 1
        if k == "-q":  # accepted for compatibility (pipeline.py passes it); no effect
            makeQemuCmd = True
        if k == "-i":
            iid = int(v)
        if k == "-o":
            outfile = True
        if k == "-a":
            (arch, endianness) = archEnd(v)

    if not arch or not endianness:
        raise Exception(
            "Either arch or endianness not found try mipsel/mipseb/armel/armeb"
        )

    if iid is None:
        raise Exception("No image id given (-i)")
    # `iid` alone was false for image 0: outfile stayed True and open(True)
    # wrote run.sh to file descriptor 1
    if outfile:
        outfile = """%s/%i/run.sh""" % (SCRATCHDIR, iid)
    if debug:
        print("processing %i" % iid)
    process(iid, arch, endianness, makeQemuCmd, outfile)


if __name__ == "__main__":
    # SIGTERM/SIGHUP -> SystemExit, so run_with_timeout() stops the emulation's
    # process group before we exit
    raise_on_sigterm()
    main()
