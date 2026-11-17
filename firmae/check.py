"""Check of the inferred emulation (REFACTORING_PLAN 4.5): what
scripts/check_emulation.sh did in Bash.

    scripts/check_emulation.sh <image ID> <arch>
        -> exec python3 -I <installation>/firmae/check.py <$0> <image ID> <arch>

makeNetwork.py runs it once per init candidate (from the FirmAE directory),
ignores its exit status and reads only scratch/<IID>/web. It starts
scratch/<IID>/run.sh in the background (output: scratch/<IID>/emulation.log),
waits until the guest answers on its web port (TAP mode: the guest addresses in
ip.N, with ping; DHCP / user-network mode: only the loopback ports recorded in
scratch/<IID>/hostfwd, and only while this image's QEMU owns them), records the
result and stops exactly this image's emulation again.

Results (unchanged contract): ping, time_ping and ip are written only when
ping succeeded, web and time_web only when the web check did; each holds one
line ("true", the time in seconds, the address).

Everything read here (isDhcp, ip_num, ip.N, hostfwd) is derived from the
untrusted firmware and its serial log: every file is opened without following
a symlink, must be a regular file and is read only up to a bound; addresses
must be IPv4 addresses. Results are written without following symlinks.
"""

import errno
import ipaddress
import os
import re
import signal
import socket
import subprocess
import sys
import time

if not __package__:
    # Started as a file by scripts/check_emulation.sh (python3 -I .../firmae/check.py):
    # only the installation directory may provide `firmae`, and it comes LAST so
    # that it can never shadow the standard library (see firmae/qemu.py).
    _HERE = os.path.dirname(os.path.abspath(__file__))
    sys.path[:] = [p for p in sys.path if os.path.abspath(p or os.getcwd()) not in (_HERE, os.getcwd())]
    sys.path.append(os.path.dirname(_HERE))

from firmae import config, hostfwd, procutil  # noqa: E402
from firmae.errors import FirmAEError  # noqa: E402

EXIT_FAILURE = 1
SIGNAL_EXIT = {signal.SIGINT: 130, signal.SIGTERM: 143, signal.SIGHUP: 129}

INITIAL_WAIT = 10          # `sleep 10` after starting run.sh, and again in each check
CURL_MAX_TIME = "2"
PROBE_TIMEOUT = 30         # safety net only: curl stops after 2 s, `ping -c 1` after ~10 s
RUN_SH_WAIT = 30           # wait_for_exit ${RUN_PID} 30
STATE_FILES = ("ping", "time_ping", "ip", "web", "time_web")
LOG_FILE = "emulation.log"
MAX_IP_NUM_BYTES = 65536   # larger ip_num files count as garbled (0 addresses)
MAX_IP_BYTES = 4096        # larger ip.N files are ignored

O_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
O_DIRECTORY = getattr(os, "O_DIRECTORY", 0)
O_CLOEXEC = getattr(os, "O_CLOEXEC", 0)


class Clock:
    """Time source of the check; tests replace it to run without waiting.
    now(): whole seconds (`date +%s` in Bash), precise(): float seconds
    (`date +%s.%N`), sleep(s). Monotonic: a clock step cannot end or
    stretch the check."""

    def now(self):
        return int(time.monotonic())

    def precise(self):
        return time.monotonic()

    def sleep(self, seconds):
        time.sleep(seconds)


class Result:
    """The line "<IP|None> <ping> <web> <ping time> <web time>" of check_network."""

    def __init__(self, ip="None", ping=False, web=False, ping_time="-1", web_time="-1"):
        self.ip, self.ping, self.web, self.ping_time, self.web_time = ip, ping, web, ping_time, web_time

    def __repr__(self):
        return "%s %s %s %s %s" % (self.ip, str(self.ping).lower(), str(self.web).lower(),
                                   self.ping_time, self.web_time)


def _say(msg):
    sys.stdout.write(msg + "\n")
    sys.stdout.flush()


def _warn(msg):
    sys.stderr.write(msg + "\n")
    sys.stderr.flush()


def elapsed(t_end, t_start):
    """`echo "$t_end - $t_start" | bc` for two %s.%N values: 9 decimals, and bc
    writes no 0 before the point (".5")."""
    d = t_end - t_start
    if d == 0:
        return "0"
    s = "%.9f" % abs(d)
    if s.startswith("0."):
        s = s[1:]
    return ("-" if d < 0 else "") + s


def probe(argv):
    """Run one curl / ping: True on exit status 0. Output goes nowhere (as
    `--output /dev/null` / `> /dev/null`), stderr stays the caller's."""
    try:
        return subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                              timeout=PROBE_TIMEOUT).returncode == 0
    except subprocess.TimeoutExpired:
        return False
    except OSError as e:
        _warn("%s: %s" % (argv[0], "command not found" if isinstance(e, FileNotFoundError) else e.strerror))
        return False


def curl_tap(url):
    return ["curl", "--max-time", CURL_MAX_TIME, "--output", "/dev/null", "--silent", url]


def curl_hostfwd(url):
    return ["curl", "--noproxy", "*", "--max-time", CURL_MAX_TIME, "--output", "/dev/null", "--silent", url]


# ---------------------------------------------------------------- the two checks

_DEFAULT = object()


def check_network(ips, check_timeout, max_ips=config.DEFAULT_CHECK_MAX_IPS, clock=None, run=probe,
                  is_local=_DEFAULT):
    """check_network of firmae.config (TAP mode): up to `check_timeout` s for a
    web answer from one of the first `max_ips` addresses, pinging them too.
    An address that is assigned to this host when it is to be probed
    (is_local, default local_address_check(); None: no such check) is skipped
    with a warning: the answer would come from the host, not from the guest.
    The check ends when no address is left."""
    clock = clock or Clock()
    if is_local is _DEFAULT:
        is_local = local_address_check()
    ips = [ip for ip in ips if ip][:max_ips]
    r = Result()
    if not ips:
        return r
    clock.sleep(INITIAL_WAIT)
    warned = set()

    def local(ip):
        if is_local is None or not is_local(ip):
            return False
        if ip not in warned:
            warned.add(ip)
            _warn("[!] %s is an address of this host, not the guest's: not probed" % ip)
        return True
    start = clock.now()
    current = clock.now()
    t_start = clock.precise()
    while current <= start + check_timeout:
        if all([local(ip) for ip in ips]):
            break
        for ip in ips:
            if not local(ip):
                if run(curl_tap("http://%s" % ip)) or run(curl_tap("https://%s" % ip)):
                    t_end = clock.precise()
                    if not r.web:
                        r.web_time = elapsed(t_end, t_start)
                    if not r.ping:
                        r.ping_time = r.web_time
                    r.ping = r.web = True
                    r.ip = ip
                if run(["ping", "-c", "1", ip]):
                    t_end = clock.precise()
                    if not r.ping:
                        r.ping_time = elapsed(t_end, t_start)
                    r.ping = True
                    r.ip = ip
            clock.sleep(1)
            # after every address, not only every round
            current = clock.now()
            if not current <= start + check_timeout:
                break
        if r.web:
            break
    return r


def check_hostfwd(scratch_dir, iid, http, https, check_timeout, run_alive=None, clock=None, run=probe,
                  owned=hostfwd.owned_by_qemu):
    """check_hostfwd of hostfwd_check.sh (DHCP mode): probe only
    http://127.0.0.1:<http> and https://127.0.0.1:<https> -- never the host's
    own 80/443, never ping -- while this image's QEMU runs; stop as soon as the
    emulation is gone; an answer counts only from a port that QEMU listens on.
    ping is reported exactly when web is (with the web time)."""
    clock = clock or Clock()
    if http is None and https is None:
        return Result()
    clock.sleep(INITIAL_WAIT)
    start = clock.now()
    current = start
    t_start = clock.precise()
    web, wtime = False, "-1"
    while current <= start + check_timeout:
        state = hostfwd.emulation_state(scratch_dir, iid, run_alive)
        if state == "dead":
            _warn("[!] hostfwd: the emulation of image %s is not running (run.sh ended, no QEMU); web=false" % iid)
            break
        port = None
        if state == "running":
            if http is not None and run(curl_hostfwd("http://127.0.0.1:%d" % http)):
                port = http
            elif https is not None and run(curl_hostfwd("https://127.0.0.1:%d" % https)):
                port = https
        if port is not None:
            t_end = clock.precise()
            # the answer counts only if it came from this image's QEMU
            if owned(scratch_dir, iid, port):
                wtime = elapsed(t_end, t_start)
                web = True
            else:
                # kept from the Bash version: the first answer that does not count ends the check
                _warn("[!] hostfwd: the answer on 127.0.0.1:%d does not count; web check stopped (web=false)" % port)
            break
        clock.sleep(1)
        current = clock.now()
    if web:
        return Result("127.0.0.1", True, True, wtime, wtime)
    return Result()


# ---------------------------------------------------------------- state files

def read_state(dfd, name, limit):
    return hostfwd.read_regular_file(name, limit, dir_fd=dfd)


def is_dhcp(dfd):
    """makeNetwork.py writes exactly "true" or "false" to isDhcp."""
    data = read_state(dfd, "isDhcp", 4096)
    return data is not None and data.replace(b"\0", b"").strip() == b"true"


def ip_count(dfd, max_ips):
    """ip_num as check_emulation.sh read it: digits only (else 0), decimal
    ("08" is 8), more than 4 digits or more than max_ips -> max_ips."""
    data = read_state(dfd, "ip_num", MAX_IP_NUM_BYTES + 1)
    if data is None or len(data) > MAX_IP_NUM_BYTES:
        return 0
    text = data.replace(b"\0", b"").rstrip(b"\n")
    if re.fullmatch(rb"[0-9]+", text) is None:
        return 0
    if len(text) > 4 or int(text, 10) > max_ips:
        return max_ips
    return int(text, 10)


def _shown(token):
    """An untrusted token for a message: printable ASCII only, bounded."""
    r = repr(token[:64])
    return r + ("..." if len(token) > 64 else "")


_THIS_NETWORK = ipaddress.IPv4Network("0.0.0.0/8")
_BROADCAST = ipaddress.IPv4Address("255.255.255.255")


def unusable_guest_ip_reason(addr):
    """None for an address the host may probe as the guest's (private or
    public unicast), else why not. The same definition as isGuestIpv4 in
    scripts/makeNetwork.py and emu_guest_ipv4 in scripts/emulate.sh."""
    if addr == _BROADCAST:
        return "limited broadcast"
    if addr.is_loopback:
        return "loopback"
    if addr.is_unspecified or addr in _THIS_NETWORK:
        return "unspecified / this network (0.0.0.0/8)"
    if addr.is_multicast:
        return "multicast"
    if addr.is_link_local:
        return "link-local"
    if addr.is_reserved:
        return "reserved"
    return None


def usable_guest_ip(ip):
    try:
        return unusable_guest_ip_reason(ipaddress.IPv4Address(ip)) is None
    except ValueError:
        return False


def _nonlocal_bind():
    """net.ipv4.ip_nonlocal_bind: with it, bind() succeeds for any address and
    says nothing about which ones are local."""
    try:
        with open("/proc/sys/net/ipv4/ip_nonlocal_bind", "rb") as f:
            return f.read(16).strip() not in (b"", b"0")
    except OSError:
        return False


def host_has_address(ip):
    """True if `ip` is assigned to this host right now (as far as bind()
    tells): bind((ip, 0)) succeeds or fails with EADDRINUSE -> local,
    EADDRNOTAVAIL -> not local. Any other error counts as local (the probe
    is skipped rather than risk reaching the host itself)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.bind((ip, 0))
        return True
    except OSError as e:
        return e.errno != errno.EADDRNOTAVAIL
    finally:
        s.close()


def local_address_check():
    """host_has_address, or None if bind() cannot tell (ip_nonlocal_bind is
    on: every address would look local); then only the address classes and
    makeNetwork's guest/host collision check protect the host."""
    if _nonlocal_bind():
        _warn("[!] net.ipv4.ip_nonlocal_bind is on: cannot tell whether a guest address is local to the host")
        return None
    return host_has_address


def guest_ips(dfd, count):
    """Addresses from ip.0 .. ip.<count-1>, whitespace-separated as the Bash
    word splitting read them; only valid IPv4 addresses are kept, and of those
    only the ones the host may probe as the guest's (usable_guest_ip)."""
    ips = []
    for idx in range(count):
        name = "ip.%d" % idx
        data = read_state(dfd, name, MAX_IP_BYTES + 1)
        if data is None:
            continue
        if len(data) > MAX_IP_BYTES:
            _say("[!] %s is larger than %d bytes: ignored" % (name, MAX_IP_BYTES))
            continue
        for token in re.split(rb"[ \t\n]+", data.replace(b"\0", b"")):
            if not token:
                continue
            try:
                addr = ipaddress.IPv4Address(token.decode("ascii"))
            except (UnicodeDecodeError, ValueError):
                _say("[!] %s: %s is not an IPv4 address: skipped" % (name, _shown(token)))
                continue
            reason = unusable_guest_ip_reason(addr)
            if reason is not None:
                _say("[!] %s: %s is %s, not a guest address: skipped" % (name, addr, reason))
                continue
            ips.append(str(addr))
    return ips


def remove_state(dfd, name):
    """unlink() never follows the last component: a symlink is removed itself."""
    try:
        os.unlink(name, dir_fd=dfd)
    except FileNotFoundError:
        pass


def write_state(dfd, name, text):
    """Replace <work>/<name> by a new regular file holding `text`. O_EXCL|O_CREAT
    (plus O_NOFOLLOW) never follows a symlink: if something reappears between
    the unlink and the open, the write fails instead."""
    remove_state(dfd, name)
    fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o666, dir_fd=dfd)
    try:
        data = text.encode()
        while data:
            data = data[os.write(fd, data):]
    finally:
        os.close(fd)


# ---------------------------------------------------------------- run.sh

def _child_signals(mask):
    def setup():
        # what bash does for a background job without job control: SIGINT and
        # SIGQUIT ignored (they reach QEMU, which installs its own handlers)
        signal.signal(signal.SIGINT, signal.SIG_IGN)
        signal.signal(signal.SIGQUIT, signal.SIG_IGN)
        if mask is not None:
            signal.pthread_sigmask(signal.SIG_SETMASK, mask)
    return setup


def start_run_sh(work, dfd, ctx):
    """`${WORK_DIR}/run.sh > ${WORK_DIR}/emulation.log 2>&1 &`: same process
    group (Ctrl-C at the terminal reaches it as before), stdin /dev/null.
    Sets ctx.child; it stays None if run.sh could not be started (the error
    is in emulation.log, as bash put it there)."""
    path = "%s/run.sh" % work
    try:
        remove_state(dfd, LOG_FILE)
        log = os.open(LOG_FILE, os.O_WRONLY | os.O_CREAT | os.O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o666, dir_fd=dfd)
    except OSError as e:
        _warn("Error: cannot create %s/%s: %s; run.sh not started" % (work, LOG_FILE, e.strerror))
        return
    # a signal between fork and the assignment below must not leave run.sh
    # unknown to the cleanup: they stay blocked (pending) until ctx.child is set
    old = signal.pthread_sigmask(signal.SIG_BLOCK, set(SIGNAL_EXIT))
    try:
        try:
            ctx.child = subprocess.Popen([path], stdin=subprocess.DEVNULL, stdout=log, stderr=log,
                                         close_fds=True, preexec_fn=_child_signals(old))
        except OSError as e:
            os.write(log, ("%s: %s\n" % (path, e.strerror)).encode())
            _warn("[!] %s could not be started: %s" % (path, e.strerror))
    finally:
        os.close(log)
        signal.pthread_sigmask(signal.SIG_SETMASK, old)


# ---------------------------------------------------------------- main

class _Signalled(BaseException):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


class _Run:
    """What the cleanup needs; finish() may run once only."""

    def __init__(self, cfg, iid, clock):
        self.cfg, self.iid, self.clock = cfg, iid, clock
        self.child = None
        self.cleaning = False
        self.pending = None
        self.finished = False

    def alive(self):
        return self.child is not None and self.child.poll() is None

    def on_signal(self, signum, frame):
        code = SIGNAL_EXIT.get(signum, 128 + signum)
        if self.cleaning or self.pending is not None:
            # already stopping; the cleanup is bounded (QEMU grace + 30 s): let it finish
            if self.pending is None:
                self.pending = code
            return
        self.pending = code
        raise _Signalled(code)

    def finish(self):
        """Stop exactly this image's QEMU, let run.sh do its own cleanup
        (network teardown), SIGKILL it after RUN_SH_WAIT seconds."""
        self.cleaning = True
        if self.finished:
            return
        self.finished = True
        procutil.stop_qemu(self.cfg.SCRATCH_DIR, self.iid, sleep=self.clock.sleep)
        procutil.wait_for_exit(self.child, RUN_SH_WAIT, sleep=self.clock.sleep)


def _finish(ctx):
    """ctx.finish(), exactly once, even if the one _Signalled of the run
    arrives just before finish() has marked the run as cleaning (after
    _check returned): on_signal raises at most once per run (it sets
    ctx.pending first), so the second call cannot be interrupted and
    finish() itself has not got past its first statement yet."""
    try:
        ctx.finish()
    except _Signalled:
        ctx.finish()


def _check(cfg, iid, work, dfd, ctx):
    """Everything between starting run.sh and the cleanup; returns the exit status."""
    rc = 0
    start_run_sh(work, dfd, ctx)
    ctx.clock.sleep(INITIAL_WAIT)

    if is_dhcp(dfd):
        # user network: only the forwarded host ports in scratch/<IID>/hostfwd,
        # and only while this image's QEMU owns them
        ports = hostfwd.read_hostfwd("hostfwd", dir_fd=dfd)
        if ports is None:
            _say("[!] %s/hostfwd is missing or invalid: no web check (web=false)" % work)
            ports = (None, None)
        http, https = ports
        _say("[*] Waiting web service... on 127.0.0.1 port(s) %s/%s (guest 80/443): terminating after %d secs..."
             % (http if http is not None else "-", https if https is not None else "-", cfg.CHECK_TIMEOUT))
        r = check_hostfwd(cfg.SCRATCH_DIR, iid, http, https, cfg.CHECK_TIMEOUT, run_alive=ctx.alive, clock=ctx.clock)
    else:
        ips = guest_ips(dfd, ip_count(dfd, cfg.CHECK_MAX_IPS))
        _say("[*] Waiting web service... from %s: terminating after %d secs..." % (" ".join(ips), cfg.CHECK_TIMEOUT))
        r = check_network(ips, cfg.CHECK_TIMEOUT, cfg.CHECK_MAX_IPS, clock=ctx.clock)

    results = []
    if r.ping:
        results += [("ping", "true\n"), ("time_ping", "%s\n" % r.ping_time), ("ip", "%s\n" % r.ip)]
    if r.web:
        results += [("web", "true\n"), ("time_web", "%s\n" % r.web_time)]
    for name, text in results:
        try:
            write_state(dfd, name, text)
        except OSError as e:
            _warn("Error: cannot write %s/%s: %s" % (work, name, e.strerror))
            rc = EXIT_FAILURE
    return rc


def package_root():
    """The installation: parent of the firmae/ package that is running."""
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def main(argv=None, root=None, clock=None):
    """argv: [<name of the script for the usage line>, <image ID>, <arch>]."""
    argv = list(sys.argv[1:] if argv is None else argv)
    prog, args = (argv[0], argv[1:]) if argv else ("check_emulation.sh", [])
    if len(args) != 2:
        _say("%s: Usage: ./check_emulation.sh [iid] [arch]" % prog)
        return EXIT_FAILURE
    iid, _arch = args          # the architecture is accepted, as before, but not needed
    if re.fullmatch(r"[0-9]+", iid) is None:
        _warn("Error: Invalid image number!")
        return EXIT_FAILURE
    try:
        cfg = config.load(root or package_root())
    except FirmAEError as e:
        _say("Error: %s" % e.message)
        return EXIT_FAILURE
    work = "%s/%s" % (cfg.SCRATCH_DIR, iid)
    try:
        dfd = os.open(work, os.O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
    except OSError as e:
        _warn("Error: %s: %s (missing, a symlink or not a directory)" % (work, e.strerror))
        return EXIT_FAILURE

    clock = clock or Clock()
    ctx = _Run(cfg, iid, clock)
    previous = {sig: signal.getsignal(sig) for sig in SIGNAL_EXIT}
    rc = 0
    try:
        try:
            # inside the try: a signal right after a handler is installed is
            # handled like any other
            for sig in SIGNAL_EXIT:
                signal.signal(sig, ctx.on_signal)
            # results of an earlier run must not be read as this run's
            for name in STATE_FILES:
                try:
                    remove_state(dfd, name)
                except OSError as e:
                    _warn("[!] cannot remove %s/%s: %s" % (work, name, e.strerror))
            _say("===== Check inferred emulation start =====")
            _say("[*] Inferred network: terminating after %d secs..." % cfg.TIMEOUT)
            rc = _check(cfg, iid, work, dfd, ctx)
            # from here on a signal only records its exit status (on_signal):
            # it can no longer interrupt the cleanup below
            ctx.cleaning = True
        except _Signalled:
            pass                # ctx.pending holds the exit status
        finally:
            _finish(ctx)
    finally:
        for sig, handler in previous.items():
            signal.signal(sig, handler)
        os.close(dfd)
    if ctx.pending is not None:
        return ctx.pending
    _say("=====  Check inferred emulation end  =====")
    return rc


if __name__ == "__main__":
    sys.exit(main())
