"""QEMU command lines. Step 4.2: the initial emulation that scripts/run.<arch>.sh
used to start (three near-identical Bash scripts) now lives here.

    python3 -m firmae.qemu initial <arch> <image ID> <QEMU_INIT>

scripts/run.<arch>.sh are thin wrappers around that line. No shell is involved:
every value is one element of an argument list, and the process ends in
os.execvpe(), so QEMU replaces this interpreter (same PID, same process group,
the caller's SIGINT/SIGKILL reach it directly and nothing is left in between).

The machine / disk / kernel / binary helpers are separate functions: the final
emulation template (scripts/makeNetwork.py) will reuse them.
"""

import errno
import glob
import os
import re
import signal
import sys

if not __package__:
    # Started as a file by scripts/run.<arch>.sh (python3 -I .../firmae/qemu.py):
    # only the installation directory may provide `firmae`, and it comes LAST so
    # that it can never shadow the standard library. Neither the working
    # directory nor this file's own directory (firmae/errors.py, config.py, ...
    # would hide stdlib/third-party modules of the same name) stays on sys.path.
    _HERE = os.path.dirname(os.path.abspath(__file__))
    sys.path[:] = [p for p in sys.path if os.path.abspath(p or os.getcwd()) not in (_HERE, os.getcwd())]
    sys.path.append(os.path.dirname(_HERE))

from firmae import config  # noqa: E402
from firmae.errors import FirmAEError  # noqa: E402

# keep in sync with check_arch() / get_qemu*() / get_kernel() in firmae.config
# (tests/unit/test_qemu_py.py runs both and compares them)
ARCHS = config.VALID_ARCHS

_QEMU_BINARY = {"armel": "qemu-system-arm", "mipseb": "qemu-system-mips", "mipsel": "qemu-system-mipsel"}
_QEMU_MACHINE = {"armel": "virt", "mipseb": "malta", "mipsel": "malta"}
_QEMU_DISK = {"armel": "/dev/vda1", "mipseb": "/dev/sda1", "mipsel": "/dev/sda1"}

_NANDSIM = "nandsim.parts=64,64,64,64,64,64,64,64,64,64"

EXIT_FAILURE = 1            # what the old scripts exited with (set -e, usage, bad arch)
EXIT_NOT_EXECUTABLE = 126   # as bash: found but not executable
EXIT_NOT_FOUND = 127        # as bash: command not found


class QemuError(Exception):
    def __init__(self, message, code=EXIT_FAILURE):
        super().__init__(message)
        self.code = code


# ---------------------------------------------------------------- shared helpers

def check_arch(arch):
    if arch not in ARCHS:
        raise QemuError("Error: Invalid architecture!")
    return arch


def check_iid(iid):
    """Image IDs are plain decimal numbers (check_number in firmae.config)."""
    if not isinstance(iid, str) or re.fullmatch(r"[0-9]+", iid) is None:
        raise QemuError("Error: Invalid image number!")
    return iid


def as_bool(name, value):
    """firmae.config evaluates `(${FIRMAE_NET})`, i.e. runs the command `true` or `false`."""
    if value not in ("true", "false"):
        raise QemuError("Error: %s must be 'true' or 'false', not %r" % (name, value))
    return value == "true"


def qemu_binary(arch):
    return _QEMU_BINARY[check_arch(arch)]


def qemu_machine(arch):
    return _QEMU_MACHINE[check_arch(arch)]


def qemu_disk(arch):
    """Root device the guest kernel sees."""
    return _QEMU_DISK[check_arch(arch)]


def kernel_path(arch, firmae_kernel, binary_dir):
    """get_kernel: binary_dir is BINARY_DIR of firmae.config (ends in '/', and the
    '/' that follows is kept: .../binaries//zImage.armel)."""
    check_arch(arch)
    if arch == "armel":
        return "%s/zImage.%s" % (binary_dir, arch)
    return "%s/vmlinux.%s.%s" % (binary_dir, arch, "4" if as_bool("FIRMAE_KERNEL", firmae_kernel) else "2")


def binary_dir_of(firmae_dir):
    return firmae_dir + "/binaries/"


def kernel_cmdline(arch, qemu_init, firmae_net, firmae_nvram, firmae_kernel, firmae_etc):
    return ("firmadyne.syscall=1 root=%s console=ttyS0 %s %s rw debug ignore_loglevel "
            "print-fatal-signals=1 FIRMAE_NET=%s FIRMAE_NVRAM=%s FIRMAE_KERNEL=%s FIRMAE_ETC=%s "
            "user_debug=31" % (qemu_disk(arch), _NANDSIM, qemu_init,
                               firmae_net, firmae_nvram, firmae_kernel, firmae_etc))


def sock_base(iid):
    """One loopback port range per image for the unused placeholder NICs
    (same formula as SOCK_BASE in the old scripts and placeholderPort() in
    makeNetwork.py). Bash arithmetic reads a leading 0 as octal."""
    digits = check_iid(iid)
    try:
        n = int(digits, 8) if len(digits) > 1 and digits[0] == "0" else int(digits)
    except ValueError:
        raise QemuError("value too great for base (error token is %r)" % digits)
    return 20000 + (n % 10000) * 4


# ---------------------------------------------------------------- initial emulation

def _initial_network(arch, firmae_net, base):
    nic = "virtio-net-device" if arch == "armel" else "e1000"
    out = []
    if firmae_net:
        # run.mipseb.sh numbered its user NICs net1..net4, the other two net0..
        # (an old copy-paste quirk, kept: the guest only sees NIC order)
        ids = range(1, 5) if arch == "mipseb" else range(0, 4 if arch == "mipsel" else 1)
        for i in ids:
            out += ["-device", "%s,netdev=net%d" % (nic, i), "-netdev", "user,id=net%d,restrict=on" % i]
    else:
        for i in range(4):
            out += ["-device", "%s,netdev=net%d" % (nic, i),
                    "-netdev", "socket,id=net%d,listen=127.0.0.1:%d" % (i, base + i)]
    return out


def build_initial_argv(arch, iid, qemu_init, *, firmae_net, firmae_nvram, firmae_kernel, firmae_etc,
                       binary_dir, scratch_dir):
    """argv (argv[0] = the QEMU binary) of the initial emulation. Pure: touches
    neither the file system nor the environment."""
    check_arch(arch)
    check_iid(iid)
    net = as_bool("FIRMAE_NET", firmae_net)
    base = sock_base(iid)       # always evaluated, as SOCK_BASE=$((...)) was
    work = "%s/%s" % (scratch_dir, iid)
    image = work + "/image.raw"
    append = kernel_cmdline(arch, qemu_init, firmae_net, firmae_nvram, firmae_kernel, firmae_etc)
    kernel = kernel_path(arch, firmae_kernel, binary_dir)

    argv = [qemu_binary(arch), "-m", "256", "-M", qemu_machine(arch), "-kernel", kernel]
    if arch == "armel":
        argv += ["-drive", "if=none,file=%s,format=raw,id=rootfs" % image,
                 "-device", "virtio-blk-device,drive=rootfs"]
    else:
        argv += ["-drive", "if=ide,format=raw,file=%s" % image]
    argv += ["-append", append,
             "-serial", "file:%s/qemu.initial.serial.log" % work,
             "-serial", "unix:%s/run/serial1.sock,server,nowait" % work,
             "-monitor", "unix:%s/run/monitor.sock,server,nowait" % work,
             "-display", "none"]
    return argv + _initial_network(arch, net, base)


def initial_env(arch, environ):
    """Environment of the QEMU process: the caller's, plus QEMU_AUDIO_DRV=none
    for ARM only (the MIPS scripts never set it)."""
    env = dict(environ)
    if arch == "armel":
        env["QEMU_AUDIO_DRV"] = "none"
    return env


def prepare_workdir(work_dir):
    """scratch/<IID>/run: private (0700) directory for the sockets; stale ones go."""
    run_dir = work_dir + "/run"
    os.makedirs(run_dir, exist_ok=True)
    os.chmod(run_dir, 0o700)
    for sock in glob.glob(glob.escape(run_dir) + "/*.sock"):
        try:
            os.remove(sock)
        except FileNotFoundError:
            pass


def _exec(argv, env):
    """Replace this process by QEMU. Python ignores SIGPIPE and SIGXFSZ; ignored
    signals survive exec, so give QEMU the dispositions a shell script would have."""
    sys.stdout.flush()
    sys.stderr.flush()
    for name in ("SIGPIPE", "SIGXFSZ"):
        if hasattr(signal, name):
            signal.signal(getattr(signal, name), signal.SIG_DFL)
    try:
        os.execvpe(argv[0], argv, env)
    except FileNotFoundError:
        raise QemuError("%s: command not found" % argv[0], EXIT_NOT_FOUND)
    except PermissionError:
        raise QemuError("%s: Permission denied" % argv[0], EXIT_NOT_EXECUTABLE)
    except OSError as e:
        raise QemuError("%s: %s" % (argv[0], e.strerror or errno.errorcode.get(e.errno, "error")))


def run_initial(arch, iid, qemu_init, root, environ=None, execute=_exec):
    """What run.<arch>.sh did. `execute` is replaceable for tests."""
    check_arch(arch)
    check_iid(iid)
    try:
        cfg = config.load(root)
    except FirmAEError as e:
        raise QemuError("Error: %s" % e.message)
    argv = build_initial_argv(arch, iid, qemu_init,
                              firmae_net=cfg.FIRMAE_NET, firmae_nvram=cfg.FIRMAE_NVRAM,
                              firmae_kernel=cfg.FIRMAE_KERNEL, firmae_etc=cfg.FIRMAE_ETC,
                              binary_dir=binary_dir_of(cfg.FIRMAE_DIR), scratch_dir=cfg.SCRATCH_DIR)
    try:
        prepare_workdir(cfg.scratch(iid))
    except OSError as e:
        raise QemuError("%s: %s" % (e.filename, e.strerror))
    return execute(argv, initial_env(arch, os.environ if environ is None else environ))


def package_root():
    """The directory holding firmae.config: parent of the firmae/ package that
    is running (the wrappers start qemu.py by its path, found from BASH_SOURCE, so the
    working directory plays no part)."""
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if len(argv) < 2 or argv[0] != "initial" or argv[1] not in ARCHS:
        sys.stderr.write("Error: Invalid architecture!\n" if len(argv) > 1 and argv[0] == "initial" else "")
        sys.stderr.write("Usage: python3 -m firmae.qemu initial {%s} <image ID> <QEMU_INIT>\n" % "|".join(ARCHS))
        return EXIT_FAILURE
    arch = argv[1]
    try:
        iid = argv[2] if len(argv) > 2 else ""
        if re.fullmatch(r"[0-9]+", iid) is None:
            print("Usage: run.%s.sh <image ID>" % arch)
            return EXIT_FAILURE
        if len(argv) < 4:     # `set -u`: ${2} unset
            sys.stderr.write("run.%s.sh: line 22: 2: unbound variable\n" % arch)
            return EXIT_FAILURE
        run_initial(arch, iid, argv[3], package_root())
    except QemuError as e:
        sys.stderr.write("%s\n" % e)
        return e.code
    return 0


if __name__ == "__main__":
    sys.exit(main())
