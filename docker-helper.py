#!/usr/bin/env python3

import sys
import threading
import subprocess as sp
import time
import os
import signal
import json
import scripts.util as util
import multiprocessing as mp
import logging, coloredlogs
coloredlogs.install(level=logging.DEBUG)
coloredlogs.install(level=logging.INFO)
#rootLogger = logging.getLogger()
#rootLogger.setLevel(logging.DEBUG)


class DockerSetupError(Exception):
    """The container cannot be started as configured; the message says why."""


def daemon_has_apparmor():
    """True when the Docker daemon confines containers with AppArmor, False when
    it does not, None when that cannot be determined."""
    try:
        out = sp.check_output(["docker", "info", "--format", "{{json .SecurityOptions}}"],
                              stderr=sp.DEVNULL, timeout=60)
        options = json.loads(out.decode())
    except (sp.CalledProcessError, sp.TimeoutExpired, OSError, ValueError) as e:
        logging.debug("[*] docker info: %s", e)
        return None
    if not isinstance(options, list):
        return None
    return any(isinstance(o, str) and "name=apparmor" in o for o in options)


def apparmor_flags(daemon_apparmor, privileged, setting):
    """Extra `docker run` flags for AppArmor. Docker's default profile
    (docker-default) denies mount, which the narrowed container needs; on hosts
    with AppArmor (e.g. native Ubuntu) the user has to opt in to running the
    container unconfined (FIRMAE_DOCKER_APPARMOR=unconfined), which weakens it
    further. --privileged is unconfined anyway."""
    if privileged or not daemon_apparmor:
        return []
    if setting == "unconfined":
        logging.warning("[!] FIRMAE_DOCKER_APPARMOR=unconfined: the container runs "
                        "without AppArmor confinement (SECURITY.md S7)")
        return ["--security-opt", "apparmor=unconfined"]
    raise DockerSetupError(
        "the Docker daemon uses AppArmor, whose default container profile denies the "
        "mount FirmAE needs inside the container. Set FIRMAE_DOCKER_APPARMOR=unconfined "
        "to run the container without AppArmor (weaker), or FIRMAE_DOCKER_PRIVILEGED=1 "
        "for the old --privileged mode (much weaker); see SECURITY.md S7.")


class docker_helper:
    def __init__(self, firmae_root, remove_image=False):
        self.firmae_root = firmae_root
        self.count = 0
        self.last_core = None
        self.__sync_status()
        self.remove_image = remove_image
        self.daemon_apparmor = daemon_has_apparmor()

    def __sync_status(self):
        containers = self.get_container_list(with_pause=True)
        self.count = len(containers)
        logging.debug("[*] current core : {}".format(self.count))

    # All docker invocations use argument lists (no shell). Firmware file names
    # and brands are passed to the in-container bash as positional parameters,
    # never pasted into a command string (SECURITY.md S6).
    RUN_IN_CONTAINER = 'cd /work/FirmAE && ./run.sh "$1" "$2" "/work/firmwares/$3"'

    # database settings handed to the container when set on the host: the
    # password, and the port (FIRMAE_DB_PORT; unset = PostgreSQL's 5432). The
    # host side (get_iid below) reads the same variables through scripts/util.py.
    PASSED_ENV = ("FIRMAE_DB_PASSWORD", "FIRMAE_DB_PORT")

    def get_container_list(self, with_pause=False):
        lines = sp.check_output(["docker", "ps"]).decode().split('\n')[1:-1]
        ret = []
        for line in lines:
            if not with_pause and line.find("Paused") != -1:
                continue
            ret.append(line.split(" ")[-1])

        return ret[::-1]

    # Before the container is stopped: let the pipeline clean up after itself
    # (SIGTERM: it unmounts, detaches its loop devices, removes its TAPs), then
    # detach whatever loop device it attached and still holds. Loop devices are
    # the kernel's, not the container's: `docker stop` alone leaves an attached
    # one behind on the Docker host (measured).
    STOP_GRACE_SECONDS = 20
    RELEASE_LOOPS = 'cd /work/FirmAE && source ./firmae.config && release_container_loops'

    def stop_core(self, container_name):
        def in_container(argv, timeout):
            try:
                return sp.run(["docker", "exec", container_name] + argv,
                              stdout=sp.DEVNULL, stderr=sp.DEVNULL, timeout=timeout).returncode
            except (OSError, sp.SubprocessError) as e:
                logging.debug("[*] %s: %s: %s", container_name, argv[0], e)
                return None
        if in_container(["pkill", "-TERM", "-f", "python3 -m firmae"], 30) == 0:
            for _ in range(self.STOP_GRACE_SECONDS):
                if not self.pipeline_running(container_name):
                    break
                time.sleep(1)
        in_container(["bash", "-c", self.RELEASE_LOOPS], 60)
        return sp.check_output(["docker", "stop", container_name])

    def run_core(self, idx, mode, brand, firmware_path, docker_name):
        return self._run_core(idx, mode, brand, firmware_path, docker_name)[0]

    # Container privileges (SECURITY.md S7). FirmAE needs, inside the container:
    # loop devices (makeImage.sh & co. attach the image's partition with an
    # offset and mount it, e2fsck), TAP/VLAN interfaces and iptables rules
    # (emulate.sh) and the TUN device QEMU opens. Each entry below was found
    # necessary by experiment (without it: mount; tunctl/iptables/QEMU TAP;
    # losetup --find; /dev/net/tun; opening /dev/loopN fail). Everything else
    # stays at Docker's defaults, which already include MKNOD (the loop nodes
    # and fixImage.sh's mknod), SYS_CHROOT (makeImage.sh) and NET_RAW (ping).
    # The /dev/loopN nodes are made on demand by add_partition (firmae.config),
    # as the container has no udev. No kernel partitions (`--partscan`, block
    # major 259) are used: 259 is also the major of NVMe disks, and with it the
    # container could mknod and open the host's disk.
    # Residual risk: `b 7:* rmw` lets the container open EVERY loop device of the
    # Docker host (other containers' images, snaps, ...), not only its own.
    NARROW_FLAGS = (
        "--cap-add", "SYS_ADMIN",                # mount/umount of the image (losetup works without)
        "--cap-add", "NET_ADMIN",                # tunctl, ip link (VLAN), iptables
        "--device", "/dev/loop-control",         # losetup --find
        "--device", "/dev/net/tun",              # tunctl, QEMU's TAP
        "--device-cgroup-rule", "b 7:* rmw",     # /dev/loopN (also any other loop device!)
    )

    def run_argv(self, env_args, firmware_root, docker_name):
        """The `docker run` command line. FIRMAE_DOCKER_PRIVILEGED=1 restores
        the old, much weaker `--privileged -v /dev:/dev` (the container can then
        do anything the host's root can, including on every host device)."""
        mounts = ["-v", "{}:/work/FirmAE".format(self.firmae_root),
                  "-v", "{}:/work/firmwares".format(firmware_root)]
        privileged = os.environ.get("FIRMAE_DOCKER_PRIVILEGED") == "1"
        if privileged:
            logging.warning("[!] FIRMAE_DOCKER_PRIVILEGED=1: running %s with --privileged "
                            "and the host's /dev (SECURITY.md S7)", docker_name)
            flags = ["-v", "/dev:/dev"] + mounts + ["--privileged=true"]
        else:
            flags = (mounts + list(self.NARROW_FLAGS)
                     + apparmor_flags(self.daemon_apparmor, privileged,
                                      os.environ.get("FIRMAE_DOCKER_APPARMOR")))
        return (["docker", "run", "-dit", "--rm"] + env_args + flags
                + ["--name", docker_name, "fcore"])

    # How long to wait for the extractor to register the image in the database
    IID_WAIT_SECONDS = 300

    def _run_core(self, idx, mode, brand, firmware_path, docker_name):
        """Returns (docker_name, ok). ok is False when the pipeline itself
        failed (container, database, extraction); a firmware that simply does
        not emulate is a normal result and still ok."""
        firmware_root = os.path.dirname(firmware_path)
        firmware = os.path.basename(firmware_path)
        # passed by name only (`-e NAME`): the value never shows up in `ps`
        env_args = []
        for name in self.PASSED_ENV:
            if name in os.environ:
                env_args += ["-e", name]
        sp.check_output(self.run_argv(env_args, firmware_root, docker_name))
        logging.info("[*] {} emulation start!".format(docker_name))
        time.sleep(5)

        t0 = time.time()
        iid = -1
        if mode == "-d":
            # interactive: attach the terminal
            sp.call(["docker", "exec", "-it", docker_name, "bash", "-c",
                     self.RUN_IN_CONTAINER, "_", mode, brand, firmware])
        else:
            # background inside the container; output goes to scratch/<fw>.log
            sp.check_output(["docker", "exec", "-d", docker_name, "bash", "-c",
                             self.RUN_IN_CONTAINER + ' > "/work/FirmAE/scratch/$3.log" 2>&1',
                             "_", mode, brand, firmware])
        firmware_log = os.path.join(self.firmae_root, "scratch", firmware + ".log")

        if mode == "-r":
            sp.call(["docker", "exec", "-it", docker_name, "bash"])

        if mode in ["-r", "-d"]:
            return docker_name, True

        time.sleep(10)
        # the extractor registers the image in the database; wait for it
        iid = ""
        for _ in range(self.IID_WAIT_SECONDS):
            time.sleep(1)
            try:
                iid = util.get_iid(firmware_path, "127.0.0.1")
            except Exception as e:
                logging.debug("[*] %s get_iid: %s", docker_name, e)
                iid = ""
            if iid:
                break
            try:
                with open(firmware_log) as f:
                    f.readline()
                    last_line = f.readline()
            except OSError:
                last_line = ""
            if last_line.find("container failed") != -1:
                logging.error("[-] %s container failed to connect to the hosts' postgresql", docker_name)
                return docker_name, False

        if not iid:
            logging.error("[-] %s getting iid failed.", docker_name)
            return docker_name, False

        # check success of extractor
        tgz_path = os.path.join(self.firmae_root, "images", str(iid) + ".tar.gz")
        for i in range(300):
            time.sleep(1)
            if os.path.exists(tgz_path):
                break
        else:
            logging.error("[-] %s extraction failed.", docker_name)
            return docker_name, False

        # check
        emulation_result = self.check_result(firmware, docker_name, brand, iid, True, since=t0)
        time_elapsed = time.time() - t0

        work_dir = os.path.join(self.firmae_root, "scratch", str(iid))
        if os.path.exists(work_dir):
            with open(os.path.join(work_dir, 'time_elapsed'), 'w') as f:
                f.write("%0.4f\n" % (time_elapsed))

            os.rename(os.path.join(self.firmae_root, 'scratch',
                                   "{0}.log".format(firmware)),
                      os.path.join(work_dir, "{0}.log".format(firmware)))

            with open(os.path.join(work_dir, 'fullname'), 'w') as f:
                f.write("%s\n" % (firmware_path))

            if self.remove_image:
                image_name = os.path.join(work_dir, 'image.raw')
                if os.path.exists(image_name):
                    os.remove(image_name)

        if emulation_result:
            logging.info("[+] %s (%d) emulation finished. (%0.4fs)", docker_name, iid, time_elapsed)

            # analyses
            if mode == "-a":
                t1 = time.time()
                analyses_result = self.check_result(firmware, docker_name, brand, iid, False, since=t0)
                time_elapsed = time.time() - t1

                if analyses_result:
                    logging.info("[+] %s (%d) analysis finished. (%0.4fs)", docker_name, iid, time_elapsed)
                else:
                    logging.error("[-] %s (%d) analysis failed. (%0.4fs)", docker_name, iid, time_elapsed)

        else:
            logging.error("[-] %s (%d) emulation failed. (%0.4fs)", docker_name, iid, time_elapsed)

        return docker_name, True

    def run_command(self, core, cmd):
        """Run the user's own command string in a container (`-c` mode)."""
        result = '[-] failed'
        try:
            result = sp.check_output(["docker", "exec", core, "bash", "-c", cmd]).decode()
        except (sp.CalledProcessError, OSError) as e:
            logging.error("[-] %s: %s", core, e)

        return result

    def run_script(self, core, script):
        """Copy the user's script into a container's / and run it (`-s` mode)."""
        result = '[-] failed'
        try:
            sp.check_output(["docker", "cp", script, "{}:/".format(core)])
            result = sp.check_output(["docker", "exec", core,
                                      "/" + os.path.basename(script)]).decode()
        except (sp.CalledProcessError, OSError) as e:
            logging.error("[-] %s: %s", core, e)

        return result

    def check_result(self, firmware, docker_name, brand, iid, is_emulation=True, since=None):
        """Wait for the result file. With `since` (epoch seconds), a result
        file older than that belongs to a previous run and is ignored."""
        time.sleep(10) # wait until re-run
        if is_emulation:
            result_path = "{}/scratch/{}/result".format(self.firmae_root, iid)
            timeout = 2400
        else:
            result_path = "{}/scratch/{}/analysis_log/result".format(self.firmae_root, iid)
            timeout = 3600

        def read_result():
            try:
                if since is not None and os.path.getmtime(result_path) < since:
                    return None
                with open(result_path) as f:
                    return f.read().strip()
            except OSError:
                return None

        for i in range(timeout):
            time.sleep(1)
            result = read_result()
            if result is not None:
                return result == "true"
            # a pipeline that failed (e.g. makeImage.sh) writes no result file:
            # do not wait out the whole timeout for it
            if i % self.PIPELINE_CHECK_SECONDS == self.PIPELINE_CHECK_SECONDS - 1 \
                    and not self.pipeline_running(docker_name):
                result = read_result()      # it may have finished just now
                if result is not None:
                    return result == "true"
                logging.error("[-] %s: the pipeline ended without writing %s", docker_name, result_path)
                return False

        return False

    PIPELINE_CHECK_SECONDS = 15

    def pipeline_running(self, docker_name):
        """True while run.sh (`python3 -m firmae`) still runs in the container.
        When that cannot be determined (docker error), assume it still runs."""
        try:
            res = sp.run(["docker", "exec", docker_name, "pgrep", "-f", "python3 -m firmae"],
                         stdout=sp.DEVNULL, stderr=sp.DEVNULL, timeout=60)
        except (OSError, sp.SubprocessError):
            return True
        return res.returncode != 1      # pgrep: 1 = no such process

    def get_docker_tap_ip(self, docker_name):
        result = 'None'
        try:
            lines = sp.check_output(["docker", "exec", docker_name, "ip", "route"]).decode().strip().splitlines()
            result = lines[-1].split(' ')[0]
        except (sp.CalledProcessError, OSError, IndexError) as e:
            logging.error("[-] %s: %s", docker_name, e)

        return result

def print_usage(argv0):
    print("[*] Usage")
    print("sudo %s [-e, -c, -s] [brand] [firmwre_name]" % argv0)
    return

def runner(args):
    """Run one firmware. Returns True on success, False on failure; it does
    not raise for ordinary errors so a pool worker can report the result."""
    (idx, dh, mode, brand, firmware_path) = args
    if not os.path.isfile(firmware_path):
        logging.error("[-] Can't find firmware file: %s", firmware_path)
        return False

    firmware = os.path.basename(firmware_path)
    docker_name = 'docker{}_{}'.format(idx, firmware)
    ok = False
    try:
        ok = dh._run_core(idx, mode, brand, firmware_path, docker_name)[1]
    except DockerSetupError as e:
        logging.error("[-] %s: not started: %s", docker_name, e)
        return False
    except Exception:
        import traceback
        traceback.print_exc()
    finally:
        # also runs on Ctrl-C so the container is not left behind
        try:
            dh.stop_core(docker_name)
        except (sp.CalledProcessError, OSError) as e:
            logging.warning("[-] %s: could not stop container: %s", docker_name, e)
    return ok

def parse_firmware_list(lines):
    """Parse `brand,path` lines of a .list file; bad lines are skipped."""
    firmwares = []
    for no, line in enumerate(lines, 1):
        brand, sep, path = line.partition(',')
        if not sep or not brand.strip() or not path.strip():
            logging.warning("[-] list line %d skipped (expected 'brand,path'): %r", no, line)
            continue
        firmwares.append([brand, path])
    return firmwares

def main():
    if len(sys.argv) < 2:
        print_usage(sys.argv[0])
        exit(1)

    firmae_root=os.path.abspath('.')
    dh = docker_helper(firmae_root, remove_image=False)

    if sys.argv[1] in ['-ec', '-ea']:
        if len(sys.argv) < 4:
            print_usage(sys.argv[0])
            exit(1)

        if not os.path.exists(os.path.join(firmae_root, "scratch")):
            os.mkdir(os.path.join(firmae_root, "scratch"))

        brand = sys.argv[2]
        mode = '-' + sys.argv[1][-1]
        firmware_path = os.path.abspath(sys.argv[3])
        if os.path.isfile(firmware_path) and not firmware_path.endswith('.list'):
            argv = (0, dh, mode, brand, firmware_path)
            if not runner(argv):
                exit(1)

        elif os.path.isfile(firmware_path) and firmware_path.endswith('.list') \
            or os.path.isdir(firmware_path):
            # TODO: check number of firmwares

            if os.path.isdir(firmware_path):
                firmwares = []
                for directory, sub_directory, filename_list in os.walk(firmware_path):
                    for filename in filename_list:
                        firmwares.append([brand, os.path.join(directory, filename)])

            else:
                # this accepts firmware list file
                with open(firmware_path, 'r') as f:
                    firmwares = f.read().splitlines()
                firmwares = parse_firmware_list(firmwares)

            if not firmwares:
                logging.error("[-] No firmware to process")
                exit(1)

            num_cores = mp.cpu_count()
            if len(firmwares) < num_cores:
                num_cores = len(firmwares)

            logging.info("[*] Using %d cores ..." % (num_cores))
            t0 = time.time()

            p = mp.Pool(num_cores)
            results = []
            for idx, firmware in enumerate(firmwares):
                brand, firmware = firmware
                arg=(idx, dh, mode, brand, firmware)
                results.append((firmware, p.apply_async(runner, args=(arg,))))
                time.sleep(1)
            p.close()
            p.join()

            failed = []
            for firmware, res in results:
                try:
                    ok = res.get()
                except Exception as e:
                    logging.error("[-] %s: worker error: %s", firmware, e)
                    ok = False
                if not ok:
                    failed.append(firmware)

            logging.info("[*] Processing %d firmware done. (%0.4fs)",
                         len(firmwares), time.time() - t0)
            if failed:
                logging.error("[-] %d of %d firmware failed: %s",
                              len(failed), len(firmwares), ", ".join(failed))
                exit(1)

    elif sys.argv[1] in ['-er', '-ed']:
        if len(sys.argv) < 3:
            print_usage(sys.argv[0])
            exit(1)

        mode = '-' + sys.argv[1][-1]
        firmware_path = os.path.abspath(sys.argv[2])
        if os.path.isfile(firmware_path):
            argv = (0, dh, mode, "auto", firmware_path)
            if not runner(argv):
                exit(1)

    elif sys.argv[1] == '-c':
        if len(sys.argv) != 3:
            print_usage(sys.argv[0])
            exit(1)

        cmd = sys.argv[2]
        for core in dh.get_container_list():
            print(core)
            print(dh.run_command(core, cmd))

    elif sys.argv[1] == '-s':
        if len(sys.argv) != 3:
            print_usage(sys.argv[0])
            exit(1)

        script = sys.argv[2]
        for core in dh.get_container_list():
            print(core)
            print(dh.run_script(core, script))

if __name__ == "__main__":
    main()
