#!/usr/bin/env python3
import os.path
import shlex
import subprocess
import signal
import sys
import time
import pdb
import re
from socket import *

version_info = sys.version_info
if version_info >= (3, 13):
    import telnetlib3 as telnetlib
else:
    import telnetlib

NETCAT_TIMEOUT = 5.0  # seconds; a dead guest must not hang the debugger


def parse_tap_ifaces(link_output, iid):
    """Names of the tap<iid>_<n> interfaces in `ip -o link` output, ordered by n."""
    found = []
    for line in link_output.splitlines():
        fields = line.split(":")
        if len(fields) < 2:
            continue
        name = fields[1].strip().split("@")[0]
        m = re.fullmatch(r"tap%d_(\d+)" % int(iid), name)
        if m:
            found.append((int(m.group(1)), name))
    return [name for _, name in sorted(found)]


class firmae_helper:
    def __init__(self, iid):
        self.iid = int(iid)
        with open("./scratch/%d/name" % iid) as f:
            self.targetName = f.read().strip()
        with open("./scratch/%d/ip" % iid) as f:
            self.targetIP = f.read().strip()
        self.telnetInit = False
        self.netcatOn = False

    def show_info(self):
        print("[*] firmware - %s" % self.targetName)
        print("[*] IP - %s" % self.targetIP)

    def connect(self):
        if not self.netcatOn:
            self.sock = socket(AF_INET, SOCK_STREAM)
            self.sock.settimeout(NETCAT_TIMEOUT)
            print("[*] connecting to netcat (%s:%d)" % (self.targetIP, 31337))
            try:
                self.sock.connect((self.targetIP, 31337))
            except timeout:
                print("[-] netcat connection timed out after %gs (is the guest running?)" % NETCAT_TIMEOUT)
                self.sock.close()
                return
            except OSError as e:
                print("[-] failed to connect netcat: %s" % e)
                self.sock.close()
                return
            self.netcatOn = True
            print("[+] netcat connected")

    def _drop_connection(self):
        self.netcatOn = False
        self.telnetInit = False
        self.sock.close()

    def sendrecv(self, cmd):
        self.connect()

        if self.netcatOn:
            try:
                self.sock.send(cmd.encode())
                time.sleep(1)
                return self.sock.recv(2048).decode(errors="replace")
            except timeout:
                print("[-] no reply from the guest within %gs (it may have died)" % NETCAT_TIMEOUT)
            except OSError as e:
                print("[-] netcat connection lost: %s" % e)
            self._drop_connection()
        return ""

    def send(self, cmd):
        self.connect()

        if self.netcatOn:
            try:
                self.sock.send(cmd.encode())
            except OSError as e:
                print("[-] netcat connection lost: %s" % e)
                self._drop_connection()

    def initalize_telnet(self):
        for command in [
            "/firmadyne/busybox mkdir -p /proc",
            "/firmadyne/busybox ln -sf /proc/mounts /etc/mtab",
            "/firmadyne/busybox mkdir -p /dev/pts",
            "/firmadyne/busybox mount -t devpts devpts /dev/pts",
        ]:
            self.send(command + "\n")
            time.sleep(0.1)
        self.telnetInit = True

    def connect_socat(self):
        argv = ['socat', '-', 'UNIX-CONNECT:./scratch/%d/run/serial1.sock' % self.iid]
        if os.getuid() != 0:
            argv.insert(0, 'sudo')
        subprocess.call(argv)

    def connect_shell(self):
        self.connect()

        if self.netcatOn:
            if not self.telnetInit:
                self.initalize_telnet()
            subprocess.call(["telnet", self.targetIP, "31338"])

    def show_processlist(self):
        print(self.sendrecv("ps\n"))

    def tap_interface(self):
        """First tap<iid>_<n> interface that exists, else tap<iid>_0."""
        try:
            out = subprocess.run(["ip", "-o", "link"], capture_output=True, text=True, timeout=10).stdout
        except (OSError, subprocess.SubprocessError):
            out = ""
        ifaces = parse_tap_ifaces(out, self.iid)
        return ifaces[0] if ifaces else "tap%d_0" % self.iid

    def tcpdump(self):
        iface = self.tap_interface()
        argument = input("sudo tcpdump -i %s " % iface)
        subprocess.call(["sudo", "tcpdump", "-i", iface] + shlex.split(argument))

    def file_transfer(self, target_filepath):
        file_name = os.path.basename(target_filepath)
        self.send("/firmadyne/busybox nc -lp 31339 > /firmadyne/%s &\n" % file_name)
        time.sleep(1)
        # file name and address are arguments, not shell text; the transfer runs in the background
        with open(target_filepath, "rb") as source:
            subprocess.Popen(["nc", self.targetIP, "31339"], stdin=source)
        while True:
            if self.sendrecv("ps\n").find("31339") != -1:
                time.sleep(1)
            else:
                break
        print("[*] transfer complete!")

    def run_gdbserver(self, PID, PORT=1337):
        print("[+] gdbserver at %s:%d attach on %s" % (self.targetIP, PORT, PID))
        print('[+] run "target remote %s:%d" in host gdb-multiarch' % (self.targetIP, PORT))
        self.send("/firmadyne/gdbserver %s:%d --attach %s\n" % (self.targetIP, PORT, PID))


def signal_handler(sig, frame):
    return


if __name__ == "__main__":
    signal.signal(signal.SIGINT, signal_handler)

    if sys.version[:1] != "3":
        # check python version is 3.X.X
        print("error : python version should be 3.X.X")
        exit(-1)
    elif len(sys.argv) != 2:
        print("usage: %s [iid]" % sys.argv[0])
        exit(-1)
    elif not sys.argv[1].isnumeric():
        # check iid is number
        print("error : iid should be number")
        exit(-1)
    elif not os.path.isdir("./scratch/%s" % (sys.argv[1])):
        print("error : invaild iid.")
        exit(-1)

    # initialize helper
    fh = firmae_helper(int(sys.argv[1]))
    fh.show_info()
    fh.connect()

    def menu():
        print("------------------------------")
        print("|       FirmAE Debugger      |")
        print("------------------------------")
        print("1. connect to socat")
        print("2. connect to shell")
        print("3. tcpdump")
        print("4. run gdbserver")
        print("5. file transfer")
        print("6. exit")

    while 1:
        menu()
        try:
            select = int(input("> "))
        except KeyboardInterrupt:
            break
        except:
            select = ""
            pass

        if select == 1:
            fh.connect_socat()
        if select == 2:
            fh.connect_shell()
        elif select == 3:
            fh.tcpdump()
        elif select == 4:
            fh.show_processlist()
            try:
                PID = input("[+] target pid : ")
            except KeyboardInterrupt:
                pass
            else:
                fh.run_gdbserver(PID)
        elif select == 5:
            target_filepath = input("[+] target file path : ")
            fh.file_transfer(target_filepath)
        elif select == 6:
            break
        print("\n")
