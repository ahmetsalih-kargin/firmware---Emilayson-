"""debug.py: tap interface naming and socket timeouts (no real guest needed)."""

import socket
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(REPO))
debug = pytest.importorskip("debug")

LINK = """\
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq state UP
7: tap5_1: <BROADCAST,MULTICAST,UP> mtu 1500 qdisc pfifo_fast state DOWN
8: tap5_0@NONE: <BROADCAST,MULTICAST,UP> mtu 1500 qdisc pfifo_fast state DOWN
9: tap55_0: <BROADCAST,MULTICAST,UP> mtu 1500
10: tap5: <BROADCAST,MULTICAST,UP> mtu 1500
"""


def test_parse_tap_ifaces_matches_only_this_iid_and_sorts():
    assert debug.parse_tap_ifaces(LINK, 5) == ["tap5_0", "tap5_1"]
    assert debug.parse_tap_ifaces(LINK, 55) == ["tap55_0"]
    assert debug.parse_tap_ifaces(LINK, 6) == []
    assert debug.parse_tap_ifaces("garbage\n\n", 5) == []


def make_helper(tmp_path, monkeypatch):
    d = tmp_path / "scratch" / "5"
    d.mkdir(parents=True)
    (d / "name").write_text("fw\n")
    (d / "ip").write_text("127.0.0.1\n")
    monkeypatch.chdir(tmp_path)
    return debug.firmae_helper(5)


def test_tap_interface_defaults_to_first_tap_zero(tmp_path, monkeypatch):
    fh = make_helper(tmp_path, monkeypatch)

    def run(*a, **k):
        raise FileNotFoundError("no ip")

    monkeypatch.setattr(debug.subprocess, "run", run)
    assert fh.tap_interface() == "tap5_0"


def test_tcpdump_uses_real_interface_name(tmp_path, monkeypatch):
    fh = make_helper(tmp_path, monkeypatch)
    monkeypatch.setattr(fh, "tap_interface", lambda: "tap5_0")
    monkeypatch.setattr("builtins.input", lambda prompt: "-n port 80")
    called = []
    monkeypatch.setattr(debug.subprocess, "call", called.append)
    fh.tcpdump()
    assert called == [["sudo", "tcpdump", "-i", "tap5_0", "-n", "port", "80"]]


def test_silent_guest_times_out_instead_of_hanging(tmp_path, monkeypatch, capsys):
    fh = make_helper(tmp_path, monkeypatch)
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    port = srv.getsockname()[1]
    monkeypatch.setattr(debug, "NETCAT_TIMEOUT", 0.3)
    monkeypatch.setattr(debug.time, "sleep", lambda s: None)
    real_connect = socket.socket.connect
    monkeypatch.setattr(socket.socket, "connect", lambda s, addr: real_connect(s, ("127.0.0.1", port)))
    try:
        assert fh.sendrecv("ps\n") == ""     # server accepts but never answers
    finally:
        srv.close()
    out = capsys.readouterr().out
    assert "no reply from the guest" in out
    assert fh.netcatOn is False


def test_connect_failure_is_reported(tmp_path, monkeypatch, capsys):
    fh = make_helper(tmp_path, monkeypatch)
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    port = srv.getsockname()[1]
    srv.close()                                # nothing listens here
    real_connect = socket.socket.connect
    monkeypatch.setattr(socket.socket, "connect", lambda s, addr: real_connect(s, ("127.0.0.1", port)))
    fh.connect()
    assert fh.netcatOn is False
    assert "failed to connect netcat" in capsys.readouterr().out
