"""analyses/initializer.py passes --no-sandbox to Chrome only when running as root
or when FIRMAE_CHROME_NO_SANDBOX=1 (SECURITY.md S11). selenium is faked."""

import importlib
import os
import sys
import types

import pytest


class FakeOptions:
    def __init__(self):
        self.args = []
        self.binary_location = None

    def add_argument(self, a):
        self.args.append(a)


@pytest.fixture
def initializer(monkeypatch, repo_root):
    captured = {}

    class Driver:
        def __init__(self, options=None):
            captured["options"] = options

        def get(self, url):
            captured["url"] = url

    selenium = types.ModuleType("selenium")
    webdriver = types.ModuleType("selenium.webdriver")
    webdriver.ChromeOptions = FakeOptions
    webdriver.Chrome = Driver
    common = types.ModuleType("selenium.webdriver.common")
    keys = types.ModuleType("selenium.webdriver.common.keys")
    keys.Keys = object
    by = types.ModuleType("selenium.webdriver.common.by")
    by.By = object
    selenium.webdriver = webdriver
    for name, mod in (("selenium", selenium), ("selenium.webdriver", webdriver),
                      ("selenium.webdriver.common", common),
                      ("selenium.webdriver.common.keys", keys),
                      ("selenium.webdriver.common.by", by)):
        monkeypatch.setitem(sys.modules, name, mod)
    monkeypatch.syspath_prepend(str(repo_root / "analyses"))
    monkeypatch.delitem(sys.modules, "initializer", raising=False)
    mod = importlib.import_module("initializer")
    monkeypatch.setattr(mod.time, "sleep", lambda s: None)
    yield mod, captured
    sys.modules.pop("initializer", None)


def run_connect(mod, captured):
    mod.Initializer("dlink", "192.168.0.1").Connect()
    return captured["options"].args


def set_euid(monkeypatch, euid):
    monkeypatch.setattr(os, "geteuid", lambda: euid, raising=False)


def test_root_gets_no_sandbox(initializer, monkeypatch):
    mod, cap = initializer
    monkeypatch.delenv("FIRMAE_CHROME_NO_SANDBOX", raising=False)
    set_euid(monkeypatch, 0)
    args = run_connect(mod, cap)
    assert "--no-sandbox" in args and "--headless" in args


def test_non_root_keeps_the_sandbox(initializer, monkeypatch):
    mod, cap = initializer
    monkeypatch.delenv("FIRMAE_CHROME_NO_SANDBOX", raising=False)
    set_euid(monkeypatch, 1000)
    args = run_connect(mod, cap)
    assert "--no-sandbox" not in args and "--headless" in args


def test_env_override_disables_the_sandbox_for_non_root(initializer, monkeypatch):
    mod, cap = initializer
    set_euid(monkeypatch, 1000)
    monkeypatch.setenv("FIRMAE_CHROME_NO_SANDBOX", "1")
    assert "--no-sandbox" in run_connect(mod, cap)
    monkeypatch.setenv("FIRMAE_CHROME_NO_SANDBOX", "0")
    assert "--no-sandbox" not in run_connect(mod, cap)


def test_platform_without_geteuid_keeps_the_sandbox(initializer, monkeypatch):
    mod, cap = initializer
    monkeypatch.delenv("FIRMAE_CHROME_NO_SANDBOX", raising=False)
    monkeypatch.delattr(os, "geteuid", raising=False)
    assert "--no-sandbox" not in run_connect(mod, cap)


# FIRMAE_BROWSER_USER (analyses/browser_user.sh) sets FIRMAE_BROWSER_PROFILE_DIR

def test_profile_dir_becomes_user_data_dir(initializer, monkeypatch):
    mod, cap = initializer
    set_euid(monkeypatch, 1000)
    monkeypatch.delenv("FIRMAE_CHROME_NO_SANDBOX", raising=False)
    monkeypatch.setenv("FIRMAE_BROWSER_PROFILE_DIR", "/var/tmp/firmae-browser/run.x/profile")
    args = run_connect(mod, cap)
    assert "--user-data-dir=/var/tmp/firmae-browser/run.x/profile" in args
    assert "--no-sandbox" not in args


def test_no_profile_dir_no_user_data_dir(initializer, monkeypatch):
    mod, cap = initializer
    monkeypatch.delenv("FIRMAE_BROWSER_PROFILE_DIR", raising=False)
    assert not [a for a in run_connect(mod, cap) if a.startswith("--user-data-dir")]
    monkeypatch.setenv("FIRMAE_BROWSER_PROFILE_DIR", "")
    assert not [a for a in run_connect(mod, cap) if a.startswith("--user-data-dir")]


def test_relative_profile_dir_is_refused(initializer, monkeypatch):
    mod, cap = initializer
    monkeypatch.setenv("FIRMAE_BROWSER_PROFILE_DIR", "profile")
    with pytest.raises(SystemExit):
        run_connect(mod, cap)
