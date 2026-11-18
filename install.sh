#!/bin/bash

# run from the project root no matter where the script is started from
cd -- "$(CDPATH= cd -- "$(dirname -- "$0")" >/dev/null && pwd)" || exit 1

sudo apt update
sudo apt install -y curl wget tar git ruby python3 python3-pip bc build-essential libglib2.0-dev

# BEGIN pep668
# PEP 668: on newer distributions (e.g. Ubuntu 24.04) the system Python is
# "externally managed" and pip refuses to install system-wide. FirmAE's pipeline runs
# as root with the system Python, so a virtual environment would not be seen by it;
# the only working option is pip's --break-system-packages, which is the user's
# decision (it may break distribution-managed Python packages). Opt in with
#   PIP_BREAK_SYSTEM_PACKAGES=1 ./install.sh      or
#   FIRMAE_PIP_ARGS=--break-system-packages ./install.sh
# FIRMAE_PIP_ARGS (default empty) is appended to every pip install below.
read -r -a PIP_EXTRA <<< "${FIRMAE_PIP_ARGS:-}"

# pip_user / pip_root: pip as the current user / as root (PIP_BREAK_SYSTEM_PACKAGES is
# passed through sudo, which would otherwise drop it)
pip_user() { python3 -m pip "$@" "${PIP_EXTRA[@]}"; }
pip_root() {
    local envs=()
    if [ -n "${PIP_BREAK_SYSTEM_PACKAGES:-}" ]; then envs=("PIP_BREAK_SYSTEM_PACKAGES=${PIP_BREAK_SYSTEM_PACKAGES}"); fi
    sudo env "${envs[@]}" python3 -m pip "$@" "${PIP_EXTRA[@]}"
}

# pip itself ignores EXTERNALLY-MANAGED inside a venv, so ask the interpreter that will
# run pip (same privileges): marker present AND not in a venv
python_externally_managed() {  # <command prefix...>: the python3 invocation to test
    [ "$("$@" -c 'import os,sys,sysconfig;print(sys.prefix==sys.base_prefix and os.path.exists(os.path.join(sysconfig.get_path("stdlib"),"EXTERNALLY-MANAGED")))' 2>/dev/null)" = "True" ]
}

pip_break_requested=0
if [ "${PIP_BREAK_SYSTEM_PACKAGES:-}" = 1 ]; then pip_break_requested=1; fi
for a in "${PIP_EXTRA[@]}"; do
    if [ "$a" = "--break-system-packages" ]; then pip_break_requested=1; fi
done
if [ "${pip_break_requested}" = 0 ] && { python_externally_managed python3 || python_externally_managed sudo python3; }; then
    echo "ERROR: this Python is externally managed (PEP 668); 'pip install' would be refused." >&2
    echo "install.sh installs FirmAE's Python packages system-wide, because the pipeline runs as root" >&2
    echo "with the system Python (a virtual environment would not be used by it). To go on, opt in to" >&2
    echo "pip's --break-system-packages explicitly, knowing that it may break distribution-managed" >&2
    echo "Python packages, and re-run install.sh with one of:" >&2
    echo "  PIP_BREAK_SYSTEM_PACKAGES=1 ./install.sh" >&2
    echo "  FIRMAE_PIP_ARGS=--break-system-packages ./install.sh" >&2
    echo "See README.md / TEST_REPORT.md for the known Ubuntu 24.04 issues." >&2
    exit 1
fi
# END pep668

pip_root install --upgrade pip
pip_root install coloredlogs

# for docker
sudo apt install -y docker.io
getent group docker >/dev/null || sudo groupadd docker
sudo usermod -aG docker "$USER"

# postgresql
sudo apt install -y postgresql
# the package does not start the service everywhere (containers, WSL without systemd),
# and psql/createdb below need it running; the final restart stays after the config edits
sudo service postgresql start || sudo /etc/init.d/postgresql start || true
# the password FirmAE's scripts use can be changed with FIRMAE_DB_PASSWORD (default: firmadyne)
# (psql substitutes :'pw' safely quoted from stdin, but not inside -c)
echo "CREATE USER firmadyne WITH PASSWORD :'pw';" | sudo -u postgres psql -v pw="${FIRMAE_DB_PASSWORD:-firmadyne}"
sudo -u postgres createdb -O firmadyne firmware
sudo -u postgres psql -d firmware < ./database/schema
# append a line only if it is not already there (re-running install.sh must not duplicate it)
append_once() {  # <line> <file>
    sudo -u postgres grep -qxF -- "$1" "$2" || echo "$1" | sudo -u postgres tee --append "$2"
}
for conf in /etc/postgresql/*/main/postgresql.conf; do
    append_once "listen_addresses = '172.17.0.1,127.0.0.1,localhost'" "$conf"
done
# Docker containers (172.17.0.0/24) may reach only the firmware DB as firmadyne,
# with a password. 'trust' for all databases/users would give every container on
# docker0 password-less superuser access (SECURITY.md S4). 'md5' also accepts
# scram-sha-256 stored passwords (PostgreSQL >= 14 default).
for hba in /etc/postgresql/*/main/pg_hba.conf; do
    append_once "host firmware firmadyne 172.17.0.0/24 md5" "$hba"
done
# listen_addresses includes 172.17.0.1, which exists only when the docker0 bridge
# is up: docker.io (installed above) should be running before PostgreSQL restarts,
# otherwise PostgreSQL starts with a warning but does not listen on 172.17.0.1
# (containers then cannot reach the database). The restart must also come after the
# edits above.
sudo systemctl start docker || true
sudo /etc/init.d/postgresql restart

sudo apt install -y libpq-dev
pip_user install psycopg2 psycopg2-binary

sudo apt install -y busybox-static bash-static fakeroot dmsetup kpartx netcat-openbsd nmap python3-psycopg2 snmp uml-utilities util-linux vlan iptables

# BEGIN unprivileged-users
# Optional (SECURITY.md S9, S11): dedicated system users for the firmware
# extractor and for the headless Chrome of the analyses. Not created by default;
# opt in with   FIRMAE_CREATE_USERS=1 ./install.sh
# and use them with
#   export FIRMAE_EXTRACT_USER=firmae-extract FIRMAE_BROWSER_USER=firmae-browser
# (setpriv comes with util-linux, installed above). Both users need read access
# to the Python modules they import (binwalk, magic, psycopg2 / selenium) and
# firmae-browser to the analyses/ directory.
if [ "${FIRMAE_CREATE_USERS:-0}" = 1 ]; then
    for firmae_user in firmae-extract firmae-browser; do
        if ! getent passwd "$firmae_user" >/dev/null; then
            sudo useradd --system --user-group --no-create-home --home-dir /nonexistent \
                --shell /usr/sbin/nologin "$firmae_user"
        fi
    done
fi
# END unprivileged-users

# for binwalk (clean up the download afterwards only if this run created it)
BINWALK_CLEANUP=0
if [ ! -e v2.3.4.tar.gz ] && [ ! -e binwalk-2.3.4 ]; then
    BINWALK_CLEANUP=1
fi
wget https://github.com/ReFirmLabs/binwalk/archive/refs/tags/v2.3.4.tar.gz && \
  tar -xf v2.3.4.tar.gz && \
  ( cd binwalk-2.3.4 && \
    sed -i 's/^install_ubireader//g' deps.sh && \
    sed -i 's/^REQUIRED_UTILS="wget tar python"/REQUIRED_UTILS="wget tar python3"/g' deps.sh && \
    echo y | ./deps.sh && \
    sudo python3 setup.py install ) && \
  if [ "${BINWALK_CLEANUP}" = 1 ]; then sudo rm -rf -- v2.3.4.tar.gz binwalk-2.3.4; fi
sudo apt install -y mtd-utils gzip bzip2 tar arj lhasa p7zip p7zip-full cabextract fusecram cramfsswap squashfs-tools sleuthkit default-jdk cpio lzop lzma srecord zlib1g-dev liblzma-dev liblzo2-dev unzip

sudo cp core/unstuff /usr/local/bin/

pip_user install python-lzo cstruct ubi_reader
sudo apt install -y python3-magic openjdk-8-jdk unrar

# for analyzer, initializer
sudo apt install -y python3-bs4
wget https://dl.google.com/linux/direct/google-chrome-stable_current_amd64.deb
sudo dpkg -i google-chrome-stable_current_amd64.deb; sudo apt -fy install
rm google-chrome-stable_current_amd64.deb
pip_user install -r ./analyses/routersploit/requirements.txt
( cd ./analyses/routersploit && patch -p1 < ../routersploit_patch )

# install FirmAE's pinned python deps last so they win over routersploit's
# older pins (e.g. requests==2.21.0, which would otherwise downgrade urllib3)
pip_user install -r ./requirements.txt

# for qemu
sudo apt install -y qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils

if ! test -e "./analyses/chromedriver"; then
    wget https://chromedriver.storage.googleapis.com/2.38/chromedriver_linux64.zip
    unzip chromedriver_linux64.zip -d ./analyses/
    rm -rf chromedriver_linux64.zip
fi
