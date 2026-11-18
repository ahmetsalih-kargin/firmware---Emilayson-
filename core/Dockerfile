FROM ubuntu:24.04
LABEL org.opencontainers.image.authors="Mingeun Kim <pr0v3rbs@kaist.ac.kr>, Minkyo Seo <0xsaika@gmail.com>"

# bypass tzdata (and other debconf) interaction; set before the first apt-get
# install, since tzdata can already be pulled in by the packages below
ENV DEBIAN_FRONTEND=noninteractive

# PEP 668: Ubuntu 24.04's Python is "externally managed" and pip refuses to
# install system-wide. FirmAE's pipeline runs as root with the system python3
# (run.sh, #!/usr/bin/env python3), so its packages must be visible there; a
# virtual environment would have to be forced onto PATH for every script. This
# image is disposable and single-purpose, so it opts in to pip's
# --break-system-packages (the same opt-in install.sh documents). Packages go
# to /usr/local, which comes first on sys.path. The pinned requirements are
# installed with --ignore-installed: otherwise pip tries to remove the apt copy
# of a package (measured: it deleted python3-psycopg2's files and failed with
# "Cannot uninstall beautifulsoup4 ... installed by debian"); with it, the apt
# copy stays intact (dpkg stays consistent) and the pinned copy shadows it.
# pip itself is not upgraded: the Debian pip 24.0 is good enough and an
# upgrade would replace files dpkg owns.
ENV PIP_BREAK_SYSTEM_PACKAGES=1

RUN apt-get update
RUN apt-get install -y apt-utils
RUN apt-get install -y wget tar bc psmisc ruby telnet
RUN apt-get install -y socat net-tools iputils-ping iptables iproute2 curl
RUN apt-get install -yy python3 python3-pip python3-dev

RUN apt-get install -y libpq-dev
# psycopg2 itself: python3-psycopg2 (apt, below) and the pinned psycopg2 from
# requirements.txt; the old unpinned `pip install psycopg2 psycopg2-binary`
# was overridden by that pin anyway, and both distributions write the same
# `psycopg2` package directory.

# fdisk (makeImage.sh) is a separate package that the ubuntu:24.04 base image
# does not contain (measured: makeImage.sh failed with "/sbin/fdisk: command not found")
RUN apt-get install -y busybox-static bash-static fakeroot git kpartx netcat-openbsd nmap python3-psycopg2 snmp uml-utilities util-linux fdisk vlan

# binwalk 2.3.4 from the Ubuntu archive (2.3.4+dfsg1, with python3-zombie-imp
# for Python 3.12) -- the same binwalk the Ubuntu 24.04 host-mode runs used.
# The upstream tarball's deps.sh no longer works on 24.04 (python3-crypto is
# gone, its pip calls hit PEP 668, and the sasquatch it builds fails with GCC 13).
RUN apt-get install -y binwalk python3-binwalk
RUN apt-get install -y mtd-utils gzip bzip2 tar arj lhasa p7zip p7zip-full cabextract fusecram cramfsswap squashfs-tools sleuthkit default-jdk cpio lzop lzma srecord zlib1g-dev liblzma-dev liblzo2-dev

# sasquatch (vendor squashfs variants; binwalk uses it for e.g. WNAP320), built
# like deps.sh did, but: -Werror is dropped (GCC 13 warns, e.g.
# -Wdangling-pointer in LzmaEnc.c) and -fcommon restores the pre-GCC-10
# behaviour its sources rely on (multiple definitions of globals).
# Pinned and verified: the sasquatch commit (master as of the 24.04 migration)
# and the squashfs-tools 4.3 tarball its build.sh would otherwise download
# unchecked (build.sh skips the download when the file is present).
ARG SASQUATCH_COMMIT=bd864a1b037bf57ca7d64a292a60ba0d6459611f
ARG SQUASHFS43_SHA256=0d605512437b1eb800b4736791559295ee5f60177e102e4d4ccd0ee241a5f3f6
RUN apt-get install -y build-essential && \
    git clone --quiet https://github.com/devttys0/sasquatch /tmp/sasquatch && \
    cd /tmp/sasquatch && \
    git -c advice.detachedHead=false checkout --quiet "$SASQUATCH_COMMIT" && \
    [ "$(git rev-parse HEAD)" = "$SASQUATCH_COMMIT" ] && \
    wget -q -O squashfs4.3.tar.gz https://downloads.sourceforge.net/project/squashfs/squashfs/squashfs4.3/squashfs4.3.tar.gz && \
    echo "$SQUASHFS43_SHA256  squashfs4.3.tar.gz" | sha256sum -c - && \
    sed -i 's/ -Werror//g' patches/patch0.txt && \
    EXTRA_CFLAGS="-fcommon -Wno-error" ./build.sh && \
    command -v sasquatch && \
    cd / && rm -rf /tmp/sasquatch

# jefferson (JFFS2) was installed by deps.sh as well. Exact versions (those of
# the first verified 24.04 image); their own dependencies are not pinned.
RUN python3 -m pip install python-lzo==1.15 cstruct==6.2 ubi_reader==0.8.16 jefferson==0.4.8
RUN apt-get install -y python3-magic unrar

# (openjdk-8-jdk is no longer installed: nothing in FirmAE runs java, and
# binwalk's `jar` comes from default-jdk above)

# for qemu
RUN apt-get install -y qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils

# for analyzer: install pinned python deps from the single source of truth.
# build-essential + libglib2.0-dev are needed to build bluepy (sdist-only).
RUN apt-get install -y build-essential libglib2.0-dev
COPY requirements.txt /tmp/requirements.txt
# requirements.txt has two parts. Everything above the marker line is imported
# by FirmAE's own code and MUST install (a failure fails the build). The part
# below it is not imported by FirmAE (presumably used by the analyses/
# routersploit submodule); some of those old pins do not install or work on
# Python 3.12, so they are installed best effort: the build goes on, prints a
# WARNING and lists them in /usr/local/share/firmae/pip-optional-failed.txt.
# Nothing is upgraded silently: a pin that fails is left out, not replaced.
# The core pins constrain this step (-c): without that, a dependency of these
# packages replaced the pinned requests 2.33.0 with the latest (measured).
RUN marker='^# Not imported by FirmAE' && \
    grep -q "$marker" /tmp/requirements.txt && \
    sed "/$marker/,\$d" /tmp/requirements.txt > /tmp/requirements-core.txt && \
    sed -n "/$marker/,\$p" /tmp/requirements.txt | grep -v -e '^#' -e '^[[:space:]]*$' > /tmp/requirements-optional.txt && \
    python3 -m pip install --no-cache-dir --ignore-installed -r /tmp/requirements-core.txt
# The pinned copies must be the ones that import (psycopg2 2.9.1 built on
# Python 3.12 but did not import, hence the pin 2.9.9): fail the build otherwise.
RUN python3 -c "import psycopg2, magic; assert psycopg2.__file__.startswith('/usr/local/'), psycopg2.__file__; assert magic.__file__.startswith('/usr/local/'), magic.__file__; print('pinned psycopg2', psycopg2.__version__)"
RUN mkdir -p /usr/local/share/firmae && \
    : > /usr/local/share/firmae/pip-optional-failed.txt && \
    if ! python3 -m pip install --no-cache-dir --ignore-installed -c /tmp/requirements-core.txt -r /tmp/requirements-optional.txt; then \
        while read -r req; do \
            python3 -m pip install --no-cache-dir --ignore-installed -c /tmp/requirements-core.txt "$req" || echo "$req" >> /usr/local/share/firmae/pip-optional-failed.txt; \
        done < /tmp/requirements-optional.txt; \
    fi && \
    if [ -s /usr/local/share/firmae/pip-optional-failed.txt ]; then \
        echo "WARNING: these pins from requirements.txt (not imported by FirmAE's own code) did not install:"; \
        cat /usr/local/share/firmae/pip-optional-failed.txt; \
    fi
# google chrome
# (the signing key lives in a dedicated keyring, referenced by signed-by)
RUN apt-get install -y gnupg
RUN wget -qO- https://dl.google.com/linux/linux_signing_key.pub | gpg --dearmor -o /usr/share/keyrings/google-chrome.gpg
RUN echo 'deb [arch=amd64 signed-by=/usr/share/keyrings/google-chrome.gpg] https://dl.google.com/linux/chrome/deb/ stable main' | tee /etc/apt/sources.list.d/google-chrome.list
RUN apt-get update
RUN apt-get install -y google-chrome-stable
RUN apt-get install -y ntfs-3g
# /bin is /usr/bin on 24.04 (merged /usr); do not fail if the link exists
RUN [ -e /bin/mount.ntfs-3g ] || ln -s /bin/ntfs-3g /bin/mount.ntfs-3g

COPY core/sudo /usr/bin/sudo
RUN chmod 755 /usr/bin/sudo

RUN mkdir -p /work/FirmAE
RUN mkdir -p /work/firmwares
COPY core/unstuff /usr/local/bin/

# build-time smoke test: the tools the pipeline needs are present and start
RUN python3 -c "import binwalk, magic, psycopg2, coloredlogs; print('python modules ok, psycopg2', psycopg2.__version__)" && \
    { binwalk --help 2>&1 || true; } | grep -q "Binwalk v" && \
    { sasquatch -h 2>&1 || true; } | grep -q SYNTAX && \
    { unsquashfs -help 2>&1 || true; } | grep -q SYNTAX && \
    qemu-system-arm --version && qemu-system-mips --version && qemu-system-mipsel --version && \
    qemu-img --version && \
    command -v tunctl && { tunctl -h > /dev/null 2>&1 || true; } && \
    which busybox bash-static kpartx losetup fdisk sfdisk mkfs.ext2 e2fsck dmsetup blockdev udevadm ip iptables curl ping socat

ENV USER=root
ENV FIRMAE_DOCKER=true
