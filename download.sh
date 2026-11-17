#!/bin/sh

set -e

# Every download is checked against binaries.sha256 (sha256sum format).
#   FIRMAE_VERIFY_DOWNLOADS=warn   (default) a file whose hash is UNKNOWN / not listed is
#                                  kept, with a WARNING
#   FIRMAE_VERIFY_DOWNLOADS=strict a file whose hash is UNKNOWN / not listed is rejected
# A known hash that does not match is always an error (the download is deleted).
# binaries.sha256 is validated first, in both modes: every line must be UNKNOWN or 64 hex
# digits plus a bare file name (optional leading '*'), no duplicates; CRLF is tolerated.
# Anything else is an error before anything is downloaded.
# Files already present in ./binaries/ are verified too: a verified one is not
# downloaded again, a mismatching one is deleted and downloaded again.

cd -- "$(CDPATH= cd -- "$(dirname -- "$0")" >/dev/null && pwd)"

SUMS=binaries.sha256
MODE="${FIRMAE_VERIFY_DOWNLOADS:-warn}"
case "${MODE}" in
  warn|strict) ;;
  *) echo "ERROR: FIRMAE_VERIFY_DOWNLOADS must be 'warn' or 'strict', not '${MODE}'" >&2; exit 1 ;;
esac
if [ ! -f "${SUMS}" ]; then
  echo "ERROR: ${SUMS} not found" >&2
  exit 1
fi

# The current temporary download is removed on every way out (error, INT/TERM/HUP, normal exit).
CURRENT_TMP=
cleanup(){
  if [ -n "${CURRENT_TMP}" ]; then rm -f -- "${CURRENT_TMP}"; fi
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

# Reads and strictly validates ${SUMS} (before anything is downloaded, in every mode) into
# TABLE: one "<name> <lowercase hash|UNKNOWN>" line per entry. A trailing CR is ignored;
# a malformed or duplicate line is fatal, because a line that silently never matches
# would leave the file it was meant to protect "unverified".
CR=$(printf '\r')
TABLE=
load_sums(){
  n=0
  while IFS= read -r line || [ -n "${line}" ]; do
    n=$((n + 1))
    line=${line%"${CR}"}
    set -f
    set -- ${line}
    set +f
    if [ $# -eq 0 ]; then continue; fi
    case "$1" in '#'*) continue ;; esac
    h=$1
    f=${2-}
    bad=
    if [ $# -ne 2 ]; then bad="expected '<sha256>  <file name>'"; fi
    if [ -z "${bad}" ] && [ "${h}" != UNKNOWN ]; then
      if ! printf '%s\n' "${h}" | grep -Eq '^[0-9A-Fa-f]{64}$'; then
        bad="hash must be UNKNOWN or 64 hex digits"
      fi
    fi
    if [ -z "${bad}" ]; then
      f=${f#\*}
      if ! printf '%s\n' "${f}" | grep -Eq '^[A-Za-z0-9._+-]+$' || [ "${f}" = . ] || [ "${f}" = .. ]; then
        bad="file name must be a bare name ([A-Za-z0-9._+-]+)"
      fi
    fi
    if [ -z "${bad}" ]; then
      case "
${TABLE}" in
        *"
${f} "*) bad="duplicate entry for ${f}" ;;
      esac
    fi
    if [ -n "${bad}" ]; then
      echo "ERROR: ${SUMS}:${n}: ${bad}" >&2
      exit 1
    fi
    h=$(printf '%s' "${h}" | tr 'A-F' 'a-f')
    TABLE="${TABLE}${f} ${h}
"
  done < "${SUMS}"
}
load_sums
mkdir -p ./binaries

# prints the listed hash of file $1 (nothing if the file is not listed)
expected_hash(){
  while read -r f h; do
    if [ "$f" = "$1" ]; then
      echo "$h"
      return 0
    fi
  done <<EOF
${TABLE}
EOF
  return 0
}

# verify <path> <name>: 0 = matches, 1 = known hash differs, 2 = no known hash
verify(){
  want=$(expected_hash "$2")
  case "${want}" in ''|UNKNOWN) return 2 ;; esac
  got=$(sha256sum "$1" | cut -d' ' -f1)
  if [ "${got}" = "${want}" ]; then
    return 0
  fi
  return 1
}

download(){
  name=${1##*/}
  dest=./binaries/${name}
  tmp=./binaries/.${name}.part
  if [ -L "${dest}" ] || { [ -e "${dest}" ] && [ ! -f "${dest}" ]; }; then
    echo "ERROR: ${dest} exists and is not a regular file (or is a symlink); not touching it" >&2
    exit 1
  fi
  if [ -f "${dest}" ]; then
    rc=0
    verify "${dest}" "${name}" || rc=$?
    case ${rc} in
      0) echo "already present and verified: ${name}"; return 0 ;;
      1) echo "WARNING: ${name} does not match ${SUMS}; downloading it again" >&2
         rm -f "${dest}" ;;
      2) if [ "${MODE}" = strict ]; then
           echo "ERROR: unverified file: ${name} (no SHA-256 in ${SUMS}; FIRMAE_VERIFY_DOWNLOADS=strict)" >&2
           exit 1
         fi
         echo "WARNING: unverified existing file: ${name} (no SHA-256 in ${SUMS}); not downloaded again" >&2
         return 0 ;;
    esac
  fi
  rm -f "${tmp}"
  CURRENT_TMP=${tmp}
  if ! wget -O "${tmp}" "$1"; then
    rm -f "${tmp}"
    echo "ERROR: download failed: $1" >&2
    exit 1
  fi
  rc=0
  verify "${tmp}" "${name}" || rc=$?
  case ${rc} in
    0) mv -f "${tmp}" "${dest}" ;;
    1) rm -f "${tmp}"
       echo "ERROR: SHA-256 mismatch for ${name}: the download was deleted" >&2
       exit 1 ;;
    *) if [ "${MODE}" = strict ]; then
         rm -f "${tmp}"
         echo "ERROR: unverified download: ${name} (no SHA-256 in ${SUMS}; FIRMAE_VERIFY_DOWNLOADS=strict)" >&2
         exit 1
       fi
       echo "WARNING: unverified download: ${name} (no SHA-256 in ${SUMS})" >&2
       mv -f "${tmp}" "${dest}" ;;
  esac
  CURRENT_TMP=
}

echo "Downloading binaries..."

echo "Downloading kernel 2.6 (MIPS)..."
download https://github.com/pr0v3rbs/FirmAE_kernel-v2.6/releases/download/v1.0/vmlinux.mipsel.2
download https://github.com/pr0v3rbs/FirmAE_kernel-v2.6/releases/download/v1.0/vmlinux.mipseb.2

echo "Downloading kernel 4.1 (MIPS)..."
download https://github.com/pr0v3rbs/FirmAE_kernel-v4.1/releases/download/v1.0/vmlinux.mipsel.4
download https://github.com/pr0v3rbs/FirmAE_kernel-v4.1/releases/download/v1.0/vmlinux.mipseb.4

echo "Downloading kernel 4.1 (ARM)..."
download https://github.com/pr0v3rbs/FirmAE_kernel-v4.1/releases/download/v1.0/zImage.armel
download https://github.com/pr0v3rbs/FirmAE_kernel-v4.1/releases/download/v1.0/vmlinux.armel

echo "Downloading busybox..."
download https://github.com/pr0v3rbs/FirmAE/releases/download/v1.0/busybox.armel
download https://github.com/pr0v3rbs/FirmAE/releases/download/v1.0/busybox.mipseb
download https://github.com/pr0v3rbs/FirmAE/releases/download/v1.0/busybox.mipsel

echo "Downloading console..."
download https://github.com/pr0v3rbs/FirmAE/releases/download/v1.0/console.armel
download https://github.com/pr0v3rbs/FirmAE/releases/download/v1.0/console.mipseb
download https://github.com/pr0v3rbs/FirmAE/releases/download/v1.0/console.mipsel

echo "Downloading libnvram..."
download https://github.com/pr0v3rbs/FirmAE/releases/download/v1.0/libnvram.so.armel
download https://github.com/pr0v3rbs/FirmAE/releases/download/v1.0/libnvram.so.mipseb
download https://github.com/pr0v3rbs/FirmAE/releases/download/v1.0/libnvram.so.mipsel
download https://github.com/pr0v3rbs/FirmAE/releases/download/v1.0/libnvram_ioctl.so.armel
download https://github.com/pr0v3rbs/FirmAE/releases/download/v1.0/libnvram_ioctl.so.mipseb
download https://github.com/pr0v3rbs/FirmAE/releases/download/v1.0/libnvram_ioctl.so.mipsel

echo "Downloading gdb..."
download https://github.com/pr0v3rbs/FirmAE/releases/download/v1.0/gdb.armel
download https://github.com/pr0v3rbs/FirmAE/releases/download/v1.0/gdb.mipseb
download https://github.com/pr0v3rbs/FirmAE/releases/download/v1.0/gdb.mipsel

echo "Downloading gdbserver..."
download https://github.com/pr0v3rbs/FirmAE/releases/download/v1.0/gdbserver.armel
download https://github.com/pr0v3rbs/FirmAE/releases/download/v1.0/gdbserver.mipseb
download https://github.com/pr0v3rbs/FirmAE/releases/download/v1.0/gdbserver.mipsel

echo "Downloading strace..."
download https://github.com/pr0v3rbs/FirmAE/releases/download/v1.0/strace.armel
download https://github.com/pr0v3rbs/FirmAE/releases/download/v1.0/strace.mipseb
download https://github.com/pr0v3rbs/FirmAE/releases/download/v1.0/strace.mipsel

echo "Done!"
