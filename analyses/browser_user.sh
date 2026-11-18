#!/bin/bash
# Sourced by analyses_all.sh when FIRMAE_BROWSER_USER is set (SECURITY.md S11):
# the web-UI initializer (selenium + headless Chrome, rendering the untrusted
# firmware web UI) runs as that unprivileged user instead of root, so
# initializer.py keeps Chrome's sandbox on (it adds --no-sandbox only as root or
# with FIRMAE_CHROME_NO_SANDBOX=1).
#
# Per run: a 0700 directory owned by the user below FIRMAE_BROWSER_TMP (default
# /var/tmp/firmae-browser; root-owned, not group/other writable, not a symlink)
# holds HOME, TMPDIR, SE_CACHE_PATH (selenium-manager) and Chrome's
# --user-data-dir (FIRMAE_BROWSER_PROFILE_DIR); it is removed afterwards. The
# user needs read access to analyses/ (initializer.py, chromedriver) and to the
# Python modules (selenium); this is checked before the run.

FIRMAE_BROWSER_TMP_DEFAULT=/var/tmp/firmae-browser
# setpriv is taken from a fixed place, not from PATH (BROWSER_SETPRIV: tests only)
BROWSER_SETPRIV="${BROWSER_SETPRIV:-/usr/bin/setpriv}"
BROWSER_SETSID="${BROWSER_SETSID:-/usr/bin/setsid}"
BROWSER_DIR=""
BROWSER_LOCK_FD=""
BROWSER_UID=""
BROWSER_GID=""

# browser_userns_warning [restrict_sysctl_file] [clone_sysctl_file]
# Chrome's sandbox needs unprivileged user namespaces (its setuid fallback does
# not work under --no-new-privs). Ubuntu 24.04 restricts them with AppArmor.
# Only a warning: FirmAE does not change system settings.
browser_userns_warning() {
    local restrict="${1:-/proc/sys/kernel/apparmor_restrict_unprivileged_userns}"
    local clone="${2:-/proc/sys/kernel/unprivileged_userns_clone}"
    local why=""
    if [ "${FIRMAE_CHROME_NO_SANDBOX:-}" = 1 ]; then
        return 0
    fi
    if [ -r "$restrict" ] && [ "$(cat -- "$restrict" 2>/dev/null)" = 1 ]; then
        why="kernel.apparmor_restrict_unprivileged_userns=1"
    elif [ -r "$clone" ] && [ "$(cat -- "$clone" 2>/dev/null)" = 0 ]; then
        why="kernel.unprivileged_userns_clone=0"
    fi
    if [ -z "$why" ]; then
        return 0
    fi
    echo "[!] ${why}: Chrome's sandbox needs unprivileged user namespaces; Chrome may fail to start"
    echo "    as '${FIRMAE_BROWSER_USER:-}'. FirmAE does not change system settings. Options:"
    echo "    1) an AppArmor profile that allows 'userns' for /opt/google/chrome/chrome"
    echo "       (see Ubuntu's apparmor 'unprivileged_userns' documentation), or"
    echo "    2) FIRMAE_CHROME_NO_SANDBOX=1: Chrome without its sandbox, still as the unprivileged user."
}

browser_fail() {
    echo "[-] FIRMAE_BROWSER_USER=${FIRMAE_BROWSER_USER:-}: $*; the initializer is not run (never as root instead)"
}

# browser_prepare <user>: sets BROWSER_UID, BROWSER_GID, BROWSER_DIR. Non-zero on error.
browser_prepare() {
    local user="$1" entry base mode
    if ! entry="$(getent passwd -- "$user")" || [ -z "$entry" ]; then
        browser_fail "no such user"
        return 2
    fi
    BROWSER_UID="$(printf '%s' "$entry" | cut -d: -f3)"
    BROWSER_GID="$(printf '%s' "$entry" | cut -d: -f4)"
    case "${BROWSER_UID}:${BROWSER_GID}" in
        *[!0-9:]*|:*|*:) browser_fail "unreadable passwd entry"; return 2 ;;
    esac
    if [ "$BROWSER_UID" -eq 0 ]; then
        browser_fail "uid 0 (root); use an unprivileged user or unset FIRMAE_BROWSER_USER"
        return 2
    fi
    if [ ! -x "$BROWSER_SETPRIV" ]; then
        browser_fail "$BROWSER_SETPRIV (util-linux) not found"
        return 2
    fi
    # setsid --wait (util-linux >= 2.31): new session, exit status passed back
    if [ ! -x "$BROWSER_SETSID" ] || ! "$BROWSER_SETSID" --help 2>&1 | grep -q -- '--wait'; then
        browser_fail "$BROWSER_SETSID with --wait (util-linux >= 2.31) not found"
        return 2
    fi
    base="${FIRMAE_BROWSER_TMP:-$FIRMAE_BROWSER_TMP_DEFAULT}"
    mkdir -m 0711 -- "$base" 2>/dev/null || true
    if [ -L "$base" ] || [ ! -d "$base" ] || [ "$(stat -c %u -- "$base")" != "$(id -u)" ]; then
        browser_fail "$base is not a directory owned by uid $(id -u) (symlink?); refusing to use it"
        return 2
    fi
    mode="$(stat -c %a -- "$base")"
    if (( 8#$mode & 8#022 )); then
        browser_fail "$base is group/other writable; refusing to use it"
        return 2
    fi
    chmod 0711 -- "$base"
    # All runs share the user's uid: one initializer at a time, and nothing of
    # an earlier one may still run (setsid: Ctrl-C does not reach its session).
    if ! exec {BROWSER_LOCK_FD}< "$base" ||
       ! flock -w "${FIRMAE_BROWSER_LOCK_WAIT:-3600}" "$BROWSER_LOCK_FD"; then
        browser_fail "another initializer as this user holds $base"
        browser_unlock
        return 2
    fi
    if ! browser_kill_user; then
        browser_fail "processes of the user survive SIGKILL"
        browser_unlock
        return 2
    fi
    if ! BROWSER_DIR="$(mktemp -d -- "$base/run.XXXXXXXX")"; then
        BROWSER_DIR=""
        browser_fail "cannot create a directory in $base"
        return 2
    fi
    # fresh directories, no process of the user exists yet: chown -R is safe here
    # (called as an `if` condition: set -e does not apply, so every step is checked)
    if ! mkdir -m 0700 -- "$BROWSER_DIR/profile" "$BROWSER_DIR/cache" "$BROWSER_DIR/tmp" ||
       ! chown -R -- "${BROWSER_UID}:${BROWSER_GID}" "$BROWSER_DIR" ||
       ! chmod 0700 -- "$BROWSER_DIR"; then
        browser_fail "cannot prepare $BROWSER_DIR"
        browser_cleanup
        return 2
    fi
    if ! browser_as test -r ./initializer.py -a -x ./initializer.py >/dev/null 2>&1; then
        browser_fail "cannot read/execute $(pwd)/initializer.py as that user (the FirmAE directory must be accessible to it)"
        browser_cleanup
        return 126
    fi
    return 0
}

# browser_as <command...>: the command as the browser user, with a fixed
# environment, in a new session (no controlling terminal: it can neither read
# root's tty through /dev/tty nor push input into it with TIOCSTI) and with
# stdin from /dev/null. stdout/stderr are the caller's (the log file).
browser_as() {
    local extra=()
    if [ -n "${FIRMAE_CHROME_NO_SANDBOX:-}" ]; then
        extra=("FIRMAE_CHROME_NO_SANDBOX=${FIRMAE_CHROME_NO_SANDBOX}")
    fi
    "$BROWSER_SETSID" --wait \
    "$BROWSER_SETPRIV" --reuid="$BROWSER_UID" --regid="$BROWSER_GID" --init-groups --no-new-privs -- \
        env -i PATH="${PATH}" LANG="${LANG:-C.UTF-8}" HOME="$BROWSER_DIR" TMPDIR="$BROWSER_DIR/tmp" \
        USER="$FIRMAE_BROWSER_USER" LOGNAME="$FIRMAE_BROWSER_USER" \
        SE_CACHE_PATH="$BROWSER_DIR/cache" FIRMAE_BROWSER_PROFILE_DIR="$BROWSER_DIR/profile" \
        "${extra[@]}" "$@" < /dev/null {BROWSER_LOCK_FD}<&-
}

# browser_kill_user: SIGKILL every process of the (dedicated) browser user and
# wait up to 10 s. Never uid 0 or our own uid (BROWSER_PKILL: tests only).
browser_kill_user() {
    local i
    case "${BROWSER_UID:-}" in ''|*[!0-9]*) return 0 ;; esac
    if [ "$BROWSER_UID" -eq 0 ]; then return 1; fi
    if [ "$BROWSER_UID" = "$(id -u)" ] && [ -z "${BROWSER_PKILL:-}" ]; then return 1; fi
    for i in $(seq 1 100); do
        if ! "${BROWSER_PGREP:-pgrep}" -U "$BROWSER_UID" >/dev/null 2>&1; then return 0; fi
        "${BROWSER_PKILL:-pkill}" -KILL -U "$BROWSER_UID" >/dev/null 2>&1 || true
        sleep 0.1
    done
    ! "${BROWSER_PGREP:-pgrep}" -U "$BROWSER_UID" >/dev/null 2>&1
}

browser_unlock() {
    if [ -n "${BROWSER_LOCK_FD:-}" ]; then
        exec {BROWSER_LOCK_FD}<&-
        BROWSER_LOCK_FD=""
    fi
}

browser_cleanup() {
    if [ -n "${BROWSER_LOCK_FD:-}" ]; then
        browser_kill_user || echo "[!] FIRMAE_BROWSER_USER=${FIRMAE_BROWSER_USER:-}: processes survive SIGKILL"
    fi
    if [ -n "${BROWSER_DIR:-}" ]; then
        rm -rf --one-file-system -- "$BROWSER_DIR" || true
        BROWSER_DIR=""
    fi
    browser_unlock
}
