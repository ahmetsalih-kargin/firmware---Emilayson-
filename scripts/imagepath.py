#!/usr/bin/env python3
"""Resolve a path inside a mounted firmware image the way chroot would.

The firmware file system is untrusted. A plain `cp x ${IMAGE_DIR}/bin/a` on the
host follows symlinks with HOST semantics, so an image containing
`bin -> /usr/bin` makes the copy land in the host's /usr/bin (SECURITY.md S5).
Inside a chroot the same symlink would point to the image's own /usr/bin.

resolve_in_root() walks the path one component at a time, re-rooting absolute
symlink targets at `root` and clamping `..` at `root`, so the result is always
a path below `root` -- the location chroot would have used. Legitimate
firmware layouts (bin -> usr/bin, /var -> /tmp/var, ...) keep working.

CLI:  imagepath.py <root> <path-inside-image> [--no-follow-final]
"""

import os
import sys

MAX_SYMLINKS = 40   # same limit as the Linux kernel (ELOOP)


class SymlinkLoop(ValueError):
    pass


def _split(path):
    return [p for p in path.split("/") if p not in ("", ".")]


def resolve_in_root(root, path, follow_final=True):
    """Return the host path that `path` names inside the image mounted at `root`.

    follow_final=False leaves a symlink in the last component unresolved
    (like lstat), which is what `file` reports on.
    """
    root = os.path.realpath(root)
    todo = _split(path)
    done = []            # symlink-free components below root
    hops = 0
    while todo:
        name = todo.pop(0)
        if name == "..":
            if done:
                done.pop()
            continue
        candidate = os.path.join(root, *done, name)
        last = not todo
        if os.path.islink(candidate) and (follow_final or not last):
            hops += 1
            if hops > MAX_SYMLINKS:
                raise SymlinkLoop("too many levels of symbolic links: %s" % path)
            target = os.readlink(candidate)
            if target.startswith("/"):
                done = []
            todo = _split(target) + todo
            continue
        done.append(name)
    return os.path.join(root, *done)


def main(argv):
    if len(argv) not in (3, 4) or (len(argv) == 4 and argv[3] != "--no-follow-final"):
        sys.stderr.write("usage: %s <root> <path> [--no-follow-final]\n" % argv[0])
        return 2
    try:
        print(resolve_in_root(argv[1], argv[2], follow_final=len(argv) == 3))
    except SymlinkLoop as e:
        sys.stderr.write("Error: %s\n" % e)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
