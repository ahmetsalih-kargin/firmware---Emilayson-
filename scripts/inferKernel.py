#!/usr/bin/env python3

import sys
import os
import subprocess

IID = -1


def ParseInit(cmd, out):
    for item in cmd.split(" "):
        if item.find("init=/") != -1:
            out.write(item + "\n")


def ParseCmd():
    if not os.path.exists("scratch/" + IID + "/kernelCmd"):
        return
    with open("scratch/" + IID + "/kernelCmd") as f:
        out = open("scratch/{}/kernelInit".format(IID), "w")
        cmds = f.read()
        for cmd in cmds.split("\n")[:-1]:
            ParseInit(cmd, out)
        out.close()


def kernel_strings(path):
    """Lines of `strings <path>`, without a shell."""
    out = subprocess.run(["strings", path], stdout=subprocess.PIPE, check=True)
    return out.stdout.decode(errors="replace").splitlines()


if __name__ == "__main__":
    # execute only if run as a script
    IID = sys.argv[1]
    if not (IID.isascii() and IID.isdigit()):
        sys.exit("usage: inferKernel.py <numeric image id>")
    kernelPath = "./images/" + IID + ".kernel"
    lines = kernel_strings(kernelPath)

    # was: strings K | grep "Linux version" > scratch/IID/kernelVersion
    with open("scratch/" + IID + "/kernelVersion", "w") as f:
        f.writelines(l + "\n" for l in lines if "Linux version" in l)

    # was: strings K | grep "init=/" | sed -e 's/^"//' -e 's/"$//' > scratch/IID/kernelCmd
    def unquote(line):
        line = line[1:] if line.startswith('"') else line
        return line[:-1] if line.endswith('"') else line
    with open("scratch/" + IID + "/kernelCmd", "w") as f:
        f.writelines(unquote(l) + "\n" for l in lines if "init=/" in l)

    ParseCmd()
