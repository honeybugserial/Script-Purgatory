#!/usr/bin/env python3
"""
Locate the helper executables SetupShucker uses.

Expected layout next to these scripts:

    bin\\innounp.exe
    bin\\7z.exe  +  bin\\7z.dll
    bin\\die\\diec.exe  (with the rest of the Detect It Easy folder)

Each tool is looked up in bin\\ and bin\\die\\ first, then on the PATH.

When compiled (PyInstaller / Nuitka) there are two bin\\ folders to check, in
this order:
    1. next to the .exe        - lets you swap in newer tools without rebuilding
    2. the bundle (_MEIPASS)   - what was packed in with --add-data / do.include
"""

import os
import shutil
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
FROZEN = bool(getattr(sys, "frozen", False))
EXE_DIR = os.path.dirname(os.path.abspath(sys.executable)) if FROZEN else HERE
BUNDLE_DIR = getattr(sys, "_MEIPASS", None) or HERE


def _bin_dirs():
    out = []
    for base in (EXE_DIR, BUNDLE_DIR, HERE):
        b = os.path.join(base, "bin")
        for d in (b, os.path.join(b, "die")):
            if d not in out:
                out.append(d)
    return out


SEARCH_DIRS = _bin_dirs()
BIN = SEARCH_DIRS[0]                     # where messages say the tools belong


def _lookup(name):
    for d in SEARCH_DIRS:
        p = os.path.join(d, name + ".exe")
        if os.path.isfile(p):
            return p
    return shutil.which(name + ".exe") or shutil.which(name)


def available(name):
    return _lookup(name) is not None


def find_tool(name, explicit=None, log=None):
    """Return the path of <name>.exe, or raise FileNotFoundError."""
    if explicit:
        if os.path.isfile(explicit):
            return os.path.abspath(explicit)
        raise FileNotFoundError(f"{name}: not found at {explicit}")
    found = _lookup(name)
    if found:
        return found
    raise FileNotFoundError(f"{name}.exe not found in {BIN} (or bin\\die) or on the PATH."
                            + (" Also looked in the bundled bin\\." if FROZEN else ""))


if __name__ == "__main__":
    for tool in sys.argv[1:] or ["innounp", "7z", "diec"]:
        try:
            print(f"{tool}: {find_tool(tool)}")
        except FileNotFoundError as e:
            print(f"{tool}: {e}")
