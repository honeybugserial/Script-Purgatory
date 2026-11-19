#!/usr/bin/env python3
"""
Helpers for files that are neither an MSI nor an Inno Setup installer:

  detect_with_die(path)   -> what Detect It Easy (diec.exe) says the file is
  unpack_with_7z(path, out_dir)  -> one level of extraction with 7-Zip
  find_installers(folder) -> the MSIs / Inno setups / other .exe files inside

Electron app installers (electron-builder NSIS) are handled by electron_extract.py.

All tools live in bin\\ next to these scripts: bin\\7z.exe + bin\\7z.dll and
bin\\die\\diec.exe (see bundled_tools.py).
"""

import json
import os
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import bundled_tools  # noqa: E402

OLE_MAGIC = b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1"
NO_WINDOW = 0x08000000 if os.name == "nt" else 0       # CREATE_NO_WINDOW


def _run(cmd, timeout=None):
    return subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8",
                          errors="replace", stdin=subprocess.DEVNULL, timeout=timeout,
                          creationflags=NO_WINDOW)


# --------------------------------------------------------------------------- #
# Detect It Easy
# --------------------------------------------------------------------------- #

def die_available():
    return bundled_tools.available("diec")


def _die_strings(node, out):
    """Collect human-readable detections from any DiE JSON layout (3.0x - 3.1x)."""
    if isinstance(node, dict):
        if isinstance(node.get("string"), str):
            out.append(node["string"].strip())
        elif node.get("name") and node.get("type"):
            ver = f"({node['version']})" if node.get("version") else ""
            info = f"[{node['info']}]" if node.get("info") else ""
            out.append(f"{node['type']}: {node['name']}{ver}{info}")
        for v in node.values():
            if isinstance(v, (dict, list)):
                _die_strings(v, out)
    elif isinstance(node, list):
        for v in node:
            _die_strings(v, out)


def detect_with_die(path, timeout=180):
    """Return a list of detection lines, e.g. ['Installer: NSIS(3.08)', ...]."""
    exe = bundled_tools.find_tool("diec")
    r = _run([exe, "-j", path], timeout=timeout)
    lines = []
    try:
        _die_strings(json.loads(r.stdout), lines)
    except ValueError:
        r = _run([exe, path], timeout=timeout)                 # older builds: plain text
        lines = [ln.strip() for ln in r.stdout.splitlines() if ln.strip()]
    seen, out = set(), []
    for ln in lines:
        if ln not in seen:
            seen.add(ln)
            out.append(ln)
    return out


def classify(lines):
    """Short verdict from DiE lines: 'msi', 'inno', 'archive', 'installer', or ''."""
    text = " ".join(lines).lower()
    if "inno setup" in text:
        return "inno"
    if "microsoft installer" in text or "windows installer" in text or ".msi" in text:
        return "msi"
    if any(k in text for k in ("sfx", "7-zip", "zip", "rar", "cab", "nsis", "nullsoft",
                               "archive", "wix", "burn")):
        return "archive"
    if "installer" in text:
        return "installer"
    return ""


# --------------------------------------------------------------------------- #
# 7-Zip
# --------------------------------------------------------------------------- #

def find_7z():
    return bundled_tools.find_tool("7z")


def sevenzip_available():
    return bundled_tools.available("7z")


def unpack_with_7z(path, out_dir, timeout=None, keep_duplicates=False):
    """Extract one level. Returns (ok, message).
    keep_duplicates: installers (NSIS especially) can hold several files with the
    same path, e.g. an x86 and an x64 foo.dll picked at install time. By default
    7-Zip overwrites, so only the last survives; with this set it keeps them all
    as foo.dll, foo_1.dll, foo_2.dll ... (-aou)."""
    exe = find_7z()
    os.makedirs(out_dir, exist_ok=True)
    # stdin closed + -p (empty password): fail instead of waiting for a prompt.
    mode = ["-aou"] if keep_duplicates else []
    r = _run([exe, "x", "-y", *mode, "-p", f"-o{out_dir}", path], timeout=timeout)
    tail = "\n".join((r.stdout + r.stderr).strip().splitlines()[-12:])
    if r.returncode in (0, 1):                     # 1 = warnings, files still extracted
        return True, tail
    return False, tail or f"7-Zip exit code {r.returncode}"


# --------------------------------------------------------------------------- #
# What is it? (cheap structural checks, no external tools)
# --------------------------------------------------------------------------- #

INNO_MANIFEST = b"JR.Inno.Setup"
NSIS_MAGIC = b"NullsoftInst"
SEVENZIP_MAGIC = b"7z\xBC\xAF\x27\x1C"


def _pe_layout(f):
    """(section names, overlay offset) of an open PE file, or None if not a PE."""
    import struct
    f.seek(0)
    head = f.read(0x40)
    if len(head) < 0x40 or head[:2] != b"MZ":
        return None
    pe = struct.unpack_from("<I", head, 0x3C)[0]
    f.seek(pe)
    hdr = f.read(24)
    if len(hdr) < 24 or hdr[:4] != b"PE\x00\x00":
        return None
    nsec = struct.unpack_from("<H", hdr, 6)[0]
    opt = struct.unpack_from("<H", hdr, 20)[0]
    f.seek(pe + 24 + opt)
    names, end = [], 0
    for _ in range(min(nsec, 96)):
        sec = f.read(40)
        if len(sec) < 40:
            break
        names.append(sec[:8].rstrip(b"\x00").decode("latin-1"))
        raw_size, raw_ptr = struct.unpack_from("<II", sec, 16)
        end = max(end, raw_ptr + raw_size)
    return names, end


def classify(path):
    """
    What kind of installer a file is, from its structure alone:
    'MSI', 'Inno Setup', 'Electron (NSIS)', 'NSIS', 'WiX Burn bundle',
    '7-Zip SFX', 'ZIP SFX', 'CAB SFX', 'InstallShield' - or None for a plain
    program / anything else. Reads only the headers and the start of the overlay.
    """
    try:
        size = os.path.getsize(path)
        with open(path, "rb") as f:
            head = f.read(8)
            if head == OLE_MAGIC:
                return "MSI" if path.lower().endswith((".msi", ".msp", ".msm")) else None
            lay = _pe_layout(f)
            if not lay:
                return None
            names, overlay = lay
            f.seek(0)
            image = f.read(min(overlay or size, 4 << 20))
            tail = b""
            if overlay and overlay < size:
                f.seek(overlay)
                tail = f.read(1 << 20)
    except OSError:
        return None
    import split_inno_arch
    if INNO_MANIFEST in image or split_inno_arch.INNO_SIGNATURE in tail:
        return "Inno Setup"
    if ".wixburn" in names:
        return "WiX Burn bundle"
    if NSIS_MAGIC in tail[:64 << 10]:
        try:
            import electron_extract
            if electron_extract.find_payloads(path):
                return "Electron (NSIS)"
        except Exception:
            pass
        return "NSIS"
    if tail[:6] == SEVENZIP_MAGIC or SEVENZIP_MAGIC in tail[:4096]:
        return "7-Zip SFX"
    if tail[:4] == b"PK\x03\x04":
        return "ZIP SFX"
    if tail[:4] == b"MSCF" or b"MSCF\x00\x00\x00\x00" in tail[:4096]:
        return "CAB SFX"
    if b"InstallShield" in image and len(tail) > 4096:
        return "InstallShield"
    return None


def find_nested(folder, max_depth=8):
    """
    Installers inside an unpacked folder, plus the plain programs next to them.
    [(path, rel, kind, size, is_installer)] - installers first (by size),
    then programs (kind 'Program'). Only .exe / .msi / .msp files are looked at.
    """
    out = []
    base_depth = folder.rstrip(os.sep).count(os.sep)
    for root, dirs, files in os.walk(folder):
        if root.count(os.sep) - base_depth >= max_depth:
            dirs[:] = []
        for name in files:
            if not name.lower().endswith((".exe", ".msi", ".msp")):
                continue
            p = os.path.join(root, name)
            kind = classify(p)
            try:
                size = os.path.getsize(p)
            except OSError:
                continue
            out.append((p, os.path.relpath(p, folder), kind or "Program", size, bool(kind)))
    out.sort(key=lambda x: (not x[4], -x[3]))
    return out


# --------------------------------------------------------------------------- #
# What came out
# --------------------------------------------------------------------------- #

def file_kind(path):
    try:
        with open(path, "rb") as f:
            head = f.read(8)
    except OSError:
        return None
    if head == OLE_MAGIC and path.lower().endswith(".msi"):
        return "MSI"
    if head[:2] == b"MZ" and path.lower().endswith(".exe"):
        import split_inno_arch
        return "Inno Setup" if split_inno_arch.looks_like_inno(path) else "EXE"
    return None


def find_installers(folder, max_depth=6):
    """[(path, kind, size)] sorted: MSI and Inno first, then other .exe by size."""
    found = []
    base_depth = folder.rstrip(os.sep).count(os.sep)
    for root, dirs, files in os.walk(folder):
        if root.count(os.sep) - base_depth >= max_depth:
            dirs[:] = []
        for name in files:
            if not name.lower().endswith((".msi", ".exe")):
                continue
            p = os.path.join(root, name)
            kind = file_kind(p)
            if kind:
                found.append((p, kind, os.path.getsize(p)))
    order = {"MSI": 0, "Inno Setup": 1, "EXE": 2}
    found.sort(key=lambda x: (order[x[1]], -x[2]))
    return found


if __name__ == "__main__":
    for f in sys.argv[1:]:
        lines = detect_with_die(f)
        print(f"{f}: {classify(lines) or '?'}")
        for ln in lines:
            print("   ", ln)
