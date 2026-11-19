#!/usr/bin/env python3
"""
Reconstruct a clean install tree for each target profile (architecture x Windows
version band) directly from a Windows Installer package (.msi).

This is the MSI counterpart of split_inno_arch.py. In an Inno extraction the
authority is install_script.iss [Files]; in an MSI it is the database itself:

    File               file key -> component, long file name, sequence
    Component          component -> directory, Condition, Attributes (0x100 = 64-bit)
    Directory          directory tree (DefaultDir "target:source", "short|long")
    FeatureComponents  component -> feature(s)
    Feature/Condition  feature levels, and conditions that change them (Level 0 = off)
    Property           default property values
    Media              which cabinet (embedded "#x.cab" or external x.cab) holds what

Files inside an MSI cabinet are stored under their File-table KEY, not their
real name, so extracting the cabinets ourselves gives an exact, collision-free
key -> bytes mapping (a lessmsi/admin-install tree can silently overwrite one
variant with another when two File rows share a destination).

For each profile the script evaluates every component condition and feature
condition with a small Windows Installer condition evaluator using three-valued
logic: properties it cannot know statically (set by AppSearch, custom actions,
or simply unknown) evaluate as UNKNOWN. Files whose inclusion depends on an
unknown are still included but flagged "conditional" in the manifest, with the
expression shown, so nothing is silently dropped. Pin values with --prop.

Many installers (security products especially) ship every architecture
unconditionally and pick drivers at runtime from custom actions. The MSI tables
cannot reveal that choice; --prune-by-pe applies a PE-header heuristic for it
(see the help text).

Usage:
    python split_msi_arch.py --msi kes_win.msi --dry-run
    python split_msi_arch.py --msi kes_win.msi --prune-by-pe
    python split_msi_arch.py --msi kes_win.msi --prop MsiNTProductType=1 --prop WINRE=

Backends (picked automatically):
    Windows        : msi.dll via ctypes + expand.exe. Standard library only.
    Linux / macOS  : msitools (msiinfo) + cabextract.
"""

import argparse
import os
import re
import shutil
import struct
import subprocess
import sys
import tempfile
from collections import OrderedDict, defaultdict
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import split_common as common  # noqa: E402
from split_common import PE_EXTS, pe_machine, prune_by_pe, write_profile  # noqa: E402,F401

# VersionNT values as Windows Installer reports them. Note: Windows Installer
# may report 603 on Windows 10/11 as well, so a ">= 1000" check can be dead.
NT_NAMES = {
    500: "win2000", 501: "winxp", 502: "win2003", 600: "winvista",
    601: "win7", 602: "win8", 603: "win81", 1000: "win10",
}

STANDARD_FOLDERS = {
    "AdminToolsFolder", "AppDataFolder", "CommonAppDataFolder", "CommonFiles64Folder",
    "CommonFilesFolder", "DesktopFolder", "FavoritesFolder", "FontsFolder",
    "LocalAppDataFolder", "MyPicturesFolder", "NetHoodFolder", "PersonalFolder",
    "PrintHoodFolder", "ProgramFiles64Folder", "ProgramFilesFolder", "ProgramMenuFolder",
    "RecentFolder", "SendToFolder", "StartMenuFolder", "StartupFolder", "System16Folder",
    "System64Folder", "SystemFolder", "TempFolder", "TemplateFolder", "WindowsFolder",
    "WindowsVolume",
}

COMP_ATTR_64BIT = 0x0100
FILE_ATTR_NONCOMPRESSED = 0x2000
FILE_ATTR_COMPRESSED = 0x4000

ARCH_NAME_RE = re.compile(r'(?i)(?:^|[_\-.\\])(x64|x86|amd64|arm64|ia64|win32|i386)(?:$|[_\-.\\])')


# --------------------------------------------------------------------------- #
# Database backends
# --------------------------------------------------------------------------- #

def _idt_unescape(s):
    return s.replace("\x11", "\r").replace("\x19", "\n").replace("\x10", "\t")


class MsitoolsBackend:
    """msitools (msiinfo) + cabextract. Linux / macOS / WSL."""

    name = "msitools"

    def __init__(self, msi_path):
        self.msi = msi_path
        for tool in ("msiinfo", "cabextract"):
            if not shutil.which(tool):
                raise RuntimeError(f"'{tool}' not found on PATH "
                                   f"(install msitools and cabextract)")
        out = subprocess.run(["msiinfo", "tables", msi_path], capture_output=True,
                             text=True, check=True).stdout
        self._tables = {t.strip() for t in out.splitlines() if t.strip()}

    def has_table(self, name):
        return name in self._tables

    def table(self, name):
        if not self.has_table(name):
            return []
        raw = subprocess.run(["msiinfo", "export", self.msi, name],
                             capture_output=True, check=True).stdout
        text = raw.decode("utf-8", errors="replace")
        lines = text.replace("\r\n", "\n").split("\n")
        if len(lines) < 3:
            return []
        cols = lines[0].split("\t")
        rows = []
        for ln in lines[3:]:
            if not ln:
                continue
            vals = [_idt_unescape(v) for v in ln.split("\t")]
            vals += [""] * (len(cols) - len(vals))
            rows.append(dict(zip(cols, vals)))
        return rows

    def summary(self):
        out = subprocess.run(["msiinfo", "suminfo", self.msi], capture_output=True,
                             text=True, check=True).stdout
        info = {}
        for ln in out.splitlines():
            if ":" in ln:
                k, v = ln.split(":", 1)
                info[k.strip().lower()] = v.strip()
        template = info.get("template", "")
        wc = info.get("word count", info.get("source", "0"))
        m = re.match(r'\s*(\d+)', wc)
        return template, int(m.group(1)) if m else 0

    def extract_stream(self, stream, dest):
        with open(dest, "wb") as f:
            subprocess.run(["msiinfo", "extract", self.msi, stream], stdout=f, check=True)

    def extract_cab(self, cab, dest_dir):
        subprocess.run(["cabextract", "-q", "-d", dest_dir, cab], check=True)


class WindowsMsiBackend:
    """msi.dll through ctypes + expand.exe. Windows, standard library only."""

    name = "msi.dll"

    def __init__(self, msi_path):
        import ctypes
        from ctypes import wintypes
        self.ct = ctypes
        self.msi_path = msi_path
        dll = ctypes.WinDLL("msi.dll")
        H = ctypes.c_ulong
        P = ctypes.POINTER
        sig = {
            "MsiOpenDatabaseW": ([wintypes.LPCWSTR, wintypes.LPCWSTR, P(H)]),
            "MsiDatabaseOpenViewW": ([H, wintypes.LPCWSTR, P(H)]),
            "MsiViewExecute": ([H, H]),
            "MsiViewFetch": ([H, P(H)]),
            "MsiViewGetColumnInfo": ([H, ctypes.c_int, P(H)]),
            "MsiRecordGetFieldCount": ([H]),
            "MsiRecordGetStringW": ([H, ctypes.c_uint, wintypes.LPWSTR, P(wintypes.DWORD)]),
            "MsiRecordReadStream": ([H, ctypes.c_uint, ctypes.c_char_p, P(wintypes.DWORD)]),
            "MsiCloseHandle": ([H]),
            "MsiGetSummaryInformationW": ([H, wintypes.LPCWSTR, ctypes.c_uint, P(H)]),
            "MsiSummaryInfoGetPropertyW": ([H, ctypes.c_uint, P(ctypes.c_uint), P(ctypes.c_int),
                                            P(wintypes.FILETIME), wintypes.LPWSTR,
                                            P(wintypes.DWORD)]),
        }
        for fn, args in sig.items():
            f = getattr(dll, fn)
            f.argtypes = args
            f.restype = ctypes.c_uint
        self.dll, self.H, self.wt = dll, H, wintypes
        self.db = H()
        rc = dll.MsiOpenDatabaseW(msi_path, None, ctypes.byref(self.db))  # NULL = read-only
        if rc:
            raise RuntimeError(f"MsiOpenDatabase failed ({rc})")
        self._tables = {r["Name"] for r in self._query("SELECT `Name` FROM `_Tables`")}

    def _rec_str(self, rec, i):
        n = self.wt.DWORD(0)
        buf = self.ct.create_unicode_buffer(1)
        rc = self.dll.MsiRecordGetStringW(rec, i, buf, self.ct.byref(n))
        if rc == 234:  # ERROR_MORE_DATA
            n.value += 1
            buf = self.ct.create_unicode_buffer(n.value)
            rc = self.dll.MsiRecordGetStringW(rec, i, buf, self.ct.byref(n))
        return buf.value if rc == 0 else ""

    def _query(self, sql):
        ct, dll = self.ct, self.dll
        view = self.H()
        if dll.MsiDatabaseOpenViewW(self.db, sql, ct.byref(view)):
            return []
        try:
            dll.MsiViewExecute(view, 0)
            colrec = self.H()
            dll.MsiViewGetColumnInfo(view, 0, ct.byref(colrec))  # MSICOLINFO_NAMES
            ncol = dll.MsiRecordGetFieldCount(colrec)
            cols = [self._rec_str(colrec, i) for i in range(1, ncol + 1)]
            dll.MsiCloseHandle(colrec)
            rows = []
            while True:
                rec = self.H()
                if dll.MsiViewFetch(view, ct.byref(rec)):  # 259 = no more items
                    break
                rows.append({c: self._rec_str(rec, i + 1) for i, c in enumerate(cols)})
                dll.MsiCloseHandle(rec)
            return rows
        finally:
            dll.MsiCloseHandle(view)

    def has_table(self, name):
        return name in self._tables

    def table(self, name):
        return self._query(f"SELECT * FROM `{name}`") if self.has_table(name) else []

    def summary(self):
        ct, wt, dll = self.ct, self.wt, self.dll
        h = self.H()
        if dll.MsiGetSummaryInformationW(self.db, None, 0, ct.byref(h)):
            return "", 0

        def prop(pid):
            dt, iv, ft = ct.c_uint(), ct.c_int(), wt.FILETIME()
            n = wt.DWORD(512)
            buf = ct.create_unicode_buffer(512)
            dll.MsiSummaryInfoGetPropertyW(h, pid, ct.byref(dt), ct.byref(iv), ct.byref(ft),
                                           buf, ct.byref(n))
            return buf.value, iv.value

        template = prop(7)[0]
        word_count = prop(15)[1]
        dll.MsiCloseHandle(h)
        return template, word_count

    def extract_stream(self, stream, dest):
        ct, dll = self.ct, self.dll
        view = self.H()
        sql = f"SELECT `Data` FROM `_Streams` WHERE `Name`='{stream}'"
        if dll.MsiDatabaseOpenViewW(self.db, sql, ct.byref(view)):
            raise RuntimeError(f"cannot query stream {stream}")
        try:
            dll.MsiViewExecute(view, 0)
            rec = self.H()
            if dll.MsiViewFetch(view, ct.byref(rec)):
                raise RuntimeError(f"stream not found: {stream}")
            with open(dest, "wb") as f:
                buf = ct.create_string_buffer(1 << 20)
                while True:
                    n = self.wt.DWORD(len(buf))
                    if dll.MsiRecordReadStream(rec, 1, buf, ct.byref(n)) or n.value == 0:
                        break
                    f.write(buf.raw[:n.value])
            dll.MsiCloseHandle(rec)
        finally:
            dll.MsiCloseHandle(view)

    def extract_cab(self, cab, dest_dir):
        subprocess.run(["expand.exe", cab, "-F:*", dest_dir], check=True,
                       stdout=subprocess.DEVNULL)


def open_backend(msi_path, forced=None):
    if forced == "msitools" or (forced is None and os.name != "nt"):
        return MsitoolsBackend(msi_path)
    return WindowsMsiBackend(msi_path)


# --------------------------------------------------------------------------- #
# Windows Installer condition evaluator (three-valued: True / False / None)
# --------------------------------------------------------------------------- #

class CondError(Exception):
    pass


_TOK_RE = re.compile(r'''
    \s*(?:
      (?P<str>"[^"]*")
    | (?P<op>~?(?:<>|><|<<|>>|>=|<=|=|<|>))
    | (?P<lp>\() | (?P<rp>\))
    | (?P<int>-?\d+)
    | (?P<id>[%$?&!]?[A-Za-z_][A-Za-z0-9_.]*)
    )''', re.X)

_KEYWORDS = {"NOT", "AND", "OR", "XOR", "EQV", "IMP"}


def tokenize(cond):
    pos, toks = 0, []
    while pos < len(cond):
        if cond[pos:].strip() == "":
            break
        m = _TOK_RE.match(cond, pos)
        if not m or m.end() == pos:
            raise CondError(f"bad token at {pos}: {cond[pos:pos+15]!r}")
        pos = m.end()
        kind = m.lastgroup
        val = m.group(kind)
        if kind == "id" and val.upper() in _KEYWORDS:
            toks.append(("kw", val.upper()))
        else:
            toks.append((kind, val))
    return toks


def _not(a):
    return None if a is None else not a


def _and(a, b):
    if a is False or b is False:
        return False
    if a is None or b is None:
        return None
    return True


def _or(a, b):
    if a is True or b is True:
        return True
    if a is None or b is None:
        return None
    return False


def _bin(f):
    return lambda a, b: None if a is None or b is None else f(a, b)


_xor = _bin(lambda a, b: a != b)
_eqv = _bin(lambda a, b: a == b)
_imp = lambda a, b: _or(_not(a), b)


class CondEval:
    """Parse and evaluate one condition against a property resolver.

    resolver(name) -> str (known value; "" = not set) or None (unknown).
    Values: ("s", str) | ("i", int) | None (unknown).
    """

    def __init__(self, cond, resolver):
        self.toks = tokenize(cond)
        self.i = 0
        self.res = resolver
        self.unknowns = set()

    def run(self):
        if not self.toks:
            return True
        v = self.imp()
        if self.i != len(self.toks):
            raise CondError(f"trailing tokens: {self.toks[self.i:]}")
        return v

    def peek(self):
        return self.toks[self.i] if self.i < len(self.toks) else (None, None)

    def take(self):
        t = self.peek()
        self.i += 1
        return t

    def _chain(self, sub, kw, fn):
        v = sub()
        while self.peek() == ("kw", kw):
            self.take()
            v = fn(v, sub())
        return v

    def imp(self): return self._chain(self.eqv, "IMP", _imp)
    def eqv(self): return self._chain(self.xor, "EQV", _eqv)
    def xor(self): return self._chain(self.or_, "XOR", _xor)
    def or_(self): return self._chain(self.and_, "OR", _or)
    def and_(self): return self._chain(self.not_, "AND", _and)

    def not_(self):
        if self.peek() == ("kw", "NOT"):
            self.take()
            return _not(self.not_())
        return self.comp()

    def comp(self):
        if self.peek()[0] == "lp":
            self.take()
            v = self.imp()
            if self.take()[0] != "rp":
                raise CondError("missing ')'")
            return v
        left = self.value()
        if self.peek()[0] == "op":
            op = self.take()[1]
            return self.compare(left, op, self.value())
        if left is None:
            return None
        return left[1] != 0 if left[0] == "i" else left[1] != ""

    def value(self):
        kind, val = self.take()
        if kind == "str":
            return ("s", val[1:-1])
        if kind == "int":
            return ("i", int(val))
        if kind == "id":
            if val[0] in "%$?&!":  # environment / component / feature states
                self.unknowns.add(val)
                return None
            v = self.res(val)
            if v is None:
                self.unknowns.add(val)
                return None
            return ("s", v)
        raise CondError(f"expected value, got {val!r}")

    @staticmethod
    def compare(a, op, b):
        if a is None or b is None:
            return None
        ci = op.startswith("~")
        op = op.lstrip("~")

        def as_int(x):
            if x[0] == "i":
                return x[1]
            if re.fullmatch(r'-?\d+', x[1].strip()):
                return int(x[1])
            return None

        if a[0] == "i" or b[0] == "i":
            ia, ib = as_int(a), as_int(b)
            if ia is None or ib is None:
                return op == "<>"  # integer vs string: only <> is true
            return {
                "=": ia == ib, "<>": ia != ib, ">": ia > ib, ">=": ia >= ib,
                "<": ia < ib, "<=": ia <= ib, "><": (ia & ib) != 0,
                "<<": ((ia >> 16) & 0xFFFF) == ib, ">>": (ia & 0xFFFF) == ib,
            }[op]
        sa, sb = a[1], b[1]
        if ci:
            sa, sb = sa.lower(), sb.lower()
        return {
            "=": sa == sb, "<>": sa != sb, ">": sa > sb, ">=": sa >= sb,
            "<": sa < sb, "<=": sa <= sb, "><": sb in sa,
            "<<": sa.startswith(sb), ">>": sa.endswith(sb),
        }[op]


def evaluate(cond, resolver, errors=None):
    """-> (True/False/None, set_of_unknown_names)."""
    if not cond or not cond.strip():
        return True, set()
    try:
        ev = CondEval(cond, resolver)
        return ev.run(), ev.unknowns
    except CondError as e:
        if errors is not None:
            errors.add(f"unparseable condition {cond!r}: {e}")
        return None, {"<parse error>"}


# --------------------------------------------------------------------------- #
# Model
# --------------------------------------------------------------------------- #

def long_name(n):
    return n.split("|", 1)[1] if "|" in n else n


def split_default_dir(dd):
    target, source = (dd.split(":", 1) + [None])[:2] if ":" in dd else (dd, dd)
    return long_name(target), long_name(source)


class Package:
    def __init__(self, be):
        self.be = be
        self.template, self.word_count = be.summary()
        self.platform = (self.template.split(";")[0] or "Intel").strip()

        self.dirs = {r["Directory"]: r for r in be.table("Directory")}
        self.components = {r["Component"]: r for r in be.table("Component")}
        self.files = sorted(be.table("File"), key=lambda r: int(r["Sequence"] or 0))
        self.features = {r["Feature"]: r for r in be.table("Feature")}
        self.feature_conds = be.table("Condition")
        self.media = sorted(be.table("Media"), key=lambda r: int(r["LastSequence"] or 0))
        self.properties = {r["Property"]: r["Value"] for r in be.table("Property")}

        self.comp_features = defaultdict(list)
        for r in be.table("FeatureComponents"):
            self.comp_features[r["Component_"]].append(r["Feature_"])

        # Properties something can overwrite at runtime -> treat as unknown.
        self.dynamic_props = {r["Property"] for r in be.table("AppSearch")}
        for r in be.table("CustomAction"):
            try:
                t = int(r["Type"] or 0)
            except ValueError:
                continue
            if t & 0x3F == 51:          # set property from formatted text
                self.dynamic_props.add(r["Source"])
        for r in be.table("Upgrade"):
            if r.get("ActionProperty"):
                self.dynamic_props.add(r["ActionProperty"])

        self._tpath, self._spath = {}, {}

    # directory paths ------------------------------------------------------ #
    def target_path(self, d):
        if d in self._tpath:
            return self._tpath[d]
        row = self.dirs.get(d)
        parent = row["Directory_Parent"] if row else ""
        if d in STANDARD_FOLDERS or not row:
            p = d
        elif not parent or parent == d:
            p = d                       # root (TARGETDIR)
        else:
            name = split_default_dir(row["DefaultDir"])[0]
            base = self.target_path(parent)
            p = base if name in (".", "") else base + "\\" + name
        self._tpath[d] = p
        return p

    def source_path(self, d):
        """Relative path of an uncompressed file's folder next to the .msi."""
        if d in self._spath:
            return self._spath[d]
        row = self.dirs.get(d)
        parent = row["Directory_Parent"] if row else ""
        if not row or not parent or parent == d:
            p = ""
        else:
            name = split_default_dir(row["DefaultDir"])[1]
            base = self.source_path(parent)
            p = base if name in (".", "") else (base + "\\" + name if base else name)
        self._spath[d] = p
        return p

    def is_compressed(self, frow):
        a = int(frow["Attributes"] or 0)
        if a & FILE_ATTR_COMPRESSED:
            return True
        if a & FILE_ATTR_NONCOMPRESSED:
            return False
        return bool(self.word_count & 2)

    def media_for(self, seq):
        for m in self.media:
            if seq <= int(m["LastSequence"] or 0):
                return m
        return None

    def arches(self):
        p = self.platform.lower()
        if p in ("x64", "amd64"):
            return ["x64"]
        if p == "arm64":
            return ["arm64"]
        if p == "intel64":
            return ["ia64"]
        return ["x86", "x64"]   # 32-bit package: native x86 and WOW64 on x64

    def all_conditions(self):
        out = [c["Condition"] for c in self.components.values() if c.get("Condition")]
        out += [c["Condition"] for c in self.feature_conds if c.get("Condition")]
        return out


def nt_breakpoints(conditions):
    bps = set()
    fwd = re.compile(r'(?i)\bVersionNT(?:64)?\s*~?(<>|>=|<=|=|<|>)\s*(\d+)')
    rev = re.compile(r'(?i)(\d+)\s*~?(<>|>=|<=|=|<|>)\s*VersionNT(?:64)?\b')
    flip = {">=": "<=", "<=": ">=", ">": "<", "<": ">", "=": "=", "<>": "<>"}
    for c in conditions:
        hits = [(op, int(v)) for op, v in fwd.findall(c)]
        hits += [(flip[op], int(v)) for v, op in rev.findall(c)]
        for op, v in hits:
            if op in (">=", "<"):
                bps.add(v)
            elif op in (">", "<="):
                bps.add(v + 1)
            else:
                bps.update((v, v + 1))
    return sorted(bps)


class Profile:
    def __init__(self, arch, rep, upper, label):
        self.arch, self.rep, self.upper, self.label = arch, rep, upper, label
        self.sel = OrderedDict()        # dest(lower) -> FileSel
        self.conflicts = []
        self.pruned = []
        self.dropped = []               # (file key, reason) excluded by condition
        self.below = False              # lowest band (anything under the first breakpoint)

    def range_text(self, long=False):
        lo = self.rep
        if lo is None:
            return "any Windows version"
        if self.below and self.upper:
            return f"VersionNT below {self.upper}" if long else f"NT < {self.upper}"
        if self.upper:
            return (f"VersionNT {lo} up to (but not including) {self.upper}" if long
                    else f"NT {lo}..<{self.upper}")
        return f"VersionNT {lo} and up" if long else f"NT >= {lo}"


class FileSel:
    __slots__ = ("key", "dest", "comp", "seq", "conditional", "why", "src_dir")

    def __init__(self, **kw):
        for k, v in kw.items():
            setattr(self, k, v)


def make_resolver(pkg, arch, version_nt, user_props, unknown_empty):
    sysprops = {
        "VersionNT": str(version_nt),
        "VersionNT64": str(version_nt) if arch in ("x64", "arm64", "ia64") else "",
        "Msix64": "6" if arch == "x64" else "",
        "Intel64": "1" if arch == "ia64" else "",
        "Installed": "", "REMOVE": "", "PATCH": "", "RESUME": "",
        "UPGRADINGPRODUCTCODE": "", "Preselected": "",
        "Privileged": "1", "AdminUser": "1",
    }
    if arch == "x86":
        sysprops["Intel"] = "6"

    def resolve(name):
        if name in user_props:
            return user_props[name]
        if name in sysprops:
            return sysprops[name]
        if name in pkg.dynamic_props:
            return "" if unknown_empty else None
        if name in pkg.properties:
            return pkg.properties[name]
        return "" if unknown_empty else None

    return resolve


def feature_states(pkg, resolve, respect_installlevel, errors, overrides=None):
    """Feature -> (True/False/None, set_of_unknowns).

    overrides: {feature: True/False} forces a feature's own state (its parent
    still applies, so switching a parent off switches its children off too).
    """
    overrides = overrides or {}
    install_level = int(resolve("INSTALLLEVEL") or pkg.properties.get("INSTALLLEVEL", "1") or 1)
    own = {}
    for f, row in pkg.features.items():
        levels = {int(row["Level"] or 0)}
        unk = set()
        for c in pkg.feature_conds:
            if c["Feature_"] != f:
                continue
            r, u = evaluate(c["Condition"], resolve, errors)
            if r is True:
                levels = {int(c["Level"] or 0)}
            elif r is None:
                levels.add(int(c["Level"] or 0))
                unk |= u

        def on(lv):
            return lv > 0 and (not respect_installlevel or lv <= install_level)

        states = {on(lv) for lv in levels}
        own[f] = (states.pop() if len(states) == 1 else None, unk)
        if f in overrides:
            own[f] = (bool(overrides[f]), set())

    memo = {}

    def state(f, depth=0):
        if f in memo:
            return memo[f]
        s, u = own.get(f, (False, set()))
        parent = pkg.features.get(f, {}).get("Feature_Parent")
        if parent and parent != f and depth < 64:
            ps, pu = state(parent, depth + 1)
            s, u = _and(s, ps), u | pu
        memo[f] = (s, u)
        return memo[f]

    return {f: state(f) for f in pkg.features}


def resolve_profile(pkg, prof, version_nt, user_props, args, errors):
    resolve = make_resolver(pkg, prof.arch, version_nt, user_props, args.unknown_empty)
    fstates = feature_states(pkg, resolve, args.default_features_only, errors,
                             getattr(args, "feature_overrides", None))

    comp_state = {}
    for c, row in pkg.components.items():
        feats = pkg.comp_features.get(c, [])
        fs, fu = False, set()
        for f in feats:
            s, u = fstates.get(f, (False, set()))
            fs = _or(fs, s)
            if s is None:
                fu |= u
        cs, cu = evaluate(row.get("Condition", ""), resolve, errors)
        if int(row["Attributes"] or 0) & COMP_ATTR_64BIT and prof.arch == "x86":
            cs = False
        # Only report the unknowns of the part that is actually undecided.
        cu = cu if cs is None else set()
        fu = fu if fs is None else set()
        comp_state[c] = (_and(fs, cs), (cu, fu), feats)

    for frow in pkg.files:
        comp = frow["Component_"]
        state, (cu, fu), feats = comp_state.get(comp, (False, (set(), set()), []))
        if state is False:
            why = "no feature" if not feats else "condition false"
            prof.dropped.append((frow["File"], why))
            continue
        cdir = pkg.components[comp]["Directory_"]
        dest = pkg.target_path(cdir) + "\\" + long_name(frow["FileName"])
        cond = pkg.components[comp].get("Condition", "")
        why = ""
        if state is None:
            parts = []
            if cu:
                parts.append(f"component condition: {cond}  [unknown: {', '.join(sorted(cu))}]")
            if fu:
                parts.append(f"feature condition  [unknown: {', '.join(sorted(fu))}]")
            why = "  +  ".join(parts) or "undecided"
        fs = FileSel(key=frow["File"], dest=dest, comp=comp, seq=int(frow["Sequence"] or 0),
                     conditional=state is None, why=why, src_dir=cdir)
        k = dest.lower()
        if k in prof.sel:
            prev = prof.sel.pop(k)
            prof.conflicts.append((dest, prev.key, fs.key))
            # Prefer a definite file over a conditional one; otherwise the later sequence.
            if prev.conditional is False and fs.conditional:
                fs = prev
        prof.sel[k] = fs


def version_bands(pkg):
    """[(rep, upper, suffix, below)] - one entry per VersionNT band, oldest first."""
    bps = nt_breakpoints(pkg.all_conditions())
    if not bps:
        return bps, [(None, None, "", False)]
    bands = [(bps[0] - 1, bps[0], f"below-{NT_NAMES.get(bps[0], 'nt' + str(bps[0]))}", True)]
    for i, b in enumerate(bps):
        upper = bps[i + 1] if i + 1 < len(bps) else None
        bands.append((b, upper, NT_NAMES.get(b, "nt" + str(b)), False))
    return bps, bands


def make_profile(pkg, arch, band, user_props, args, errors):
    rep, upper, suffix, below = band
    p = Profile(arch, rep, upper, f"{arch}-{suffix}" if suffix else arch)
    p.below = below
    # With nothing VersionNT-gated, evaluate at a nominal modern value.
    resolve_profile(pkg, p, 603 if rep is None else rep, user_props, args, errors)
    return p


def build_profiles(pkg, user_props, args, errors):
    arches = args.arches.split(",") if args.arches else pkg.arches()
    bps, bands = version_bands(pkg)

    profiles = []
    for arch in arches:
        last_sig = None
        for band in bands:
            upper = band[1]
            p = make_profile(pkg, arch, band, user_props, args, errors)
            sig = tuple(sorted((d, s.key, s.conditional) for d, s in p.sel.items()))
            if sig == last_sig:
                profiles[-1].upper = upper   # same result as the band below: widen it
                continue
            last_sig = sig
            profiles.append(p)
    return arches, bps, profiles


# Properties the profile itself supplies (arch / version / fresh install).
PROFILE_PROPS = {"VersionNT", "VersionNT64", "Msix64", "Intel", "Intel64", "Installed",
                 "REMOVE", "PATCH", "RESUME", "UPGRADINGPRODUCTCODE", "Preselected",
                 "Privileged", "AdminUser"}

KNOWN_CHOICES = {
    "MsiNTProductType": [("1", "workstation"), ("2", "domain controller"), ("3", "server")],
}

_CMP_RE = re.compile(
    r'([A-Za-z_][A-Za-z0-9_.]*)\s*(~?(?:<>|>=|<=|=|<|>))\s*("[^"]*"|-?\d+)'
    r'|("[^"]*"|-?\d+)\s*(~?(?:<>|>=|<=|=|<|>))\s*([A-Za-z_][A-Za-z0-9_.]*)')
_FLIP = {">=": "<=", "<=": ">=", ">": "<", "<": ">", "=": "=", "<>": "<>"}


class PropInfo:
    def __init__(self, name):
        self.name = name
        self.default = None        # value in the Property table, or None
        self.dynamic = False       # overwritten at runtime (AppSearch / custom action)
        self.literals = set()      # (op, literal) it is compared against
        self.n_conditions = 0
        self.n_files = 0

    def candidates(self):
        """[(value, note)] worth offering: each side of every comparison found."""
        out = []

        def add(v, note=""):
            if v not in [x for x, _ in out]:
                out.append((v, note))

        for v, note in KNOWN_CHOICES.get(self.name, []):
            add(v, note)
        if self.default not in (None, ""):
            add(self.default, "MSI default")
        nums, strs = set(), set()
        for op, lit in self.literals:
            op = op.lstrip("~")
            if re.fullmatch(r'-?\d+', lit):
                v = int(lit)
                nums.update({">=": (v, v - 1), "<": (v, v - 1), ">": (v + 1, v),
                             "<=": (v, v + 1)}.get(op, (v,)))
            else:
                strs.add(lit)
        for v in sorted(nums):
            add(str(v))
        for v in sorted(strs):
            add(v)
        if not nums and not strs and "1" not in [x for x, _ in out]:
            add("1", "set")          # used as a plain on/off flag
        return out


def scan_properties(pkg):
    """Every property the component/feature conditions depend on, most impactful first."""
    infos = {}

    def props_of(cond):
        try:
            return {v for k, v in tokenize(cond) if k == "id" and v[0] not in "%$?&!"}
        except CondError:
            return set(re.findall(r'\b([A-Za-z_][A-Za-z0-9_.]*)\b', cond)) - _KEYWORDS

    def note(cond):
        if not cond:
            return set()
        names = props_of(cond) - PROFILE_PROPS
        for n in names:
            infos.setdefault(n, PropInfo(n)).n_conditions += 1
        for m in _CMP_RE.finditer(cond):
            if m.group(1):
                name, op, lit = m.group(1), m.group(2), m.group(3)
            else:
                lit, op, name = m.group(4), m.group(5), m.group(6)
                op = ("~" if op.startswith("~") else "") + _FLIP[op.lstrip("~")]
            if name in infos:
                infos[name].literals.add((op, lit.strip('"')))
        return names

    comp_props = {c: note(r.get("Condition", "")) for c, r in pkg.components.items()}
    feat_own = defaultdict(set)
    for c in pkg.feature_conds:
        feat_own[c["Feature_"]] |= note(c.get("Condition", ""))

    def feat_chain(f, depth=0):
        out = set(feat_own.get(f, ()))
        parent = pkg.features.get(f, {}).get("Feature_Parent")
        if parent and parent != f and depth < 64:
            out |= feat_chain(parent, depth + 1)
        return out

    chains = {f: feat_chain(f) for f in pkg.features}
    files_per_comp = defaultdict(int)
    for f in pkg.files:
        files_per_comp[f["Component_"]] += 1
    for c, names in comp_props.items():
        allp = set(names)
        for f in pkg.comp_features.get(c, []):
            allp |= chains.get(f, set())
        for n in allp:
            if n in infos:
                infos[n].n_files += files_per_comp[c]

    for n, info in infos.items():
        info.default = pkg.properties.get(n)
        info.dynamic = n in pkg.dynamic_props
    return sorted(infos.values(), key=lambda i: (-i.n_files, i.name.lower()))


def feature_file_counts(pkg):
    """feature -> number of files in its components (own, not children)."""
    files_per_comp = defaultdict(int)
    for f in pkg.files:
        files_per_comp[f["Component_"]] += 1
    out = defaultdict(int)
    for c, feats in pkg.comp_features.items():
        for f in feats:
            out[f] += files_per_comp[c]
    return out


# --------------------------------------------------------------------------- #
# Extraction
# --------------------------------------------------------------------------- #

def extract_payload(pkg, msi_path, work, warnings, be=None, log=print):
    """Extract every referenced cabinet into work/cab. Returns key -> path lookup."""
    be = be or pkg.be
    msi_dir = os.path.dirname(os.path.abspath(msi_path))
    cab_out = os.path.join(work, "cab")
    os.makedirs(cab_out, exist_ok=True)
    for m in pkg.media:
        cab = m.get("Cabinet", "")
        if not cab:
            continue
        if cab.startswith("#"):
            cab_file = os.path.join(work, cab[1:])
            log(f"  extracting embedded stream {cab[1:]}")
            be.extract_stream(cab[1:], cab_file)
        else:
            cab_file = os.path.join(msi_dir, cab)
            if not os.path.isfile(cab_file):
                warnings.append(f"external cabinet missing next to the .msi: {cab}")
                continue
            log(f"  extracting external cabinet {cab}")
        be.extract_cab(cab_file, cab_out)

    on_disk = {n.lower(): os.path.join(cab_out, n) for n in os.listdir(cab_out)}

    def locate(frow):
        if pkg.is_compressed(frow):
            p = on_disk.get(frow["File"].lower())
            if p:
                return p
        comp = pkg.components.get(frow["Component_"], {})
        rel = pkg.source_path(comp.get("Directory_", ""))
        cand = os.path.join(msi_dir, rel.replace("\\", os.sep), long_name(frow["FileName"]))
        if os.path.isfile(cand):
            return cand
        return on_disk.get(frow["File"].lower())

    return {f["File"]: locate(f) for f in pkg.files}


def unreferenced_cabs(pkg, msi_path):
    msi_dir = os.path.dirname(os.path.abspath(msi_path))
    used = {m["Cabinet"].lower() for m in pkg.media if m.get("Cabinet")}
    return sorted(n for n in os.listdir(msi_dir)
                  if n.lower().endswith(".cab") and n.lower() not in used)


# --------------------------------------------------------------------------- #
# Reporting / writing
# --------------------------------------------------------------------------- #

def arch_named_unconditional(pkg):
    """Folders whose name says x64/x86 but whose components have no condition."""
    hits = set()
    for c in pkg.components.values():
        if c.get("Condition"):
            continue
        path = pkg.target_path(c["Directory_"])
        if ARCH_NAME_RE.search(path.split("\\")[-1]):
            hits.add(path)
    return sorted(hits)


def print_report(pkg, backend, arches, bps, profiles, errors, warnings, extra):
    print(f"\nPackage       : {len(pkg.files)} files, {len(pkg.components)} components, "
          f"{len(pkg.features)} features   (backend: {backend})")
    print(f"Template      : {pkg.template or '(none)'}   -> profiles for: {', '.join(arches)}")
    print("NT breakpoints: " + (", ".join(str(b) for b in bps) if bps
                               else "(none - nothing is VersionNT-gated)"))
    conds = sum(1 for c in pkg.components.values() if c.get("Condition"))
    c64 = sum(1 for c in pkg.components.values() if int(c["Attributes"] or 0) & COMP_ATTR_64BIT)
    print(f"Components    : {conds} conditional, {c64} marked 64-bit")
    print(f"Profiles      : {len(profiles)}")

    print("\nResolved target profiles")
    for p in profiles:
        ncond = sum(1 for s in p.sel.values() if s.conditional)
        print(f"  {p.label:<24} {p.range_text():<16} {len(p.sel):>5} files"
              f"  ({ncond} conditional, {len(p.pruned)} pruned)")

    by_expr = defaultdict(int)
    for p in profiles:
        for s in p.sel.values():
            if s.conditional:
                by_expr[s.why] += 1
    if by_expr:
        print("\nConditions the script could not decide (files kept, flagged) - pin with --prop:")
        for w, n in sorted(by_expr.items(), key=lambda x: -x[1])[:25]:
            print(f"  {n:>5}x  {w}")

    for title, lines in extra:
        if lines:
            print(f"\n{title}")
            for ln in lines:
                print(f"  {ln}")
    if errors or warnings:
        print("\nWarnings")
        for w in sorted(errors) + warnings:
            print(f"  {w}")


def write_trees(output_root, profiles, located, header, force):
    if os.path.exists(output_root):
        if not force:
            ans = input(f"Output root '{output_root}' exists. Delete and recreate? [y/N] ")
            if ans.strip().lower() not in ("y", "yes"):
                print("Aborted.")
                return
        shutil.rmtree(output_root)
    os.makedirs(output_root)

    summary = header + [f"Generated  : {datetime.now(timezone.utc):%Y-%m-%d %H:%M:%SZ}", ""]
    for p in profiles:
        write_profile(os.path.join(output_root, p.label), p, located)
        summary.append(f"{p.label}  ({p.arch}, {p.range_text(long=True)}) - {len(p.sel)} files")

    with open(os.path.join(output_root, "_SUMMARY.txt"), "w", encoding="utf-8") as f:
        f.write("\n".join(summary) + "\n")
    print(f"\nDone. {len(profiles)} profiles written to: {output_root}")


# --------------------------------------------------------------------------- #
# Adapter used by the GUI (same interface as split_inno_arch.InnoProject)
# --------------------------------------------------------------------------- #

class Decider:
    def __init__(self, name, choices, auto_text, info, n_files, allow_not_set=True):
        self.name, self.choices, self.auto_text, self.info, self.n_files = \
            name, choices, auto_text, info, n_files
        self.allow_not_set = allow_not_set


class MsiProject:
    kind = "MSI"
    supports_all = False
    decider_label = "Properties"
    feature_label = "Features"
    decider_help = ("Properties the package's conditions depend on, most files affected "
                    "first. 'auto' uses the MSI's default value, or leaves it undecided "
                    "when a custom action sets it at install time. You can also type any "
                    "value.")
    feature_help = ("Click a row's Include cell to cycle auto -> on -> off. Switching a "
                    "feature off also removes its sub-features.")
    unknown_option = "Treat undecided properties as 'not set' (plain MSI rules)"
    default_option = "Only features a default install selects (INSTALLLEVEL)"

    def __init__(self, path, log=print):
        self.path = os.path.abspath(path)
        self.be = open_backend(self.path)
        self.pkg = Package(self.be)
        if not self.pkg.files:
            raise RuntimeError("The File table is empty (bootstrapper or transform?).")
        self._props = scan_properties(self.pkg)
        self._bps, self._bands = version_bands(self.pkg)
        self._fcounts = feature_file_counts(self.pkg)

    def info_text(self):
        pkg = self.pkg
        cond = sum(1 for c in pkg.components.values() if c.get("Condition"))
        return (f"{os.path.basename(self.path)}  ·  MSI, template {pkg.template or '?'}  ·  "
                f"{len(pkg.files)} files, {len(pkg.components)} components ({cond} conditional), "
                f"{len(pkg.features)} features, {len(self._props)} deciding properties  ·  "
                f"backend {self.be.name}")

    def arches(self):
        return self.pkg.arches()

    def arch_note(self):
        if self.pkg.platform.lower() in ("intel", ""):
            return ("32-bit package: on 64-bit Windows it installs its 32-bit files plus "
                    "whatever x64 parts its conditions allow.")
        return f"{self.pkg.platform} package: installs only on that architecture."

    def bands(self):
        return list(self._bands)

    def band_text(self, band):
        rep, upper, _, below = band

        def nm(v):
            return NT_NAMES.get(v, f"NT {v}")
        if rep is None:
            return "Any version"
        if below:
            return f"Older than {nm(upper)}   (VersionNT < {upper})"
        if upper:
            return f"{nm(rep)} up to {nm(upper)}   ({rep} ≤ VersionNT < {upper})"
        return f"{nm(rep)} and newer   (VersionNT ≥ {rep})"

    def band_hint(self):
        return ("Bands come from the VersionNT checks in the package. Windows Installer can "
                "report VersionNT 603 on Windows 10/11, so the newest band is the one for "
                "current systems.")

    def options(self):
        return []

    def deciders(self):
        out = []
        for info in self._props:
            auto_val = None if info.dynamic or info.default is None else info.default
            auto_text = f"auto: {auto_val!r}" if auto_val is not None else "auto: undecided"
            bits = [f"affects {info.n_files} files"]
            if info.default is not None:
                bits.append(f"MSI default {info.default!r}")
            if info.dynamic:
                bits.append("set at runtime")
            cmp = sorted({f"{op}{lit}" for op, lit in info.literals})
            if cmp:
                bits.append("compared: " + " ".join(cmp[:6]) + (" …" if len(cmp) > 6 else ""))
            out.append(Decider(info.name, info.candidates(), auto_text, "  ·  ".join(bits),
                               info.n_files))
        return out

    def features(self):
        feats = self.pkg.features

        def order(f):
            try:
                return int(feats[f].get("Display") or 0)
            except ValueError:
                return 0

        out = []
        for f in sorted(feats, key=order):
            row = feats[f]
            parent = row.get("Feature_Parent") or ""
            if parent == f or parent not in feats:
                parent = ""
            title = row.get("Title") or ""
            text = f"{title}  [{f}]" if title and title != f else f
            out.append((f, parent, text, self._fcounts.get(f, 0), True))
        # parents must come before children for the tree widget
        done, ordered = set(), []

        def add(item):
            if item[0] in done:
                return
            if item[1]:
                for it in out:
                    if it[0] == item[1]:
                        add(it)
            done.add(item[0])
            ordered.append(item)
        for it in out:
            add(it)
        return ordered

    def compute(self, arch, band, values, overrides, opts):
        from types import SimpleNamespace
        errors = set()
        args = SimpleNamespace(unknown_empty=opts.get("unknown_empty"),
                               default_features_only=opts.get("default_only"),
                               feature_overrides=dict(overrides))
        prof = make_profile(self.pkg, arch, band, values, args, errors)
        rep = band[0]
        resolve = make_resolver(self.pkg, arch, 603 if rep is None else rep, values,
                                args.unknown_empty)
        fstates = feature_states(self.pkg, resolve, args.default_features_only, errors,
                                 args.feature_overrides)
        return prof, fstates, errors

    def dest_of(self, key):
        for f in self.pkg.files:
            if f["File"] == key:
                comp = self.pkg.components.get(f["Component_"], {})
                return (self.pkg.target_path(comp.get("Directory_", "")) + "\\" +
                        long_name(f["FileName"]))
        return ""

    def extract(self, work, log=print, be=None):
        warnings = []
        located = extract_payload(self.pkg, self.path, work, warnings,
                                  be=be or open_backend(self.path), log=log)
        for w in warnings:
            log(w)
        return located

    def notes(self):
        extra = unreferenced_cabs(self.pkg, self.path)
        if extra:
            return ["Not part of the MSI file tables (installed by custom actions, copy "
                    "manually if needed): " + ", ".join(extra)]
        return []

    def cli_command(self, arch, values, overrides, opts):
        parts = ["python", "split_msi_arch.py", "--msi", _q(os.path.basename(self.path)),
                 "--arches", arch]
        skipped = []
        for name, val in sorted(values.items()):
            if val is None:
                skipped.append(name)
            else:
                parts += ["--prop", _q(f"{name}={val}")]
        for f, on in sorted(overrides.items()):
            parts += ["--feature", _q(f"{f}={'on' if on else 'off'}")]
        if opts.get("unknown_empty"):
            parts.append("--unknown-empty")
        if opts.get("default_only"):
            parts.append("--default-features-only")
        if opts.get("prune"):
            parts.append("--prune-by-pe")
        return " ".join(parts), skipped

    def cleanup(self):
        pass


_q = common.q


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #

def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Split an .msi into one clean install tree per target profile.")
    ap.add_argument("--msi", required=True, help="The .msi (external .cab files must sit next to it).")
    ap.add_argument("--output-root", help="Default: <msi folder>/_sorted")
    ap.add_argument("--prop", action="append", default=[], metavar="NAME=VALUE",
                    help="Pin a property (repeatable). 'NAME=' means not set.")
    ap.add_argument("--unknown-empty", action="store_true",
                    help="Treat unknown properties as not set (plain MSI semantics) instead of "
                         "keeping their files as 'conditional'.")
    ap.add_argument("--default-features-only", action="store_true",
                    help="Respect INSTALLLEVEL (what a silent default install picks). "
                         "Default: include every feature that is not switched off (Level 0).")
    ap.add_argument("--feature", action="append", default=[], metavar="NAME=on|off",
                    help="Force a feature on or off (repeatable). Off also removes its children.")
    ap.add_argument("--arches", help="Override profile architectures, e.g. 'x86,x64'.")
    ap.add_argument("--prune-by-pe", action="store_true",
                    help="Also drop foreign-architecture binaries by PE header (for packages "
                         "that ship every arch unconditionally and choose at runtime).")
    ap.add_argument("--backend", choices=["msidll", "msitools"],
                    help="Force a backend (default: msi.dll on Windows, msitools elsewhere).")
    ap.add_argument("--work-dir", help="Keep extracted cabinets here instead of a temp folder.")
    ap.add_argument("--dry-run", action="store_true", help="Resolve and print the plan; copy nothing.")
    ap.add_argument("--force", action="store_true", help="Overwrite the output root without asking.")
    args = ap.parse_args(argv)

    msi_path = os.path.abspath(args.msi)
    if not os.path.isfile(msi_path):
        sys.exit(f"Not found: {msi_path}")
    output_root = args.output_root or os.path.join(os.path.dirname(msi_path), "_sorted")

    user_props = {}
    for p in args.prop:
        if "=" not in p:
            sys.exit(f"--prop needs NAME=VALUE, got {p!r}")
        k, v = p.split("=", 1)
        user_props[k.strip()] = v

    args.feature_overrides = {}
    for f in args.feature:
        name, _, val = f.partition("=")
        if val.lower() not in ("on", "off", "1", "0", "true", "false"):
            sys.exit(f"--feature needs NAME=on|off, got {f!r}")
        args.feature_overrides[name.strip()] = val.lower() in ("on", "1", "true")

    forced = {"msidll": "msidll", "msitools": "msitools"}.get(args.backend)
    try:
        be = open_backend(msi_path, forced)
    except Exception as e:
        sys.exit(f"Cannot open the MSI database: {e}")

    pkg = Package(be)
    if not pkg.files:
        sys.exit("No File table rows - nothing to sort (is this a bootstrapper/transform?).")

    errors, warnings = set(), []
    arches, bps, profiles = build_profiles(pkg, user_props, args, errors)

    need_files = not args.dry_run or args.prune_by_pe
    located = {}
    tmp = None
    try:
        if need_files:
            work = args.work_dir or tempfile.mkdtemp(prefix="msisplit_")
            tmp = None if args.work_dir else work
            print("\nExtracting payload")
            located = extract_payload(pkg, msi_path, work, warnings)
            missing = sorted(k for k, v in located.items() if not v)
            if missing:
                warnings.append(f"{len(missing)} File rows not found in cabinets/source tree "
                                f"(first: {', '.join(missing[:5])})")
            if args.prune_by_pe:
                prune_by_pe(profiles, located)

        all_selected = {s.key for p in profiles for s in p.sel.values()}
        never = sorted(f["File"] for f in pkg.files if f["File"] not in all_selected)
        conflicts = sorted({f"{p.label}: {d}  ({a} vs {b})"
                            for p in profiles for d, a, b in p.conflicts})
        root_dirs = sorted({pkg.target_path(c["Directory_"]).split("\\")[0]
                            for c in pkg.components.values()})
        extra = [
            ("Destination roots (MSI folder properties; TARGETDIR = ROOTDRIVE unless set)",
             root_dirs),
            ("Arch-named folders with NO component condition (likely chosen by custom actions;"
             " try --prune-by-pe)", arch_named_unconditional(pkg)),
            ("Same destination selected twice in a profile", conflicts),
            ("Never selected in any profile (file keys)",
             never[:40] + ([f"... and {len(never) - 40} more"] if len(never) > 40 else [])),
            ("Cabinets next to the .msi that the Media table does not reference "
             "(payload handled by custom actions, not by this split)",
             unreferenced_cabs(pkg, msi_path)),
        ]
        print_report(pkg, be.name, arches, bps, profiles, errors, warnings, extra)

        if args.dry_run:
            print(f"\nDRY RUN - nothing written. Output would go to: {output_root}")
            return
        header = [f"Source msi : {msi_path}", f"Template   : {pkg.template}",
                  f"Profiles   : {len(profiles)}"]
        write_trees(output_root, profiles, located, header, args.force)
    finally:
        if tmp:
            shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    main()
