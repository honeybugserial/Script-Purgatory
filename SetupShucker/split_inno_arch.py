#!/usr/bin/env python3
"""
Reconstruct a clean install tree per target profile (architecture x Windows
version band) from an Inno Setup installer.

innounp regenerates install_script.iss; its [Files] section says which entry is
installed where and under which conditions. Variants of the same file are
extracted as "name,1.ext", "name,2.ext" (collision numbering only). This script
evaluates every [Files] entry for each profile, applies Inno's rule that the
LAST matching entry for a destination wins, and copies the result into clean
trees with the original {app}\\... layout.

What it evaluates per entry:
  Check:             arch functions (Is64BitInstallMode, IsX64, IsARM64, IsWin64,
                     ...), IsComponentSelected/IsTaskSelected, not/and/or.
                     Any other function is a "check" you can set true/false;
                     until then its files are kept and flagged as undecided.
  MinVersion / OnlyBelowVersion   -> Windows version bands
  Components: / Tasks:            -> selection (all on by default, or the
                                     installer's default selection)
  Languages:                      -> chosen language
  Flags: dontcopy                 -> never installed

By default every architecture x Windows-version profile is written, one folder
each (x86-baseline, x64-win7, x64-win10, ...); identical neighbouring bands are
merged, and if all architectures come out the same you get 'all-...' folders.

Usage:
    python split_inno_arch.py --setup Setup.exe --dry-run
    python split_inno_arch.py --setup Setup.exe --arches x64 --band 2   # one profile
    python split_inno_arch.py --extract-root extracted_folder
    python split_inno_arch.py --setup Setup.exe --check IsWin11=true --task desktopicon=off

innounp is expected at bin\\innounp.exe next to this script (or on the PATH).
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
import bundled_tools  # noqa: E402

import split_common as common  # noqa: E402
from split_common import (PE_EXTS, pe_machine, safe_win_path, write_profile,  # noqa: E402,F401
                          all_profiles, write_all, prune_by_pe)
NT_NAMES = {
    (5, 0): "win2000", (5, 1): "winxp", (5, 2): "win2003", (6, 0): "winvista",
    (6, 1): "win7", (6, 2): "win8", (6, 3): "win81", (10, 0): "win10",
}
NT_TITLES = {
    (5, 0): "Windows 2000", (5, 1): "Windows XP", (5, 2): "Windows Server 2003",
    (6, 0): "Windows Vista", (6, 1): "Windows 7", (6, 2): "Windows 8",
    (6, 3): "Windows 8.1", (10, 0): "Windows 10",
}
INNO_SIGNATURE = b"Inno Setup Setup Data ("


# --------------------------------------------------------------------------- #
# Small helpers
# --------------------------------------------------------------------------- #

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


def _not(a):
    return None if a is None else not a


def nt_tuple(t):
    return tuple(t) + (0,) * (2 - len(t))


def nt_fmt(t):
    return f"{t[0]}.{t[1]}"


def nt_title(t):
    return NT_TITLES.get(nt_tuple(t), f"NT {nt_fmt(t)}")


def looks_like_inno(path, chunk=8 << 20):
    """Scan an .exe for Inno Setup's plain-text setup-data signature."""
    try:
        with open(path, "rb") as f:
            tail = b""
            while True:
                block = f.read(chunk)
                if not block:
                    return False
                if INNO_SIGNATURE in tail + block:
                    return True
                tail = block[-len(INNO_SIGNATURE):]
    except OSError:
        return False


# --------------------------------------------------------------------------- #
# .iss parsing
# --------------------------------------------------------------------------- #

def split_iss_params(line):
    parts, buf, in_q = [], [], False
    for ch in line:
        if ch == '"':
            in_q = not in_q
            buf.append(ch)
        elif ch == ';' and not in_q:
            parts.append("".join(buf))
            buf = []
        else:
            buf.append(ch)
    if buf:
        parts.append("".join(buf))
    return parts


def parse_param(tok):
    m = re.match(r'^\s*([A-Za-z0-9_]+)\s*:\s*(.*)$', tok)
    if not m:
        return None
    key, val = m.group(1), m.group(2).strip()
    if len(val) >= 2 and val.startswith('"') and val.endswith('"'):
        val = val[1:-1].replace('""', '"')
    return key, val


def parse_nt_version(value):
    """'0.0,10.0' / '6.1' / '0,6.0' -> NT tuple, or None when unconstrained."""
    if not value:
        return None
    parts = value.split(',')
    nt = (parts[1] if len(parts) >= 2 else parts[0]).strip()
    if nt in ("", "0", "0.0"):
        return None
    nums = []
    for x in nt.split('.'):
        m = re.match(r'\d+', x)
        nums.append(int(m.group(0)) if m else 0)
    return nt_tuple(tuple(nums[:2]))


def read_iss(path):
    for enc in ("utf-8-sig", "utf-16", "cp1252"):
        try:
            with open(path, "r", encoding=enc) as f:
                return f.read()
        except (UnicodeError, UnicodeDecodeError):
            continue
    with open(path, "r", encoding="latin-1") as f:
        return f.read()


def iss_sections(text):
    sections, cur = defaultdict(list), None
    for line in text.splitlines():
        s = line.strip()
        m = re.match(r'^\[([^\]]+)\]\s*$', s)
        if m:
            cur = m.group(1).strip().lower()
            continue
        if cur and s and not s.startswith(';'):
            sections[cur].append(line)
    return sections


def param_rows(lines):
    rows = []
    for line in lines:
        params = {}
        for tok in split_iss_params(line):
            p = parse_param(tok)
            if p:
                params[p[0].lower()] = p[1]
        if params:
            rows.append(params)
    return rows


class Entry:
    __slots__ = ("order", "source", "dest_dir", "dest_name", "dest", "check",
                 "components", "tasks", "languages", "flags", "min_nt", "below_nt")

    def __init__(self, **kw):
        for k, v in kw.items():
            setattr(self, k, v)


# --------------------------------------------------------------------------- #
# Expression evaluation (three-valued)
# --------------------------------------------------------------------------- #

class ExprError(Exception):
    pass


def _tokens_check(expr):
    """Tokens for a Check: expression: kw / ( / ) / call text."""
    i, out, n = 0, [], len(expr)
    while i < n:
        c = expr[i]
        if c.isspace():
            i += 1
        elif c in "()":
            out.append(c)
            i += 1
        elif c.isalpha() or c == '_':
            j = i
            while j < n and (expr[j].isalnum() or expr[j] in "_."):
                j += 1
            word = expr[i:j]
            k = j
            while k < n and expr[k].isspace():
                k += 1
            if word.lower() in ("not", "and", "or"):
                out.append(word.lower())
                i = j
            elif k < n and expr[k] == '(':             # function call: capture args
                depth, q, m = 0, False, k
                while m < n:
                    ch = expr[m]
                    if ch == "'":
                        q = not q
                    elif not q and ch == '(':
                        depth += 1
                    elif not q and ch == ')':
                        depth -= 1
                        if depth == 0:
                            break
                    m += 1
                if m >= n:
                    raise ExprError("unbalanced call")
                out.append(("call", word, expr[k + 1:m].strip()))
                i = m + 1
            else:
                out.append(("call", word, None))
                i = j
        else:
            raise ExprError(f"unexpected {c!r}")
    return out


def _tokens_names(expr):
    """Tokens for Components:/Tasks: expressions: names, and/or/not, parens."""
    out = []
    for m in re.finditer(r'\(|\)|[^\s()]+', expr):
        t = m.group(0)
        out.append(t.lower() if t.lower() in ("not", "and", "or") else t)
    return out


class _Parser:
    """not > and > or; two operands side by side mean 'or' (Inno name lists)."""

    def __init__(self, toks, leaf):
        self.t, self.i, self.leaf = toks, 0, leaf

    def peek(self):
        return self.t[self.i] if self.i < len(self.t) else None

    def take(self):
        self.i += 1
        return self.t[self.i - 1]

    def parse(self):
        v = self.or_()
        if self.i != len(self.t):
            raise ExprError("trailing tokens")
        return v

    def _starts_operand(self):
        p = self.peek()
        return p is not None and p not in ("and", "or", ")")

    def or_(self):
        v = self.and_()
        while self.peek() == "or" or self._starts_operand():
            if self.peek() == "or":
                self.take()
            v = _or(v, self.and_())
        return v

    def and_(self):
        v = self.not_()
        while self.peek() == "and":
            self.take()
            v = _and(v, self.not_())
        return v

    def not_(self):
        if self.peek() == "not":
            self.take()
            return _not(self.not_())
        if self.peek() == "(":
            self.take()
            v = self.or_()
            if self.take() != ")":
                raise ExprError("missing ')'")
            return v
        tok = self.take()
        if tok is None:
            raise ExprError("unexpected end")
        return self.leaf(tok)


# Arch functions per profile. Is64BitInstallMode depends on the [Setup] section.
def arch_functions(arch, in64):
    base = {
        "x86": dict(iswin64=False, isx64=False, isx64os=False, isx64compatible=False,
                    isarm64=False, isia64=False, isx86=True, isx86os=True,
                    isx86compatible=True, isarm32compatible=False),
        "x64": dict(iswin64=True, isx64=True, isx64os=True, isx64compatible=True,
                    isarm64=False, isia64=False, isx86=False, isx86os=False,
                    isx86compatible=True, isarm32compatible=False),
        "arm64": dict(iswin64=True, isx64=False, isx64os=False, isx64compatible=True,
                      isarm64=True, isia64=False, isx86=False, isx86os=False,
                      isx86compatible=True, isarm32compatible=True),
    }[arch]
    base["is64bitinstallmode"] = arch in in64
    return base


# --------------------------------------------------------------------------- #
# Project
# --------------------------------------------------------------------------- #

class Decider:
    def __init__(self, name, choices, auto_text, info, n_files):
        self.name, self.choices, self.auto_text, self.info, self.n_files = \
            name, choices, auto_text, info, n_files


class FileSel:
    __slots__ = ("key", "dest", "comp", "seq", "conditional", "why", "src_dir")

    def __init__(self, **kw):
        for k, v in kw.items():
            setattr(self, k, v)


class Profile:
    def __init__(self, arch, band, label):
        self.arch, self.band, self.label = arch, band, label
        self.sel = OrderedDict()
        self.conflicts, self.pruned, self.dropped = [], [], []

    def range_text(self, long=False):
        rep, upper, _, below = self.band
        if rep is None:
            return "any Windows version"
        if below:
            return f"older than {nt_title(upper)}" if long else f"NT < {nt_fmt(upper)}"
        if upper:
            return (f"{nt_title(rep)} up to (not including) {nt_title(upper)}" if long
                    else f"NT {nt_fmt(rep)}..<{nt_fmt(upper)}")
        return f"{nt_title(rep)} and newer" if long else f"NT >= {nt_fmt(rep)}"


class InnoProject:
    kind = "Inno Setup"
    supports_all = True
    decider_label = "Checks"
    feature_label = "Components & Tasks"
    decider_help = ("Custom Check functions in the script. The installer runs these at "
                    "install time, so the script cannot know their result. 'auto' keeps "
                    "their files and flags them as undecided.")
    feature_help = ("Click a row's Include cell to cycle auto -> on -> off. By default "
                    "every component and task is included; tick 'Only the installer's "
                    "default selection' on the Target tab to follow its defaults.")
    unknown_option = "Treat undecided checks as false"
    default_option = "Only the installer's default selection"

    def __init__(self, path, innounp=None, log=print):
        """path: setup .exe, an install_script.iss, or a folder that contains one."""
        self.log = log
        self.innounp_path = innounp
        self.setup = None
        self.extract_root = None
        self._tmp = None
        path = os.path.abspath(path)
        if os.path.isdir(path):
            iss = os.path.join(path, "install_script.iss")
            self.extract_root = path
        elif path.lower().endswith(".iss"):
            iss = path
            self.extract_root = os.path.dirname(path)
        else:
            self.setup = path
            iss = self._script_from_setup(path)
        if not os.path.isfile(iss):
            raise FileNotFoundError(f"install_script.iss not found ({iss})")
        self.iss = iss
        self.path = path
        self._parse(read_iss(iss))

    # ---- setup / innounp --------------------------------------------------
    def _innounp(self):
        return bundled_tools.find_tool("innounp", self.innounp_path, log=self.log)

    def _run_innounp(self, out_dir, extra=()):
        exe = self._innounp()
        cmd = [exe, "-x", "-a", "-y", self.setup, *extra]
        r = subprocess.run(cmd, cwd=out_dir, capture_output=True, text=True,
                           encoding="utf-8", errors="replace")
        return r.returncode, (r.stdout or "") + (r.stderr or "")

    def _script_from_setup(self, setup):
        self._tmp = tempfile.mkdtemp(prefix="innoscan_")
        self.log("Reading install_script.iss with innounp")
        rc, out = self._run_innounp(self._tmp, ["install_script.iss"])
        iss = os.path.join(self._tmp, "install_script.iss")
        if not os.path.isfile(iss):          # older builds ignore the mask: full extract
            rc, out = self._run_innounp(self._tmp)
        if not os.path.isfile(iss):
            raise RuntimeError(f"innounp could not read this installer (exit {rc}).\n"
                               + out.strip()[-1500:])
        return iss

    # ---- parsing -----------------------------------------------------------
    def _parse(self, text):
        sec = iss_sections(text)
        self.setup_keys = {}
        for line in sec.get("setup", []):
            if "=" in line:
                k, v = line.split("=", 1)
                self.setup_keys[k.strip().lower()] = v.strip()

        def toks(v):
            return set(re.findall(r'[a-z0-9]+', (v or "").lower()))

        allowed = toks(self.setup_keys.get("architecturesallowed"))
        in64 = toks(self.setup_keys.get("architecturesinstallin64bitmode"))
        self.in64 = set()
        if in64 & {"x64", "x64os", "x64compatible", "win64"}:
            self.in64.add("x64")
        if in64 & {"arm64", "x64compatible", "win64"}:
            self.in64.add("arm64")
        self.setup_min = parse_nt_version(self.setup_keys.get("minversion", ""))

        self.entries = []
        for i, p in enumerate(param_rows(sec.get("files", []))):
            if "source" not in p:
                continue
            source = p["source"].replace("/", "\\")
            dest_dir = safe_win_path(
                p.get("destdir", "").replace("/", "\\") or source.rsplit("\\", 1)[0])
            dest_name = safe_win_path(p.get("destname") or source.rsplit("\\", 1)[-1])
            self.entries.append(Entry(
                order=i, source=source, dest_dir=dest_dir, dest_name=dest_name,
                dest=dest_dir.rstrip("\\") + "\\" + dest_name,
                check=p.get("check", ""), components=p.get("components", ""),
                tasks=p.get("tasks", ""), languages=p.get("languages", ""),
                flags=toks(p.get("flags", "")),
                min_nt=parse_nt_version(p.get("minversion", "")),
                below_nt=parse_nt_version(p.get("onlybelowversion", ""))))

        self.types = [r.get("name", "") for r in param_rows(sec.get("types", []))]
        self.components = OrderedDict()
        for r in param_rows(sec.get("components", [])):
            if r.get("name"):
                self.components[r["name"].lower()] = r
        self.tasks = OrderedDict()
        for r in param_rows(sec.get("tasks", [])):
            if r.get("name"):
                self.tasks[r["name"].lower()] = r
        self.languages = [r.get("name", "") for r in param_rows(sec.get("languages", []))
                          if r.get("name")]

        # Arch set: allowed by [Setup], plus whatever the checks reference.
        refs = " ".join(e.check.lower() for e in self.entries)
        arches = []
        if not allowed or allowed & {"x86", "x86os", "x86compatible"}:
            arches.append("x86")
        if not allowed or allowed & {"x64", "x64os", "x64compatible", "win64"}:
            arches.append("x64")
        if (allowed & {"arm64"}) or "isarm64" in refs:
            arches.append("arm64")
        self._arches = arches or ["x86", "x64"]

        self._scan_checks()

    def _check_calls(self, check):
        try:
            return [t for t in _tokens_check(check) if isinstance(t, tuple)]
        except ExprError:
            return [("call", check, None)]

    def _call_key(self, name, args):
        return f"{name}({args})" if args is not None else name

    def _scan_checks(self):
        known = set(arch_functions("x64", set())) | {
            "iscomponentselected", "wizardiscomponentselected",
            "istaskselected", "wizardistaskselected"}
        counts = defaultdict(int)
        for e in self.entries:
            for _, name, args in self._check_calls(e.check):
                if name.lower() not in known:
                    counts[self._call_key(name, args)] += 1
        self._check_counts = counts

    # ---- interface used by the GUI ------------------------------------------
    def info_text(self):
        src = os.path.basename(self.setup) if self.setup else self.iss
        return (f"{src}  ·  Inno Setup  ·  {len(self.entries)} [Files] entries, "
                f"{len(self.components)} components, {len(self.tasks)} tasks, "
                f"{len(self._check_counts)} custom checks")

    def arches(self):
        return list(self._arches)

    def arch_note(self):
        if self.in64:
            return ("64-bit install mode on " + ", ".join(sorted(self.in64)) +
                    " (ArchitecturesInstallIn64BitMode), so {app} goes to the 64-bit "
                    "Program Files there.")
        return "Installs in 32-bit mode on every architecture."

    def bands(self):
        bps = sorted({v for e in self.entries for v in (e.min_nt, e.below_nt) if v})
        if self.setup_min:
            bps = [b for b in bps if b > self.setup_min]
        floor = self.setup_min
        if not bps:
            return [(floor if floor else None, None,
                     NT_NAMES.get(floor, "nt" + nt_fmt(floor)) if floor else "baseline", False)]
        out = []
        if floor:
            out.append((floor, bps[0], NT_NAMES.get(floor, "nt" + nt_fmt(floor)), False))
        else:
            out.append(((0, 0), bps[0], "baseline", True))
        for i, b in enumerate(bps):
            upper = bps[i + 1] if i + 1 < len(bps) else None
            out.append((b, upper, NT_NAMES.get(b, "nt" + nt_fmt(b)), False))
        return out

    def band_text(self, band):
        rep, upper, _, below = band
        if rep is None:
            return "Any version"
        if below:
            return f"Older than {nt_title(upper)}   (NT < {nt_fmt(upper)})"
        if upper:
            return f"{nt_title(rep)} up to {nt_title(upper)}   ({nt_fmt(rep)} ≤ NT < {nt_fmt(upper)})"
        return f"{nt_title(rep)} and newer   (NT ≥ {nt_fmt(rep)})"

    def band_hint(self):
        return ("Bands come from MinVersion / OnlyBelowVersion in [Files]. The newest "
                "band is the one for current Windows.")

    def options(self):
        """Extra single-choice settings for the Target tab: (key, label, values)."""
        if len(self.languages) > 1:
            return [("language", "Language", self.languages)]
        return []

    def deciders(self):
        out = []
        for name, n in sorted(self._check_counts.items(), key=lambda x: (-x[1], x[0].lower())):
            out.append(Decider(name, [("true", ""), ("false", "")], "auto: undecided",
                               f"used by {n} [Files] entries", n))
        return out

    def features(self):
        """[(iid, parent_iid, text, n_files, toggleable)]"""
        counts = defaultdict(int)
        for e in self.entries:
            for n in _tokens_names(e.components):
                if n not in ("and", "or", "not", "(", ")"):
                    counts["c:" + n.lower()] += 1
            for n in _tokens_names(e.tasks):
                if n not in ("and", "or", "not", "(", ")"):
                    counts["t:" + n.lower()] += 1
        out = []
        for prefix, table, title in (("c:", self.components, "Components"),
                                     ("t:", self.tasks, "Tasks")):
            if not table:
                continue
            root = "#" + title
            out.append((root, "", title, "", False))
            for name, row in table.items():
                parent = prefix + name.rsplit("\\", 1)[0] if "\\" in name else root
                desc = row.get("description", "")
                text = f"{desc}  [{row.get('name')}]" if desc else row.get("name")
                out.append((prefix + name, parent, text, counts.get(prefix + name, 0), True))
        return out

    # ---- evaluation -----------------------------------------------------------
    def _selection(self, overrides, default_only):
        first_type = self.types[0].lower() if self.types else None

        def default_comp(row):
            if "fixed" in (row.get("flags", "").lower()):
                return True
            if not first_type:
                return True
            return first_type in (row.get("types", "").lower().split())

        def default_task(row):
            return "unchecked" not in row.get("flags", "").lower()

        def resolve(prefix, table, default_fn):
            st = {}
            for name in table:
                own = overrides.get(prefix + name)
                if own is None:
                    own = default_fn(table[name]) if default_only else True
                st[name] = own
            for name in table:                     # a child needs its parent
                p = name
                while "\\" in p:
                    p = p.rsplit("\\", 1)[0]
                    if p in st and not st[p]:
                        st[name] = False
            return st

        return (resolve("c:", self.components, default_comp),
                resolve("t:", self.tasks, default_task))

    def _names_true(self, expr, table):
        if not expr.strip():
            return True

        def leaf(tok):
            return bool(table.get(tok.lower(), False))

        try:
            return _Parser(_tokens_names(expr), leaf).parse()
        except ExprError:
            return None

    def _eval_check(self, check, archf, comps, tasks, values, unknown_false, unk):
        if not check.strip():
            return True

        def leaf(tok):
            _, name, args = tok
            lname = name.lower()
            if lname in archf and not args:
                return archf[lname]
            if lname in ("iscomponentselected", "wizardiscomponentselected") and args:
                return self._names_true(args.strip("'\" "), comps)
            if lname in ("istaskselected", "wizardistaskselected") and args:
                return self._names_true(args.strip("'\" "), tasks)
            key = self._call_key(name, args)
            v = values.get(key)
            if v is None:
                unk.add(key)
                return False if unknown_false else None
            return v

        try:
            return _Parser(_tokens_check(check), leaf).parse()
        except ExprError:
            v = values.get(check)
            if v is None:
                unk.add(check)
                return False if unknown_false else None
            return v

    def compute(self, arch, band, values, overrides, opts):
        """values: {check: True/False}; overrides: {iid: bool}; opts: dict."""
        rep, upper, suffix, below = band
        label = f"{arch}-{suffix}" if suffix else arch
        prof = Profile(arch, band, label)
        nt = rep if rep is not None else (10, 0)
        archf = arch_functions(arch, self.in64)
        comps, tasks = self._selection(overrides, opts.get("default_only"))
        lang = opts.get("language") or (self.languages[0] if self.languages else None)
        unknown_false = opts.get("unknown_empty")
        vals = {k: (v in (True, "true", "1", "on")) for k, v in values.items() if v is not None}

        for e in self.entries:
            if "dontcopy" in e.flags:
                prof.dropped.append((e.source, "dontcopy (not installed)"))
                continue
            if e.min_nt and nt_tuple(nt) < e.min_nt:
                prof.dropped.append((e.source, f"MinVersion {nt_fmt(e.min_nt)}"))
                continue
            if e.below_nt and not nt_tuple(nt) < e.below_nt:
                prof.dropped.append((e.source, f"OnlyBelowVersion {nt_fmt(e.below_nt)}"))
                continue
            if e.languages and lang and lang.lower() not in e.languages.lower().split():
                prof.dropped.append((e.source, f"language {e.languages}"))
                continue
            unk = set()
            state = self._eval_check(e.check, archf, comps, tasks, vals, unknown_false, unk)
            state = _and(state, self._names_true(e.components, comps))
            state = _and(state, self._names_true(e.tasks, tasks))
            if state is False:
                prof.dropped.append((e.source, "condition false"))
                continue
            why = ""
            if state is None:
                why = f"Check: {e.check}  [undecided: {', '.join(sorted(unk))}]"
            fs = FileSel(key=e.source, dest=e.dest, comp=e.components or e.tasks or "",
                         seq=e.order, conditional=state is None, why=why, src_dir=e.dest_dir)
            k = e.dest.lower()
            if k in prof.sel:
                prev = prof.sel.pop(k)
                prof.conflicts.append((e.dest, prev.key, fs.key))
                if prev.conditional is False and fs.conditional:
                    fs = prev                       # keep the definite one
            prof.sel[k] = fs

        fstates = {}
        for name, on in comps.items():
            fstates["c:" + name] = (on, set())
        for name, on in tasks.items():
            fstates["t:" + name] = (on, set())
        return prof, fstates, set()

    def dest_of(self, key):
        for e in self.entries:
            if e.source == key:
                return e.dest
        return ""

    # ---- extraction -------------------------------------------------------------
    def extract(self, work, log=print, be=None):
        """Return {source: path on disk}."""
        root = self.extract_root
        if not root:
            root = os.path.join(work, "inno")
            os.makedirs(root, exist_ok=True)
            log("Extracting with innounp")
            rc, out = self._run_innounp(root)
            if rc != 0:
                log(f"innounp exit code {rc}: {out.strip()[-500:]}")
        located = {}
        for e in self.entries:
            p = os.path.join(root, e.source.replace("\\", os.sep))
            located[e.source] = p if os.path.isfile(p) else None
        return located

    def notes(self):
        return []

    def summary_extra(self, profiles):
        return [("Never-selected variants (present but never installed):",
                 never_selected(self, profiles))]

    def cli_command(self, arch, values, overrides, opts):
        src = self.setup or self.extract_root
        flag = "--setup" if self.setup else "--extract-root"
        parts = ["python", "split_inno_arch.py", flag, _q(os.path.basename(src) if self.setup else src)]
        if arch:
            parts += ["--arches", arch]
        if opts.get("single_band") is not None:
            parts += ["--band", str(opts["single_band"])]
        for k, v in sorted(values.items()):
            if v is not None:
                parts += ["--check", _q(f"{k}={'true' if v in (True, 'true') else 'false'}")]
        for iid, on in sorted(overrides.items()):
            kind = "--component" if iid.startswith("c:") else "--task"
            parts += [kind, _q(f"{iid[2:]}={'on' if on else 'off'}")]
        if opts.get("language"):
            parts += ["--language", _q(opts["language"])]
        if opts.get("unknown_empty"):
            parts.append("--undecided-false")
        if opts.get("default_only"):
            parts.append("--default-selection-only")
        if opts.get("prune"):
            parts.append("--prune-by-pe")
        if opts.get("skip_undecided"):
            parts.append("--skip-undecided")
        return " ".join(parts), []

    def cleanup(self):
        if self._tmp:
            shutil.rmtree(self._tmp, ignore_errors=True)


_q = common.q


def never_selected(proj, profiles):
    """innounp ',N' variants that no profile ends up installing."""
    used = {s.key for p in profiles for s in p.sel.values()}
    return sorted({e.source for e in proj.entries
                   if e.source not in used and re.search(r',\d+\.', e.source.rsplit("\\", 1)[-1])})


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #

def _pairs(items, what, truthy=("true", "on", "1", "yes"), falsy=("false", "off", "0", "no")):
    out = {}
    for it in items:
        name, _, val = it.partition("=")
        v = val.strip().lower()
        if v not in truthy + falsy:
            sys.exit(f"--{what} needs NAME=on|off (or true|false), got {it!r}")
        out[name.strip()] = v in truthy
    return out


def main(argv=None):
    ap = argparse.ArgumentParser(description="Split an Inno Setup installer into one clean "
                                             "tree per architecture / Windows version.")
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--setup", help="The installer .exe (innounp extracts it).")
    src.add_argument("--extract-root", help="A folder already extracted by innounp "
                                            "(contains install_script.iss).")
    ap.add_argument("--innounp", help="Path to innounp.exe (default: bundled / PATH).")
    ap.add_argument("--output-root", help="Default: _sorted next to the input.")
    ap.add_argument("--arches", help="Comma list, e.g. 'x64'. Default: all the script allows.")
    ap.add_argument("--check", action="append", default=[], metavar="NAME=true|false")
    ap.add_argument("--component", action="append", default=[], metavar="NAME=on|off")
    ap.add_argument("--task", action="append", default=[], metavar="NAME=on|off")
    ap.add_argument("--language", help="Language name from [Languages] (default: first).")
    ap.add_argument("--undecided-false", action="store_true",
                    help="Treat checks you did not set as false instead of keeping their files.")
    ap.add_argument("--default-selection-only", action="store_true",
                    help="Use the installer's default components/tasks instead of all of them.")
    ap.add_argument("--prune-by-pe", action="store_true",
                    help="Drop wrong-architecture binaries by PE header.")
    ap.add_argument("--skip-undecided", action="store_true",
                    help="Leave out files whose Check is still undecided.")
    ap.add_argument("--band", type=int,
                    help="Only this Windows-version band (0 = oldest). Default: every band.")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--force", action="store_true")
    args = ap.parse_args(argv)

    try:
        proj = InnoProject(args.setup or args.extract_root, innounp=args.innounp)
    except Exception as e:
        sys.exit(str(e))

    values = _pairs(args.check, "check")
    overrides = {"c:" + k.lower(): v for k, v in _pairs(args.component, "component").items()}
    overrides.update({"t:" + k.lower(): v for k, v in _pairs(args.task, "task").items()})
    opts = dict(unknown_empty=args.undecided_false, default_only=args.default_selection_only,
                language=args.language)
    arches = args.arches.split(",") if args.arches else proj.arches()

    opts["prune"] = args.prune_by_pe
    if args.band is not None:
        bands = proj.bands()
        if not 0 <= args.band < len(bands):
            sys.exit(f"--band must be 0..{len(bands) - 1}")
        profiles = []
        for arch in arches:
            p, _, _ = proj.compute(arch, bands[args.band], values, overrides, opts)
            if args.skip_undecided:
                for k in [k for k, s in p.sel.items() if s.conditional]:
                    s = p.sel.pop(k)
                    p.dropped.append((s.key, "undecided (left out)"))
            profiles.append(p)
    else:
        profiles = all_profiles(proj, values, overrides, opts, arches, args.skip_undecided)

    print(f"\n{proj.info_text()}")
    print(f"Architectures : {', '.join(arches)}   ({proj.arch_note()})")
    print("\nResolved target profiles")
    for p in profiles:
        und = sum(1 for s in p.sel.values() if s.conditional)
        print(f"  {p.label:<22} {p.range_text():<20} {len(p.sel):>5} files  ({und} undecided)")
    dead = never_selected(proj, profiles)
    if dead:
        print("\nNever-selected variants (present but never installed)")
        for d in dead:
            print(f"  {d}")
    undecided = defaultdict(int)
    for p in profiles:
        for s in p.sel.values():
            if s.conditional:
                undecided[s.why] += 1
    if undecided:
        print("\nUndecided (files kept, flagged) - set with --check NAME=true|false:")
        for w, n in sorted(undecided.items(), key=lambda x: -x[1])[:25]:
            print(f"  {n:>5}x  {w}")

    base = os.path.dirname(os.path.abspath(args.setup)) if args.setup else os.path.abspath(args.extract_root)
    output_root = args.output_root or os.path.join(base, "_sorted")
    if args.dry_run:
        print(f"\nDRY RUN - nothing written. Output would go to: {output_root}")
        proj.cleanup()
        return

    if os.path.exists(output_root):
        if not args.force and input(f"'{output_root}' exists. Replace? [y/N] ").strip().lower() not in ("y", "yes"):
            proj.cleanup()
            return
        shutil.rmtree(output_root)
    work = tempfile.mkdtemp(prefix="innosplit_")
    try:
        located = proj.extract(work)
        if args.prune_by_pe:
            prune_by_pe(profiles, located)
        write_all(output_root, profiles, located, proj)
        print(f"\nDone. {len(profiles)} profiles written to: {output_root}")
    finally:
        shutil.rmtree(work, ignore_errors=True)
        proj.cleanup()


if __name__ == "__main__":
    main()
