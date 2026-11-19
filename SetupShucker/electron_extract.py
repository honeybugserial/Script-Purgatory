#!/usr/bin/env python3
"""
Electron backend: installers made by electron-builder's NSIS target.

electron-builder packs the finished app folder into one archive per architecture
and embeds it in the NSIS installer's $PLUGINSDIR (templates/nsis/include/
extractAppPackage.nsh):

    $PLUGINSDIR\\app-32.7z     ia32   -> x86
    $PLUGINSDIR\\app-64.7z     x64    -> x64
    $PLUGINSDIR\\app-arm64.7z  arm64  -> arm64

Those three are the only names it uses. With "useZip": true the archives are
.zip instead of .7z. A multi-arch ("universal") installer carries several of
them and picks one at install time. The nsis-web target embeds nothing and
downloads <name>-<version>-<arch>.nsis.7z instead; such a package is accepted
directly.

Each architecture's archive is a complete app, so each one becomes a profile
on its own: nothing is mixed between them. 7-Zip does all the work.

    python electron_extract.py --input setup.exe --dry-run
    python electron_extract.py --input setup.exe              # -> setup_electron\\<arch>\\
    python electron_extract.py --input setup.exe --arches x64 --output-root D:\\apps\\foo
    python electron_extract.py --input setup.exe --folder locales=off
    python electron_extract.py --input unpacked_folder        # $PLUGINSDIR already on disk
    python electron_extract.py --input app-64.7z              # a payload on its own
"""

import argparse
import os
import re
import shutil
import sys
import tempfile
from collections import OrderedDict

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import installer_detect as detect  # noqa: E402
import split_common as common  # noqa: E402
from split_generic import FileSel, Profile  # noqa: E402

# electron-builder suffix -> Windows arch name used everywhere else in SetupShucker
SUFFIX_ARCH = {"32": "x86", "64": "x64", "arm64": "arm64"}
ARCH_ORDER = ("x64", "arm64", "x86")
_EMBEDDED = re.compile(r"(?:^|[\\/])\$pluginsdir[\\/]app-(32|64|arm64)\.(7z|zip)$", re.I)
_BARE = re.compile(r"^app-(32|64|arm64)\.(7z|zip)$", re.I)
_WEB = re.compile(r"-(ia32|x64|arm64)\.nsis\.7z$", re.I)          # nsis-web package
_WEB_ARCH = {"ia32": "x86", "x64": "x64", "arm64": "arm64"}


class Payload:
    """One embedded app archive.
    source  : the setup .exe it is inside, or None when it is a file on disk
    inner   : path inside the setup (as 7-Zip lists it), or the file's own path
    """
    __slots__ = ("arch", "name", "source", "inner", "size")

    def __init__(self, arch, name, source, inner, size):
        self.arch, self.name, self.source, self.inner, self.size = arch, name, source, inner, size

    def __repr__(self):
        return f"Payload({self.arch}, {self.name}, {self.size:,} bytes)"


def _sort(payloads):
    return sorted(payloads, key=lambda p: ARCH_ORDER.index(p.arch))


def list_7z(path, timeout=300):
    """[(path_inside, size, is_folder)] from `7z l -slt`. [] if 7-Zip cannot open it."""
    r = detect._run([detect.find_7z(), "l", "-slt", "-p", path], timeout=timeout)
    if r.returncode not in (0, 1):
        return []
    out, cur, started = [], {}, False

    def flush():
        if "Path" in cur:
            folder = cur.get("Folder") == "+" or "D" in cur.get("Attributes", "")[:1]
            out.append((cur["Path"], int(cur.get("Size") or 0), folder))

    for ln in r.stdout.splitlines():
        if ln.startswith("----------"):            # entries start after this line
            started = True
            continue
        if not started:
            continue
        if not ln.strip():
            flush()
            cur = {}
            continue
        k, sep, v = ln.partition(" = ")
        if sep:
            cur[k.strip()] = v
    flush()
    return out


_payload_cache = {}


def find_payloads(path):
    """
    Electron app archives in `path`, which may be:
      - an electron-builder NSIS setup .exe   (looks inside with 7-Zip)
      - a folder 7-Zip already unpacked it to ($PLUGINSDIR\\app-*.7z on disk)
      - a bare app-64.7z / app-32.zip / foo-1.0.0-x64.nsis.7z
    Returns [Payload] (x64 first), or [] when it is not one of those.
    """
    path = os.path.abspath(path)
    try:
        stamp = (path, os.path.getmtime(path), os.path.getsize(path))
    except OSError:
        return []
    if stamp in _payload_cache:
        return list(_payload_cache[stamp])
    found = _find_payloads(path)
    _payload_cache[stamp] = found
    return list(found)


def _find_payloads(path):
    found = {}
    if os.path.isdir(path):
        for root, dirs, files in os.walk(path):
            if os.path.relpath(root, path).count(os.sep) >= 3:
                dirs[:] = []
            for name in files:
                full = os.path.join(root, name)
                m = _EMBEDDED.search(os.path.relpath(full, path)) or _BARE.match(name)
                if m:
                    arch = SUFFIX_ARCH[m.group(1).lower()]
                    found.setdefault(arch, Payload(arch, name, None, full, os.path.getsize(full)))
        return _sort(found.values())

    name = os.path.basename(path)
    m = _BARE.match(name)
    if m:
        return [Payload(SUFFIX_ARCH[m.group(1).lower()], name, None, path, os.path.getsize(path))]
    m = _WEB.search(name)
    if m:
        return [Payload(_WEB_ARCH[m.group(1).lower()], name, None, path, os.path.getsize(path))]
    if not _is_pe(path) or not detect.sevenzip_available():
        return []
    for inner, size, folder in list_7z(path):
        m = None if folder else _EMBEDDED.search(inner)
        if m:
            arch = SUFFIX_ARCH[m.group(1).lower()]
            found.setdefault(arch, Payload(arch, os.path.basename(inner.replace("\\", "/")),
                                           path, inner, size))
    return _sort(found.values())


def looks_like_electron(path):
    return bool(find_payloads(path))


def _is_pe(path):
    try:
        with open(path, "rb") as f:
            return f.read(2) == b"MZ"
    except OSError:
        return False


def default_output(path):
    """<folder>\\<stem>_electron next to the input."""
    path = os.path.abspath(path.rstrip("\\/"))
    if os.path.isdir(path):
        return path + "_electron"
    stem = os.path.basename(path)
    for ext in (".nsis.7z", ".7z", ".zip", ".exe"):
        if stem.lower().endswith(ext):
            stem = stem[: -len(ext)]
            break
    return os.path.join(os.path.dirname(path), stem + "_electron")


# --------------------------------------------------------------------------- #
# Project (the interface SetupShucker.py drives, see split_common)
# --------------------------------------------------------------------------- #

class _Pkg:
    """A payload plus the files listed inside it."""
    def __init__(self, payload, archive, files):
        self.p, self.archive = payload, archive
        self.files = files                       # [(rel with '\\', size)]
        self.prefix = payload.name


class ElectronProject:
    kind = "Electron"
    supports_all = True
    decider_label = "Conditions"
    feature_label = "Folders"
    decider_help = ("Nothing to set: an Electron installer has no install conditions. "
                    "Each architecture is its own complete app package.")
    feature_help = ("Top-level folders of the app. Click a row's Include cell to cycle "
                    "auto -> on -> off (e.g. switch off locales\\ to keep only the "
                    "languages you need in a later step).")
    unknown_option = None                         # these GUI options mean nothing here
    default_option = None

    def __init__(self, path, log=print):
        self.path = os.path.abspath(path)
        self.log = log
        self._tmp = None
        self.located = {}
        payloads = find_payloads(self.path)
        if not payloads:
            raise RuntimeError("No Electron app package (app-32 / app-64 / app-arm64 .7z or "
                               ".zip) found.")
        self.default_output = default_output(self.path)
        self.pkgs = OrderedDict()
        try:
            for p in payloads:
                archive = p.inner
                if p.source:                       # still inside the setup: take it out
                    if not self._tmp:
                        self._tmp = tempfile.mkdtemp(prefix="electron_")
                    log(f"Taking {p.name} out of {os.path.basename(p.source)}…")
                    sub = os.path.join(self._tmp, p.arch)
                    os.makedirs(sub, exist_ok=True)
                    r = detect._run([detect.find_7z(), "e", "-y", "-p", f"-o{sub}",
                                     p.source, p.inner])
                    archive = os.path.join(sub, p.name)
                    if r.returncode not in (0, 1) or not os.path.isfile(archive):
                        raise RuntimeError(f"7-Zip could not take {p.inner} out of "
                                           f"{p.source}:\n" + _tail(r))
                log(f"Listing {p.name}…")
                files = [(rel.replace("/", "\\"), size)
                         for rel, size, folder in list_7z(archive) if not folder]
                if not files:
                    raise RuntimeError(f"7-Zip could not list {p.name}.")
                self.pkgs[p.arch] = _Pkg(p, archive, files)
        except Exception:
            self.cleanup()
            raise
        self.tops = OrderedDict()
        for pkg in self.pkgs.values():
            counts = OrderedDict()
            for rel, _ in pkg.files:
                t = _top(rel)
                counts[t] = counts.get(t, 0) + 1
            for t, n in counts.items():
                self.tops[t] = max(self.tops.get(t, 0), n)

    # ---- GUI interface -----------------------------------------------------
    def info_text(self):
        parts = "; ".join(f"{a} ({k.p.name}, {k.p.size / 1048576:,.0f} MB, {len(k.files)} files)"
                          for a, k in self.pkgs.items())
        return f"{os.path.basename(self.path)}  ·  Electron app (electron-builder)  ·  {parts}"

    def arches(self):
        return list(self.pkgs)

    def arch_note(self):
        return ("One complete app package per architecture: " +
                ", ".join(f"{k.p.name} = {a}" for a, k in self.pkgs.items()) +
                ". Nothing is shared or mixed between them.")

    def bands(self):
        return [(None, None, "", False)]

    def band_text(self, band):
        return "Any version"

    def band_hint(self):
        return ""

    def options(self):
        return []

    def deciders(self):
        return []

    def features(self):
        return [("d:" + t, "", t or "(files in the app folder)", n, True)
                for t, n in self.tops.items()]

    def _key(self, arch, rel):
        return self.pkgs[arch].prefix + "\\" + rel

    def compute(self, arch, band, values, overrides, opts):
        prof = Profile(arch, band, arch)
        for rel, _ in self.pkgs[arch].files:
            key = self._key(arch, rel)
            if not overrides.get("d:" + _top(rel), True):
                prof.dropped.append((key, "folder switched off"))
                continue
            prof.sel[rel.lower()] = FileSel(key=key, dest=rel, comp=None,
                                            conditional=False, why="")
        fstates = {"d:" + t: (overrides.get("d:" + t, True), set()) for t in self.tops}
        return prof, fstates, set()

    def dest_of(self, key):
        return key.split("\\", 1)[1] if "\\" in key else key

    def extract(self, work, log=print, be=None):
        """Unpack every package into work\\<arch>; {key: path on disk}."""
        work = work or self._ensure_tmp()
        located = {}
        for arch, pkg in self.pkgs.items():
            dest = os.path.join(work, "app_" + arch)
            log(f"Unpacking {pkg.p.name} ({pkg.p.size / 1048576:,.0f} MB)…")
            ok, msg = detect.unpack_with_7z(pkg.archive, dest)
            if not ok:
                raise RuntimeError(f"7-Zip could not unpack {pkg.p.name}:\n{msg}")
            for rel, _ in pkg.files:
                p = os.path.join(dest, rel.replace("\\", os.sep))
                if os.path.isfile(p):
                    located[self._key(arch, rel)] = p
        self.located = located
        return located

    def _ensure_tmp(self):
        if not self._tmp:
            self._tmp = tempfile.mkdtemp(prefix="electron_")
        return self._tmp

    def notes(self):
        return ["Electron mode: each architecture's app package is written as it is. "
                "resources\\app.asar holds the app's own code; the rest is the Electron "
                "runtime."]

    def summary_extra(self, profiles):
        rows = []
        for p in profiles:
            pkg = self.pkgs.get(p.arch)
            if not pkg:
                continue
            exes = [(rel, self.located.get(self._key(p.arch, rel)))
                    for rel, _ in pkg.files
                    if "\\" not in rel and rel.lower().endswith(".exe")
                    and not rel.lower().startswith("uninstall")]
            exes = [(r, f) for r, f in exes if f]
            if not exes:
                continue
            rel, f = max(exes, key=lambda x: os.path.getsize(x[1]))
            pe = common.pe_machine(f)
            line = f"{p.label}: {rel} is PE {pe or '?'}"
            if pe and pe != p.arch:
                line += f"   ! package is named for {p.arch}"
            rows.append(line)
        return [("Main executable check:", rows)]

    def cli_command(self, arch, values, overrides, opts):
        parts = ["python", "electron_extract.py", "--input", common.q(self.path)]
        if arch:
            parts += ["--arches", arch]
        for iid, on in sorted(overrides.items()):
            parts += ["--folder", common.q(f"{iid[2:] or '.'}={'on' if on else 'off'}")]
        if opts.get("prune"):
            parts.append("--prune-by-pe")
        return " ".join(parts), []

    def cleanup(self):
        if self._tmp:
            shutil.rmtree(self._tmp, ignore_errors=True)
            self._tmp = None


def _top(rel):
    return rel.split("\\", 1)[0].lower() if "\\" in rel else ""


def _tail(r):
    return "\n".join((r.stdout + r.stderr).strip().splitlines()[-12:])


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #

def main(argv=None):
    ap = argparse.ArgumentParser(description="Extract the app from an electron-builder "
                                             "NSIS installer (app-32/64/arm64.7z).")
    ap.add_argument("--input", required=True,
                    help="Setup .exe, a folder it was unpacked to, or an app-*.7z.")
    ap.add_argument("--output-root", help="Default: <input>_electron next to the input. "
                                          "Each architecture goes into its own subfolder.")
    ap.add_argument("--arches", help="Comma list (x64, x86, arm64). Default: all found.")
    ap.add_argument("--folder", action="append", default=[], metavar="NAME=on|off")
    ap.add_argument("--prune-by-pe", action="store_true")
    ap.add_argument("--dry-run", action="store_true", help="Only show what is inside.")
    ap.add_argument("--force", action="store_true")
    args = ap.parse_args(argv)

    try:
        proj = ElectronProject(args.input, log=lambda m: None)
    except Exception as e:
        sys.exit(str(e))
    try:
        overrides = {}
        for it in args.folder:
            name, _, val = it.partition("=")
            name = "" if name.strip() == "." else name.strip().lower()
            overrides["d:" + name] = val.strip().lower() in ("on", "true", "1", "yes")
        arches = proj.arches()
        if args.arches:
            want = [a.strip().lower().replace("ia32", "x86") for a in args.arches.split(",")]
            missing = [a for a in want if a not in arches]
            if missing:
                sys.exit(f"Not in this installer: {', '.join(missing)}")
            arches = want
        opts = dict(prune=args.prune_by_pe)
        profiles = [proj.compute(a, proj.bands()[0], {}, overrides, opts)[0] for a in arches]

        print(f"\n{proj.info_text()}")
        for p in profiles:
            print(f"  {p.label:<8} {len(p.sel):>5} files  ({len(p.dropped)} left out)")
        output_root = args.output_root or proj.default_output
        if args.dry_run:
            print(f"\nDRY RUN - nothing written. Output would go to: {output_root}")
            return
        existing = [p.label for p in profiles if os.path.exists(os.path.join(output_root, p.label))]
        if existing:
            if not args.force and input(f"{output_root} already has {', '.join(existing)}. "
                                        "Replace? [y/N] ").strip().lower() not in ("y", "yes"):
                return
            for lbl in existing:
                shutil.rmtree(os.path.join(output_root, lbl))
        work = tempfile.mkdtemp(prefix="electron_work_")
        try:
            located = proj.extract(work, log=print)
            if args.prune_by_pe:
                common.prune_by_pe(profiles, located)
            sections = common.write_all(output_root, profiles, located, proj)
        finally:
            shutil.rmtree(work, ignore_errors=True)
        print(f"\nDone. {len(profiles)} profiles written to: {output_root}")
        for title, rows in sections:
            print(title)
            for r in rows:
                print("  " + r)
    finally:
        proj.cleanup()


if __name__ == "__main__":
    main()
