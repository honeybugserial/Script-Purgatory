#!/usr/bin/env python3
"""
Generic backend: split ANY unpacked installer or archive by architecture.

Used when there are no install rules to read (NSIS, InstallShield, SFX archives,
zips, a folder someone already unpacked, ...). Every file gets an architecture:

  1. its PE header (x86 / x64 / ARM64)                   - binaries
  2. an arch word in its path (x64, amd64, win32, arm64…) - anything else
  3. driver companions (.inf .cat .pdb …) follow the binaries in their folder
  4. otherwise it is neutral and goes into every profile

Each architecture profile then gets the neutral files plus its own binaries.
A 64-bit profile keeps a 32-bit binary only when no 64-bit build of that file
exists (it would run under WOW64); such files are marked undecided so they can
be left out with one click. ARM64 profiles treat x64/x86 builds the same way.

    python split_generic.py --input unpacked_folder --dry-run
    python split_generic.py --input setup.exe            # 7-Zip unpacks it first
    python split_generic.py --input setup.exe --arches x64 --strip-arch-folders
"""

import argparse
import os
import re
import shutil
import sys
import tempfile
from collections import OrderedDict, defaultdict

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import split_common as common  # noqa: E402

ARCHES = ("x86", "x64", "arm64")
_ARCH_WORDS = [
    ("arm64", re.compile(r"(?<![a-z0-9])(arm64(ec)?|aarch64)(?![a-z0-9])")),
    ("x64", re.compile(r"(?<![a-z0-9])(x64|amd64|win64|x86[_-]64|x8664|64[_-]?bit)(?![a-z0-9])")),
    ("x86", re.compile(r"(?<![a-z0-9])(x86|i[3-6]86|win32|ia32|32[_-]?bit)(?![a-z0-9])")),
]
COMPANION_EXTS = {".inf", ".cat", ".pdb", ".lib", ".exp", ".manifest", ".cer", ".pnf"}
INTERNAL_DIRS = {"$pluginsdir", "$temp", "[nsis].nsi"}     # NSIS bookkeeping
# what a target can fall back to when it has no native build of a file
FALLBACK = {"x86": (), "x64": ("x86",), "arm64": ("x64", "x86")}


def arch_word(text):
    """(arch, matched word) for the first arch word in text, else (None, None)."""
    t = text.lower()
    for arch, rx in _ARCH_WORDS:
        m = rx.search(t)
        if m:
            return arch, m.group(1)
    return None, None


def arch_word_at(text):
    """(arch, start, end) of the first arch word in text (same priority as
    arch_word), else None."""
    t = text.lower()
    for arch, rx in _ARCH_WORDS:
        m = rx.search(t)
        if m:
            return arch, m.start(1), m.end(1)
    return None


_DUP_SUFFIX = re.compile(r"^(.*)_(\d+)(\.[^.\\]*)?$")


def strip_arch_segments(rel):
    """'bin\\x64\\a.dll' -> 'bin\\a.dll' (only whole folder names that are arch words)."""
    parts = rel.split("\\")
    keep = [p for p in parts[:-1] if not _is_pure_arch(p)]
    return "\\".join(keep + parts[-1:])


def _is_pure_arch(seg):
    s = seg.lower()
    return any(rx.fullmatch(s) for _, rx in _ARCH_WORDS)


class FileSel:
    __slots__ = ("key", "dest", "comp", "conditional", "why")

    def __init__(self, **kw):
        for k, v in kw.items():
            setattr(self, k, v)


class Profile:
    def __init__(self, arch, band, label):
        self.arch, self.band, self.label = arch, band, label
        self.sel = OrderedDict()
        self.conflicts, self.pruned, self.dropped = [], [], []

    def range_text(self, long=False):
        return "any Windows version"


class Item:
    # rel: path as unpacked (may be foo_1.dll); orig: the path the installer
    # really writes it to (foo.dll); dup: several files share that path
    __slots__ = ("rel", "path", "arch", "how", "top", "name", "orig", "dup")


class GenericProject:
    kind = "Generic"
    supports_all = True
    decider_label = "Conditions"
    feature_label = "Folders"
    decider_help = ("Nothing to set: without install rules, files are sorted by their PE "
                    "header and by arch words in their paths.")
    feature_help = ("Top-level folders of the unpacked payload. Click a row's Include cell "
                    "to cycle auto -> on -> off. Installer internals ($PLUGINSDIR) are off "
                    "on auto.")
    unknown_option = "Leave out binaries that have no native build for the target"
    default_option = "Include installer internals ($PLUGINSDIR, uninstallers)"

    def __init__(self, path, log=print):
        import installer_detect as detect
        self.path = os.path.abspath(path)
        self.log = log
        self._tmp = None
        self.source_kind = None          # 'NSIS', '7-Zip SFX', ... (structural check)
        self.unpacked = False
        if os.path.isdir(self.path):
            self.root = self.path
        else:
            self.source_kind = detect.classify(self.path)
            if not detect.sevenzip_available():
                raise RuntimeError(
                    f"{os.path.basename(self.path)} needs unpacking, but 7-Zip "
                    "(bin\\7z.exe) was not found.")
            self._tmp = tempfile.mkdtemp(prefix="generic_")
            log(f"Unpacking {os.path.basename(self.path)} with 7-Zip…")
            self._dup_paths = self._duplicated_paths()
            ok, msg = detect.unpack_with_7z(self.path, self._tmp,
                                            keep_duplicates=bool(self._dup_paths))
            if not ok or not any(os.scandir(self._tmp)):
                self.cleanup()
                keys = ("cannot", "can not", "unsupported", "wrong password", "error")
                why = [ln.strip() for ln in msg.splitlines()
                       if any(k in ln.lower() for k in keys)
                       and not ln.strip().lower().startswith("error: " + self.path[:1].lower())
                       and self.path not in ln]
                raise RuntimeError(f"7-Zip could not unpack {os.path.basename(self.path)}: it is "
                                   "not an installer or archive 7-Zip can open."
                                   + ("\n\n" + "\n".join(why[-6:]) if why else ""))
            self.root = self._tmp
            self.unpacked = True
        self._scan()
        log("Looking for installers inside…")
        self.nested = [n for n in detect.find_nested(self.root)
                       if os.path.abspath(n[0]) != self.path]

    def _duplicated_paths(self):
        """Lower-case paths that occur more than once inside the archive."""
        try:
            import electron_extract
            listing = electron_extract.list_7z(self.path)
        except Exception:
            return set()
        seen, dups = set(), set()
        for inner, _, folder in listing:
            if folder:
                continue
            k = inner.replace("/", "\\").lower()
            (dups if k in seen else seen).add(k)
        return dups

    # ---- scanning ----------------------------------------------------------
    def _scan(self):
        dup_paths = getattr(self, "_dup_paths", set())
        items = []
        for dirpath, _, files in os.walk(self.root):
            for name in files:
                full = os.path.join(dirpath, name)
                rel = os.path.relpath(full, self.root).replace(os.sep, "\\")
                it = Item()
                it.rel, it.path = rel, full
                it.orig, it.dup = rel, False
                if dup_paths:                       # foo_1.dll -> foo.dll (7-Zip -aou rename)
                    if rel.lower() in dup_paths:
                        it.dup = True
                    else:
                        m = _DUP_SUFFIX.match(rel)
                        if m and (m.group(1) + (m.group(3) or "")).lower() in dup_paths:
                            it.orig, it.dup = m.group(1) + (m.group(3) or ""), True
                it.name = it.orig.rsplit("\\", 1)[-1].lower()
                it.top = it.orig.split("\\", 1)[0].lower() if "\\" in it.orig else ""
                it.arch, it.how = None, ""
                if os.path.splitext(name)[1].lower() in common.PE_EXTS or _has_mz(full):
                    m = common.pe_arch(full)
                    if m == "any":
                        it.how = "PE AnyCPU (.NET)"
                    elif m:
                        it.arch, it.how = m, f"PE {m}"
                items.append(it)
        if not items:
            raise RuntimeError("Nothing to sort: the folder is empty.")
        items = _merge_identical_dups(items)
        _arch_words_with_counterparts(items)
        # driver companions follow the binaries in their folder
        by_dir = defaultdict(list)
        for it in items:
            by_dir[it.orig.rsplit("\\", 1)[0].lower() if "\\" in it.orig else ""].append(it)
        for d, group in by_dir.items():
            pes = {it.arch for it in group if it.how.startswith("PE ") and it.arch}
            if len(pes) == 1:
                (only,) = pes
                for it in group:
                    if it.arch is None and os.path.splitext(it.name)[1] in COMPANION_EXTS:
                        it.arch, it.how = only, f"next to {only} binaries"
        # kernel drivers never run under WOW64 / emulation: their folders are strict
        self.driver_dirs = {d for d, group in by_dir.items()
                            if any(it.name.endswith(".sys") for it in group)}
        self.items = sorted(items, key=lambda i: i.rel.lower())
        self.by_key = {it.rel: it for it in self.items}
        # which architectures each file name exists for (to find counterparts)
        self.builds = defaultdict(set)
        for it in self.items:
            if it.arch in ARCHES:
                self.builds[it.name].add(it.arch)
        present = {it.arch for it in self.items}
        self._arches = [a for a in ARCHES if a in present] or ["x86", "x64"]
        self.tops = OrderedDict()
        for it in self.items:
            self.tops[it.top] = self.tops.get(it.top, 0) + 1

    # ---- GUI interface -----------------------------------------------------
    def info_text(self):
        n = defaultdict(int)
        for it in self.items:
            n[it.arch or "neutral"] += 1
        parts = ", ".join(f"{v} {k}" for k, v in sorted(n.items(), key=lambda x: -x[1]))
        src = os.path.basename(self.path) or self.path
        if self.unpacked:
            what = (f"{self.source_kind} installer, unpacked with 7-Zip" if self.source_kind
                    else "unpacked with 7-Zip")
        else:
            what = "folder"
        return (f"{src}  ·  {what}  ·  sorted generically by PE header / path  ·  "
                f"{len(self.items)} files: {parts}")

    def installers_inside(self):
        return [n for n in self.nested if n[4]]

    def arches(self):
        return list(self._arches)

    def arch_note(self):
        return ("Worked out per file from PE headers and arch words in paths. "
                "Files that are neither go into every profile.")

    def bands(self):
        return [(None, None, "", False)]

    def band_text(self, band):
        return "Any version"

    def band_hint(self):
        return ""

    def options(self):
        return [("arch_folders", "Arch-named folders (x64\\, x86\\, …)",
                 ["Keep them in the path", "Remove them from the path"])]

    def deciders(self):
        return []

    def _internal(self, top):
        return top in INTERNAL_DIRS or top.startswith("$plugins")

    def features(self):
        out = []
        for top, n in self.tops.items():
            label = top or "(files in the top folder)"
            if self._internal(top):
                label += "   - installer internals"
            elif top.startswith("$"):
                label += "   - installed outside the program folder"
            out.append(("d:" + top, "", label, n, True))
        return out

    def _folder_on(self, top, overrides, opts):
        iid = "d:" + top
        if iid in overrides:
            return overrides[iid]
        if self._internal(top):
            return bool(opts.get("default_only"))
        return True

    def compute(self, arch, band, values, overrides, opts):
        prof = Profile(arch, band, arch)
        strip = str(opts.get("arch_folders", "")).startswith("Remove")
        strict = opts.get("unknown_empty")
        for it in self.items:
            if not self._folder_on(it.top, overrides, opts):
                prof.dropped.append((it.rel, "folder switched off"))
                continue
            if it.name.startswith("uninst") and it.name.endswith(".exe") \
                    and not opts.get("default_only"):
                prof.dropped.append((it.rel, "uninstaller (installer internals)"))
                continue
            conditional, why = False, ""
            if it.arch is not None and it.arch != arch:
                d = it.orig.rsplit("\\", 1)[0].lower() if "\\" in it.orig else ""
                if d in self.driver_dirs:
                    prof.dropped.append((it.rel, f"{it.arch} driver package ({it.how}); "
                                                 f"drivers cannot run as {arch}"))
                    continue
                if it.arch not in FALLBACK.get(arch, ()):
                    prof.dropped.append((it.rel, f"{it.arch} file ({it.how})"))
                    continue
                better = [a for a in (arch,) + FALLBACK[arch][:FALLBACK[arch].index(it.arch)]
                          if a in self.builds[it.name]]
                if better:
                    prof.dropped.append((it.rel, f"{it.arch} build; {better[0]} build present"))
                    continue
                if strict:
                    prof.dropped.append((it.rel, f"{it.arch} only, no {arch} build"))
                    continue
                conditional = True
                why = (f"{it.arch} only, no {arch} build "
                       f"({'WOW64' if arch == 'x64' else 'emulated'}; {it.how})")
            dest = strip_arch_segments(it.orig) if strip else it.orig
            fs = FileSel(key=it.rel, dest=dest, comp=it.how, conditional=conditional, why=why)
            k = dest.lower()
            if k in prof.sel:
                prev = prof.sel[k]
                prev_it = self.by_key[prev.key]
                prev_native = prev_it.arch == arch
                new_native = it.arch == arch
                prof.conflicts.append((dest, prev.key, it.rel))
                if (prev_native and not new_native) or (not prev.conditional and conditional):
                    continue
                if prev_it.dup and it.dup and prev_it.arch == it.arch:
                    # same path, different content, nothing to tell them apart by:
                    # the installer picks one at install time - show it as undecided
                    n = sum(1 for x in self.items if x.orig.lower() == it.orig.lower())
                    fs.conditional, fs.why = True, (
                        f"{n} different versions of this file in the installer (it picks "
                        f"one at install time); keeping {it.rel} - check")
            prof.sel[k] = fs
        fstates = {"d:" + t: (self._folder_on(t, overrides, opts), set()) for t in self.tops}
        return prof, fstates, set()

    def dest_of(self, key):
        it = self.by_key.get(key)
        return it.orig if it else key

    def extract(self, work, log=print, be=None):
        return {it.rel: it.path for it in self.items}

    def notes(self):
        return ["Generic mode: this installer has no install rules SetupShucker can read, "
                "so each profile is the neutral files plus that architecture's binaries."]

    def summary_extra(self, profiles):
        return []

    def cli_command(self, arch, values, overrides, opts):
        parts = ["python", "split_generic.py", "--input", common.q(self.path)]
        if arch:
            parts += ["--arches", arch]
        if str(opts.get("arch_folders", "")).startswith("Remove"):
            parts.append("--strip-arch-folders")
        if opts.get("unknown_empty"):
            parts.append("--native-only")
        if opts.get("default_only"):
            parts.append("--keep-internals")
        if opts.get("skip_undecided"):
            parts.append("--native-only")
        for iid, on in sorted(overrides.items()):
            parts += ["--folder", common.q(f"{iid[2:] or '.'}={'on' if on else 'off'}")]
        if opts.get("prune"):
            parts.append("--prune-by-pe")
        return " ".join(_dedupe(parts)), []

    def cleanup(self):
        if self._tmp:
            shutil.rmtree(self._tmp, ignore_errors=True)
            self._tmp = None


def _dedupe(parts):
    out = []
    for p in parts:
        if p.startswith("--") and p in out and p not in ("--folder",):
            continue
        out.append(p)
    return out


def _merge_identical_dups(items):
    """Same path, same bytes: keep one copy (no choice to make)."""
    import hashlib
    groups = defaultdict(list)
    for it in items:
        if it.dup:
            groups[it.orig.lower()].append(it)
    drop = set()
    for group in groups.values():
        seen = {}
        for it in group:
            try:
                size = os.path.getsize(it.path)
                with open(it.path, "rb") as f:
                    digest = hashlib.sha1(f.read()).hexdigest()
            except OSError:
                continue
            key = (size, digest)
            if key in seen:
                drop.add(id(it))
            else:
                seen[key] = it
        if len(seen) == 1:                         # all copies identical: not a duplicate
            for it in group:
                it.dup = False
    return [it for it in items if id(it) not in drop]


def _arch_words_with_counterparts(items):
    """
    An arch word in the path of a non-binary file (x64\\config.json, win32\\x.py,
    32bit-icons.png ...) only makes it arch-specific when the same path exists
    for another architecture (x86\\config.json), or when it sits in an arch
    folder that has a sibling arch folder (bin\\x64\\ next to bin\\x86\\).
    Otherwise the word is just part of a name, and the file goes to every profile.
    """
    cands = []
    for it in items:
        if it.arch is None and not it.how:
            hit = arch_word_at(it.orig)
            if hit:
                cands.append((it, hit))
    if not cands:
        return
    by_key = defaultdict(set)
    for it, (arch, a, b) in cands:
        by_key[it.orig[:a].lower() + "{arch}" + it.orig[b:].lower()].add(arch)
    # arch folders per parent: 'bin\\' -> {'x64', 'x86'}
    folders = defaultdict(set)
    for it in items:
        parts = it.orig.split("\\")[:-1]
        for i, seg in enumerate(parts):
            if _is_pure_arch(seg):
                a, _ = arch_word(seg)
                folders["\\".join(parts[:i]).lower()].add(a)
    for it, (arch, a, b) in cands:
        key = it.orig[:a].lower() + "{arch}" + it.orig[b:].lower()
        seg_start = it.orig.rfind("\\", 0, a) + 1
        seg_end = it.orig.find("\\", b)
        seg = it.orig[seg_start:seg_end] if seg_end != -1 else ""
        parent = it.orig[:max(seg_start - 1, 0)].lower()
        sibling = bool(seg) and _is_pure_arch(seg) and len(folders.get(parent, ())) > 1
        if len(by_key[key]) > 1 or sibling:
            it.arch, it.how = arch, f"'{it.orig[a:b]}' in path"


def _has_mz(path):
    try:
        with open(path, "rb") as f:
            return f.read(2) == b"MZ"
    except OSError:
        return False


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #

def main(argv=None):
    ap = argparse.ArgumentParser(description="Split any unpacked installer by architecture "
                                             "(PE headers + arch-named paths).")
    ap.add_argument("--input", required=True, help="A folder, or a file 7-Zip can unpack.")
    ap.add_argument("--output-root", help="Default: _sorted next to the input.")
    ap.add_argument("--arches", help="Comma list, e.g. 'x64'. Default: every one found.")
    ap.add_argument("--strip-arch-folders", action="store_true",
                    help="Remove folder names like x64\\ or win32\\ from destination paths.")
    ap.add_argument("--native-only", action="store_true",
                    help="Leave out binaries that have no build for the target architecture.")
    ap.add_argument("--keep-internals", action="store_true",
                    help="Keep $PLUGINSDIR and uninstallers.")
    ap.add_argument("--folder", action="append", default=[], metavar="NAME=on|off")
    ap.add_argument("--prune-by-pe", action="store_true")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--force", action="store_true")
    args = ap.parse_args(argv)

    try:
        proj = GenericProject(args.input)
    except Exception as e:
        sys.exit(str(e))
    overrides = {}
    for it in args.folder:
        name, _, val = it.partition("=")
        name = "" if name.strip() == "." else name.strip().lower()
        overrides["d:" + name] = val.strip().lower() in ("on", "true", "1", "yes")
    opts = dict(unknown_empty=args.native_only, default_only=args.keep_internals,
                prune=args.prune_by_pe,
                arch_folders="Remove" if args.strip_arch_folders else "Keep")
    arches = args.arches.split(",") if args.arches else proj.arches()
    profiles = common.all_profiles(proj, {}, overrides, opts, arches)

    print(f"\n{proj.info_text()}")
    for p in profiles:
        und = sum(1 for s in p.sel.values() if s.conditional)
        print(f"  {p.label:<22} {len(p.sel):>5} files  ({und} undecided, "
              f"{len(p.dropped)} left out)")
    base = proj.path if os.path.isdir(proj.path) else os.path.dirname(proj.path)
    output_root = args.output_root or os.path.join(base, "_sorted")
    if args.dry_run:
        print(f"\nDRY RUN - nothing written. Output would go to: {output_root}")
        proj.cleanup()
        return
    if os.path.exists(output_root):
        if not args.force and input(f"'{output_root}' exists. Replace? [y/N] ").strip().lower() \
                not in ("y", "yes"):
            proj.cleanup()
            return
        shutil.rmtree(output_root)
    try:
        located = proj.extract(None)
        if args.prune_by_pe:
            common.prune_by_pe(profiles, located)
        common.write_all(output_root, profiles, located, proj)
        print(f"\nDone. {len(profiles)} profiles written to: {output_root}")
    finally:
        proj.cleanup()


if __name__ == "__main__":
    main()
