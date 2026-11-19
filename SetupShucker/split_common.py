#!/usr/bin/env python3
"""
Pieces shared by every backend (split_inno_arch, split_msi_arch, split_generic).

A backend is a "project" object the GUI drives through the same methods:

    info_text() arches() arch_note() bands() band_text(b) band_hint() options()
    deciders() features() compute(arch, band, values, overrides, opts)
    dest_of(key) extract(work, log) notes() cli_command(...) cleanup()

plus the labels decider_label / feature_label / decider_help / feature_help /
unknown_option / default_option, and supports_all (True when "write every
profile" makes sense). Profiles carry .label .arch .band .sel .dropped .pruned
.conflicts and range_text(); each .sel value has .key .dest .conditional .why
(and optionally .comp).

This module holds what does not depend on the installer format: PE-header
reading, PE pruning, Windows-safe paths, building every profile, and writing
profile folders with their _PROFILE.txt / _SUMMARY.txt.
"""

import os
import re
import shutil
import struct
from collections import OrderedDict, defaultdict
from datetime import datetime, timezone

PE_EXTS = {".exe", ".dll", ".sys", ".ocx", ".cpl", ".scr", ".efi", ".drv", ".ax",
           ".mui", ".tlb", ".winmd", ".pyd", ".node"}

# --------------------------------------------------------------------------- #
# Paths
# --------------------------------------------------------------------------- #

_BAD_PATH_CHARS = re.compile(r'[<>:"/|?*\x00-\x1f]')


def safe_win_path(path):
    """Make a destination like '{code:GetExtractPath|}\\x.bin' usable as a Windows
    path: illegal characters become '_' (the rule innounp uses for its own output)."""
    parts = []
    for part in path.split("\\"):
        part = _BAD_PATH_CHARS.sub("_", part).rstrip(" .")
        if part:
            parts.append(part)
    return "\\".join(parts)


def q(s):
    """Quote a command-line argument when it needs it (cmd.exe rules)."""
    return f'"{s}"' if any(c in s for c in ' "&|<>^()') else s


# --------------------------------------------------------------------------- #
# PE headers
# --------------------------------------------------------------------------- #

PE_MACHINES = {0x014C: "x86", 0x8664: "x64", 0xAA64: "arm64", 0x0200: "ia64",
               0x01C0: "arm", 0x01C4: "arm", 0x0EBC: "ebc", 0xA641: "arm64"}


def pe_machine(path):
    """'x86', 'x64', 'arm64', ... for a PE file, None if it is not one."""
    try:
        with open(path, "rb") as f:
            head = f.read(0x40)
            if len(head) < 0x40 or head[0:2] != b"MZ":
                return None
            f.seek(struct.unpack_from("<I", head, 0x3C)[0])
            sig = f.read(6)
            if len(sig) < 6 or sig[0:4] != b"PE\x00\x00":
                return None
            machine = struct.unpack_from("<H", sig, 4)[0]
    except (OSError, struct.error):
        return None
    return PE_MACHINES.get(machine, f"0x{machine:X}")


def pe_arch(path):
    """Like pe_machine(), but .NET 'AnyCPU' assemblies (IL-only PE32 without the
    32BITREQUIRED flag) come back as 'any' - their x86 header is only a label."""
    m = pe_machine(path)
    if m != "x86":
        return m
    try:
        with open(path, "rb") as f:
            head = f.read(0x40)
            pe = struct.unpack_from("<I", head, 0x3C)[0]
            f.seek(pe)
            hdr = f.read(24)
            nsec = struct.unpack_from("<H", hdr, 6)[0]
            opt_size = struct.unpack_from("<H", hdr, 20)[0]
            opt = f.read(opt_size)
            if len(opt) < 96 + 15 * 8 or struct.unpack_from("<H", opt, 0)[0] != 0x10B:
                return m
            rva, size = struct.unpack_from("<II", opt, 96 + 14 * 8)   # CLR header
            if not rva or not size:
                return m
            for _ in range(nsec):
                sec = f.read(40)
                if len(sec) < 40:
                    break
                vsize, vaddr, rsize, rptr = struct.unpack_from("<IIII", sec, 8)
                if vaddr <= rva < vaddr + max(vsize, rsize):
                    f.seek(rptr + rva - vaddr + 16)
                    flags = struct.unpack("<I", f.read(4))[0]
                    if flags & 0x1 and not flags & 0x2:     # ILONLY, not 32BITREQUIRED
                        return "any"
                    return m
    except (OSError, struct.error):
        pass
    return m


def prune_by_pe(profiles, located):
    """
    Heuristic for packages that ship all architectures unconditionally:
      x86 profile : drop every 64-bit PE, and whole folders whose PEs are all 64-bit.
      x64 profile : drop x86 kernel drivers (.sys), and whole folders whose PEs are
                    all x86 and contain a .sys (driver package folders, incl. .inf/.cat).
                    32-bit user-mode files stay: they run under WOW64.
    Folders holding .efi images are left alone (they target firmware, not Windows).
    """
    foreign = {"x86": {"x64", "arm64", "ia64"}, "x64": {"x86"}, "arm64": set()}
    for p in profiles:
        bad = foreign.get(p.arch, set())
        if not bad:
            continue
        by_dir = defaultdict(list)
        for k, s in p.sel.items():
            by_dir[s.dest.rsplit("\\", 1)[0].lower()].append(k)
        machines = {}
        for k, s in p.sel.items():
            ext = os.path.splitext(s.dest)[1].lower()
            if ext in PE_EXTS and ext != ".efi" and located.get(s.key):
                machines[k] = pe_machine(located[s.key])
        efi_dirs = {d for d, keys in by_dir.items() if any(k.endswith(".efi") for k in keys)}
        drop = {}
        for d, keys in by_dir.items():
            if d in efi_dirs:
                continue
            pes = [machines[k] for k in keys if machines.get(k)]
            has_sys = any(k.endswith(".sys") for k in keys)
            if pes and all(m in bad for m in pes) and (p.arch == "x86" or has_sys):
                for k in keys:
                    drop[k] = f"folder is all-{pes[0]} PE"
        for k, m in machines.items():
            if k in drop or m not in bad or k.rsplit("\\", 1)[0] in efi_dirs:
                continue
            if p.arch == "x86" or k.endswith(".sys"):
                drop[k] = f"PE machine {m}"
        for k, reason in drop.items():
            s = p.sel.pop(k)
            p.pruned.append((s.dest, s.key, reason))


# --------------------------------------------------------------------------- #
# Every profile
# --------------------------------------------------------------------------- #

def drop_undecided(p):
    for k in [k for k, s in p.sel.items() if s.conditional]:
        s = p.sel.pop(k)
        p.dropped.append((s.key, "undecided (left out)"))


def _signature(p):
    return tuple(sorted((d, s.key, s.conditional) for d, s in p.sel.items()))


def all_profiles(proj, values=None, overrides=None, opts=None, arches=None,
                 skip_undecided=False):
    """
    One profile per distinct (architecture, Windows version band) result.
    Neighbouring bands that give the same tree are merged; when every
    architecture gives identical trees (and PE pruning is off) they collapse
    into a single 'all-...' set.
    """
    values, overrides, opts = values or {}, overrides or {}, opts or {}
    arches = list(arches or proj.arches())
    per_arch = OrderedDict()
    for arch in arches:
        profs, last = [], None
        for band in proj.bands():
            p, _, _ = proj.compute(arch, band, values, overrides, opts)
            if skip_undecided:
                drop_undecided(p)
            sig = _signature(p)
            if profs and sig == last:
                prev = profs[-1]
                rep, _, suffix, below = prev.band
                upper = band[1]
                if below and upper is None:      # identical on every version
                    prev.band = (None, None, suffix, False)
                else:
                    prev.band = (rep, upper, suffix, below)
                continue
            last = sig
            profs.append(p)
        per_arch[arch] = profs

    lists = list(per_arch.values())
    if (len(lists) > 1 and not opts.get("prune")
            and all([_signature(p) for p in l] == [_signature(p) for p in lists[0]]
                    for l in lists[1:])):
        out = []
        for p in lists[0]:
            p.arch = "all (" + ", ".join(arches) + ")"
            suffix = p.band[2]
            p.label = "all-" + suffix if suffix else "all"
            out.append(p)
        return out
    return [p for l in lists for p in l]


# --------------------------------------------------------------------------- #
# Writing
# --------------------------------------------------------------------------- #

def _long(path):
    """Windows: allow paths past 260 characters (deep node_modules trees etc.)."""
    if os.name == "nt" and len(path) >= 240 and not path.startswith("\\\\?\\"):
        path = os.path.abspath(path)
        return "\\\\?\\UNC\\" + path[2:] if path.startswith("\\\\") else "\\\\?\\" + path
    return path


def write_profile(pdir, p, located, settings=None, progress=None):
    """Copy one profile's files into pdir and write its _PROFILE.txt."""
    os.makedirs(pdir, exist_ok=True)
    man = [f"Profile      : {p.label}", f"Architecture : {p.arch}",
           f"Windows      : {p.range_text(long=True)}", f"File count   : {len(p.sel)}"]
    man += settings or []
    man += ["", "Destination  <-  source"]
    total = len(p.sel)
    for i, s in enumerate(p.sel.values(), 1):
        if progress and (i % 25 == 0 or i == total):
            progress(i, total)
        src = located.get(s.key)
        if not src:
            man.append(f"  [MISSING] {s.dest}  <-  {s.key}")
            continue
        dst = _long(os.path.join(pdir, safe_win_path(s.dest).replace("\\", os.sep)))
        os.makedirs(os.path.dirname(dst), exist_ok=True)
        shutil.copy2(src, dst)
        comp = getattr(s, "comp", None)
        flag = "  [UNDECIDED] " + s.why if s.conditional else ""
        man.append(f"  {s.dest}  <-  {s.key}{f' [{comp}]' if comp else ''}{flag}")
    if p.conflicts:
        man += ["", "Same destination from several sources (kept the later/definite one):"]
        man += [f"  {d}: {a} vs {b}" for d, a, b in p.conflicts]
    if p.pruned:
        man += ["", "Pruned by PE-header check:"]
        man += [f"  {d}  <-  {k}  ({r})" for d, k, r in p.pruned]
    with open(os.path.join(pdir, "_PROFILE.txt"), "w", encoding="utf-8") as f:
        f.write("\n".join(man) + "\n")


def write_all(output_root, profiles, located, proj, settings=None, progress=None):
    """Write every profile into output_root/<label> plus _SUMMARY.txt.
    proj.summary_extra(profiles) -> [(title, [lines])] adds backend sections."""
    os.makedirs(output_root, exist_ok=True)
    total = sum(len(p.sel) for p in profiles) or 1
    done = 0
    for p in profiles:
        base = done

        def prog(i, n, base=base):
            if progress:
                progress(base + i, total)
        write_profile(os.path.join(output_root, p.label), p, located, settings, progress=prog)
        done += len(p.sel)
    lines = [f"Source     : {proj.path}",
             f"Generated  : {datetime.now(timezone.utc):%Y-%m-%d %H:%M:%SZ}",
             f"Profiles   : {len(profiles)}", ""]
    for p in profiles:
        miss = sum(1 for s in p.sel.values() if not located.get(s.key))
        und = sum(1 for s in p.sel.values() if s.conditional)
        extra = "".join([f", {und} undecided" if und else "",
                         f", {miss} missing" if miss else "",
                         f", {len(p.pruned)} pruned" if p.pruned else ""])
        lines.append(f"{p.label}  ({p.arch}, {p.range_text(long=True)}) - {len(p.sel)} files{extra}")
    sections = proj.summary_extra(profiles) if hasattr(proj, "summary_extra") else []
    for title, rows in sections:
        if rows:
            lines += ["", title] + [f"  {r}" for r in rows]
    with open(os.path.join(output_root, "_SUMMARY.txt"), "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    return sections
