#!/usr/bin/env python3
"""
phoneinfo.py - pull make / model / storage / OS / IMEI / SIM / phone number /
carrier-lock / APN info from Android phones over ADB.

Looks best with the `rich` package (pip install rich); falls back to plain
text without it.

Usage:
  python phoneinfo.py                      # find phones, pick one, show report, ask to save
  python phoneinfo.py --all                # read every connected phone, no picker
  python phoneinfo.py -s R58N12ABCDE       # just this phone (repeat -s for more)
  python phoneinfo.py --txt r.txt --html r.html --csv r.csv --json r.json
                                           # save straight to these files, no prompt
  python phoneinfo.py --no-prompt          # never ask anything (good for scripts)
  python phoneinfo.py --root               # rooted phones: retry blocked reads via su
  python phoneinfo.py --adb "C:\\platform-tools\\adb.exe"

Requirements: Python 3.7+, adb (Android SDK platform-tools), and on the phone:
Developer options -> USB debugging ON, plus the "Allow USB debugging?" prompt accepted.
"""

import argparse
import csv
import html
import json
import math
import os
import re
import shutil
import subprocess
import sys
import webbrowser
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path

try:
    from rich import box
    from rich.console import Console, Group
    from rich.markup import escape
    from rich.panel import Panel
    from rich.prompt import Confirm, Prompt
    from rich.table import Table
    from rich.text import Text
    HAVE_RICH = True
except ImportError:            # plain-text fallback
    HAVE_RICH = False

    def escape(s):
        return s

VERSION = "2.0"


# ==========================================================================
# console UI (rich when available, plain text otherwise)
# ==========================================================================

MARKUP_RE = re.compile(r"\[/?(?:bold|dim|italic|green|red|yellow|cyan|blue|magenta|white)"
                       r"(?: (?:bold|dim|green|red|yellow|cyan|blue|magenta|white))*\]|\[/\]")
TONE_STYLE = {"ok": "green", "warn": "yellow", "bad": "bold red", "": ""}


class UI:
    def __init__(self, interactive):
        self.interactive = interactive
        self.console = Console(highlight=False) if HAVE_RICH else None
        self._status = None

    # -- basic output --
    def print(self, *objs, **kw):
        if self.console:
            self.console.print(*objs, **kw)
        else:
            print(*[MARKUP_RE.sub("", o) if isinstance(o, str) else o for o in objs])

    def ok(self, msg):
        self.print(f"  [green]✓[/] {msg}" if self.console else f"  [ok] {msg}")

    def warn(self, msg):
        self.print(f"  [yellow]![/] {msg}" if self.console else f"  [!]  {msg}")

    def err(self, msg):
        self.print(f"  [bold red]✗[/] {msg}" if self.console else f"  [x]  {msg}")

    def step(self, msg):
        if self._status is not None:
            self._status.update(f"[cyan]{msg}…")
        elif not self.console:
            print(f"  ... {msg}")

    @contextmanager
    def status(self, msg):
        if self.console:
            with self.console.status(f"[cyan]{msg}…", spinner="dots") as st:
                self._status = st
                try:
                    yield
                finally:
                    self._status = None
        else:
            print(f"{msg}...")
            yield

    def rule(self, title=""):
        if self.console:
            self.console.rule(title, style="cyan")
        else:
            print("\n" + "-" * 20 + f" {MARKUP_RE.sub('', title)} " + "-" * 20)

    # -- input --
    def ask(self, prompt, default=""):
        if self.console:
            return Prompt.ask(prompt, default=default, show_default=bool(default), console=self.console)
        ans = input(f"{MARKUP_RE.sub('', prompt)}" + (f" [{default}]" if default else "") + ": ").strip()
        return ans or default

    def confirm(self, prompt, default=True):
        if self.console:
            return Confirm.ask(prompt, default=default, console=self.console)
        ans = input(f"{MARKUP_RE.sub('', prompt)} [{'Y/n' if default else 'y/N'}]: ").strip().lower()
        return default if not ans else ans.startswith("y")


# ==========================================================================
# adb plumbing
# ==========================================================================

def run(cmd, timeout=60):
    try:
        p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                           timeout=timeout)
    except (subprocess.TimeoutExpired, OSError):
        return ""
    return p.stdout.decode("utf-8", "replace").replace("\r", "")


def find_adb(explicit):
    if explicit:
        return explicit if os.path.isfile(explicit) or shutil.which(explicit) else None
    found = shutil.which("adb")
    if found:
        return found
    candidates = [
        os.path.expandvars(r"%LOCALAPPDATA%\Android\Sdk\platform-tools\adb.exe"),
        os.path.expanduser("~/Library/Android/sdk/platform-tools/adb"),
        os.path.expanduser("~/Android/Sdk/platform-tools/adb"),
        os.path.join("platform-tools", "adb.exe"),
        os.path.join("platform-tools", "adb"),
        "adb.exe",
    ]
    for c in candidates:
        if os.path.isfile(c):
            return os.path.abspath(c)
    return None


def adb_version(adb):
    m = re.search(r"version\s+([\d.]+)", run([adb, "version"], 20))
    return m.group(1) if m else "unknown"


def list_devices(adb):
    out = run([adb, "devices"], 30)
    devs = []
    for line in out.splitlines():
        if "\t" in line:
            serial, state = line.split("\t", 1)
            devs.append((serial.strip(), state.strip()))
    return devs


def shquote(s):
    return "'" + s.replace("'", "'\\''") + "'"


# ==========================================================================
# helpers
# ==========================================================================

def luhn_ok(num):
    total = 0
    for i, ch in enumerate(reversed(num)):
        d = int(ch)
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def looks_like_imei(s):
    return (re.fullmatch(r"\d{15}", s) is not None
            and len(set(s)) > 2 and luhn_ok(s))


def looks_like_iccid(s):
    return re.fullmatch(r"89\d{16,20}[Ff]?", s) is not None


def looks_like_phone_number(s):
    return re.fullmatch(r"\+?\d{7,15}", s) is not None and len(set(s.lstrip("+"))) > 2


def clean(v):
    return "" if v is None or v.strip() in ("", "NULL", "null") else v.strip()


def split_list(v):
    return [x.strip() for x in v.split(",")] if v else []


def gb(n_bytes):
    return f"{n_bytes / 1e9:.1f} GB"


def nominal_storage(n_bytes):
    """Round raw flash size to the size printed on the box (32/64/128 GB...)."""
    g = n_bytes / 1e9
    if g <= 0:
        return ""
    size = 2 ** round(math.log2(g))
    return f"{size // 1024} TB" if size >= 1024 else f"{size} GB"


def nominal_ram(gib):
    for s in (0.5, 1, 1.5, 2, 3, 4, 6, 8, 10, 12, 16, 18, 20, 24, 32, 64):
        if gib <= s:
            return f"{s:g} GB"
    return f"{round(gib)} GB"


def parse_parcel_string(out):
    """Decode the String16 returned by `service call` (Result: Parcel(...))."""
    words = []
    for line in out.splitlines():
        if "0x" not in line or ":" not in line:
            continue
        hexpart = line.split(":", 1)[1].split("'", 1)[0]
        words += re.findall(r"\b[0-9a-fA-F]{8}\b", hexpart)
    if len(words) < 2 or int(words[0], 16) != 0:      # non-zero = exception
        return None
    n = int(words[1], 16)
    if n <= 0 or n > 256:
        return None
    data = b"".join(int(w, 16).to_bytes(4, "little") for w in words[2:])
    s = data[:n * 2].decode("utf-16-le", "replace").strip("\x00 ").strip()
    return s or None


def parse_content_rows(out):
    rows = []
    for line in out.splitlines():
        if not line.startswith("Row:"):
            continue
        parts = line.split(" ", 2)
        if len(parts) < 3:
            continue
        rows.append(dict(re.findall(r"(\w+)=(.*?)(?=, \w+=|$)", parts[2])))
    return rows


# Samsung CSC codes -> firmware branding (branding is a hint, NOT proof of a lock)
SAMSUNG_CSC = {
    "XAA": "US unlocked (no carrier)", "TMB": "T-Mobile", "TMK": "Metro by T-Mobile",
    "ATT": "AT&T", "AIO": "Cricket", "VZW": "Verizon", "SPR": "Sprint",
    "USC": "US Cellular", "TFN": "Tracfone", "XAC": "Canada unlocked (no carrier)",
    "BTU": "UK unlocked (no carrier)", "EUX": "EU unlocked (no carrier)",
}
LOCK_SIM_STATES = ("NETWORK_LOCKED", "PERSO_LOCKED", "CARD_RESTRICTED")


# ==========================================================================
# the phone
# ==========================================================================

class Phone:
    def __init__(self, adb, serial, use_root=False, ui=None):
        self.adb = adb
        self.serial = serial
        self.use_root = use_root
        self.ui = ui
        self.props = {}

    # progress reporting (no-ops if no UI)
    def _step(self, msg):
        if self.ui:
            self.ui.step(msg)

    def _ok(self, msg):
        if self.ui:
            self.ui.ok(msg)

    def _warn(self, msg):
        if self.ui:
            self.ui.warn(msg)

    def sh(self, cmd, timeout=60):
        return run([self.adb, "-s", self.serial, "shell", cmd], timeout).strip()

    def su(self, cmd, timeout=90):
        return self.sh("su -c " + shquote(cmd), timeout)

    def query(self, cmd):
        """content query, retried as root if allowed and the first try returned nothing."""
        rows = parse_content_rows(self.sh(cmd))
        if not rows and self.use_root:
            rows = parse_content_rows(self.su(cmd))
        return rows

    def p(self, *keys):
        for k in keys:
            v = self.props.get(k, "").strip()
            if v:
                return v
        return ""

    # ---- collection -------------------------------------------------------

    def collect(self):
        self._step("Reading system properties")
        for line in self.sh("getprop").splitlines():
            m = re.match(r"^\[(.*?)\]: \[(.*)\]$", line)
            if m:
                self.props[m.group(1)] = m.group(2).strip()
        if not self.props:
            raise RuntimeError("could not read system properties (is the phone still connected?)")
        p = self.p
        info = {"adb_serial": self.serial,
                "collected_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")}

        # identity
        info["manufacturer"] = p("ro.product.manufacturer", "ro.product.vendor.manufacturer")
        info["brand"] = p("ro.product.brand", "ro.product.vendor.brand")
        info["model"] = p("ro.product.model", "ro.product.vendor.model", "ro.product.system.model")
        info["marketing_name"] = p("ro.product.marketname", "ro.product.vendor.marketname",
                                   "ro.config.marketing_name", "ro.vendor.oplus.market.name",
                                   "ro.oppo.market.name")
        info["codename"] = p("ro.product.device", "ro.product.vendor.device")
        info["serial"] = p("ro.serialno", "ro.boot.serialno")
        info["oem_serial"] = p("ril.serialnumber")            # Samsung sticker serial
        info["region_csc"] = p("ro.csc.sales_code", "ril.sales_code",
                               "ro.boot.carrierid", "ro.carrier")
        self._ok(f"{len(self.props)} system properties read "
                 f"([bold]{escape(info['manufacturer'])} {escape(info['model'])}[/])")

        # software
        info["android_version"] = p("ro.build.version.release_or_codename", "ro.build.version.release")
        info["sdk"] = p("ro.build.version.sdk")
        info["security_patch"] = p("ro.build.version.security_patch")
        info["build"] = p("ro.build.display.id", "ro.build.id")
        info["fingerprint"] = p("ro.build.fingerprint", "ro.vendor.build.fingerprint")
        bb = p("gsm.version.baseband")
        info["baseband"] = split_list(bb)[0] if bb else ""
        info["bootloader"] = p("ro.bootloader", "ro.boot.bootloader")
        self._ok(f"Android {escape(info['android_version'] or '?')}"
                 + (f" (SDK {info['sdk']})" if info["sdk"] else "")
                 + f", security patch {info['security_patch'] or 'unknown'}")

        # hardware
        self._step("Reading hardware (chipset, RAM, storage, screen)")
        soc = " ".join(x for x in (p("ro.soc.manufacturer"), p("ro.soc.model")) if x)
        info["chipset"] = soc or p("ro.board.platform", "ro.hardware.chipname", "ro.hardware")
        info["cpu_abi"] = p("ro.product.cpu.abi")
        self._ram(info)
        self._storage(info)
        self._screen(info)
        hw = [info.get("chipset"),
              info.get("ram") and info["ram"].split(" (")[0] + " RAM",
              info.get("storage") and info["storage"] + " storage"]
        hw = [escape(x) for x in hw if x]
        (self._ok if hw else self._warn)("Hardware: " + (", ".join(hw) or "not readable"))

        # security state
        self._step("Checking bootloader / root state")
        info["bootloader_locked"] = {"1": "yes", "0": "no"}.get(p("ro.boot.flash.locked"), "unknown")
        info["verified_boot"] = p("ro.boot.verifiedbootstate")
        info["su_present"] = "yes" if self.sh("command -v su 2>/dev/null || which su 2>/dev/null") else "no"
        self._ok(f"Bootloader locked: {info['bootloader_locked']}, su binary: {info['su_present']}")

        # battery
        self._step("Checking battery")
        self._battery(info)
        if info.get("battery_level"):
            self._ok(f"Battery {info['battery_level']}, health {info.get('battery_health', '?')}")

        # radio: IMEIs, SIMs, numbers
        self._step("Probing IMEI / ICCID / phone number (can take a few seconds)")
        imeis, iccids, numbers = self._probe_ids()
        info["imeis"] = imeis
        if imeis:
            self._ok(f"{len(imeis)} IMEI(s) found")
        else:
            self._warn("IMEI not readable over adb on this build (dial *#06# on the phone)")

        self._step("Reading SIM slots and phone numbers")
        info["sims"] = self._sims(iccids, numbers)
        info["other_numbers"] = [n for n in numbers
                                 if n not in [s.get("number") for s in info["sims"]]]
        inserted = [s for s in info["sims"] if s["state"] not in ("ABSENT", "NOT_READY", "unknown")]
        self._ok(f"{len(info['sims'])} SIM slot(s), {len(inserted)} SIM(s) inserted")

        self._step("Checking carrier lock")
        self._carrier_lock(info)
        (self._warn if info["carrier_lock"].startswith("LOCKED") else self._ok)(
            f"Carrier lock: {info['carrier_lock']}")

        self._step("Reading APNs")
        info["apns"] = self._apns(info["sims"])
        if info["apns"]:
            self._ok(f"{len(info['apns'])} APN(s) read")
        else:
            self._warn("APNs not readable on this build (try --root)")
        return info

    def _ram(self, info):
        m = re.search(r"MemTotal:\s+(\d+)\s*kB", self.sh("cat /proc/meminfo"))
        if m:
            gib = int(m.group(1)) / 1024 / 1024
            info["ram"] = f"{nominal_ram(gib)} ({gib:.2f} GiB usable)"

    def _storage(self, info):
        # Raw flash size from block devices (skip SD cards / removable)
        script = ("for b in /sys/block/sd? /sys/block/mmcblk?; do "
                  "[ -e $b/size ] || continue; "
                  "echo \"$(basename $b) $(cat $b/size) $(cat $b/removable 2>/dev/null) "
                  "$(cat $b/device/type 2>/dev/null)\"; done")
        total = 0
        for line in self.sh(script).splitlines():
            parts = line.split()
            if len(parts) >= 2 and parts[1].isdigit():
                removable = len(parts) > 2 and parts[2] == "1"
                is_sd = len(parts) > 3 and parts[3].upper() == "SD"
                if not removable and not is_sd:
                    total += int(parts[1]) * 512
        if total:
            info["storage"] = nominal_storage(total)

        # What the user actually has on /data
        lines = [l for l in self.sh("df -k /data 2>/dev/null").splitlines() if l.strip()]
        if len(lines) >= 2:
            nums = [x for x in lines[-1].split() if x.isdigit()]
            if len(nums) >= 3:
                size, used, free = (int(x) * 1024 for x in nums[:3])
                info["data_partition"] = f"{gb(used)} used of {gb(size)} ({gb(free)} free)"
                if "storage" not in info:
                    info["storage"] = nominal_storage(size) + " (estimated)"

    def _screen(self, info):
        size = re.findall(r"size:\s*(\d+x\d+)", self.sh("wm size"))
        dens = re.findall(r"density:\s*(\d+)", self.sh("wm density"))
        if size:
            info["screen"] = size[0] + (f" @ {dens[0]} dpi" if dens else "")

    def _battery(self, info):
        out = self.sh("dumpsys battery")
        b = {k.strip().lower(): v.strip()
             for k, v in re.findall(r"^[ \t]*([A-Za-z ]+?):[ \t]*(\S.*)$", out, re.M)}
        health = {"1": "unknown", "2": "good", "3": "overheat", "4": "dead",
                  "5": "over voltage", "6": "failure", "7": "cold"}
        if "level" in b:
            info["battery_level"] = b["level"] + "%"
        if "health" in b:
            info["battery_health"] = health.get(b["health"], b["health"])
        if b.get("temperature", "").lstrip("-").isdigit():
            info["battery_temp"] = f"{int(b['temperature']) / 10:.1f} C"
        cyc = self.sh("cat /sys/class/power_supply/battery/cycle_count 2>/dev/null")
        if cyc.isdigit():
            info["battery_cycles"] = cyc

    # ---- IMEI / ICCID / numbers via IPhoneSubInfo ---------------------------

    def _probe_iphonesubinfo(self, root=False):
        """Try IPhoneSubInfo getter transactions (all read-only) and keep what
        they return. Transaction codes differ per Android version, so we sweep
        them and classify/validate the results afterwards."""
        variants = [("", 0), ("s16 com.android.shell", 0)]
        for slot in (0, 1):
            variants += [(f"i32 {slot}", slot),
                         (f"i32 {slot} s16 com.android.shell", slot),
                         (f"i32 {slot} s16 com.android.shell s16 null", slot)]
        cmds = []
        for code in range(1, 16):
            for args, slot in variants:
                cmds.append(f"echo @@{slot}; service call iphonesubinfo {code} {args}")

        # Send in chunks so old adbd's 4 KB command limit isn't hit
        scripts, chunk = [], []
        for c in cmds:
            if sum(len(x) + 2 for x in chunk) + len(c) > 3000:
                scripts.append("; ".join(chunk))
                chunk = []
            chunk.append(c)
        if chunk:
            scripts.append("; ".join(chunk))

        found = []   # (slot, value)
        for script in scripts:
            out = self.su(script) if root else self.sh(script)
            for block in out.split("@@")[1:]:
                slot_s, _, body = block.partition("\n")
                val = parse_parcel_string(body)
                if val:
                    found.append((int(slot_s.strip() or 0), val.strip()))
        return found

    def _probe_ids(self):
        imsi_prefixes = [x for x in split_list(self.p("gsm.sim.operator.numeric")) if x]
        imeis, iccids, numbers = [], [], []

        def is_imsi(v):
            return any(v.startswith(px) for px in imsi_prefixes)

        def add_imei(v):
            if looks_like_imei(v) and not is_imsi(v) and v not in imeis:
                imeis.append(v)

        found = self._probe_iphonesubinfo()
        if self.use_root and not found:
            self._step("Retrying IMEI probe as root")
            found = self._probe_iphonesubinfo(root=True)
        for _, v in sorted(found, key=lambda t: t[0]):
            if looks_like_imei(v) and not is_imsi(v):
                add_imei(v)
            elif looks_like_iccid(v):
                if v not in iccids:
                    iccids.append(v)
            elif looks_like_phone_number(v) and not is_imsi(v) and len(v.lstrip("+")) != 15:
                if v not in numbers:
                    numbers.append(v)

        # Fallbacks: old Android dumpsys, and vendor props some OEMs expose
        for v in re.findall(r"\b\d{15}\b", self.sh("dumpsys iphonesubinfo 2>/dev/null")):
            add_imei(v)
        for k, v in self.props.items():
            if "imei" in k.lower():
                for part in split_list(v):
                    add_imei(part)
        return imeis, iccids, numbers

    # ---- SIMs + phone numbers -----------------------------------------------

    def _isub_numbers(self):
        """Numbers per slot from `dumpsys isub` (often masked on retail builds)."""
        by_slot = {}
        for line in self.sh("dumpsys isub 2>/dev/null").splitlines():
            slot = re.search(r"(?:simSlotIndex|slotIndex|mSimSlotIndex)=(-?\d+)", line)
            num = re.search(r"\b(?:number|mNumber|phoneNumber)=(\+?\d{7,15})\b", line)
            if slot and num and int(slot.group(1)) >= 0:
                by_slot.setdefault(int(slot.group(1)), num.group(1))
        return by_slot

    def _sims(self, probed_iccids, probed_numbers):
        p = self.p
        states = split_list(p("gsm.sim.state"))
        sim_ops = split_list(p("gsm.sim.operator.alpha"))
        mccmnc = split_list(p("gsm.sim.operator.numeric"))
        country = split_list(p("gsm.sim.operator.iso-country"))
        network = split_list(p("gsm.operator.alpha"))
        net_type = split_list(p("gsm.network.type"))
        roaming = split_list(p("gsm.operator.isroaming"))
        cfg = p("persist.radio.multisim.config").lower()
        slots = {"ssss": 1, "dsds": 2, "dsda": 2, "tsts": 3}.get(cfg, max(len(states), 1))

        # Subscription DB: ICCID, number, eSIM flag, sub id (blocked on some builds)
        by_slot = {}
        for r in self.query("content query --uri content://telephony/siminfo"):
            sid = r.get("sim_id", "-1")
            if sid.lstrip("-").isdigit() and int(sid) >= 0:
                by_slot[int(sid)] = r
        isub = self._isub_numbers()

        def at(lst, i):
            return lst[i] if i < len(lst) else ""

        sims = []
        for i in range(slots):
            r = by_slot.get(i, {})
            number, source = clean(r.get("number")), "subscription db"
            if not number and isub.get(i):
                number, source = isub[i], "dumpsys isub"
            sims.append({
                "slot": i + 1,
                "state": at(states, i) or "unknown",
                "sim_operator": at(sim_ops, i),
                "network": at(network, i),
                "network_type": at(net_type, i),
                "roaming": {"true": "yes", "false": "no"}.get(at(roaming, i), ""),
                "mcc_mnc": at(mccmnc, i),
                "country": at(country, i).upper(),
                "iccid": clean(r.get("icc_id")),
                "number": number,
                "number_source": source if number else "",
                "esim": {"1": "yes", "0": "no"}.get(r.get("is_embedded", ""), ""),
                "sub_id": clean(r.get("_id")),
            })

        present = [s for s in sims if s["state"] not in ("ABSENT", "NOT_READY", "unknown")] or sims

        # If siminfo was blocked, place probed ICCIDs in order on present SIMs
        if probed_iccids and not any(s["iccid"] for s in sims):
            for s, icc in zip(present, probed_iccids):
                s["iccid"] = icc
        # Exactly one present SIM with no number and exactly one probed number:
        # that's almost certainly its line number.
        if len(present) == 1 and not present[0]["number"] and len(probed_numbers) == 1:
            present[0]["number"] = probed_numbers[0]
            present[0]["number_source"] = "iphonesubinfo (could be voicemail #)"
        return sims

    # ---- carrier lock ---------------------------------------------------------

    def _carrier_lock(self, info):
        evidence, notes = [], []

        for s in info["sims"]:
            if s["state"].upper() in LOCK_SIM_STATES:
                evidence.append(f"SIM {s['slot']} rejected by phone ({s['state']})")

        csc = self.p("ro.csc.sales_code", "ril.sales_code").upper()
        if csc in SAMSUNG_CSC:
            notes.append(f"Samsung firmware: {csc} = {SAMSUNG_CSC[csc]}")
        elif csc:
            notes.append(f"firmware region/CSC: {csc}")

        pkgs = self.sh("pm list packages 2>/dev/null")
        unlock_apps = sorted(set(re.findall(
            r"package:(\S*(?:simlock|deviceunlock|networkunlock|devicelock)\S*)", pkgs, re.I)))
        if unlock_apps:
            notes.append("carrier unlock/lock app installed: " + ", ".join(unlock_apps))

        if evidence:
            verdict = "LOCKED"
        elif any(s["state"] in ("READY", "LOADED") for s in info["sims"]):
            verdict = "no lock detected with the inserted SIM"
            notes.append("only conclusive if the inserted SIM is from a different carrier")
        else:
            verdict = "unknown (no SIM inserted)"
            notes.append("insert a SIM from another carrier: if it is rejected, the phone is locked")

        info["carrier_lock"] = verdict
        info["carrier_lock_details"] = "; ".join(evidence + notes)

    # ---- APNs -----------------------------------------------------------------

    def _apns(self, sims):
        apn_keys = ("name", "apn", "type", "numeric", "proxy", "port", "mmsc",
                    "mmsproxy", "mmsport", "user", "password", "authtype",
                    "protocol", "roaming_protocol", "carrier_enabled", "_id")
        base = "content query --uri content://telephony/carriers"

        rows = self.query(base + ' --where "current=1"')
        if not rows:
            for mm in {s["mcc_mnc"] for s in sims if s["mcc_mnc"]}:
                rows += self.query(base + f" --where \"numeric='{mm}'\"")

        # Which APN each SIM actually has selected
        preferred = set()
        for s in sims:
            uris = [f"content://telephony/carriers/preferapn/subId/{s['sub_id']}"] if s["sub_id"] else []
            for uri in uris + ["content://telephony/carriers/preferapn"]:
                for r in self.query(f"content query --uri {uri}"):
                    if clean(r.get("_id")):
                        preferred.add(r["_id"])

        apns = []
        for r in rows[:60]:
            a = {k: clean(r.get(k)) for k in apn_keys}
            a["preferred"] = "yes" if a["_id"] and a["_id"] in preferred else ""
            apns.append(a)

        # Fallback: at least the APNs in use, from the telephony registry
        if not apns:
            reg = self.sh("dumpsys telephony.registry 2>/dev/null")
            seen = set()
            for name, _id, numeric, apn in re.findall(
                    r"\[ApnSetting\]\s*([^,]*),\s*(\d+),\s*(\d+),\s*([^,\s]+)", reg):
                if (numeric, apn) not in seen:
                    seen.add((numeric, apn))
                    apns.append({"name": name.strip(), "apn": apn, "numeric": numeric,
                                 "_id": _id, "type": "", "preferred": "in use"})
        return apns


# ==========================================================================
# shared report structure
# ==========================================================================

SECTIONS = [
    ("Device", ["manufacturer", "brand", "model", "marketing_name", "codename",
                "serial", "oem_serial", "region_csc"]),
    ("Hardware", ["chipset", "cpu_abi", "ram", "storage", "data_partition", "screen"]),
    ("Software", ["android_version", "sdk", "security_patch", "build", "baseband",
                  "bootloader", "fingerprint"]),
    ("Security", ["bootloader_locked", "verified_boot", "su_present"]),
    ("Carrier lock", ["carrier_lock", "carrier_lock_details"]),
    ("Battery", ["battery_level", "battery_health", "battery_temp", "battery_cycles"]),
]
LABELS = {"region_csc": "Region / CSC", "cpu_abi": "CPU ABI", "ram": "RAM", "sdk": "SDK",
          "su_present": "su binary", "oem_serial": "OEM serial",
          "carrier_lock": "Status", "carrier_lock_details": "Details"}
MONO_KEYS = {"serial", "oem_serial", "fingerprint", "build", "baseband", "bootloader"}


def label(k):
    return LABELS.get(k, k.replace("_", " ").capitalize())


def tone(k, v):
    """'ok' / 'warn' / 'bad' / '' — drives colours in the console and HTML."""
    v = str(v)
    vl = v.lower()
    if k == "carrier_lock":
        return "bad" if v.startswith("LOCKED") else "ok" if vl.startswith("no lock") else "warn"
    if k == "bootloader_locked":
        return {"yes": "ok", "no": "warn"}.get(vl, "")
    if k == "verified_boot":
        return "ok" if vl == "green" else "warn" if vl in ("yellow", "orange", "red") else ""
    if k == "su_present":
        return "warn" if vl == "yes" else "ok"
    if k == "battery_health":
        return "ok" if vl == "good" else "bad" if vl not in ("", "unknown") else ""
    if k == "state":
        if v.upper() in LOCK_SIM_STATES:
            return "bad"
        return "ok" if v.upper() in ("READY", "LOADED") else "" if v.upper() == "ABSENT" else "warn"
    return ""


def device_title(info):
    return " ".join(x for x in (info.get("manufacturer", "").capitalize(), info.get("model")) if x) \
        or "Unknown device"


def device_subtitle(info):
    bits = [info.get("marketing_name"),
            info.get("android_version") and f"Android {info['android_version']}",
            info.get("storage"),
            info.get("ram") and info["ram"].split(" (")[0] + " RAM"]
    return " · ".join(b for b in bits if b)


def sim_network(s):
    net = " ".join(x for x in (s.get("network"), s.get("network_type")) if x)
    return net + (" (roaming)" if s.get("roaming") == "yes" else "")


def apn_proxy(a):
    return f"{a['proxy']}:{a.get('port') or ''}" if a.get("proxy") else ""


def apn_mms(a):
    parts = [a.get("mmsc") or ""]
    if a.get("mmsproxy"):
        parts.append(f"proxy {a['mmsproxy']}:{a.get('mmsport') or ''}")
    return "  ".join(x for x in parts if x)


def apn_protocol(a):
    if not a.get("protocol"):
        return ""
    return f"{a['protocol']} / {a.get('roaming_protocol') or '-'}"


def apn_auth(a):
    return " / ".join(x for x in (a.get("user"), a.get("password")) if x)


# ==========================================================================
# console rendering
# ==========================================================================

def format_info(info):
    """Plain-text report (used for the .txt file and the no-rich console)."""
    L = []
    L.append("=" * 72)
    L.append(f" {device_title(info)}   [{info['adb_serial']}]   {info.get('collected_at', '')}")
    if device_subtitle(info):
        L.append(f" {device_subtitle(info)}")
    L.append("=" * 72)
    for name, keys in SECTIONS:
        rows = [(label(k), info[k]) for k in keys if info.get(k)]
        if rows:
            L.append(f"\n {name}")
            for k, v in rows:
                L.append(f"   {k:<18} {v}")

    L.append("\n Radio")
    imeis = info.get("imeis") or []
    if imeis:
        for i, v in enumerate(imeis, 1):
            L.append(f"   {'IMEI ' + str(i):<18} {v}")
    else:
        L.append(f"   {'IMEI':<18} not readable over adb on this build (dial *#06#)")
    for s in info.get("sims", []):
        bits = [s["state"]]
        for k in ("sim_operator", "mcc_mnc", "country"):
            if s.get(k) and s[k] not in bits:
                bits.append(s[k])
        if sim_network(s):
            bits.append("network: " + sim_network(s))
        L.append(f"   {'SIM ' + str(s['slot']):<18} {' | '.join(bits)}")
        if s.get("number"):
            L.append(f"   {'  Phone number':<18} {s['number']}  ({s['number_source']})")
        elif s["state"] in ("READY", "LOADED"):
            L.append(f"   {'  Phone number':<18} not stored on SIM / not readable")
        if s.get("iccid"):
            L.append(f"   {'  ICCID':<18} {s['iccid']}")
        if s.get("esim"):
            L.append(f"   {'  eSIM':<18} {s['esim']}")
    if info.get("other_numbers"):
        L.append(f"   {'Other numbers':<18} {', '.join(info['other_numbers'])}"
                 "  (line or voicemail numbers, slot unknown)")

    L.append("\n APNs")
    apns = info.get("apns") or []
    if apns:
        for a in apns:
            mark = "*" if a.get("preferred") else " "
            extras = [("type", a.get("type")), ("mcc/mnc", a.get("numeric")), ("proxy", apn_proxy(a)),
                      ("mms", apn_mms(a)), ("protocol", apn_protocol(a)), ("auth", apn_auth(a))]
            line = f"{a.get('name') or '(no name)'}  apn={a.get('apn') or '-'}"
            line += "".join(f"  |  {k}={v}" for k, v in extras if v)
            if a.get("carrier_enabled") == "0":
                line += "  |  DISABLED"
            L.append(f"  {mark} {line}")
        if any(a.get("preferred") for a in apns):
            L.append("   (* = selected / in use)")
    else:
        L.append("   not readable on this build (try --root, or Settings > Mobile network > APNs)")
    return "\n".join(L)


def styled(key, value):
    return Text(str(value), style=TONE_STYLE[tone(key, value)])


def render_rich(ui, info):
    c = ui.console
    c.print()
    head = Text.assemble((device_title(info), "bold white"), "\n", (device_subtitle(info), "cyan"))
    c.print(Panel(head, title="[bold cyan]Device report[/]",
                  subtitle=f"[dim]{escape(info['adb_serial'])} · {info.get('collected_at', '')}[/]",
                  box=box.DOUBLE, border_style="cyan", padding=(0, 2)))

    panels = []
    for name, keys in SECTIONS:
        rows = [(k, info[k]) for k in keys if info.get(k)]
        if not rows:
            continue
        g = Table.grid(padding=(0, 2))
        g.add_column(style="dim", no_wrap=True)
        g.add_column(overflow="fold")
        for k, v in rows:
            g.add_row(label(k), styled(k, v))
        panels.append(Panel(g, title=f"[bold]{name}[/]", title_align="left",
                            border_style="blue", box=box.ROUNDED, padding=(0, 1)))
    if c.width >= 110:
        for i in range(0, len(panels), 2):
            g = Table.grid(expand=True, padding=(0, 1))
            g.add_column(ratio=1)
            g.add_column(ratio=1)
            g.add_row(panels[i], panels[i + 1] if i + 1 < len(panels) else "")
            c.print(g)
    else:
        for pnl in panels:
            c.print(pnl)

    # Radio
    ids = Table.grid(padding=(0, 2))
    ids.add_column(style="dim", no_wrap=True)
    ids.add_column()
    if info.get("imeis"):
        for i, v in enumerate(info["imeis"], 1):
            ids.add_row(f"IMEI {i}", Text(v, style="bold"))
    else:
        ids.add_row("IMEI", Text("not readable over adb on this build (dial *#06#)", style="yellow"))
    if info.get("other_numbers"):
        ids.add_row("Other numbers", Text(", ".join(info["other_numbers"]) +
                                          "  (line or voicemail, slot unknown)", style="dim"))

    sims = Table(box=box.SIMPLE_HEAD, expand=True, header_style="bold cyan", pad_edge=False)
    for col in ("Slot", "State", "Carrier", "Network", "MCC/MNC", "Phone number", "ICCID", "eSIM"):
        sims.add_column(col, overflow="fold")
    for s in info.get("sims", []):
        num = Text(s["number"]) if s.get("number") else Text("—", style="dim")
        if s.get("number") and "voicemail" in s.get("number_source", ""):
            num.append(" *", style="yellow")
        sims.add_row(str(s["slot"]), styled("state", s["state"]), s.get("sim_operator", ""),
                     sim_network(s), " ".join(x for x in (s.get("mcc_mnc"), s.get("country")) if x),
                     num, s.get("iccid", ""), s.get("esim", ""))
    parts = [ids, sims]
    if any("voicemail" in s.get("number_source", "") for s in info.get("sims", [])):
        parts.append(Text("* read straight from the SIM; could be the voicemail number", style="dim"))
    c.print(Panel(Group(*parts), title="[bold]Radio / SIM[/]", title_align="left",
                  border_style="blue", box=box.ROUNDED, padding=(0, 1)))

    # APNs
    apns = info.get("apns") or []
    if apns:
        t = Table(box=box.SIMPLE_HEAD, expand=True, header_style="bold cyan", pad_edge=False)
        t.add_column("", width=1)
        for col in ("Name", "APN", "Type", "MCC/MNC", "MMS", "Proxy", "Protocol", "Auth"):
            t.add_column(col, overflow="fold")
        for a in apns:
            name = Text(a.get("name") or "(no name)",
                        style="dim strike" if a.get("carrier_enabled") == "0" else "")
            t.add_row(Text("★", style="bold green") if a.get("preferred") else "", name,
                      Text(a.get("apn") or "-", style="bold"), a.get("type", ""), a.get("numeric", ""),
                      apn_mms(a), apn_proxy(a), apn_protocol(a), apn_auth(a))
        body = Group(t, Text("★ = selected / in use", style="dim")) \
            if any(a.get("preferred") for a in apns) else t
    else:
        body = Text("Not readable on this build. Try --root, or check Settings > Mobile network > APNs.",
                    style="yellow")
    c.print(Panel(body, title="[bold]APNs[/]", title_align="left",
                  border_style="blue", box=box.ROUNDED, padding=(0, 1)))


def show_report(ui, info):
    if ui.console:
        render_rich(ui, info)
    else:
        print("\n" + format_info(info))


# ==========================================================================
# HTML report
# ==========================================================================

HTML_CSS = """
:root{--bg:#f4f5f7;--card:#fff;--text:#1c2230;--muted:#667085;--border:#e2e5ea;
--accent:#2563eb;--ok:#15803d;--warn:#b45309;--bad:#b91c1c;--chip:#eef2fb}
@media (prefers-color-scheme:dark){:root{--bg:#0e1117;--card:#161b24;--text:#e5e7eb;
--muted:#98a2b3;--border:#273041;--accent:#7aa2ff;--ok:#4ade80;--warn:#fbbf24;--bad:#f87171;--chip:#1d2433}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text);
font:14px/1.5 system-ui,-apple-system,"Segoe UI",Roboto,Helvetica,Arial,sans-serif}
.wrap{max-width:1120px;margin:0 auto;padding:28px 16px 56px}
.top{display:flex;flex-wrap:wrap;justify-content:space-between;align-items:flex-end;gap:8px;
border-bottom:2px solid var(--accent);padding-bottom:12px}
.top h1{margin:0;font-size:22px;letter-spacing:-.01em}
.top .meta{color:var(--muted);font-size:13px}
nav{margin-top:12px;display:flex;flex-wrap:wrap;gap:8px}
nav a{color:var(--accent);text-decoration:none;background:var(--chip);padding:4px 10px;border-radius:999px;font-size:13px}
.device{margin-top:32px}
.dev-head h2{margin:0;font-size:20px}
.dev-head .sub{color:var(--muted);margin-top:2px}
.chips{display:flex;flex-wrap:wrap;gap:6px;margin-top:10px}
.chip{background:var(--chip);border-radius:999px;padding:3px 10px;font-size:12px}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(330px,1fr));gap:14px;margin-top:16px}
.card{background:var(--card);border:1px solid var(--border);border-radius:12px;padding:14px 16px;min-width:0}
.card.wide{grid-column:1/-1}
.card h3{margin:0 0 10px;font-size:12px;text-transform:uppercase;letter-spacing:.07em;color:var(--muted)}
dl{display:grid;grid-template-columns:max-content 1fr;gap:5px 18px;margin:0}
dt{color:var(--muted)}dd{margin:0;overflow-wrap:anywhere}
.mono{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:12.5px}
.tbl{overflow-x:auto}
table{width:100%;border-collapse:collapse;font-size:13px}
th,td{text-align:left;padding:7px 8px;border-bottom:1px solid var(--border);vertical-align:top}
th{color:var(--muted);font-weight:600;font-size:12px;white-space:nowrap}
tr:last-child td{border-bottom:none}
.ok{color:var(--ok)}.warn{color:var(--warn)}.bad{color:var(--bad)}.dim{color:var(--muted)}
.badge{display:inline-block;padding:1px 9px;border-radius:999px;font-size:12px;font-weight:600;
border:1px solid currentColor}
.star{color:var(--ok);font-weight:700}
.note{color:var(--muted);font-size:12px;margin-top:8px}
footer{margin-top:40px;color:var(--muted);font-size:12px;text-align:center}
@media print{body{background:#fff}.card{break-inside:avoid}nav{display:none}}
"""


def e(v):
    return html.escape(str(v)) if v not in (None, "") else ""


def html_value(k, v):
    t = tone(k, v)
    cls = " mono" if k in MONO_KEYS else ""
    if t and k in ("carrier_lock", "bootloader_locked", "verified_boot", "su_present", "battery_health"):
        return f'<span class="badge {t}">{e(v)}</span>'
    return f'<span class="{t}{cls}">{e(v)}</span>'


def html_device(info, idx):
    out = [f'<section class="device" id="dev{idx}">',
           '<div class="dev-head">',
           f'<h2>{e(device_title(info))}</h2>',
           '<div class="sub">' + " · ".join(
               x for x in (e(info.get("marketing_name") or info.get("codename")),
                           f'<span class="mono dim">{e(info["adb_serial"])}</span>',
                           f'<span class="dim">{e(info.get("collected_at"))}</span>') if x) + "</div>",
           '<div class="chips">']
    for chip in (info.get("android_version") and f"Android {info['android_version']}",
                 info.get("security_patch") and f"Patch {info['security_patch']}",
                 info.get("storage"), info.get("ram") and info["ram"].split(" (")[0] + " RAM",
                 info.get("battery_level") and f"Battery {info['battery_level']}"):
        if chip:
            out.append(f'<span class="chip">{e(chip)}</span>')
    lock = info.get("carrier_lock", "")
    if lock:
        out.append(f'<span class="badge {tone("carrier_lock", lock)}">Carrier: {e(lock)}</span>')
    out.append("</div></div><div class=\"grid\">")

    for name, keys in SECTIONS:
        rows = [(k, info[k]) for k in keys if info.get(k)]
        if rows:
            wide = " wide" if name == "Carrier lock" else ""
            out.append(f'<div class="card{wide}"><h3>{e(name)}</h3><dl>')
            out += [f"<dt>{e(label(k))}</dt><dd>{html_value(k, v)}</dd>" for k, v in rows]
            out.append("</dl></div>")

    # Radio
    out.append('<div class="card wide"><h3>Radio / SIM</h3><dl>')
    if info.get("imeis"):
        out += [f'<dt>IMEI {i}</dt><dd class="mono"><b>{e(v)}</b></dd>'
                for i, v in enumerate(info["imeis"], 1)]
    else:
        out.append('<dt>IMEI</dt><dd class="warn">not readable over adb on this build (dial *#06#)</dd>')
    if info.get("other_numbers"):
        out.append(f'<dt>Other numbers</dt><dd class="mono">{e(", ".join(info["other_numbers"]))}'
                   ' <span class="dim">(line or voicemail, slot unknown)</span></dd>')
    out.append('</dl><div class="tbl" style="margin-top:12px"><table><thead><tr>'
               "<th>Slot</th><th>State</th><th>Carrier</th><th>Network</th><th>MCC/MNC</th>"
               "<th>Phone number</th><th>ICCID</th><th>eSIM</th></tr></thead><tbody>")
    vm = False
    for s in info.get("sims", []):
        num = e(s.get("number")) or '<span class="dim">—</span>'
        if s.get("number") and "voicemail" in s.get("number_source", ""):
            num += ' <span class="warn">*</span>'
            vm = True
        out.append(f"<tr><td>{s['slot']}</td><td class=\"{tone('state', s['state'])}\">{e(s['state'])}</td>"
                   f"<td>{e(s.get('sim_operator'))}</td><td>{e(sim_network(s))}</td>"
                   f"<td class=\"mono\">{e(' '.join(x for x in (s.get('mcc_mnc'), s.get('country')) if x))}</td>"
                   f"<td class=\"mono\">{num}</td><td class=\"mono\">{e(s.get('iccid'))}</td>"
                   f"<td>{e(s.get('esim'))}</td></tr>")
    out.append("</tbody></table></div>")
    if vm:
        out.append('<div class="note">* read straight from the SIM; could be the voicemail number</div>')
    out.append("</div>")

    # APNs
    out.append('<div class="card wide"><h3>APNs</h3>')
    apns = info.get("apns") or []
    if apns:
        out.append('<div class="tbl"><table><thead><tr><th></th><th>Name</th><th>APN</th><th>Type</th>'
                   "<th>MCC/MNC</th><th>MMS</th><th>Proxy</th><th>Protocol</th><th>Auth</th>"
                   "</tr></thead><tbody>")
        for a in apns:
            star = '<span class="star">★</span>' if a.get("preferred") else ""
            name = e(a.get("name") or "(no name)")
            if a.get("carrier_enabled") == "0":
                name = f'<s class="dim">{name}</s>'
            out.append(f"<tr><td>{star}</td><td>{name}</td><td class=\"mono\"><b>{e(a.get('apn') or '-')}</b></td>"
                       f"<td>{e(a.get('type'))}</td><td class=\"mono\">{e(a.get('numeric'))}</td>"
                       f"<td class=\"mono\">{e(apn_mms(a))}</td><td class=\"mono\">{e(apn_proxy(a))}</td>"
                       f"<td>{e(apn_protocol(a))}</td><td class=\"mono\">{e(apn_auth(a))}</td></tr>")
        out.append("</tbody></table></div>")
        if any(a.get("preferred") for a in apns):
            out.append('<div class="note">★ = selected / in use</div>')
    else:
        out.append('<div class="warn">Not readable on this build. Try --root, or check '
                   "Settings &gt; Mobile network &gt; APNs.</div>")
    out.append("</div></div></section>")
    return "\n".join(out)


def build_html(results):
    generated = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    title = device_title(results[0]) if len(results) == 1 else f"{len(results)} phones"
    nav = ""
    if len(results) > 1:
        nav = "<nav>" + "".join(f'<a href="#dev{i}">{e(device_title(r))}</a>'
                                for i, r in enumerate(results)) + "</nav>"
    body = "\n".join(html_device(r, i) for i, r in enumerate(results))
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Phone report – {e(title)}</title>
<style>{HTML_CSS}</style></head>
<body><div class="wrap">
<div class="top"><h1>Phone report</h1><div class="meta">{e(title)} · generated {generated}</div></div>
{nav}
{body}
<footer>Generated by phoneinfo.py v{VERSION} over adb</footer>
</div></body></html>
"""


# ==========================================================================
# saving
# ==========================================================================

def flatten(info):
    flat = {k: v for k, v in info.items()
            if k not in ("imeis", "sims", "apns", "other_numbers")}
    for i, v in enumerate(info.get("imeis", []), 1):
        flat[f"imei{i}"] = v
    for s in info.get("sims", []):
        for k, v in s.items():
            if k not in ("slot", "sub_id"):
                flat[f"sim{s['slot']}_{k}"] = v
    flat["other_numbers"] = ", ".join(info.get("other_numbers", []))
    flat["apns"] = "; ".join(
        f"{'*' if a.get('preferred') else ''}{a.get('name')} ({a.get('apn')}) [{a.get('type')}]"
        for a in info.get("apns", []))
    return flat


def write_csv(path, results):
    flats = [flatten(r) for r in results]
    header = []
    for f in flats:
        for k in f:
            if k not in header:
                header.append(k)
    imei_cols = [h for h in header if h.startswith("imei")]
    rest = [h for h in header if h not in imei_cols]
    pos = rest.index("model") + 1 if "model" in rest else len(rest)
    header = rest[:pos] + imei_cols + rest[pos:]
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=header)
        w.writeheader()
        for f in flats:
            w.writerow(f)


def write_txt(path, results):
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(f"Phone report - generated {datetime.now():%Y-%m-%d %H:%M:%S}\n\n")
        fh.write("\n\n".join(format_info(r) for r in results) + "\n")


def write_html(path, results):
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(build_html(results))


def write_json(path, results):
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(results, fh, indent=2)


WRITERS = {"t": (".txt", write_txt, "Text"), "h": (".html", write_html, "HTML"),
           "c": (".csv", write_csv, "CSV"), "j": (".json", write_json, "JSON")}


def default_basename(results):
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    tag = (results[0].get("model") or results[0]["adb_serial"]) if len(results) == 1 \
        else f"{len(results)}phones"
    return "phoneinfo_" + re.sub(r"[^A-Za-z0-9._-]+", "-", tag) + "_" + stamp


def prompt_save(ui, results):
    ui.print()
    ui.rule("[bold]Save report[/]")
    menu = [("b", "Text + HTML", "recommended"), ("t", "Text only", ""), ("h", "HTML only", ""),
            ("c", "CSV", "spreadsheet, one row per phone"), ("j", "JSON", ""),
            ("a", "Everything", "txt, html, csv, json"), ("n", "Don't save", "")]
    if ui.console:
        t = Table.grid(padding=(0, 2))
        t.add_column()
        t.add_column()
        t.add_column(style="dim")
        for key, name, note in menu:
            t.add_row(Text(f"[{key}]", style="bold cyan"), name, note)
        ui.console.print(t)
    else:
        for key, name, note in menu:
            print(f"  [{key}] {name}" + (f"  ({note})" if note else ""))

    while True:
        ans = ui.ask("Choose", default="b").strip().lower()[:1]
        if ans in "bthcjan" and ans:
            break
        ui.warn("Pick one of: b, t, h, c, j, a, n")
    if ans == "n":
        ui.print("[dim]Not saved.[/]")
        return
    keys = {"b": "th", "a": "thcj"}.get(ans, ans)

    base = default_basename(results)
    name = ui.ask("File name (without extension)", default=base).strip().strip('"')
    root, ext = os.path.splitext(name)
    if ext.lower() in (".txt", ".html", ".htm", ".csv", ".json"):
        name = root
    folder = os.path.dirname(os.path.abspath(name))
    os.makedirs(folder, exist_ok=True)

    saved = save_files(ui, results, {k: name + WRITERS[k][0] for k in keys})
    html_path = saved.get("h")
    if html_path and ui.interactive and ui.confirm("Open the HTML report in your browser?", default=True):
        webbrowser.open(Path(html_path).as_uri())


def save_files(ui, results, targets):
    saved = {}
    for key, path in targets.items():
        ext, fn, kind = WRITERS[key]
        path = os.path.abspath(path)
        try:
            fn(path, results)
            saved[key] = path
            ui.ok(f"{kind:<5} saved → [bold]{escape(path)}[/]")
        except OSError as ex:
            ui.err(f"Could not save {kind}: {escape(str(ex))}")
    return saved


# ==========================================================================
# startup, discovery, device picker
# ==========================================================================

SETUP_STEPS = [
    "Enable [bold]Developer options[/]: Settings → About phone → tap [bold]Build number[/] 7 times",
    "Turn on [bold]USB debugging[/]: Settings → System → Developer options",
    "Connect with a [bold]data[/] USB cable (some cables are charge-only)",
    "Unlock the phone and accept [bold]\"Allow USB debugging?\"[/] (tick [italic]Always allow[/])",
]
TROUBLESHOOT = [
    "Swap the cable or USB port; avoid hubs",
    "On the phone, pull down notifications → USB → choose [bold]File transfer[/]",
    "Toggle USB debugging off/on, or Developer options → [bold]Revoke USB debugging authorizations[/]",
    "Windows: install your phone's USB driver (Samsung USB Driver / Google USB Driver)",
    "Linux: you may need udev rules (package [bold]android-udev-rules[/])",
    "Still stuck? run [bold]adb kill-server[/] then try again",
]
STATE_HINTS = {
    "unauthorized": "accept the \"Allow USB debugging?\" prompt on the phone (unlock it first)",
    "offline": "replug the cable, or run adb kill-server",
    "no permissions": "Linux USB permissions: add udev rules or run adb as root",
    "recovery": "phone is in recovery mode; boot it normally",
    "sideload": "phone is in sideload mode; boot it normally",
    "bootloader": "phone is in bootloader/fastboot mode; boot it normally",
}


def numbered(items):
    return "\n".join(f"  [cyan]{i}.[/] {s}" for i, s in enumerate(items, 1))


def banner(ui, adb, ver):
    if ui.console:
        ui.console.print(Panel(
            Text.assemble(("Android phone info", "bold white"), (f"  v{VERSION}\n", "dim"),
                          ("Make, model, storage, IMEI, SIM, numbers, carrier lock and APNs over adb", "cyan")),
            box=box.DOUBLE, border_style="cyan", padding=(0, 2)))
        ui.console.print(Panel(numbered(SETUP_STEPS), title="[bold]Before you start[/]",
                               title_align="left", border_style="dim", box=box.ROUNDED))
    else:
        print("=" * 64 + f"\n Android phone info v{VERSION}\n" + "=" * 64)
        print("Before you start:\n" + MARKUP_RE.sub("", numbered(SETUP_STEPS)))
        print("Tip: `pip install rich` for a much nicer display.\n")
    ui.ok(f"adb {ver} found at [dim]{escape(adb)}[/]")


def probe_device(adb, serial):
    out = run([adb, "-s", serial, "shell",
               "getprop ro.product.manufacturer; getprop ro.product.model; "
               "getprop ro.build.version.release"], 15)
    lines = [l.strip() for l in out.splitlines()] + ["", "", ""]
    name = " ".join(x for x in (lines[0].capitalize(), lines[1]) if x)
    return name, lines[2]


def discover(ui, adb, wanted):
    while True:
        with ui.status("Searching for devices"):
            ui.step("Starting adb server and listing devices")
            devs = list_devices(adb)
            if wanted:
                devs = [d for d in devs if d[0] in wanted]
            details = []
            for serial, state in devs:
                name, android = "", ""
                if state == "device":
                    ui.step(f"Asking {serial} what it is")
                    name, android = probe_device(adb, serial)
                details.append({"serial": serial, "state": state, "name": name, "android": android})

        ready = [d for d in details if d["state"] == "device"]
        if details:
            show_device_table(ui, details, ready)
        for d in details:
            if d["state"] != "device":
                hint = next((h for k, h in STATE_HINTS.items() if d["state"].startswith(k)),
                            "not in normal adb mode")
                ui.warn(f"[bold]{escape(d['serial'])}[/] is [yellow]{escape(d['state'])}[/]: {hint}")
        if ready:
            ui.ok(f"{len(ready)} device(s) ready")
            return ready

        if not details:
            ui.err("No devices found" + (f" matching {', '.join(wanted)}" if wanted else ""))
        else:
            ui.err("No device is ready yet")
        if ui.console:
            ui.console.print(Panel(numbered(SETUP_STEPS) + "\n\n[bold]Still not showing?[/]\n" +
                                   "\n".join(f"  • {t}" for t in TROUBLESHOOT),
                                   title="[bold yellow]Checklist[/]", title_align="left",
                                   border_style="yellow", box=box.ROUNDED))
        else:
            print(MARKUP_RE.sub("", "Checklist:\n" + numbered(SETUP_STEPS) + "\n" +
                                "\n".join(f"  - {t}" for t in TROUBLESHOOT)))
        if not ui.interactive:
            return []
        ans = ui.ask("Press [bold]Enter[/] to search again, or [bold]q[/] to quit", default="")
        if ans.lower().startswith("q"):
            return []


def show_device_table(ui, details, ready):
    if ui.console:
        t = Table(box=box.ROUNDED, header_style="bold cyan", border_style="dim",
                  title="Connected devices", title_style="bold")
        for col in ("#", "Serial", "Status", "Device", "Android"):
            t.add_column(col)
        for d in details:
            num = str(ready.index(d) + 1) if d in ready else ""
            status = Text("ready", style="green") if d["state"] == "device" else Text(d["state"], style="yellow")
            t.add_row(num, d["serial"], status, d["name"] or Text("—", style="dim"), d["android"])
        ui.console.print(t)
    else:
        print("\nConnected devices:")
        for d in details:
            num = f"{ready.index(d) + 1}." if d in ready else "  "
            print(f"  {num} {d['serial']:<24} {d['state']:<14} {d['name']} {d['android']}")


def choose_devices(ui, ready, args):
    if len(ready) == 1 or args.all or args.serial or not ui.interactive:
        return ready
    while True:
        ans = ui.ask(f"Which device? [bold]1-{len(ready)}[/], several like [bold]1,3[/], "
                     f"or [bold]a[/] for all", default="1").strip().lower()
        if ans in ("a", "all"):
            return ready
        try:
            picks = sorted({int(x) for x in re.split(r"[,\s]+", ans) if x})
            if picks and all(1 <= n <= len(ready) for n in picks):
                return [ready[n - 1] for n in picks]
        except ValueError:
            pass
        ui.warn(f"Enter a number from 1 to {len(ready)}, a list like 1,2, or a")


def confirm_start(ui, chosen):
    """Ask before reading. Returns 'start', 'rescan' or 'quit'."""
    if not ui.interactive:
        return "start"
    names = ", ".join(escape(d["name"] or d["serial"]) for d in chosen)
    ui.print()
    if ui.console:
        ui.console.print(Panel(
            f"Ready to read [bold]{names}[/]\n"
            "[dim]Keep the phone unlocked and connected until the report appears.[/]",
            border_style="green", box=box.ROUNDED, padding=(0, 2)))
    else:
        print(f"Ready to read {names}. Keep the phone unlocked and connected.")
    while True:
        ans = ui.ask("Press [bold]Enter[/] to start, [bold]r[/] to rescan, "
                     "or [bold]q[/] to quit", default="").strip().lower()
        if ans in ("", "s", "start", "y", "yes"):
            return "start"
        if ans.startswith("r"):
            return "rescan"
        if ans.startswith("q") or ans.startswith("n"):
            return "quit"
        ui.warn("Press Enter to start, r to rescan, or q to quit")


def offer_rich_install(interactive):
    """Offer to install `rich` once, then restart the script with it."""
    if HAVE_RICH or not interactive or os.environ.get("PHONEINFO_NO_RICH"):
        return
    ans = input("For a much nicer display this script uses the 'rich' package. "
                "Install it now with pip? [Y/n]: ").strip().lower()
    if ans and not ans.startswith("y"):
        return
    rc = subprocess.call([sys.executable, "-m", "pip", "install", "--user", "rich"])
    if rc == 0:
        os.environ["PHONEINFO_NO_RICH"] = "1"      # don't loop if import still fails
        os.execv(sys.executable, [sys.executable] + sys.argv)
    print("Couldn't install rich; continuing with plain output.\n")


# ==========================================================================
# main
# ==========================================================================

def main():
    ap = argparse.ArgumentParser(description="Dump Android phone info over adb.")
    ap.add_argument("-s", "--serial", action="append", help="only this device (repeatable)")
    ap.add_argument("--all", action="store_true", help="read every ready device without asking")
    ap.add_argument("--txt", help="save a text report to this file")
    ap.add_argument("--html", help="save an HTML report to this file")
    ap.add_argument("--json", help="save JSON to this file")
    ap.add_argument("--csv", help="save CSV to this file")
    ap.add_argument("--no-prompt", action="store_true", help="never ask anything")
    ap.add_argument("--root", action="store_true", help="retry blocked reads with su")
    ap.add_argument("--adb", help="path to adb executable")
    args = ap.parse_args()

    interactive = sys.stdin.isatty() and sys.stdout.isatty() and not args.no_prompt
    offer_rich_install(interactive)
    ui = UI(interactive)

    adb = find_adb(args.adb)
    if not adb:
        if ui.console:
            ui.console.print(Panel(
                "adb was not found.\n\n"
                "Download [bold]Android SDK Platform-Tools[/] from\n"
                "  https://developer.android.com/tools/releases/platform-tools\n"
                "unzip it, then either add the folder to your PATH, put this script inside it,\n"
                "or run with [bold]--adb path/to/adb[/].",
                title="[bold red]adb missing[/]", border_style="red", box=box.ROUNDED))
        else:
            print("adb not found. Install Android SDK Platform-Tools "
                  "(https://developer.android.com/tools/releases/platform-tools) or pass --adb PATH.")
        return 1

    banner(ui, adb, adb_version(adb))
    while True:
        ready = discover(ui, adb, args.serial)
        if not ready:
            return 1
        chosen = choose_devices(ui, ready, args)
        action = confirm_start(ui, chosen)
        if action == "start":
            break
        if action == "quit":
            ui.print("[dim]Bye.[/]")
            return 0
        ui.print()                                  # "rescan": loop and search again

    results = []
    for d in chosen:
        ui.print()
        ui.rule(f"[bold]{escape(d['name'] or d['serial'])}[/] [dim]{escape(d['serial'])}[/]")
        try:
            with ui.status(f"Reading {d['serial']}"):
                info = Phone(adb, d["serial"], args.root, ui).collect()
        except KeyboardInterrupt:
            ui.err("Interrupted")
            break
        except Exception as ex:  # keep going with the other phones
            ui.err(f"Failed to read {escape(d['serial'])}: {escape(str(ex))}")
            continue
        results.append(info)
        show_report(ui, info)

    if not results:
        ui.err("Nothing was read.")
        return 1

    targets = {k: p for k, p in (("t", args.txt), ("h", args.html), ("j", args.json), ("c", args.csv)) if p}
    if targets:
        ui.print()
        save_files(ui, results, targets)
    elif ui.interactive:
        try:
            prompt_save(ui, results)
        except (KeyboardInterrupt, EOFError):
            ui.print("\n[dim]Not saved.[/]")
    ui.print("\n[dim]Done.[/]")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\nCancelled.")
        sys.exit(130)
