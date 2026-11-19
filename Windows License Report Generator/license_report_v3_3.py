#!/usr/bin/env python3
"""
license_report.py - printable software license sheet to hand over with a computer.

Reads the Windows and Microsoft Office licenses on this PC and makes a clean,
printable page with the device details and each product's full key.

  * Windows: the full installed key is read from the registry when it's there
    (and the OEM key from the firmware), checked against the last 5 characters
    Windows reports.
  * Office 2013+ only keeps the last 5 characters of its key, so you're asked for
    the full key; what you type is checked against those last 5 before it's used.

Usage:
    license_report.exe                         # asks for keys / recipient, then opens the sheet
    license_report.exe --office-key XXXXX-XXXXX-XXXXX-XXXXX-XXXXX   (repeatable; matched by last 5)
    license_report.exe --issued-to "Jane Smith" --no-prompt
    license_report.exe --mask                  # show only the last 5 of every key

Optional license_report.toml next to the exe:
    organization = "Your Company"
    prepared_by  = "Your Name"

Standard library only, so it builds cleanly with PyInstaller.
"""

from __future__ import annotations

import argparse
import datetime as dt
import html
import json
import os
import re
import subprocess
import sys
from pathlib import Path

FROZEN = getattr(sys, "frozen", False)
SCRIPT_DIR = Path(sys.executable if FROZEN else __file__).resolve().parent
CONFIG_PATH = SCRIPT_DIR / "license_report.toml"

# ProgramW6432 is the real 64-bit Program Files even when this program runs as 32-bit
_PF_DIRS = dict.fromkeys(d for d in (os.environ.get("ProgramW6432"), os.environ.get("ProgramFiles"),
                                     os.environ.get("ProgramFiles(x86)"), r"C:\Program Files",
                                     r"C:\Program Files (x86)") if d)
OSPP_CANDIDATES = [rf"{base}\Microsoft Office\{ver}\OSPP.VBS"
                   for base in _PF_DIRS for ver in ("Office16", "Office15", "Office14")]


def system_tool(rel: str) -> str:
    """
    Path to a 64-bit Windows tool. A 32-bit program (e.g. 32-bit Python/PyInstaller) on 64-bit
    Windows is silently redirected to the 32-bit registry, which doesn't have the Windows key;
    the Sysnative folder gets the real 64-bit tool instead.
    """
    windir = os.environ.get("SystemRoot", r"C:\Windows")
    native = os.path.join(windir, "Sysnative", rel)
    return native if os.path.exists(native) else os.path.join(windir, "System32", rel)

KEY_RE = re.compile(r"^[A-Z0-9]{5}(-[A-Z0-9]{5}){4}$")
CLEARED_KEY = "BBBBB-BBBBB-BBBBB-BBBBB-BBBBB"   # what the registry decodes to after slmgr /cpky


# --- Collecting data -----------------------------------------------------------
PS_SCRIPT = r"""
$ErrorActionPreference = 'SilentlyContinue'
[Console]::OutputEncoding = [Text.Encoding]::UTF8
$os   = Get-CimInstance Win32_OperatingSystem
$cs   = Get-CimInstance Win32_ComputerSystem
$csp  = Get-CimInstance Win32_ComputerSystemProduct
$bios = Get-CimInstance Win32_BIOS
$svc  = Get-CimInstance SoftwareLicensingService
$win  = Get-CimInstance SoftwareLicensingProduct -Filter "ApplicationID='55c92734-d682-4d71-983e-d6ec3f16059f' AND PartialProductKey IS NOT NULL"
$cv   = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
$c2r  = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Office\ClickToRun\Configuration'
[pscustomobject]@{
  ComputerName     = $env:COMPUTERNAME
  Manufacturer     = $cs.Manufacturer
  Model            = $cs.Model
  ModelName        = $csp.Version
  Serial           = $bios.SerialNumber
  OSCaption        = $os.Caption
  DisplayVersion   = $cv.DisplayVersion
  Build            = "$($cv.CurrentBuild).$($cv.UBR)"
  DigitalProductId = @($cv.DigitalProductId | ForEach-Object { [int]$_ })
  BackupKey        = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SoftwareProtectionPlatform').BackupProductKeyDefault
  OEMKey           = $svc.OA3xOriginalProductKey
  OEMKeyDesc       = $svc.OA3xOriginalProductKeyDescription
  Windows          = @($win | ForEach-Object { [pscustomobject]@{
                        Name = $_.Name; Description = $_.Description
                        LicenseStatus = $_.LicenseStatus; PartialProductKey = $_.PartialProductKey
                        ProductKeyChannel = $_.ProductKeyChannel } })
  C2RProducts      = $c2r.ProductReleaseIds
  C2RVersion       = $c2r.VersionToReport
} | ConvertTo-Json -Depth 4 -Compress
"""


def collect_system() -> dict:
    """Machine + Windows licensing info via PowerShell/CIM."""
    try:
        r = subprocess.run(
            [system_tool(r"WindowsPowerShell\v1.0\powershell.exe") if os.name == "nt" else "powershell",
             "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", PS_SCRIPT],
            capture_output=True, timeout=120,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        out = r.stdout.decode("utf-8", errors="replace").strip()
        data = json.loads(out[out.find("{"):]) if "{" in out else {}
    except Exception as e:
        data = {"_error": f"Could not read system info: {e}"}
    if isinstance(data.get("Windows"), dict):              # a single item comes back unwrapped
        data["Windows"] = [data["Windows"]]
    return data


def find_ospp() -> str | None:
    return next((p for p in OSPP_CANDIDATES if os.path.isfile(p)), None)


def run_ospp(path: str) -> str:
    r = subprocess.run(
        [system_tool("cscript.exe") if os.name == "nt" else "cscript", "//Nologo", path, "/dstatus"],
        capture_output=True, timeout=180,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    enc = "oem" if sys.platform == "win32" else "utf-8"
    return (r.stdout + r.stderr).decode(enc, errors="replace")


def load_config() -> dict:
    if not CONFIG_PATH.is_file():
        return {}
    try:
        import tomllib
        with open(CONFIG_PATH, "rb") as f:
            return tomllib.load(f)
    except Exception as e:
        print(f"Note: couldn't read {CONFIG_PATH.name}: {e}")
        return {}


# --- Keys ------------------------------------------------------------------------------
def decode_windows_key(dpid: list[int] | None) -> str | None:
    """Decode the installed Windows key from the registry DigitalProductId (Windows 8+ format)."""
    if not dpid or len(dpid) < 67:
        return None
    key = list(dpid[52:67])
    is_win8 = (key[14] // 6) & 1
    key[14] = (key[14] & 0xF7) | ((is_win8 & 2) * 4)
    chars = "BCDFGHJKMPQRTVWXY2346789"
    out, last = "", 0
    for _ in range(25):
        cur = 0
        for j in range(14, -1, -1):
            cur = cur * 256 + key[j]
            key[j] = cur // 24
            cur %= 24
        out = chars[cur] + out
        last = cur
    if is_win8:
        out = out[1:1 + last] + "N" + out[1 + last:]
    return "-".join(out[i:i + 5] for i in range(0, 25, 5))


def normalize_key(text: str) -> str | None:
    raw = re.sub(r"[^A-Za-z0-9]", "", text or "").upper()
    if len(raw) != 25:
        return None
    k = "-".join(raw[i:i + 5] for i in range(0, 25, 5))
    return k if KEY_RE.match(k) else None


def masked(last5: str) -> str:
    return f"•••••-•••••-•••••-•••••-{last5}"


# --- Parsing OSPP output ---------------------------------------------------------------
def parse_ospp(text: str) -> list[dict]:
    """Split OSPP /dstatus output into one dict per license block."""
    licenses = []
    for block in re.split(r"\n-{20,}\s*\n", text.replace("\r\n", "\n")):
        if "LICENSE NAME" not in block and "SKU ID" not in block:
            continue
        d = {}
        for line in block.splitlines():
            if ":" not in line:
                continue
            key, _, value = line.strip().partition(":")
            d[key.strip().upper()] = value.strip()
        licenses.append(d)
    return licenses


EDITIONS = [  # (token in SKU name, friendly edition) - checked in order
    ("O365ProPlus", "Microsoft 365 Apps for enterprise"),
    ("O365Business", "Microsoft 365 Apps for business"),
    ("O365HomePrem", "Microsoft 365 Family/Personal"),
    ("ProPlus", "Professional Plus"), ("HomeBusiness", "Home & Business"),
    ("HomeStudent", "Home & Student"), ("Professional", "Professional"),
    ("Standard", "Standard"), ("ProjectPro", "Project Professional"),
    ("ProjectStd", "Project Standard"), ("VisioPro", "Visio Professional"),
    ("VisioStd", "Visio Standard"), ("Personal", "Personal"),
]
OFFICE_YEAR = {"14": "2010", "15": "2013", "16": "2016", "19": "2019", "21": "2021", "24": "2024"}


def friendly_office_name(license_name: str) -> str:
    """'Office 21, Office21ProPlus2021VL_KMS_Client_AE edition' -> 'Office Professional Plus 2021'."""
    m = re.search(r"Office\s*(\d\d),\s*(\S+)", license_name or "")
    if not m:
        return license_name or "Microsoft Office"
    ver, sku = m.group(1), m.group(2)
    year = (re.search(r"(20\d\d)", sku) or [None, OFFICE_YEAR.get(ver, "")])[1]
    for token, name in EDITIONS:
        if token.lower() in sku.lower():
            if name.startswith("Microsoft 365"):
                return name
            if name.startswith(("Project", "Visio")):
                return f"Microsoft {name} {year}".strip()
            return f"Microsoft Office {name} {year}".strip()
    for app in ("Visio", "Project", "Access", "Excel", "Word", "Outlook", "PowerPoint", "Publisher"):
        if app.lower() in sku.lower():
            return f"Microsoft {app} {year}".strip()
    return f"Microsoft Office {year}".strip()


CHANNELS = {
    "VOLUME_KMSCLIENT": "Volume license (KMS)", "VOLUME_MAK": "Volume license (MAK)",
    "RETAIL": "Retail license", "OEM": "OEM license", "TIMEBASED_SUB": "Subscription",
    "TIMEBASED_DEMO": "Trial",
}
WIN_CHANNELS = {
    "OEM:DM": "OEM license (built into this PC)", "OEM:NONSLP": "OEM license",
    "Retail": "Retail license", "Volume:MAK": "Volume license (MAK)",
    "Volume:GVLK": "Volume license (KMS)",
}

# status -> (label, css class)
OFFICE_STATUS = {
    "LICENSED": ("Activated", "ok"),
    "OOB_GRACE": ("Not activated (grace period)", "warn"),
    "OOT_GRACE": ("Not activated (grace period)", "warn"),
    "EXTENDED_GRACE": ("Not activated (extended grace)", "warn"),
    "NON_GENUINE_GRACE": ("Not genuine", "bad"),
    "NOTIFICATIONS": ("Not activated", "bad"),
    "UNLICENSED": ("Unlicensed", "bad"),
}
WIN_STATUS = {
    0: ("Unlicensed", "bad"), 1: ("Activated", "ok"), 2: ("Not activated (grace period)", "warn"),
    3: ("Not activated (grace period)", "warn"), 4: ("Not genuine", "bad"),
    5: ("Not activated", "bad"), 6: ("Not activated (extended grace)", "warn"),
}


# --- Building the product list -----------------------------------------------------------
WIN_EDITIONS = {
    "Core": "Home", "CoreSingleLanguage": "Home Single Language", "CoreCountrySpecific": "Home",
    "CoreN": "Home N", "Professional": "Pro", "ProfessionalN": "Pro N",
    "ProfessionalEducation": "Pro Education", "ProfessionalWorkstation": "Pro for Workstations",
    "Enterprise": "Enterprise", "EnterpriseS": "Enterprise LTSC", "IoTEnterprise": "IoT Enterprise",
    "IoTEnterpriseS": "IoT Enterprise LTSC", "Education": "Education",
}


def oem_edition(desc: str | None) -> str:
    """'[4.0] Professional OEM:DM' -> 'Windows Pro'."""
    m = re.search(r"\]\s*(\S+)", desc or "")
    return f"Windows {WIN_EDITIONS.get(m.group(1), m.group(1))}" if m else ""


def windows_key_sources(sysinfo: dict) -> list[tuple[str, str | None]]:
    """Every place a full Windows key can come from, in order of preference."""
    return [
        ("Registry (installed key)", decode_windows_key(sysinfo.get("DigitalProductId"))),
        ("Registry (backup copy)", normalize_key(sysinfo.get("BackupKey") or "")),
        ("Firmware (OEM key)", normalize_key(sysinfo.get("OEMKey") or "")),
    ]


def windows_products(sysinfo: dict) -> list[dict]:
    out = []
    sources = windows_key_sources(sysinfo)
    oem = sources[2][1]
    for w in sysinfo.get("Windows") or []:
        last5 = (w.get("PartialProductKey") or "").upper()
        label, cls = WIN_STATUS.get(w.get("LicenseStatus"), ("Unknown status", "warn"))
        channel = w.get("ProductKeyChannel") or ""
        p = {
            "kind": "windows", "title": sysinfo.get("OSCaption") or w.get("Name") or "Windows",
            "type": WIN_CHANNELS.get(channel, channel or "—"), "status": label, "cls": cls,
            "last5": last5, "key": None, "key_note": "", "extra": [],
            "kms": channel == "Volume:GVLK", "error": "",
        }
        # Use the first source whose key really is the installed one (same last 5),
        # and remember what each source said so a mismatch can be explained.
        p["sources"] = []
        for name, val in sources:
            if not val:
                p["sources"].append((name, "nothing found"))
            elif val == CLEARED_KEY:
                p["sources"].append((name, "cleared from the registry (slmgr /cpky)"))
            elif last5 and val.endswith(last5):
                p["sources"].append((name, f"{val}  ✔ matches"))
                p["key"] = p["key"] or val
            else:
                p["sources"].append((name, f"{val}  ✖ ends in {val[-5:]}, not {last5}"))
        # The firmware key is often for the edition the PC shipped with (e.g. Pro),
        # so show it separately whenever it isn't the installed key
        if oem and oem != p["key"]:
            ed = oem_edition(sysinfo.get("OEMKeyDesc"))
            p["extra"].append((f"Original OEM key ({ed})" if ed else "Original OEM key (firmware)", oem))
        out.append(p)
    return out


def office_products(licenses: list[dict]) -> list[dict]:
    out = []
    for d in licenses:
        raw_status = re.sub(r"[-\s]", "", d.get("LICENSE STATUS", "")).upper() or "UNKNOWN"
        label, cls = OFFICE_STATUS.get(raw_status, (raw_status.title(), "warn"))
        m = re.search(r",\s*([A-Z_]+)\s+channel", d.get("LICENSE DESCRIPTION", ""))
        chan = m.group(1) if m else ""
        last5 = next((v for k, v in d.items() if k.startswith("LAST 5 CHARACTERS")), "").upper()
        err = d.get("ERROR CODE", "")
        if err and d.get("ERROR DESCRIPTION"):
            err = f"{err}: {d['ERROR DESCRIPTION']}"
        out.append({
            "kind": "office", "title": friendly_office_name(d.get("LICENSE NAME", "")),
            "type": CHANNELS.get(chan, chan.title() or "—"), "status": label, "cls": cls,
            "last5": last5, "key": None, "key_note": "", "extra": [],
            "kms": chan == "VOLUME_KMSCLIENT", "error": err,
        })
    return out


def apply_given_keys(products: list[dict], keys: list[str]) -> list[str]:
    """Match --office-key / --windows-key values to products by their last 5 characters."""
    problems = []
    for k in keys:
        nk = normalize_key(k)
        if not nk:
            problems.append(f"'{k}' isn't a valid 25-character key; ignored")
            continue
        match = next((p for p in products if p["last5"] and nk.endswith(p["last5"])), None)
        if match:
            match["key"] = nk
        else:
            problems.append(f"{nk} doesn't match any installed product (last 5 differ); ignored")
    return problems


def ask_for_keys(products: list[dict]) -> None:
    """Ask for any full keys we couldn't read, checking each against its last 5."""
    for p in products:
        if p["key"] or p["kms"] or not p["last5"]:
            continue
        print(f"\n{p['title']} - installed key ends in {p['last5']}")
        if p.get("sources"):
            print("  Couldn't read a matching full key automatically. What was found:")
            for name, result in p["sources"]:
                print(f"    {name + ':':27} {result}")
        while True:
            try:
                text = input("  Full product key (Enter to show last 5 only): ").strip()
            except EOFError:
                return
            if not text:
                break
            nk = normalize_key(text)
            if not nk:
                print("  That isn't a 25-character key (XXXXX-XXXXX-XXXXX-XXXXX-XXXXX). Try again.")
                continue
            if not nk.endswith(p["last5"]):
                print(f"  That key ends in {nk[-5:]}, but the installed key ends in {p['last5']}.")
                if input("  Use it anyway? [y/N] ").strip().lower() != "y":
                    continue
            p["key"] = nk
            print("  ✔ Key accepted" + (" (matches the installed key)" if nk.endswith(p["last5"]) else ""))
            break


# --- HTML --------------------------------------------------------------------------------
SEAL_SVG = """<svg viewBox="0 0 256 256" aria-hidden="true"><rect x="8" y="8" width="240" height="240" rx="52" fill="#163a6b"/>
<rect x="8" y="8" width="240" height="232" rx="52" fill="#1f4e8c"/><path d="M62 40h88l34 34v132H62z" fill="#fff"/>
<path d="M150 40v34h34z" fill="#d6dee9"/><g fill="#a0b0c7"><rect x="80" y="70" width="54" height="11" rx="5.5"/>
<rect x="80" y="94" width="86" height="11" rx="5.5"/><rect x="80" y="117" width="86" height="11" rx="5.5"/>
<rect x="80" y="140" width="60" height="11" rx="5.5"/></g><circle cx="178" cy="178" r="63" fill="#1f4e8c"/>
<circle cx="178" cy="182" r="54" fill="#13633a"/><circle cx="178" cy="178" r="54" fill="#1a7f43"/>
<path d="M154 179l17 17 33-36" fill="none" stroke="#fff" stroke-width="15" stroke-linecap="round" stroke-linejoin="round"/></svg>"""

CSS = """
:root{--ink:#14171c;--muted:#5b6370;--faint:#8a919c;--line:#d9dee5;--soft:#f4f6f9;--accent:#1f4e8c;
--ok:#1a7f43;--ok-bg:#e6f4ec;--warn:#9a6200;--warn-bg:#fdf3dc;--bad:#b42318;--bad-bg:#fdecea}
*{box-sizing:border-box;-webkit-print-color-adjust:exact;print-color-adjust:exact}
html{background:#e7eaee}
body{margin:0;font:14px/1.45 "Segoe UI",system-ui,-apple-system,Roboto,Arial,sans-serif;color:var(--ink)}
.toolbar{max-width:816px;margin:16px auto 0;display:flex;justify-content:space-between;gap:12px;align-items:center}
.check{font-weight:600;padding:8px 12px;border-radius:6px;flex:1}
.check.ok{background:var(--ok-bg);color:var(--ok)}.check.warn{background:var(--warn-bg);color:var(--warn)}
.check.bad{background:var(--bad-bg);color:var(--bad)}
button{font:inherit;font-weight:600;background:var(--accent);color:#fff;border:0;border-radius:6px;padding:9px 18px;cursor:pointer}
.sheet{max-width:816px;margin:14px auto 28px;background:#fff;padding:22px;box-shadow:0 2px 16px rgba(0,0,0,.09)}
.frame{border:2px solid var(--accent);padding:5px}
.inner{border:1px solid #b9c6d8;padding:30px 36px 26px}
.head{display:flex;align-items:center;gap:18px;padding-bottom:16px;border-bottom:1px solid var(--line)}
.head svg{width:58px;height:58px;flex:none}
.org{font-size:11.5px;letter-spacing:.14em;text-transform:uppercase;color:var(--accent);font-weight:700}
h1{margin:2px 0 0;font-size:25px;letter-spacing:-.01em;font-weight:700}
.lead{margin:2px 0 0;color:var(--muted);font-size:13px}
.device{display:grid;grid-template-columns:repeat(4,1fr);gap:4px 18px;margin:16px 0 4px}
.device div span,.meta div span{display:block;font-size:10px;text-transform:uppercase;letter-spacing:.1em;color:var(--faint)}
.device div b,.meta div b{font-weight:600;word-break:break-word}
.meta{display:grid;grid-template-columns:repeat(2,1fr);gap:4px 18px;margin:12px 0 2px;padding-top:12px;border-top:1px dashed var(--line)}
h2{font-size:11.5px;letter-spacing:.14em;text-transform:uppercase;color:var(--muted);margin:22px 0 10px;
display:flex;align-items:center;gap:10px}
h2::after{content:"";flex:1;border-top:1px solid var(--line)}
.product{border:1px solid var(--line);border-radius:8px;padding:14px 16px 14px;margin-bottom:12px;break-inside:avoid}
.ptop{display:flex;justify-content:space-between;align-items:flex-start;gap:12px}
.ptop h3{margin:0;font-size:17px}
.ptop small{display:block;color:var(--muted);font-size:12.5px;margin-top:1px}
.status{font-size:12px;font-weight:700;padding:3px 10px;border-radius:999px;white-space:nowrap}
.status.ok{background:var(--ok-bg);color:var(--ok)}.status.warn{background:var(--warn-bg);color:var(--warn)}
.status.bad{background:var(--bad-bg);color:var(--bad)}
.keybox{margin-top:12px;background:var(--soft);border:1px dashed #aab6c6;border-radius:6px;padding:9px 14px;
display:flex;align-items:baseline;gap:16px;flex-wrap:wrap}
.keybox .lbl{font-size:10px;text-transform:uppercase;letter-spacing:.1em;color:var(--faint);min-width:84px}
.key{font-family:Consolas,"Cascadia Mono","Courier New",monospace;font-size:20px;font-weight:700;letter-spacing:.08em}
.key.partial{font-size:15px;font-weight:600;color:var(--muted)}
.key.kms{font-family:inherit;font-size:13.5px;font-weight:600;letter-spacing:0;color:var(--muted)}
.note{margin:7px 0 0;font-size:12px;color:var(--muted)}
.extra{margin:6px 0 0;font-size:12px;color:var(--muted)}
.extra b{font-family:Consolas,"Cascadia Mono",monospace;color:var(--ink);font-weight:600}
.empty{border:1px dashed var(--line);border-radius:8px;padding:12px 16px;color:var(--muted)}
.notice{margin-top:18px;padding:11px 14px;background:var(--soft);border-left:3px solid var(--accent);font-size:12.5px}
.sign{display:grid;grid-template-columns:1.4fr 1fr;gap:28px;margin-top:30px}
.sign div{border-top:1px solid var(--ink);padding-top:4px;font-size:11px;color:var(--muted)}
.sign b{display:block;color:var(--ink);font-size:13px;margin-bottom:2px;min-height:18px}
.fine{margin-top:16px;font-size:10px;color:var(--faint);text-align:center}
details{max-width:816px;margin:0 auto 32px;background:#fff;padding:10px 16px}
details pre{white-space:pre-wrap;font-size:11px;color:var(--muted)}
@media (max-width:640px){.sheet{padding:10px;margin:8px}.inner{padding:20px 16px}.device,.meta{grid-template-columns:1fr 1fr}
.sign{grid-template-columns:1fr}.key{font-size:16px}.toolbar{flex-direction:column;align-items:stretch;padding:0 8px}}
.inner{display:flex;flex-direction:column}.bottom{margin-top:auto}
@page{size:auto;margin:10mm}
@media print{html{background:#fff}body{font-size:12.5px}.toolbar,details{display:none}
.sheet{margin:0;max-width:none;box-shadow:none;padding:0}
.inner{min-height:calc(100vh - 16px);padding:22px 28px 16px}
.head{padding-bottom:12px}.head svg{width:50px;height:50px}h1{font-size:23px}
.device{margin-top:12px}.meta{margin-top:10px;padding-top:10px}
h2{margin:16px 0 8px}.product{padding:10px 14px;margin-bottom:9px}.ptop h3{font-size:15.5px}
.keybox{margin-top:8px;padding:7px 12px}.key{font-size:18px}.note{margin-top:5px;font-size:11px}
.notice{margin-top:14px;padding:9px 12px;font-size:11.5px}.sign{margin-top:26px}.fine{margin-top:10px}}
"""

e = html.escape


def product_html(p: dict, mask: bool) -> str:
    if p["kms"]:
        key_line = ('<div class="keybox"><span class="lbl">Product key</span><span class="key kms">'
                    'Not needed — activated by the organization\'s KMS server</span></div>')
    elif p["key"] and not mask:
        key_line = f'<div class="keybox"><span class="lbl">Product key</span><span class="key">{e(p["key"])}</span></div>'
    elif p["last5"]:
        key_line = f'<div class="keybox"><span class="lbl">Product key</span><span class="key partial">{e(masked(p["last5"]))}</span></div>'
    else:
        key_line = ""
    extra = "".join(f'<p class="extra">{e(k)}: <b>{e(v if not mask else masked(v[-5:]))}</b></p>'
                    for k, v in p["extra"])
    err = f'<p class="note">{e(p["error"])}</p>' if p["error"] and p["cls"] != "ok" else ""
    return (f'<div class="product"><div class="ptop"><div><h3>{e(p["title"])}</h3><small>{e(p["type"])}</small></div>'
            f'<span class="status {p["cls"]}">{e(p["status"])}</span></div>{key_line}{extra}{err}</div>')


def build_html(sysinfo: dict, win: list[dict], office: list[dict], ospp_path: str | None,
               ospp_raw: str, cfg: dict, issued_to: str, mask: bool, notes: list[str]) -> str:
    today = dt.date.today()
    name = sysinfo.get("ComputerName") or os.environ.get("COMPUTERNAME", "This PC")
    model = sysinfo.get("ModelName") or sysinfo.get("Model") or "—"
    maker = (sysinfo.get("Manufacturer") or "").title() if (sysinfo.get("Manufacturer") or "").isupper() \
        else (sysinfo.get("Manufacturer") or "")
    device = [
        ("Device", f"{maker} {model}".strip() or "—"),
        ("Serial number", sysinfo.get("Serial") or "—"),
        ("Computer name", name),
        ("Operating system", " ".join(x for x in (sysinfo.get("OSCaption", "").replace("Microsoft ", ""),
                                                  sysinfo.get("DisplayVersion")) if x) or "—"),
    ]
    device_html = "".join(f"<div><span>{e(k)}</span><b>{e(str(v))}</b></div>" for k, v in device)
    meta = [("Issued to", issued_to or ""), ("Date issued", today.strftime("%B %d, %Y").replace(" 0", " "))]
    meta_html = "".join(f"<div><span>{e(k)}</span><b>{e(v) or '&nbsp;'}</b></div>" for k, v in meta)

    # On-screen check (not printed): anything that isn't activated or is missing a full key
    everything = win + office
    issues = [f"{p['title']}: {p['status'].lower()}" for p in everything if p["cls"] != "ok"]
    issues += [f"{p['title']}: full key not entered" for p in everything
               if not p["key"] and not p["kms"] and p["last5"] and not mask]
    if not everything:
        check = ("warn", "⚠ No licenses were found on this computer.")
    elif issues:
        check = ("bad" if any(p["cls"] == "bad" for p in everything) else "warn",
                 "⚠ Check before printing — " + "; ".join(issues))
    else:
        check = ("ok", "✔ Everything is activated and every key is filled in — ready to print.")

    win_html = "".join(product_html(p, mask) for p in win) or \
        '<div class="empty">No Windows license information was found.</div>'
    products = sysinfo.get("C2RProducts") or ""
    if office:
        office_html = "".join(product_html(p, mask) for p in office)
    elif "O365" in products:
        office_html = ('<div class="product"><div class="ptop"><div><h3>Microsoft 365 Apps</h3>'
                       '<small>Subscription</small></div></div><p class="note">Licensed through the '
                       'Microsoft account used to sign in to Office; there is no product key.</p></div>')
    elif ospp_path:
        office_html = '<div class="empty">Office is installed, but no product key licenses were reported.</div>'
    else:
        office_html = ""
    office_section = f"<h2>Microsoft Office</h2>{office_html}" if office_html else ""

    org = cfg.get("organization") or ""
    prepared = cfg.get("prepared_by") or ""
    notes_html = "".join(f"<br>{e(n)}" for n in notes)
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Software License Information – {e(name)}</title><style>{CSS}</style></head>
<body>
<div class="toolbar"><div class="check {check[0]}">{e(check[1])}</div><button onclick="window.print()">Print</button></div>
<main class="sheet"><div class="frame"><div class="inner">
<div class="head">{SEAL_SVG}<div>{f'<div class="org">{e(org)}</div>' if org else ''}
<h1>Software License Information</h1><p class="lead">Licensed software supplied with this computer</p></div></div>
<section class="device">{device_html}</section>
<section class="meta">{meta_html}</section>
<h2>Windows</h2>{win_html}
{office_section}
<div class="bottom"><div class="notice"><b>Keep this document in a safe place.</b> It records the software licensed for this
computer. The product keys may be needed to reinstall or reactivate the software.</div>
<div class="sign"><div><b>{e(prepared)}</b>Prepared by</div><div><b>&nbsp;</b>Signature</div></div>
<p class="fine">Device record {e(name)} · generated {dt.datetime.now():%Y-%m-%d %H:%M}{notes_html}</p></div>
</div></div></main>
<details><summary>Raw OSPP output</summary><pre>{e(ospp_raw or "(not run)")}</pre></details>
</body></html>"""


# --- Main ---------------------------------------------------------------------------------
def main() -> int:
    ap = argparse.ArgumentParser(description="Create a printable software license sheet for this PC.")
    ap.add_argument("--office-key", action="append", default=[], metavar="KEY",
                    help="full Office key (repeatable; matched to products by its last 5 characters)")
    ap.add_argument("--windows-key", metavar="KEY", help="full Windows key, if it can't be read automatically")
    ap.add_argument("--issued-to", default=None, help="name of the person receiving the computer")
    ap.add_argument("--no-prompt", action="store_true", help="don't ask any questions")
    ap.add_argument("--mask", action="store_true", help="show only the last 5 characters of every key")
    ap.add_argument("-o", "--output", help="where to save the sheet (default: next to this program)")
    ap.add_argument("--no-open", action="store_true", help="don't open the sheet when done")
    ap.add_argument("--debug", action="store_true", help="show where each Windows key came from")
    args = ap.parse_args()
    interactive = not args.no_prompt and sys.stdin is not None and sys.stdin.isatty()

    cfg, notes = load_config(), []
    print("Reading Windows and device info...")
    sysinfo = collect_system()
    if sysinfo.get("_error"):
        notes.append(sysinfo["_error"])

    ospp_path, ospp_raw, licenses = find_ospp(), "", []
    if ospp_path:
        print("Reading Office licenses...")
        try:
            ospp_raw = run_ospp(ospp_path)
            licenses = parse_ospp(ospp_raw)
            if "0x80070005" in ospp_raw or "access is denied" in ospp_raw.lower():
                print("Note: Office reported 'access denied'; run as administrator for full details.")
        except Exception as ex:
            print(f"Note: couldn't run OSPP.VBS: {ex}")

    win, office = windows_products(sysinfo), office_products(licenses)
    if args.debug:
        import platform
        ps_path = system_tool(r"WindowsPowerShell\v1.0\powershell.exe") if os.name == "nt" else "-"
        print(f"\n[debug] this program is {platform.architecture()[0]}; PowerShell: {ps_path}")
        print(f"[debug] DigitalProductId bytes read: {len(sysinfo.get('DigitalProductId') or [])}; "
              f"OEM key edition: {sysinfo.get('OEMKeyDesc') or '-'}; OSPP: {ospp_path or 'not found'}")
        for p in win:
            print(f"[debug] {p['title']} (installed key ends in {p['last5']}):")
            for name, result in p.get("sources", []):
                print(f"[debug]   {name + ':':27} {result}")
    given = args.office_key + ([args.windows_key] if args.windows_key else [])
    for problem in apply_given_keys(win + office, given):
        print("Note: " + problem)

    issued_to = args.issued_to
    if interactive and not args.mask:
        ask_for_keys(win + office)
    if interactive and issued_to is None:
        try:
            issued_to = input("\nIssued to (name, or Enter to leave blank): ").strip()
        except EOFError:
            issued_to = ""

    page = build_html(sysinfo, win, office, ospp_path, ospp_raw, cfg, issued_to or "", args.mask, notes)
    name = re.sub(r'[<>:"/\\|?*]', "_", sysinfo.get("ComputerName") or os.environ.get("COMPUTERNAME", "PC"))
    out = Path(args.output) if args.output else SCRIPT_DIR / f"Software License - {name} - {dt.date.today()}.html"
    out.write_text(page, encoding="utf-8")

    print(f"\nSaved: {out}")
    for p in win + office:
        key = "KMS" if p["kms"] else ("full key" if p["key"] else f"last 5 only ({p['last5']})")
        print(f"  {p['title']}: {p['status']} - {key}")
    if not args.no_open and hasattr(os, "startfile"):
        os.startfile(str(out))
    return 0


if __name__ == "__main__":
    sys.exit(main())
