#!/usr/bin/env python3
"""
license_status_report.py - printable software license status report (Windows + Microsoft Office).

Collects:
  * Machine details  (name, make/model, serial number)
  * Windows          activation status, channel, the full installed key (decoded from
                     the registry and checked against what Windows reports), and the
                     OEM key embedded in the firmware (if any)
  * Microsoft Office every license OSPP.VBS /dstatus reports, plus the installed
                     Click-to-Run products/version

and writes an HTML report next to this script (or the .exe), then opens it.

Usage:
    python license_status_report.py             # write report and open it
    python license_status_report.py --mask      # show only the last 5 of the Windows keys
    python license_status_report.py -o C:\\path\\report.html --no-open

Note: Office 2013 and later only keep the last 5 characters of the product key on the
computer, so that's all that can be shown for Office. Windows keeps its full installed
key in the registry unless it has been cleared (slmgr /cpky).

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
  Domain           = $cs.Domain
  Manufacturer     = $cs.Manufacturer
  Model            = $cs.Model
  ModelName        = $csp.Version
  Serial           = $bios.SerialNumber
  OSCaption        = $os.Caption
  DisplayVersion   = $cv.DisplayVersion
  Build            = "$($cv.CurrentBuild).$($cv.UBR)"
  InstallDate      = if ($os.InstallDate) { $os.InstallDate.ToString('yyyy-MM-dd') } else { $null }
  DigitalProductId = @($cv.DigitalProductId | ForEach-Object { [int]$_ })
  BackupKey        = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SoftwareProtectionPlatform').BackupProductKeyDefault
  OEMKey           = $svc.OA3xOriginalProductKey
  OEMKeyDesc       = $svc.OA3xOriginalProductKeyDescription
  Windows          = @($win | ForEach-Object { [pscustomobject]@{
                        Name = $_.Name; Description = $_.Description
                        LicenseStatus = $_.LicenseStatus; PartialProductKey = $_.PartialProductKey
                        ProductKeyChannel = $_.ProductKeyChannel
                        GracePeriodRemaining = $_.GracePeriodRemaining } })
  C2RProducts      = $c2r.ProductReleaseIds
  C2RVersion       = $c2r.VersionToReport
  C2RPlatform      = $c2r.Platform
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
    if isinstance(data.get("Windows"), dict):              # single item comes back unwrapped
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


# --- Windows key ---------------------------------------------------------------------
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


def masked(last5: str) -> str:
    return f"•••••-•••••-•••••-•••••-{last5}"


# --- Parsing OSPP output --------------------------------------------------------
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
                return f"{name} {year}".strip()
            return f"Office {name} {year}".strip()
    for app in ("Visio", "Project", "Access", "Excel", "Word", "Outlook", "PowerPoint", "Publisher"):
        if app.lower() in sku.lower():
            return f"{app} {year}".strip()
    return f"Office {year}".strip()


CHANNELS = {
    "VOLUME_KMSCLIENT": "Volume license (KMS)", "VOLUME_MAK": "Volume license (MAK)",
    "RETAIL": "Retail", "OEM": "OEM", "TIMEBASED_SUB": "Subscription",
    "TIMEBASED_DEMO": "Trial", "BYPASS": "Bypass",
}


def office_channel(desc: str) -> str:
    m = re.search(r",\s*([A-Z_]+)\s+channel", desc or "")
    return CHANNELS.get(m.group(1), m.group(1).title()) if m else (desc or "")


# status -> (label, css class)
OFFICE_STATUS = {
    "LICENSED": ("Activated", "ok"),
    "OOB_GRACE": ("Not activated (grace period)", "warn"),
    "OOT_GRACE": ("Not activated (grace period)", "warn"),
    "EXTENDED_GRACE": ("Not activated (extended grace)", "warn"),
    "NON_GENUINE_GRACE": ("Not genuine (grace period)", "bad"),
    "NOTIFICATIONS": ("Not activated", "bad"),
    "UNLICENSED": ("Unlicensed", "bad"),
}
WIN_STATUS = {
    0: ("Unlicensed", "bad"), 1: ("Activated", "ok"), 2: ("Not activated (grace period)", "warn"),
    3: ("Not activated (grace period)", "warn"), 4: ("Not genuine (grace period)", "bad"),
    5: ("Not activated", "bad"), 6: ("Not activated (extended grace)", "warn"),
}


def office_entries(licenses: list[dict]) -> list[dict]:
    entries = []
    for d in licenses:
        raw_status = re.sub(r"[-\s]", "", d.get("LICENSE STATUS", "")).upper() or "UNKNOWN"
        label, cls = OFFICE_STATUS.get(raw_status, (raw_status.title(), "warn"))
        rows = [("License type", office_channel(d.get("LICENSE DESCRIPTION", "")))]
        key = next((v for k, v in d.items() if k.startswith("LAST 5 CHARACTERS")), "")
        rows.append(("Product key", f"{masked(key)}  (last 5 only)" if key else "—"))
        grace = d.get("REMAINING GRACE")
        if grace:
            days = re.match(r"(\d+)\s*day", grace)
            if cls == "ok" and "KMS" in rows[0][1]:
                rows.append(("KMS renewal due", f"within {days.group(1)} days" if days else grace))
            else:
                rows.append(("Time remaining", f"{days.group(1)} days" if days else grace))
        kms = (d.get("KMS MACHINE REGISTRY OVERRIDE DEFINED") or d.get("KMS MACHINE NAME FROM DNS")
               or d.get("KMS MACHINE NAME"))
        if kms and "not available" not in kms.lower():
            rows.append(("KMS server", kms))
        if d.get("ERROR CODE"):
            rows.append(("Error", f"{d['ERROR CODE']} — {d.get('ERROR DESCRIPTION', '')}".strip(" —")))
        if d.get("PRODUCT ID"):
            rows.append(("Product ID", d["PRODUCT ID"]))
        entries.append({
            "title": friendly_office_name(d.get("LICENSE NAME", "")),
            "subtitle": d.get("LICENSE NAME", ""),
            "status": label, "cls": cls, "rows": rows,
        })
    return entries


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


def normalize_key(text: str) -> str | None:
    raw = re.sub(r"[^A-Za-z0-9]", "", text or "").upper()
    return "-".join(raw[i:i + 5] for i in range(0, 25, 5)) if len(raw) == 25 else None


def windows_entries(sysinfo: dict, mask: bool) -> list[dict]:
    entries = []
    decoded = decode_windows_key(sysinfo.get("DigitalProductId"))
    backup = normalize_key(sysinfo.get("BackupKey") or "")
    oem_key = normalize_key(sysinfo.get("OEMKey") or "")
    for w in sysinfo.get("Windows") or []:
        status = w.get("LicenseStatus")
        label, cls = WIN_STATUS.get(status, (f"Status {status}", "warn"))
        last5 = (w.get("PartialProductKey") or "").upper()
        rows = [("License type", w.get("ProductKeyChannel") or "—")]
        if last5:
            # Only trust a key that really is the installed one (same last 5)
            full = next((k for k in (decoded, backup, oem_key)
                         if k and k != CLEARED_KEY and k.endswith(last5)), None)
            if full:
                rows.append(("Installed key", masked(last5) if mask else full))
            elif decoded == CLEARED_KEY:
                rows.append(("Installed key", f"{masked(last5)}  (full key cleared from registry)"))
            elif not decoded:
                rows.append(("Installed key", f"{masked(last5)}  (registry key not readable)"))
            else:
                rows.append(("Installed key", f"{masked(last5)}  (registry key doesn't match)"))
        grace = w.get("GracePeriodRemaining") or 0
        if grace and cls != "ok":
            rows.append(("Time remaining", f"{int(grace) // 1440} days"))
        elif grace and "volume" in (w.get("ProductKeyChannel") or "").lower():
            rows.append(("KMS renewal due", f"within {int(grace) // 1440} days"))
        entries.append({
            "title": sysinfo.get("OSCaption") or w.get("Name") or "Windows",
            "subtitle": w.get("Description") or "",
            "status": label, "cls": cls, "rows": rows,
        })
    oem = sysinfo.get("OEMKey")
    if entries and oem:
        shown = masked(oem[-5:]) if mask else oem
        installed = next((v for k, v in entries[0]["rows"] if k == "Installed key"), "")
        if installed != shown:                      # don't repeat the same key twice
            ed = oem_edition(sysinfo.get("OEMKeyDesc"))
            entries[0]["rows"].append((f"OEM key (firmware, {ed})" if ed else "OEM key (firmware)", shown))
        else:
            entries[0]["rows"] = [(k + " (also in firmware)" if k == "Installed key" else k, v)
                                  for k, v in entries[0]["rows"]]
        if sysinfo.get("OEMKeyDesc"):
            entries[0]["rows"].append(("OEM key edition", sysinfo["OEMKeyDesc"]))
    return entries


# --- HTML ------------------------------------------------------------------------
CSS = """
:root{--ink:#16181d;--muted:#5d6470;--line:#e3e6ea;--soft:#f5f6f8;--accent:#1f4e8c;
--ok:#1a7f43;--ok-bg:#e6f4ec;--warn:#9a6200;--warn-bg:#fdf3dc;--bad:#b42318;--bad-bg:#fdecea}
*{box-sizing:border-box;-webkit-print-color-adjust:exact;print-color-adjust:exact}
html{background:#e9ecef}
body{margin:0;font:14px/1.45 "Segoe UI",system-ui,-apple-system,Roboto,Arial,sans-serif;color:var(--ink)}
.page{max-width:820px;margin:24px auto;background:#fff;padding:36px 40px;border-radius:10px;
box-shadow:0 2px 14px rgba(0,0,0,.08)}
header{display:flex;justify-content:space-between;align-items:flex-start;gap:16px;
border-bottom:3px solid var(--accent);padding-bottom:14px}
.eyebrow{font-size:11px;letter-spacing:.12em;text-transform:uppercase;color:var(--accent);font-weight:700}
h1{margin:2px 0 0;font-size:26px;letter-spacing:-.01em}
.generated{text-align:right;color:var(--muted);font-size:12px;white-space:nowrap}
.machine{display:grid;grid-template-columns:repeat(4,1fr);gap:10px 18px;margin:18px 0 6px;
background:var(--soft);border:1px solid var(--line);border-radius:8px;padding:14px 16px}
.machine div span{display:block;font-size:10.5px;text-transform:uppercase;letter-spacing:.08em;color:var(--muted)}
.machine div b{font-weight:600;word-break:break-word}
.summary{margin:16px 0 4px;padding:10px 14px;border-radius:8px;font-weight:600;display:flex;gap:10px;align-items:center}
.summary.ok{background:var(--ok-bg);color:var(--ok)} .summary.bad{background:var(--bad-bg);color:var(--bad)}
.summary.warn{background:var(--warn-bg);color:var(--warn)}
h2{font-size:13px;letter-spacing:.1em;text-transform:uppercase;color:var(--muted);margin:24px 0 10px;
display:flex;align-items:center;gap:10px}
h2::after{content:"";flex:1;border-top:1px solid var(--line)}
.card{border:1px solid var(--line);border-radius:8px;margin-bottom:12px;break-inside:avoid;overflow:hidden}
.card-head{display:flex;justify-content:space-between;align-items:center;gap:12px;padding:11px 14px;
border-bottom:1px solid var(--line)}
.card-head h3{margin:0;font-size:16px}
.card-head small{display:block;color:var(--muted);font-size:11.5px;margin-top:1px}
.badge{font-size:12px;font-weight:700;padding:4px 10px;border-radius:999px;white-space:nowrap}
.badge.ok{background:var(--ok-bg);color:var(--ok)} .badge.warn{background:var(--warn-bg);color:var(--warn)}
.badge.bad{background:var(--bad-bg);color:var(--bad)}
.card-head{border-left:5px solid var(--line)}
.card.ok .card-head{border-left-color:var(--ok)} .card.warn .card-head{border-left-color:var(--warn)}
.card.bad .card-head{border-left-color:var(--bad)}
dl{display:grid;grid-template-columns:170px 1fr;margin:0;padding:10px 14px;gap:5px 14px}
dt{color:var(--muted)} dd{margin:0;font-weight:500;word-break:break-word}
dd.key{font-family:Consolas,"Cascadia Mono",monospace;font-size:13.5px;letter-spacing:.02em}
dd.key small{font-family:"Segoe UI",system-ui,sans-serif;color:var(--muted);font-weight:400;letter-spacing:0}
.empty{border:1px dashed var(--line);border-radius:8px;padding:14px;color:var(--muted)}
.products{color:var(--muted);font-size:12.5px;margin:-4px 0 10px}
footer{margin-top:22px;padding-top:10px;border-top:1px solid var(--line);color:var(--muted);font-size:11px}
.toolbar{max-width:820px;margin:16px auto 0;display:flex;justify-content:flex-end}
button{font:inherit;font-weight:600;background:var(--accent);color:#fff;border:0;border-radius:6px;
padding:8px 16px;cursor:pointer}
details{max-width:820px;margin:0 auto 32px;background:#fff;border-radius:8px;padding:10px 16px}
details pre{white-space:pre-wrap;font-size:11.5px;color:var(--muted)}
@media (max-width:640px){.page{padding:22px 18px;margin:0;border-radius:0}.machine{grid-template-columns:1fr 1fr}
dl{grid-template-columns:1fr}dt{margin-top:4px}header{flex-direction:column}.generated{text-align:left}}
@page{margin:10mm 12mm}
@media print{html{background:#fff}body{font-size:12px}
.page{margin:0;max-width:none;box-shadow:none;border-radius:0;padding:0}
.toolbar,details{display:none}
header{padding-bottom:8px}h1{font-size:22px}
.machine{margin:10px 0 4px;padding:9px 12px;gap:6px 14px}
.summary{margin:10px 0 0;padding:6px 12px}
h2{margin:14px 0 6px;font-size:11.5px}.products{margin:-2px 0 6px;font-size:11px}
.card{margin-bottom:8px}.card-head{padding:6px 12px}.card-head h3{font-size:14px}
.card-head small{font-size:10.5px}.badge{font-size:11px;padding:3px 9px}
dl{padding:6px 12px;gap:2px 14px;grid-template-columns:150px 1fr}dd.key{font-size:12px}
footer{margin-top:12px;padding-top:6px;font-size:10px}}
"""

e = html.escape
KEY_ROWS = ("Product key", "Installed key", "OEM key (firmware")     # shown in a monospace font


def key_value_html(v: str) -> str:
    """Key in monospace; any '(explanation)' after it in the normal font."""
    m = re.match(r"^(.*?)\s{2}(\(.*\))$", v)
    return f"{e(m.group(1))} <small>{e(m.group(2))}</small>" if m else e(v)


def card_html(entry: dict) -> str:
    rows = "".join(
        f'<dt>{e(k)}</dt><dd class="key">{key_value_html(str(v))}</dd>' if k.startswith(KEY_ROWS)
        else f'<dt>{e(k)}</dt><dd>{e(str(v))}</dd>'
        for k, v in entry["rows"]
    )
    sub = f"<small>{e(entry['subtitle'])}</small>" if entry["subtitle"] else ""
    return (f'<div class="card {entry["cls"]}"><div class="card-head"><div><h3>{e(entry["title"])}</h3>{sub}</div>'
            f'<span class="badge {entry["cls"]}">{e(entry["status"])}</span></div><dl>{rows}</dl></div>')


def build_html(sysinfo: dict, win: list[dict], office: list[dict], ospp_path: str | None,
               ospp_raw: str, notes: list[str]) -> str:
    now = dt.datetime.now()
    name = sysinfo.get("ComputerName") or os.environ.get("COMPUTERNAME", "This PC")
    model = " ".join(x for x in (sysinfo.get("ModelName"), f"({sysinfo['Model']})" if sysinfo.get("Model")
                                 and sysinfo.get("Model") != sysinfo.get("ModelName") else None) if x)
    winver = " ".join(x for x in (sysinfo.get("DisplayVersion"),
                                  f"build {sysinfo['Build']}" if sysinfo.get("Build") else None) if x)
    machine = [
        ("Computer", name), ("Manufacturer", sysinfo.get("Manufacturer") or "—"),
        ("Model", model or "—"), ("Serial number", sysinfo.get("Serial") or "—"),
        ("Windows", sysinfo.get("OSCaption") or "—"), ("Version", winver or "—"),
        ("Installed", sysinfo.get("InstallDate") or "—"), ("Domain / workgroup", sysinfo.get("Domain") or "—"),
    ]
    machine_html = "".join(f"<div><span>{e(k)}</span><b>{e(str(v))}</b></div>" for k, v in machine)

    everything = win + office
    bad = [x for x in everything if x["cls"] != "ok"]
    n = len(everything)
    if not everything:
        summary = ('warn', "⚠ No license information found")
    elif bad:
        summary = ('bad' if any(x["cls"] == "bad" for x in bad) else 'warn',
                   f"⚠ {len(bad)} of {n} product{'s' if n != 1 else ''} "
                   f"need{'s' if len(bad) == 1 else ''} attention")
    else:
        summary = ('ok', "✔ Activated" if n == 1 else f"✔ All {n} products activated")

    win_html = "".join(card_html(x) for x in win) or '<div class="empty">No Windows license information was found.</div>'

    products = sysinfo.get("C2RProducts")
    prod_line = ""
    if products:
        ver = f" · version {sysinfo['C2RVersion']}" if sysinfo.get("C2RVersion") else ""
        plat = f" · {sysinfo['C2RPlatform']}" if sysinfo.get("C2RPlatform") else ""
        names = ", ".join(p.strip() for p in str(products).split(",") if p.strip())
        prod_line = f'<p class="products">Installed (Click-to-Run): {e(names)}{e(ver)}{e(plat)}</p>'
    if office:
        office_html = "".join(card_html(x) for x in office)
    elif ospp_path:
        sub = (" Microsoft 365 subscriptions are licensed by the signed-in account, not a product key."
               if products and "O365" in products else "")
        office_html = f'<div class="empty">Office is installed, but no product key licenses were reported.{e(sub)}</div>'
    else:
        office_html = '<div class="empty">Microsoft Office was not found on this computer.</div>'

    notes_html = "".join(f"<br>{e(n)}" for n in notes)
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>License Report – {e(name)}</title><style>{CSS}</style></head>
<body>
<div class="toolbar"><button onclick="window.print()">Print</button></div>
<main class="page">
<header><div><div class="eyebrow">Software License Report</div><h1>{e(name)}</h1></div>
<div class="generated">Generated<br><b>{now:%Y-%m-%d %H:%M}</b></div></header>
<section class="machine">{machine_html}</section>
<div class="summary {summary[0]}">{e(summary[1])}</div>
<h2>Windows</h2>{win_html}
<h2>Microsoft Office</h2>{prod_line}{office_html}
<footer>The Windows installed key is read from the registry and checked against the last 5 characters Windows
reports; the OEM key comes from the PC's firmware. Office 2013 and later keep only the last 5 characters of
their product key on the computer.{notes_html}</footer>
</main>
<details><summary>Raw OSPP output</summary><pre>{e(ospp_raw or "(not run)")}</pre></details>
</body></html>"""


# --- Main ----------------------------------------------------------------------------
def main() -> int:
    ap = argparse.ArgumentParser(description="Create a printable Windows/Office license status report.")
    ap.add_argument("-o", "--output", help="where to save the report (default: next to this script)")
    ap.add_argument("--mask", action="store_true", help="show only the last 5 of the Windows keys")
    ap.add_argument("--no-open", action="store_true", help="don't open the report when done")
    args = ap.parse_args()

    notes = []
    print("Reading Windows and machine info...")
    sysinfo = collect_system()
    if sysinfo.get("_error"):
        notes.append(sysinfo["_error"])

    ospp_path, ospp_raw, licenses = find_ospp(), "", []
    if ospp_path:
        print(f"Checking Office licenses ({ospp_path})...")
        try:
            ospp_raw = run_ospp(ospp_path)
            licenses = parse_ospp(ospp_raw)
            if "0x80070005" in ospp_raw or "access is denied" in ospp_raw.lower():
                notes.append("OSPP reported 'access denied'; run this as administrator for full Office details.")
        except Exception as ex:
            notes.append(f"Could not run OSPP.VBS: {ex}")
    else:
        print("Office (OSPP.VBS) not found.")

    win = windows_entries(sysinfo, args.mask)
    office = office_entries(licenses)
    page = build_html(sysinfo, win, office, ospp_path, ospp_raw, notes)

    name = re.sub(r'[<>:"/\\|?*]', "_", sysinfo.get("ComputerName") or os.environ.get("COMPUTERNAME", "PC"))
    out = Path(args.output) if args.output else SCRIPT_DIR / f"License Report - {name} - {dt.date.today()}.html"
    out.write_text(page, encoding="utf-8")
    print(f"Report saved: {out}")
    for x in win + office:
        print(f"  {x['title']}: {x['status']}")
    if not args.no_open and hasattr(os, "startfile"):
        os.startfile(str(out))
    return 0


if __name__ == "__main__":
    sys.exit(main())
