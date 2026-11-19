#!/usr/bin/env python3
"""
vmware_setup.py - one script for setting up VMware Workstation on a fresh machine
==================================================================================

Replaces the old collection of fetch_unlocker.bat + gh_fetch.py +
vmware_defaults.py + get.ps1.

Commands (run with no command for an interactive menu):

    setup          Full post-install workflow: download/verify the DrDonk Unlocker,
                   check patch status, patch VMware (asks first), then set the
                   host-wide VMware defaults (asks first).
    status         Read-only health report: Windows hypervisor / WSL2 / VBS state
                   (why VMware runs in Hyper-V mode), VMware install, Unlocker patch
                   status, and whether the host defaults are in place.
    unlock         Download/verify the Unlocker and patch VMware.
    relock         Remove the Unlocker patches (restores VMware's original files).
    patch-status   Run the Unlocker's check.exe only (read-only).
    defaults       Host-wide VMware defaults: --apply | --check | --revert
                   (side-channel mitigations off, no automatic VMware Tools installs).
    hypervisor     Show, or switch, the Windows hypervisor boot setting (off | auto).
    win11-iso      Rebuild a Windows 11 ISO with an autounattend.xml that skips the
                   TPM/CPU checks and the forced online account.
    ventoy         Configure a Ventoy USB to apply the same bypass without changing the ISO.
    ventoy-remove  Undo the Ventoy configuration.
    fetch          Generic: download a release asset from any GitHub repo.

Every run writes a timestamped log file to ./logs next to this script.
Nothing is changed on the system without an interactive "y" from you; with no
interactive terminal every prompt counts as NO.

Exit codes: 0 OK - 1 error - 2 not compliant / verification failed - 3 aborted - 130 Ctrl+C

Requires Python 3.8+ and the packages `rich` and `requests`
(the script offers to install them if missing).
"""
from __future__ import annotations

import argparse
import contextlib
import datetime as dt
import difflib
import hashlib
import importlib
import io
import json
import logging
import os
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import xml.etree.ElementTree as ET
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, Tuple

VERSION = "2.0.0"
WINDOWS = os.name == "nt"
LINUX = sys.platform.startswith("linux")

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_NOT_COMPLIANT = 2
EXIT_ABORTED = 3
EXIT_INTERRUPTED = 130

SCRIPT_PATH = Path(__file__).resolve()
SCRIPT_DIR = SCRIPT_PATH.parent


# =========================================================================== #
# Dependency bootstrap (rich + requests)
# =========================================================================== #
def _bootstrap_dependencies() -> None:
    needed = (("rich", "rich>=13.0"), ("requests", "requests>=2.28"))
    missing = []
    for mod, spec in needed:
        try:
            importlib.import_module(mod)
        except ImportError:
            missing.append(spec)
    if not missing:
        return
    sys.stderr.write(f"This script needs these Python packages: {', '.join(missing)}\n")
    cmd = [sys.executable, "-m", "pip", "install", *missing]
    interactive = sys.stdin is not None and sys.stdin.isatty()
    if interactive:
        try:
            ans = input(f"Install them now with:  {subprocess.list2cmdline(cmd)}  ? [y/N] ")
        except (EOFError, KeyboardInterrupt):
            ans = ""
        if ans.strip().lower() in ("y", "yes"):
            rc = subprocess.call(cmd)
            if rc == 0:
                import site
                importlib.invalidate_caches()
                with contextlib.suppress(Exception):
                    site.addsitedir(site.getusersitepackages())
                try:
                    for mod, _ in needed:
                        importlib.import_module(mod)
                    return
                except ImportError:
                    sys.stderr.write("Installed, but Python could not load them yet. Please run the script again.\n")
                    sys.exit(EXIT_ERROR)
            sys.stderr.write(f"pip failed with exit code {rc}.\n")
            sys.exit(EXIT_ERROR)
    sys.stderr.write(f"Install them with:  {subprocess.list2cmdline(cmd)}\n")
    if not WINDOWS:
        sys.stderr.write("(If you run this script with sudo, install them for the Python that sudo uses.)\n")
    sys.exit(EXIT_ERROR)


_bootstrap_dependencies()

import requests  # noqa: E402
from requests.adapters import HTTPAdapter  # noqa: E402
from rich import box  # noqa: E402
from rich.console import Console  # noqa: E402
from rich.markup import escape  # noqa: E402
from rich.panel import Panel  # noqa: E402
from rich.progress import (  # noqa: E402
    BarColumn, DownloadColumn, Progress, TextColumn, TimeRemainingColumn, TransferSpeedColumn,
)
from rich.prompt import Confirm, Prompt  # noqa: E402
from rich.rule import Rule  # noqa: E402
from rich.syntax import Syntax  # noqa: E402
from rich.table import Table  # noqa: E402
from rich.text import Text  # noqa: E402

try:
    from urllib3.util.retry import Retry  # noqa: E402
except ImportError:  # pragma: no cover
    Retry = None  # type: ignore

# =========================================================================== #
# Console, logging and reporting
# =========================================================================== #
console = Console(highlight=False, log_path=False)
log = logging.getLogger("vmware_setup")
log.setLevel(logging.DEBUG)
log.propagate = False
LOG_FILE: Optional[Path] = None


def e(obj: Any) -> str:
    """Escape arbitrary text (paths, command output) for rich markup."""
    return escape(str(obj))


def plain(markup: str) -> str:
    try:
        return Text.from_markup(markup).plain
    except Exception:
        return markup


def render_plain(renderable: Any, width: int = 120) -> str:
    buf = io.StringIO()
    Console(file=buf, width=width, color_system=None, highlight=False, emoji=False).print(renderable)
    return buf.getvalue().rstrip()


def setup_logging(log_dir: Optional[Path]) -> None:
    global LOG_FILE
    if log_dir is None:
        return
    try:
        log_dir.mkdir(parents=True, exist_ok=True)
        stamp = dt.datetime.now().strftime("%Y%m%d-%H%M%S")
        path = log_dir / f"vmware_setup-{stamp}.log"
        n = 1
        while path.exists():
            path = log_dir / f"vmware_setup-{stamp}-{n}.log"
            n += 1
        handler = logging.FileHandler(path, encoding="utf-8")
        handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)-7s %(message)s", "%Y-%m-%d %H:%M:%S"))
        log.addHandler(handler)
        LOG_FILE = path
    except OSError as exc:
        console.print(f"[yellow]⚠ Could not create a log file in {e(log_dir)}: {e(exc)} (continuing without one)[/]")


class UI:
    """Rich console output + the same messages (as plain text) in the log file."""

    def __init__(self) -> None:
        self.verbose = False
        self.warnings: List[str] = []
        self.errors: List[str] = []

    def info(self, msg: str) -> None:
        console.log(f"[cyan]•[/] {msg}")
        log.info(plain(msg))

    def ok(self, msg: str) -> None:
        console.log(f"[green]✔[/] {msg}")
        log.info("OK: " + plain(msg))

    def warn(self, msg: str) -> None:
        self.warnings.append(plain(msg))
        console.log(f"[yellow]⚠ {msg}[/]")
        log.warning(plain(msg))

    def err(self, msg: str) -> None:
        self.errors.append(plain(msg))
        console.log(f"[bold red]✖ {msg}[/]")
        log.error(plain(msg))

    def debug(self, msg: str) -> None:
        log.debug(plain(msg))
        if self.verbose:
            console.log(f"[dim]  {msg}[/]")

    def section(self, title: str) -> None:
        console.print()
        console.print(Rule(f"[bold]{title}"))
        log.info("==================== %s ====================", plain(title))

    def show(self, renderable: Any) -> None:
        """Print a table/panel and put a plain-text copy in the log."""
        console.print(renderable)
        log.info("\n%s", render_plain(renderable))

    def raw(self, line: str, style: str = "dim") -> None:
        """A line of output from an external program."""
        console.print(Text(line, style=style))
        log.info("  | %s", line)


ui = UI()


class Summary:
    STYLE = {"ok": "[green]✔ OK[/]", "warn": "[yellow]⚠ WARN[/]", "fail": "[bold red]✖ FAIL[/]",
             "skip": "[dim]– skipped[/]", "info": "[cyan]• info[/]"}

    def __init__(self, title: str) -> None:
        self.title = title
        self.rows: List[Tuple[str, str, str]] = []

    def add(self, step: str, status: str, detail: str = "") -> None:
        self.rows.append((step, status, detail))
        log.info("SUMMARY %-22s %-5s %s", step, status.upper(), detail)

    @property
    def worst(self) -> str:
        statuses = {s for _, s, _ in self.rows}
        for s in ("fail", "warn"):
            if s in statuses:
                return s
        return "ok"

    def render(self) -> Table:
        t = Table(title=self.title, box=box.ROUNDED, header_style="bold", expand=True)
        t.add_column("Step", style="bold", no_wrap=True)
        t.add_column("Result", no_wrap=True)
        t.add_column("Details", overflow="fold")
        for step, status, detail in self.rows:
            t.add_row(e(step), self.STYLE.get(status, status), e(detail))
        return t


class StepError(Exception):
    """An expected failure with a message suitable for the user."""


class Aborted(Exception):
    """The user declined something; stop without treating it as an error."""


# =========================================================================== #
# Generic helpers
# =========================================================================== #
def interactive() -> bool:
    return sys.stdin is not None and sys.stdin.isatty()


def confirm(question: str, default: bool = False) -> bool:
    """Yes/no prompt. No terminal, EOF or Ctrl+C all count as NO."""
    if not interactive():
        ui.warn(f"Can't ask \"{e(question)}\" (no interactive terminal) - treating as NO.")
        return False
    try:
        ans = Confirm.ask(question, default=default)
    except (EOFError, KeyboardInterrupt):
        console.print()
        ans = False
    log.info("PROMPT %s -> %s", plain(question), "yes" if ans else "no")
    return ans


def ask_text(question: str, default: str = "") -> Optional[str]:
    if not interactive():
        ui.warn(f"Can't ask \"{e(question)}\" (no interactive terminal).")
        return None
    try:
        ans = Prompt.ask(question, default=default or None)
    except (EOFError, KeyboardInterrupt):
        console.print()
        return None
    log.info("PROMPT %s -> %s", plain(question), ans)
    return ans


def ask_number(question: str, low: int, high: int) -> Optional[int]:
    for _ in range(5):
        ans = ask_text(f"{question} [{low}-{high}]")
        if ans is None:
            return None
        ans = ans.strip()
        if ans.isdigit() and low <= int(ans) <= high:
            return int(ans)
        ui.warn(f"Enter a number from {low} to {high}.")
    ui.err("Too many invalid answers.")
    return None


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def fmt_size(n: float) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or unit == "TB":
            return f"{n:.0f} {unit}" if unit in ("B", "KB") else f"{n:.2f} {unit}"
        n /= 1024
    return f"{n} B"


def _rmtree_onexc(func: Callable, path: str, exc: Any) -> None:
    # Files copied off a mounted ISO are read-only; clear the flag and retry.
    with contextlib.suppress(OSError):
        os.chmod(path, 0o666)
        func(path)


def rmtree(path: Path) -> None:
    if not path.exists():
        return
    if sys.version_info >= (3, 12):
        shutil.rmtree(path, onexc=_rmtree_onexc)  # type: ignore[call-arg]
    else:
        shutil.rmtree(path, onerror=_rmtree_onexc)


def is_admin() -> bool:
    if WINDOWS:
        try:
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())  # type: ignore[attr-defined]
        except Exception:
            return False
    return hasattr(os, "geteuid") and os.geteuid() == 0


def ps_quote(s: str) -> str:
    """Quote a string as a PowerShell single-quoted literal."""
    return "'" + str(s).replace("'", "''") + "'"


@dataclass
class CmdResult:
    rc: int
    output: str
    seconds: float
    timed_out: bool = False


def run_cmd(cmd: Sequence[str] | str, *, cwd: Optional[Path] = None, env: Optional[Dict[str, str]] = None,
            timeout: Optional[float] = 120, stream: bool = False, encoding: str = "utf-8",
            quiet: bool = False, log_output: bool = True) -> CmdResult:
    """
    Run a program. stdin is closed so nothing can hang waiting for a keypress.
    stream=True shows each output line live (and logs it); otherwise the
    output is captured and only logged.
    """
    shown = cmd if isinstance(cmd, str) else subprocess.list2cmdline([str(c) for c in cmd])
    ui.debug(f"$ {e(shown)}" + (f"   (in {e(cwd)})" if cwd else ""))
    log.info("RUN %s%s", shown, f"   (cwd={cwd})" if cwd else "")
    start = time.monotonic()
    full_env = dict(os.environ)
    if env:
        full_env.update(env)
    try:
        proc = subprocess.Popen(
            cmd if isinstance(cmd, str) else [str(c) for c in cmd],
            cwd=str(cwd) if cwd else None, env=full_env,
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        )
    except OSError as exc:
        raise StepError(f"Could not start {shown}: {exc}") from exc

    timed_out = threading.Event()

    def _kill() -> None:
        timed_out.set()
        with contextlib.suppress(OSError):
            proc.kill()

    timer = threading.Timer(timeout, _kill) if timeout else None
    if timer:
        timer.daemon = True
        timer.start()
    chunks: List[bytes] = []
    try:
        assert proc.stdout is not None
        if stream:
            for raw in iter(proc.stdout.readline, b""):
                chunks.append(raw)
                line = raw.decode(encoding, errors="replace").rstrip("\r\n")
                if not quiet:
                    ui.raw(line)
                else:
                    log.info("  | %s", line)
        else:
            chunks.append(proc.stdout.read())
        proc.wait()
    except KeyboardInterrupt:
        _kill()
        proc.wait()
        raise
    finally:
        if timer:
            timer.cancel()
    output = b"".join(chunks)
    if b"\x00" in output[:200] and encoding == "utf-8":  # wsl.exe and friends write UTF-16LE
        text = output.decode("utf-16-le", errors="replace")
    else:
        text = output.decode(encoding, errors="replace")
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    if not stream and log_output:
        for line in text.splitlines():
            log.debug("  | %s", line)
    res = CmdResult(proc.returncode, text, time.monotonic() - start, timed_out.is_set())
    log.info("EXIT %s after %.1fs%s", res.rc, res.seconds, " (TIMED OUT)" if res.timed_out else "")
    if res.timed_out:
        raise StepError(f"{shown} did not finish within {timeout:.0f}s and was stopped.")
    return res


def powershell_json(script: str, timeout: float = 90) -> Any:
    """Run a PowerShell snippet that ends in ConvertTo-Json and return the parsed result."""
    exe = shutil.which("powershell.exe") or shutil.which("powershell") or shutil.which("pwsh")
    if not exe:
        raise StepError("PowerShell was not found.")
    prefix = "[Console]::OutputEncoding = [Text.Encoding]::UTF8; $ProgressPreference = 'SilentlyContinue'; "
    res = run_cmd([exe, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", prefix + script],
                  timeout=timeout)
    out = res.output.strip()
    if res.rc != 0:
        raise StepError(f"PowerShell failed (exit {res.rc}): {out[-400:]}")
    if not out:
        return None
    # Ignore anything printed before the JSON
    start = min([i for i in (out.find("{"), out.find("[")) if i >= 0] or [0])
    try:
        return json.loads(out[start:])
    except ValueError as exc:
        raise StepError(f"Could not parse PowerShell output as JSON: {exc}: {out[:300]}") from exc


def atomic_write_bytes(path: Path, data: bytes) -> None:
    """Write via a temp file in the same folder + os.replace, so a failure never leaves a half-written file."""
    path.parent.mkdir(parents=True, exist_ok=True)
    orig_stat = path.stat() if path.exists() else None
    fd, tmp = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=str(path.parent))
    ui.debug(f"Temp file: {e(tmp)}")
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        if orig_stat is not None:
            with contextlib.suppress(OSError):
                shutil.copymode(path, tmp)
            if not WINDOWS and hasattr(os, "chown"):
                with contextlib.suppress(OSError):
                    os.chown(tmp, orig_stat.st_uid, orig_stat.st_gid)
        last_exc: Optional[BaseException] = None
        for attempt in range(1, 6):  # os.replace can fail briefly on Windows if a scanner holds the file
            try:
                os.replace(tmp, path)
                last_exc = None
                break
            except PermissionError as exc:
                last_exc = exc
                ui.debug(f"Replace attempt {attempt}/5 failed ({e(exc)}); retrying...")
                time.sleep(0.5 * attempt)
        if last_exc:
            raise last_exc
        ui.debug(f"Atomically replaced {e(path)} ({len(data)} bytes)")
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp)
        raise


def backup_file(path: Path) -> Optional[Path]:
    """Timestamped, verified copy next to the original. Returns None if there is nothing to back up."""
    if not path.exists():
        ui.debug(f"No existing file to back up at {e(path)}")
        return None
    ts = dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    bak = path.with_name(f"{path.name}.bak-{ts}")
    n = 1
    while bak.exists():
        bak = path.with_name(f"{path.name}.bak-{ts}-{n}")
        n += 1
    shutil.copy2(path, bak)
    if bak.read_bytes() != path.read_bytes():
        raise OSError(f"Backup verification failed for {bak}")
    ui.ok(f"Backup created and verified: [bold]{e(bak)}[/]")
    return bak


def restore_backup(path: Path, backup: Optional[Path], existed: bool) -> None:
    try:
        if backup and backup.exists():
            shutil.copy2(backup, path)
            ui.warn(f"Rolled back {e(path)} from {e(backup)}")
        elif not existed and path.exists():
            path.unlink()
            ui.warn(f"Rolled back by removing newly created {e(path)}")
    except OSError as exc:
        ui.err(f"ROLLBACK FAILED for {e(path)}: {e(exc)} - restore it manually from {e(backup)}")


def process_names() -> Optional[List[str]]:
    try:
        if WINDOWS:
            out = run_cmd(["tasklist", "/FO", "CSV", "/NH"], timeout=30, encoding="mbcs", log_output=False).output
            return [ln.split('","')[0].strip('"') for ln in out.splitlines() if ln.strip()]
        out = run_cmd(["ps", "-eo", "comm="], timeout=30, log_output=False).output
        return [ln.strip() for ln in out.splitlines() if ln.strip()]
    except StepError as exc:
        ui.debug(f"Process list failed: {e(exc)}")
        return None


VMWARE_PROCS = {"vmware.exe", "vmware-vmx.exe", "vmplayer.exe", "vmware-kvm.exe", "vmrest.exe",
                "vmware", "vmware-vmx", "vmplayer"}


def running_vmware() -> Optional[List[str]]:
    names = process_names()
    if names is None:
        return None
    hits: Dict[str, int] = {}
    for n in names:
        if n.lower() in VMWARE_PROCS:
            hits[n] = hits.get(n, 0) + 1
    return [f"{k} (x{v})" for k, v in sorted(hits.items())]


def wait_for_vmware_closed(purpose: str) -> bool:
    """Ask the user to close VMware until it is closed, or they give up. True = closed (or unknown)."""
    while True:
        procs = running_vmware()
        if procs is None:
            ui.warn("Could not check whether VMware is running; make sure it is closed.")
            return True
        if not procs:
            ui.ok("VMware is not running.")
            return True
        ui.warn(f"VMware is running: {e(', '.join(procs))}")
        ui.info(f"Close VMware and power off all VMs before {purpose}.")
        if not confirm("I've closed VMware - check again?", default=True):
            return False


# =========================================================================== #
# VMware install detection
# =========================================================================== #
def detect_workstation() -> Dict[str, str]:
    info: Dict[str, str] = {}
    if WINDOWS:
        try:
            import winreg
            for product in ("VMware Workstation", "VMware Player"):
                for view in (winreg.KEY_WOW64_64KEY, winreg.KEY_WOW64_32KEY):
                    try:
                        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, rf"SOFTWARE\VMware, Inc.\{product}",
                                            0, winreg.KEY_READ | view) as k:
                            for name in ("InstallPath", "ProductVersion", "BuildNumber"):
                                with contextlib.suppress(FileNotFoundError):
                                    info[name] = str(winreg.QueryValueEx(k, name)[0]).rstrip("\\/")
                    except FileNotFoundError:
                        continue
                    if info.get("InstallPath"):
                        info["Product"] = product
                        ui.debug(f"Registry hit: {e(info)}")
                        break
                if info.get("InstallPath"):
                    break
        except OSError as exc:
            ui.debug(f"Registry query failed: {e(exc)}")
        if "InstallPath" not in info:
            for pf in (os.environ.get("ProgramFiles(x86)"), os.environ.get("ProgramFiles")):
                if pf and (Path(pf) / "VMware" / "VMware Workstation" / "vmware.exe").exists():
                    info["InstallPath"] = str(Path(pf) / "VMware" / "VMware Workstation")
                    info["Product"] = "VMware Workstation"
                    ui.debug("Found install via default path fallback")
                    break
    elif LINUX:
        exe = shutil.which("vmware") or shutil.which("vmplayer")
        if exe:
            info["InstallPath"] = exe
            info["Product"] = "VMware Workstation"
            with contextlib.suppress(StepError):
                out = run_cmd([exe, "--version"], timeout=20).output.strip().splitlines()
                if out:
                    info["ProductVersion"] = out[0]
        elif Path("/usr/lib/vmware").is_dir():
            info["InstallPath"] = "/usr/lib/vmware"
    return info


# =========================================================================== #
# GitHub release download
# =========================================================================== #
GITHUB_API = os.environ.get("GITHUB_API_URL", "https://api.github.com").rstrip("/")
ARCHIVE_SUFFIXES = (".zip", ".tar.gz", ".tgz", ".tar.xz", ".txz", ".tar.bz2",
                    ".7z", ".gz", ".xz", ".bz2", ".dmg", ".pkg", ".deb", ".rpm")


def parse_repo(arg: str) -> str:
    """Accept owner/name, github.com/owner/name, or a full URL (with or without .git)."""
    arg = arg.strip()
    m = re.match(r"(?:https?://)?(?:www\.)?github\.com/([^/]+/[^/?#]+)", arg)
    repo = re.sub(r"\.git$", "", (m.group(1) if m else arg).strip("/"))
    if not re.fullmatch(r"[\w.-]+/[\w.-]+", repo):
        raise StepError(f"Not a valid repo: {arg!r} (expected owner/name or a GitHub URL)")
    return repo


def http_session() -> requests.Session:
    s = requests.Session()
    s.headers["User-Agent"] = f"vmware_setup.py/{VERSION}"
    if Retry is not None:
        retry = Retry(total=4, connect=4, read=3, backoff_factor=1.5,
                      status_forcelist=(429, 500, 502, 503, 504), allowed_methods=frozenset(["GET", "HEAD"]),
                      respect_retry_after_header=True, raise_on_status=False)
        s.mount("https://", HTTPAdapter(max_retries=retry))
        s.mount("http://", HTTPAdapter(max_retries=retry))
    return s


class GitHub:
    def __init__(self) -> None:
        self.s = http_session()
        self.s.headers["Accept"] = "application/vnd.github+json"
        self.s.headers["X-GitHub-Api-Version"] = "2022-11-28"
        token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
        if token:
            self.s.headers["Authorization"] = f"Bearer {token}"
            ui.debug("Using GITHUB_TOKEN/GH_TOKEN for the GitHub API")

    def find_asset(self, repo: str, pattern: "re.Pattern[str]", prerelease: bool = False):
        """Return (release, asset, newest_tag) for the newest release that has a matching asset."""
        url = f"{GITHUB_API}/repos/{repo}/releases"
        ui.info(f"Looking up releases for [bold]{e(repo)}[/]...")
        try:
            r = self.s.get(url, params={"per_page": 100}, timeout=30)
        except requests.RequestException as exc:
            raise StepError(f"Could not reach GitHub: {exc}") from exc
        ui.debug(f"GET {e(url)} -> HTTP {r.status_code}, rate limit remaining "
                 f"{r.headers.get('x-ratelimit-remaining', '?')}")
        if r.status_code == 404:
            raise StepError(f"Repo not found (or private): {repo}")
        if r.status_code in (403, 429) and r.headers.get("x-ratelimit-remaining") == "0":
            reset = r.headers.get("x-ratelimit-reset")
            when = dt.datetime.fromtimestamp(int(reset)).strftime("%H:%M") if reset and reset.isdigit() else "later"
            raise StepError(f"GitHub API rate limit reached (resets at {when}). Set GITHUB_TOKEN to raise the limit.")
        if not r.ok:
            raise StepError(f"GitHub API error HTTP {r.status_code}: {r.text[:300]}")
        try:
            releases = r.json()
        except ValueError as exc:
            raise StepError(f"GitHub returned something that isn't JSON: {exc}") from exc
        if not isinstance(releases, list):
            raise StepError(f"Unexpected GitHub API response: {str(releases)[:300]}")

        newest_tag = None
        for release in releases:
            if release.get("draft") or (release.get("prerelease") and not prerelease):
                continue
            newest_tag = newest_tag or release.get("tag_name")
            for asset in release.get("assets", []):
                if pattern.search(asset.get("name", "")):
                    return release, asset, newest_tag
        kind = "releases" if prerelease else "stable releases"
        raise StepError(f"No asset matching {pattern.pattern!r} in the {kind} of {repo}.")

    @staticmethod
    def expected_sha256(asset: Dict[str, Any]) -> Optional[str]:
        digest = (asset.get("digest") or "").lower()
        if digest.startswith("sha256:") and re.fullmatch(r"[0-9a-f]{64}", digest[7:]):
            return digest[7:]
        return None

    def existing_matches(self, path: Path, asset: Dict[str, Any]) -> Tuple[bool, bool]:
        """(matches, verified) for a file already on disk."""
        if not path.is_file():
            return False, False
        size, expected = asset.get("size"), self.expected_sha256(asset)
        if size is not None and path.stat().st_size != size:
            ui.info(f"Existing {e(path.name)} is {path.stat().st_size} bytes, release is {size}; re-downloading.")
            return False, False
        if expected:
            ui.info(f"Checking existing {e(path.name)} against the published SHA-256...")
            if sha256_file(path) == expected:
                return True, True
            ui.warn(f"Existing {e(path.name)} does not match the published checksum; re-downloading.")
            return False, False
        return size is not None, False

    def download(self, asset: Dict[str, Any], out_dir: Path, require_checksum: bool = False,
                 skip_existing: bool = True) -> Tuple[Path, bool]:
        """Stream to a .part file, verify size + SHA-256, then move into place. Returns (path, verified)."""
        name = Path(asset["name"]).name  # never let an asset name escape out_dir
        out_path, part_path = out_dir / name, out_dir / (name + ".part")
        expected = self.expected_sha256(asset)
        if require_checksum and not expected:
            raise StepError(f"{name} has no published SHA-256 digest, and a checksum is required.")

        if skip_existing:
            matches, verified = self.existing_matches(out_path, asset)
            if matches:
                how = "SHA-256 verified" if verified else "size matches, no checksum published"
                ui.ok(f"Already downloaded: {e(out_path)} ({how}); skipping download.")
                return out_path, verified

        out_dir.mkdir(parents=True, exist_ok=True)
        url = asset["browser_download_url"]
        ui.info(f"Downloading [bold]{e(name)}[/] ({fmt_size(asset.get('size') or 0)}) to {e(out_dir)}")
        ui.debug(f"URL: {e(url)}")
        sha = hashlib.sha256()
        done = 0
        try:
            with self.s.get(url, stream=True, timeout=(15, 60), headers={"Accept": "application/octet-stream"}) as dl:
                if not dl.ok:
                    raise StepError(f"Download failed: HTTP {dl.status_code}")
                total = int(dl.headers.get("content-length") or 0)
                encoded = bool(dl.headers.get("content-encoding"))
                with Progress(TextColumn("  {task.description}"), BarColumn(), DownloadColumn(),
                              TransferSpeedColumn(), TimeRemainingColumn(), console=console, transient=True) as prog:
                    task = prog.add_task(name, total=(total if total and not encoded else None))
                    with open(part_path, "wb") as f:
                        for chunk in dl.iter_content(65536):
                            f.write(chunk)
                            sha.update(chunk)
                            done += len(chunk)
                            prog.update(task, advance=len(chunk))
            if total and not encoded and done != total:
                raise StepError(f"Download incomplete: got {done} of {total} bytes.")
            if asset.get("size") and done != asset["size"]:
                raise StepError(f"Downloaded {done} bytes but the release lists {asset['size']}.")
            ui.ok(f"Downloaded {fmt_size(done)}")
            if expected:
                if sha.hexdigest() != expected:
                    raise StepError(f"SHA-256 mismatch for {name}; the file was discarded.\n"
                                    f"expected {expected}\n got      {sha.hexdigest()}")
                ui.ok(f"SHA-256 verified against GitHub's published digest ({expected[:16]}...)")
            else:
                ui.warn(f"No checksum is published for {e(name)}; it could not be verified. "
                        f"SHA-256 = {sha.hexdigest()}")
            os.replace(part_path, out_path)
        except requests.RequestException as exc:
            with contextlib.suppress(OSError):
                part_path.unlink()
            raise StepError(f"Network error while downloading {name}: {exc}") from exc
        except BaseException:
            with contextlib.suppress(OSError):
                part_path.unlink()
            raise
        return out_path, bool(expected)


def launch_file(path: Path) -> None:
    path = path.resolve()
    if path.name.lower().endswith(ARCHIVE_SUFFIXES):
        raise StepError(f"{path.name} looks like an archive or installer package, not something to run "
                        "directly. It has been downloaded; open it manually.")
    ui.info(f"Launching {e(path.name)}...")
    if WINDOWS:
        if path.suffix.lower() in (".exe", ".com", ".bat", ".cmd"):
            subprocess.Popen([str(path)], cwd=str(path.parent),
                             creationflags=subprocess.CREATE_NEW_CONSOLE)  # type: ignore[attr-defined]
        else:
            os.startfile(str(path))  # type: ignore[attr-defined]
    else:
        path.chmod(path.stat().st_mode | 0o111)
        subprocess.Popen([str(path)], cwd=str(path.parent))


# =========================================================================== #
# DrDonk Unlocker
# =========================================================================== #
UNLOCKER_REPO = "DrDonk/unlocker"
UNLOCKER_ASSET_RE = re.compile(r"^unlocker\d+\.zip$", re.I)
UNLOCKER_PLAT = "windows" if WINDOWS else "linux"
EXE = ".exe" if WINDOWS else ""
UNLOCKER_MARKER = ".vmware_setup.json"
UNLOCKER_ENV = {"UNLOCK_QUIET": "1"}  # the tools wait for Enter at the end unless this is set

# The unlocker tools always exit with code 0, even when they refuse to run,
# so their output has to be checked for these messages instead.
UNLOCKER_FAIL_MARKERS = {
    "Re-run with admin/root privileges": "the tool says it needs administrator/root rights",
    "VMware is not installed on this computer": "VMware Workstation is not installed",
    "Aborting patching!": "VMware or a VM is still running",
    "Aborting uninstall as backup folder does not exist!": "no backup of the original VMware files was found",
    "Error copying darwinPre15.iso": "could not copy darwinPre15.iso (macOS VMware Tools)",
    "Error copying darwin.iso": "could not copy darwin.iso (macOS VMware Tools)",
}


def unlocker_dir(work: Path) -> Path:
    return work / "unlocker"


def unlocker_tool(udir: Path, name: str) -> Path:
    return udir / UNLOCKER_PLAT / f"{name}{EXE}"


def read_marker(udir: Path) -> Dict[str, Any]:
    with contextlib.suppress(OSError, ValueError):
        data = json.loads((udir / UNLOCKER_MARKER).read_text(encoding="utf-8"))
        if isinstance(data, dict):
            return data
    return {}


def safe_extract_zip(zip_path: Path, dest: Path) -> List[zipfile.ZipInfo]:
    """Extract with path-traversal protection; zipfile checks every member's CRC as it reads."""
    dest = dest.resolve()
    with zipfile.ZipFile(zip_path) as zf:
        bad = zf.testzip()
        if bad:
            raise StepError(f"{zip_path.name} is corrupt (bad CRC in {bad}).")
        members = zf.infolist()
        for m in members:
            target = (dest / m.filename).resolve()
            if dest != target and dest not in target.parents:
                raise StepError(f"Refusing to extract {m.filename!r}: it would land outside {dest}")
        zf.extractall(dest)
    return members


def find_payload_root(extracted: Path) -> Path:
    """The release zip has windows/, linux/, iso/ at its root; tolerate one extra wrapping folder."""
    if (extracted / UNLOCKER_PLAT).is_dir():
        return extracted
    subdirs = [p for p in extracted.iterdir() if p.is_dir()]
    if len(subdirs) == 1 and (subdirs[0] / UNLOCKER_PLAT).is_dir():
        return subdirs[0]
    raise StepError(f"The Unlocker zip does not contain a {UNLOCKER_PLAT}/ folder; the layout may have changed.")


def verify_unlocker_files(udir: Path, members_sizes: Optional[Dict[str, int]] = None) -> List[str]:
    """Return a list of problems (empty = OK)."""
    problems = []
    for tool in ("check", "unlock", "relock"):
        p = unlocker_tool(udir, tool)
        if not p.is_file():
            problems.append(f"{UNLOCKER_PLAT}/{p.name} is missing")
    for iso in ("darwin.iso", "darwinPre15.iso"):
        if not (udir / "iso" / iso).is_file():
            problems.append(f"iso/{iso} is missing")
    if members_sizes:
        for rel, size in members_sizes.items():
            p = udir / rel
            if p.is_file() and p.stat().st_size != size:
                problems.append(f"{rel} is {p.stat().st_size} bytes, expected {size}")
    return problems


def ensure_unlocker(work: Path, summary: Summary) -> Path:
    """Make sure the latest Unlocker is downloaded, verified and extracted to work/unlocker. Returns that folder."""
    ui.section("Unlocker: download and verify")
    udir = unlocker_dir(work)
    marker = read_marker(udir)
    gh = GitHub()
    try:
        release, asset, newest = gh.find_asset(UNLOCKER_REPO, UNLOCKER_ASSET_RE)
    except StepError as exc:
        if marker and not verify_unlocker_files(udir):
            ui.warn(f"{e(exc)}")
            ui.warn(f"Using the Unlocker already extracted in {e(udir)} ({e(marker.get('tag', '?'))}) instead.")
            summary.add("Unlocker package", "warn", f"GitHub unreachable; used existing {marker.get('tag', '?')}")
            return udir
        raise
    tag = release.get("tag_name", "?")
    note = f"  [dim](newest release {e(newest)} has no matching asset)[/]" if newest and newest != tag else ""
    ui.ok(f"Latest release: [bold]{e(asset['name'])}[/] ({e(tag)}, published {e(str(release.get('published_at', '?'))[:10])}){note}")

    expected_sha = gh.expected_sha256(asset)
    if marker:
        if marker.get("tag") != tag:
            ui.info(f"Local Unlocker is {e(marker.get('tag', '?'))}; updating to {e(tag)}.")
        elif verify_unlocker_files(udir, marker.get("sizes")):
            ui.warn("Local Unlocker files are missing or changed: "
                    f"{e('; '.join(verify_unlocker_files(udir, marker.get('sizes'))))}. Re-extracting.")
    if (marker.get("tag") == tag and marker.get("asset") == asset["name"]
            and (not expected_sha or marker.get("sha256") == expected_sha)
            and not verify_unlocker_files(udir, marker.get("sizes"))):
        ui.ok(f"{e(tag)} is already extracted in {e(udir)} and all files check out; nothing to download.")
        summary.add("Unlocker package", "ok", f"{asset['name']} ({tag}) already in place, verified")
        return udir

    if not expected_sha:
        ui.warn("GitHub publishes no SHA-256 for this asset, so the download can't be verified.")
        if not confirm("Use the unverified Unlocker download anyway?", default=False):
            raise Aborted("Unverified Unlocker download declined.")
    zip_path, verified = gh.download(asset, work / "downloads")
    summary.add("Unlocker package", "ok" if verified else "warn",
                f"{asset['name']} ({tag}), " + ("SHA-256 verified" if verified else "NOT verified"))

    ui.section("Unlocker: extract")
    staging = Path(tempfile.mkdtemp(prefix=".unlocker-extract-", dir=str(work)))
    try:
        ui.info(f"Extracting {e(zip_path.name)} (CRC-checked)...")
        try:
            members = safe_extract_zip(zip_path, staging)
        except (OSError, zipfile.BadZipFile) as exc:
            hint = (" Microsoft Defender often flags the Unlocker as a 'hack tool' and blocks extraction; "
                    "check Windows Security > Protection history.") if WINDOWS else ""
            with contextlib.suppress(OSError):
                if isinstance(exc, zipfile.BadZipFile):
                    zip_path.unlink()  # corrupt download; fetch it again next run
            raise StepError(f"Could not extract {zip_path.name}: {exc}.{hint}") from exc
        root = find_payload_root(staging)
        prefix = root.relative_to(staging).as_posix()
        sizes = {}
        for m in members:
            if m.is_dir():
                continue
            rel = m.filename[len(prefix) + 1:] if prefix not in ("", ".") and m.filename.startswith(prefix + "/") else m.filename
            sizes[rel] = m.file_size
        problems = verify_unlocker_files(root, sizes)
        if problems:
            raise StepError("Extracted Unlocker is incomplete: " + "; ".join(problems))
        ui.ok(f"{len(sizes)} files extracted, sizes and CRCs match the zip")

        # Install into the stable folder, keeping backup/ (the original VMware files relock needs)
        udir.mkdir(parents=True, exist_ok=True)
        for item in udir.iterdir():
            if item.name in ("backup",):
                continue
            if item.is_dir():
                rmtree(item)
            else:
                item.unlink()
        for item in root.iterdir():
            shutil.move(str(item), str(udir / item.name))
        if not WINDOWS:
            for tool in (udir / UNLOCKER_PLAT).iterdir():
                with contextlib.suppress(OSError):
                    tool.chmod(tool.stat().st_mode | 0o755)
    finally:
        rmtree(staging)

    problems = verify_unlocker_files(udir, sizes)
    if problems:
        hint = " Antivirus (e.g. Microsoft Defender) may have quarantined it - check Protection history." if WINDOWS else ""
        raise StepError("Files are missing or changed after extraction: " + "; ".join(problems) + hint)
    marker_data = {"tag": tag, "asset": asset["name"], "sha256": expected_sha or sha256_file(zip_path),
                   "verified": verified, "extracted": dt.datetime.now().isoformat(timespec="seconds"), "sizes": sizes}
    (udir / UNLOCKER_MARKER).write_text(json.dumps(marker_data, indent=2), encoding="utf-8")
    ui.ok(f"Unlocker {e(tag)} ready in [bold]{e(udir)}[/]")
    migrate_legacy_backups(work, udir)
    if (udir / "backup").is_dir():
        ui.info("Kept the existing backup/ folder (original VMware files needed by relock).")
    summary.add("Unlocker extract", "ok", f"{tag} in {udir}")
    return udir


@dataclass
class PatchStatus:
    state: str  # patched | unpatched | partial | notinstalled | noadmin | unknown
    patched: int = 0
    unpatched: int = 0
    unknown: int = 0
    vmware_version: str = ""
    output: str = ""

    @property
    def text(self) -> str:
        return {
            "patched": f"VMware IS PATCHED - all {self.patched} files",
            "unpatched": f"VMware is NOT PATCHED ({self.unpatched} files unpatched)",
            "partial": f"VMware is PARTIALLY PATCHED - {self.patched} patched, {self.unpatched} unpatched, "
                       f"{self.unknown} unknown",
            "notinstalled": "VMware Workstation is NOT INSTALLED",
            "noadmin": "Patch status needs administrator rights",
            "unknown": "Patch status COULD NOT BE DETERMINED - see the check output",
        }[self.state]

    @property
    def style(self) -> str:
        return {"patched": "green", "unpatched": "red"}.get(self.state, "yellow")


def parse_check_output(text: str) -> PatchStatus:
    m = re.search(r"VMware version:\s*(\S+)", text)
    st = PatchStatus("unknown", output=text, vmware_version=m.group(1) if m else "")
    st.patched = len(re.findall(r"Patch Status:\s*Patched\b", text))
    st.unpatched = len(re.findall(r"Patch Status:\s*Unpatched\b", text))
    st.unknown = len(re.findall(r"Patch Status:\s*Unknown\b", text))
    if "Re-run with admin/root privileges" in text:
        st.state = "noadmin"
    elif "VMware is not installed" in text:
        st.state = "notinstalled"
    elif st.patched + st.unpatched + st.unknown == 0:
        st.state = "unknown"
    elif st.unpatched == 0 and st.unknown == 0:
        st.state = "patched"
    elif st.patched == 0 and st.unknown == 0:
        st.state = "unpatched"
    else:
        st.state = "partial"
    return st


def run_patch_check(udir: Path, label: str = "current status") -> PatchStatus:
    ui.section(f"Unlocker: check ({label})")
    tool = unlocker_tool(udir, "check")
    if not tool.is_file():
        raise StepError(f"{tool} is missing.")
    res = run_cmd([str(tool)], cwd=tool.parent, env=UNLOCKER_ENV, timeout=180, stream=True)
    st = parse_check_output(res.output)
    console.print()
    console.print(Panel(Text(st.text, style=f"bold {st.style}"), border_style=st.style, expand=False))
    log.info("PATCH STATUS: %s", st.text)
    return st


def run_unlocker_tool(udir: Path, tool_name: str, title: str) -> List[str]:
    """Run unlock/relock with live output. Returns the list of problems found in its output."""
    tool = unlocker_tool(udir, tool_name)
    if not tool.is_file():
        raise StepError(f"{tool} is missing.")
    console.print(Rule(f"[dim]{tool.name} output[/]", style="dim"))
    res = run_cmd([str(tool)], cwd=tool.parent, env=UNLOCKER_ENV, timeout=1200, stream=True)
    console.print(Rule(f"[dim]{tool.name} exit code {res.rc} ({res.seconds:.0f}s)[/]", style="dim"))
    problems = [why for marker, why in UNLOCKER_FAIL_MARKERS.items() if marker in res.output]
    if res.rc != 0:
        problems.append(f"{tool.name} exited with code {res.rc}")
    if tool_name == "unlock" and not problems and "Patching Complete!" not in res.output:
        problems.append("unlock did not report 'Patching Complete!'")
    if "already exists, skipping backup" in res.output:
        ui.info("The Unlocker kept an existing backup of the original files (that's expected on a re-run).")
    return problems


def do_unlock(udir: Path, summary: Summary, before: PatchStatus) -> bool:
    ui.section("Unlocker: patch VMware")
    if before.state == "patched":
        ui.ok("VMware is already patched - nothing to do.")
        summary.add("Unlock", "skip", "already patched")
        return True
    if before.state == "notinstalled":
        ui.warn("VMware Workstation is not installed - skipping unlock.")
        summary.add("Unlock", "skip", "VMware not installed")
        return True
    if before.state == "noadmin":
        summary.add("Unlock", "fail", "needs administrator rights")
        raise StepError("The Unlocker needs administrator rights. Re-run this script elevated.")
    ui.info("unlock patches VMware's vmware-vmx and vmwarebase files so macOS guests can be created, "
            f"and backs up the originals to {e(udir / 'backup')} (relock restores them).")
    if not wait_for_vmware_closed("patching"):
        summary.add("Unlock", "skip", "VMware still running")
        return True
    if not confirm("Run unlock now?", default=False):
        summary.add("Unlock", "skip", "skipped by you")
        return True
    problems = run_unlocker_tool(udir, "unlock", "unlock")
    after = run_patch_check(udir, "after unlock")
    if problems:
        for p in problems:
            ui.err(f"unlock: {e(p)}")
        summary.add("Unlock", "fail", "; ".join(problems))
        return False
    if after.state == "patched":
        ui.ok("Patch confirmed by check.")
        summary.add("Unlock", "ok", f"patched and confirmed ({after.patched} files)")
        return True
    ui.warn(f"unlock finished, but check says: {e(after.text)}")
    summary.add("Unlock", "warn", f"ran, but check says: {after.text}")
    return False


def migrate_legacy_backups(work: Path, udir: Path) -> None:
    """
    The old batch file extracted each release to its own folder (unlocker428/ etc.), and the Unlocker keeps the
    original VMware files in <that folder>/backup/<version>. Copy any of those into the stable folder so relock works.
    """
    for d in sorted(work.glob("unlocker*")):
        src_root = d / "backup"
        if d == udir or not src_root.is_dir():
            continue
        for ver_dir in src_root.iterdir():
            dst = udir / "backup" / ver_dir.name
            if ver_dir.is_dir() and not dst.exists():
                shutil.copytree(ver_dir, dst)
                ui.ok(f"Copied the original-file backup for VMware {e(ver_dir.name)} from {e(ver_dir)} into {e(dst)}")


def find_legacy_backup(work: Path, version: str) -> Optional[Path]:
    """Older runs extracted to versioned folders like unlocker428/; their backup/ holds the original files."""
    for d in sorted(work.glob("unlocker*"), reverse=True):
        if d.is_dir() and d.name != "unlocker" and (d / "backup" / version).is_dir():
            return d / "backup" / version
    return None


def do_relock(work: Path, udir: Path, summary: Summary) -> bool:
    ui.section("Unlocker: remove patches (relock)")
    before = run_patch_check(udir, "before relock")
    if before.state in ("unpatched", "notinstalled", "noadmin"):
        msg = {"unpatched": "VMware is not patched - nothing to undo.",
               "notinstalled": "VMware Workstation is not installed.",
               "noadmin": "Needs administrator rights."}[before.state]
        (ui.ok if before.state == "unpatched" else ui.warn)(msg)
        summary.add("Relock", "skip" if before.state != "noadmin" else "fail", msg)
        return before.state != "noadmin"
    ver = before.vmware_version
    backup = udir / "backup" / ver if ver else None
    if backup is None or not backup.is_dir():
        legacy = find_legacy_backup(work, ver) if ver else None
        if legacy:
            ui.warn(f"No backup for VMware {e(ver)} in {e(udir / 'backup')}, but found one at {e(legacy)}.")
            if confirm("Copy that backup into place so relock can use it?", default=True):
                shutil.copytree(legacy, udir / "backup" / ver, dirs_exist_ok=True)
                ui.ok("Backup copied.")
        else:
            ui.warn(f"No backup of the original VMware {e(ver or '?')} files found under {e(udir / 'backup')}. "
                    "relock will refuse to run; reinstalling (repairing) VMware also removes the patches.")
    if not wait_for_vmware_closed("relocking"):
        summary.add("Relock", "skip", "VMware still running")
        return True
    if not confirm("Run relock now (restore the original VMware files)?", default=False):
        summary.add("Relock", "skip", "skipped by you")
        return True
    problems = run_unlocker_tool(udir, "relock", "relock")
    after = run_patch_check(udir, "after relock")
    if problems:
        for p in problems:
            ui.err(f"relock: {e(p)}")
        summary.add("Relock", "fail", "; ".join(problems))
        return False
    if after.state == "unpatched":
        summary.add("Relock", "ok", "original files restored, confirmed by check")
        return True
    summary.add("Relock", "warn", f"ran, but check says: {after.text}")
    return False


# =========================================================================== #
# Host-wide VMware defaults (config.ini / /etc/vmware/config)
# =========================================================================== #
# key -> (desired value, description)
SETTINGS: Dict[str, Tuple[str, str]] = {
    "ulm.disableMitigations": ("TRUE", "Disable side-channel mitigations (only matters on Hyper-V/WHP hosts)"),
    "tools.remindInstall": ("FALSE", "Don't nag to install VMware Tools"),
    "tools.upgrade.policy": ("manual", "Never auto-upgrade VMware Tools"),
    "isolation.tools.autoInstall.disable": ("TRUE", "Block automatic Tools install/upgrade"),
}

# VMware writes key = "value"; also accept unquoted values so they're found (and fixed) rather than duplicated.
LINE_RE = re.compile(r'^\s*(?P<key>[A-Za-z0-9_.:\-]+)\s*=\s*(?:"(?P<qval>[^"]*)"|(?P<val>[^"#;]*?))\s*$')


def _line_value(m: "re.Match[str]") -> str:
    return m.group("qval") if m.group("qval") is not None else (m.group("val") or "")


@dataclass
class VmConfigFile:
    path: Path
    lines: List[str] = field(default_factory=list)
    newline: str = "\r\n" if WINDOWS else "\n"
    encoding: str = "utf-8"
    bom: bool = False
    existed: bool = False
    trailing_newline: bool = True

    @classmethod
    def load(cls, path: Path) -> "VmConfigFile":
        if not path.exists():
            return cls(path=path, existed=False)
        if not path.is_file():
            raise IsADirectoryError(f"{path} exists but is not a regular file")
        raw = path.read_bytes()
        bom = raw.startswith(b"\xef\xbb\xbf")
        text, encoding = raw.decode("latin-1"), "latin-1"
        for enc in ("utf-8-sig", "cp1252"):
            try:
                text = raw.decode(enc)
                encoding = "utf-8" if enc == "utf-8-sig" else enc
                break
            except UnicodeDecodeError:
                continue
        newline = "\r\n" if "\r\n" in text else ("\n" if "\n" in text else ("\r\n" if WINDOWS else "\n"))
        return cls(path=path, lines=text.splitlines(), newline=newline, encoding=encoding, bom=bom,
                   existed=True, trailing_newline=text.endswith(("\n", "\r")) or not text)

    def items(self) -> Iterable[Tuple[str, str]]:
        for line in self.lines:
            m = LINE_RE.match(line)
            if m:
                yield m.group("key"), _line_value(m)

    def _indexes(self, key: str) -> List[int]:
        k = key.lower()
        return [i for i, line in enumerate(self.lines)
                if (m := LINE_RE.match(line)) and m.group("key").lower() == k]

    def count(self, key: str) -> int:
        return len(self._indexes(key))

    def get(self, key: str) -> Optional[str]:
        idx = self._indexes(key)
        if not idx:
            return None
        m = LINE_RE.match(self.lines[idx[-1]])
        return _line_value(m) if m else None  # last one wins

    def is_canonical(self, key: str) -> bool:
        """Quoted and spelled exactly like the managed key."""
        idx = self._indexes(key)
        if len(idx) != 1:
            return False
        m = LINE_RE.match(self.lines[idx[0]])
        return bool(m and m.group("qval") is not None and m.group("key") == key)

    def set(self, key: str, value: str) -> None:
        idx = self._indexes(key)
        new_line = f'{key} = "{value}"'
        if idx:
            self.lines[idx[0]] = new_line
            for i in reversed(idx[1:]):
                del self.lines[i]
        else:
            self.lines.append(new_line)

    def remove(self, key: str) -> int:
        idx = self._indexes(key)
        for i in reversed(idx):
            del self.lines[i]
        return len(idx)

    def render(self) -> str:
        text = self.newline.join(self.lines)
        if self.lines and self.trailing_newline:
            text += self.newline
        return text

    def to_bytes(self) -> bytes:
        data = self.render().encode(self.encoding, errors="strict")
        return (b"\xef\xbb\xbf" + data) if self.bom else data

    def unmanaged_lines(self, managed: Iterable[str]) -> List[str]:
        managed_l = {k.lower() for k in managed}
        return [line for line in self.lines
                if not ((m := LINE_RE.match(line)) and m.group("key").lower() in managed_l)]


def default_config_path() -> Path:
    if WINDOWS:
        return Path(os.environ.get("ProgramData") or r"C:\ProgramData") / "VMware" / "VMware Workstation" / "config.ini"
    return Path("/etc/vmware/config")


def user_home() -> Path:
    """The real user's home, even under sudo on Linux."""
    if not WINDOWS and os.environ.get("SUDO_USER"):
        try:
            import pwd
            return Path(pwd.getpwnam(os.environ["SUDO_USER"]).pw_dir)
        except (KeyError, ImportError):
            pass
    return Path.home()


def inventory_path() -> Path:
    if WINDOWS:
        appdata = os.environ.get("APPDATA") or str(Path.home() / "AppData" / "Roaming")
        return Path(appdata) / "VMware" / "inventory.vmls"
    return user_home() / ".vmware" / "inventory.vmls"


def default_vm_dirs() -> List[Path]:
    if WINDOWS:
        cands = [Path.home() / "Documents" / "Virtual Machines"]
        if os.environ.get("OneDrive"):
            cands.append(Path(os.environ["OneDrive"]) / "Documents" / "Virtual Machines")
    else:
        cands = [user_home() / "vmware"]
    return [p for p in cands if p.is_dir()]


def can_write(path: Path) -> bool:
    """
    Real write-permission check that never modifies anything.
    os.access() ignores Windows ACLs, so an existing file is opened for append (writing nothing).
    """
    if path.exists():
        try:
            with open(path, "ab"):
                pass
            return True
        except OSError as exc:
            ui.debug(f"Write probe failed for {e(path)}: {e(exc)}")
            return False
    if WINDOWS:
        return is_admin()
    d = path.parent
    while not d.exists() and d != d.parent:
        d = d.parent
    return os.access(d, os.W_OK)


@dataclass
class Change:
    key: str
    current: Optional[str]
    desired: Optional[str]
    action: str  # ok | add | update | normalize | remove


ACTION_STYLE = {"ok": "[green]no change[/]", "add": "[bold cyan]add[/]", "update": "[bold yellow]update[/]",
                "normalize": "[yellow]tidy (dedupe/quote)[/]", "remove": "[bold magenta]remove[/]"}


def plan_changes(cfg: VmConfigFile, settings: Dict[str, Tuple[str, str]], revert: bool) -> List[Change]:
    plan = []
    for key, (desired, _) in settings.items():
        cur, n = cfg.get(key), cfg.count(key)
        if revert:
            plan.append(Change(key, cur, None, "remove" if n else "ok"))
        elif cur is None:
            plan.append(Change(key, None, desired, "add"))
        elif cur.strip().lower() != desired.lower():
            plan.append(Change(key, cur, desired, "update"))
        elif not cfg.is_canonical(key):
            plan.append(Change(key, cur, desired, "normalize"))
        else:
            plan.append(Change(key, cur, desired, "ok"))
    return plan


def render_plan(plan: List[Change], settings: Dict[str, Tuple[str, str]], title: str) -> Table:
    t = Table(title=title, box=box.ROUNDED, header_style="bold", expand=True)
    t.add_column("Key", style="bold")
    t.add_column("Purpose", style="dim")
    t.add_column("Current")
    t.add_column("Target")
    t.add_column("Action")
    for c in plan:
        t.add_row(c.key, settings[c.key][1],
                  e(c.current) if c.current is not None else "[dim]<not set>[/]",
                  e(c.desired) if c.desired is not None else "[dim]<removed>[/]",
                  ACTION_STYLE[c.action])
    return t


def show_diff(before: str, after: str, label: str) -> None:
    diff = "\n".join(difflib.unified_diff(before.splitlines(), after.splitlines(),
                                          fromfile=f"{label} (before)", tofile=f"{label} (after)", lineterm=""))
    if diff:
        console.print(Panel(Syntax(diff, "diff", theme="ansi_dark", word_wrap=True),
                            title="Planned diff", border_style="blue"))
        log.info("Planned diff:\n%s", diff)


def verify_config(path: Path, settings: Dict[str, Tuple[str, str]], revert: bool,
                  unmanaged_before: List[str]) -> bool:
    ui.info(f"Verifying by re-reading [bold]{e(path)}[/] from disk...")
    try:
        cfg = VmConfigFile.load(path)
    except OSError as exc:
        ui.err(f"Could not re-read the file for verification: {e(exc)}")
        return False
    good = True
    for key, (desired, _) in settings.items():
        cur, n = cfg.get(key), cfg.count(key)
        if revert:
            if n:
                ui.err(f"{key}: still present ({n}x) after revert")
                good = False
            else:
                ui.ok(f"{key}: removed")
        elif cur is None or cur.lower() != desired.lower():
            ui.err(f'{key}: expected "{desired}", found {e(cur)!r}')
            good = False
        elif n != 1:
            ui.err(f"{key}: present {n} times (expected exactly once)")
            good = False
        else:
            ui.ok(f'{key} = "{e(cur)}"')
    if cfg.unmanaged_lines(settings) != unmanaged_before:
        ui.err("Unrelated lines in the file changed unexpectedly")
        good = False
    else:
        ui.ok("All unrelated lines preserved exactly")
    return good


# ---- per-VM .vmx scan ------------------------------------------------------ #
def find_vmx_files(inv: Path, extra_dirs: List[Path]) -> List[Path]:
    found: Dict[str, Path] = {}

    def add(p: Path) -> None:
        found[str(p).lower() if WINDOWS else str(p)] = p

    if inv.is_file():
        try:
            icfg = VmConfigFile.load(inv)
            n = 0
            for key, val in icfg.items():
                if re.fullmatch(r"vmlist\d+\.config", key, re.I) and val.lower().endswith(".vmx"):
                    add(Path(val))
                    n += 1
            ui.ok(f"VM inventory {e(inv)}: {n} VM(s) listed")
        except OSError as exc:
            ui.warn(f"Could not read VM inventory {e(inv)}: {e(exc)}")
    else:
        ui.info(f"No VM inventory yet at {e(inv)} (normal on a fresh install)")

    for d in extra_dirs:
        if not d.is_dir():
            ui.warn(f"VM folder {e(d)} is not a directory; skipped")
            continue
        before = len(found)
        for root, _dirs, files in os.walk(d, onerror=lambda exc: ui.debug(f"walk error: {e(exc)}")):
            for f in files:
                if f.lower().endswith(".vmx"):
                    add(Path(root) / f)
        ui.ok(f"Scanned {e(d)}: {len(found) - before} more .vmx file(s)")
    return sorted(found.values(), key=lambda p: str(p).lower())


@dataclass
class VmFinding:
    path: Path
    status: str  # ok | override | missing | error | locked
    issues: List[Tuple[str, str, str]] = field(default_factory=list)  # key, value, severity
    note: str = ""


def scan_vm(vmx: Path, settings: Dict[str, Tuple[str, str]]) -> VmFinding:
    if not vmx.exists():
        return VmFinding(vmx, "missing", note="file not found (stale inventory entry?)")
    try:
        cfg = VmConfigFile.load(vmx)
    except OSError as exc:
        return VmFinding(vmx, "error", note=str(exc))
    f = VmFinding(vmx, "ok")
    for key, (desired, _) in settings.items():
        cur = cfg.get(key)
        if cur is None or cur.lower() == desired.lower():
            continue
        sev = "warn" if (key == "tools.upgrade.policy" and cur.lower() == "useglobal") else "conflict"
        f.issues.append((key, cur, sev))
    if f.issues:
        f.status = "override"
    if Path(str(vmx) + ".lck").exists():
        f.note = "VM appears to be running (lock present)"
        if f.issues:
            f.status = "locked"
    return f


def scan_and_fix_vms(settings: Dict[str, Tuple[str, str]], fix: bool, dry_run: bool, vm_dirs: List[Path]) -> bool:
    ui.section("Per-VM override scan")
    dirs = list(dict.fromkeys(default_vm_dirs() + vm_dirs))
    vmxs = find_vmx_files(inventory_path(), dirs)
    if not vmxs:
        ui.info("No VMs found to scan.")
        return True
    findings = [scan_vm(v, settings) for v in vmxs]

    t = Table(box=box.ROUNDED, expand=True, header_style="bold", title=f"{len(findings)} VM(s) scanned")
    t.add_column("VM (.vmx)", overflow="fold")
    t.add_column("Status")
    t.add_column("Details", overflow="fold")
    for f in findings:
        details = []
        for key, val, sev in f.issues:
            if sev == "warn":
                details.append(f'[yellow]{key} = "{e(val)}"[/] (follows the Preferences > Updates checkbox)')
            else:
                details.append(f'[red]{key} = "{e(val)}"[/] overrides global "{settings[key][0]}"')
        if f.note:
            details.append(f"[dim]{e(f.note)}[/]")
        status = {"ok": "[green]inherits global[/]", "override": "[yellow]overrides[/]",
                  "locked": "[red]overrides, running[/]", "missing": "[dim]missing[/]",
                  "error": "[red]read error[/]"}[f.status]
        t.add_row(e(f.path), status, "\n".join(details) or "[dim]-[/]")
    ui.show(t)

    to_fix = [f for f in findings if f.status == "override"]
    for f in findings:
        if f.status == "locked":
            ui.warn(f"Skipping running VM: {e(f.path)} (power it off and re-run)")
    if not fix:
        if to_fix:
            ui.info("Re-run with [bold]--fix-vms[/] to correct these VMs (each .vmx is backed up first).")
        return True
    if not to_fix:
        ui.ok("No VM files need fixing.")
        return True
    if dry_run:
        ui.info(f"\\[dry-run] would fix {len(to_fix)} VM file(s)")
        return True
    console.print("[bold]These files will be modified (each backed up first):[/]")
    for f in to_fix:
        console.print(f"   • {e(f.path)}")
    if not confirm(f"Fix {len(to_fix)} VM file(s) now?", default=False):
        ui.warn("VM fixes skipped by you")
        return True

    all_ok = True
    for f in to_fix:
        ui.info(f"Fixing [bold]{e(f.path)}[/]")
        bak = None
        try:
            cfg = VmConfigFile.load(f.path)
            unmanaged = cfg.unmanaged_lines(settings)
            for key, _val, _sev in f.issues:
                cfg.set(key, settings[key][0])
            bak = backup_file(f.path)
            atomic_write_bytes(f.path, cfg.to_bytes())
            check = VmConfigFile.load(f.path)
            bad = [k for k, _, _ in f.issues if (check.get(k) or "").lower() != settings[k][0].lower()]
            if bad or check.unmanaged_lines(settings) != unmanaged:
                ui.err(f"Verification failed for {e(f.path)} ({', '.join(bad) or 'unrelated lines changed'})")
                restore_backup(f.path, bak, True)
                all_ok = False
            else:
                ui.ok(f"Fixed and verified {e(f.path)}")
        except (OSError, UnicodeError) as exc:
            ui.err(f"Failed to fix {e(f.path)}: {e(exc)} (original file left unchanged)")
            all_ok = False
    return all_ok


def run_defaults(mode: str, summary: Summary, *, dry_run: bool = False, skip: Sequence[str] = (),
                 config_path: Optional[Path] = None, scan_vms: bool = False, fix_vms: bool = False,
                 vm_dirs: Sequence[Path] = (), force: bool = False) -> int:
    """mode: apply | check | revert. Returns an exit code."""
    title = {"apply": "APPLY", "check": "CHECK (read-only)", "revert": "REVERT"}[mode] + (" · DRY-RUN" if dry_run else "")
    ui.section(f"VMware host defaults - {title}")
    if not (WINDOWS or LINUX):
        ui.err("Unsupported OS. This targets VMware Workstation on Windows or Linux.")
        summary.add("VMware defaults", "fail", "unsupported OS")
        return EXIT_ERROR
    cfg_path = config_path or default_config_path()
    settings = {k: v for k, v in SETTINGS.items() if k not in skip}
    for k in skip:
        ui.info(f"Leaving [bold]{e(k)}[/] alone (--skip)")
    if not settings:
        ui.err("Every key was skipped; nothing to do.")
        return EXIT_ERROR

    writes = mode in ("apply", "revert") and not dry_run
    ws = detect_workstation()
    procs = running_vmware()
    env = Table(box=box.SIMPLE_HEAVY, show_header=False, expand=True)
    env.add_column(style="bold", width=24)
    env.add_column(overflow="fold")
    env.add_row("Workstation install", e(ws.get("InstallPath", "")) or "[yellow]not detected[/]")
    env.add_row("Workstation version", e(ws.get("ProductVersion", "")) or "[dim]unknown[/]")
    env.add_row("Global config file", e(cfg_path))
    env.add_row("Config file exists", "[green]yes[/]" if cfg_path.exists() else "[yellow]no (will be created)[/]")
    env.add_row("Write access", ("[green]yes[/]" if can_write(cfg_path) else "[red]no[/]") if writes else "[dim]not needed[/]")
    env.add_row("VMware processes", "[yellow]could not check[/]" if procs is None
                else (e(", ".join(procs)) if procs else "[green]none running[/]"))
    ui.show(env)

    if writes and not can_write(cfg_path):
        ui.err(f"No write access to {e(cfg_path)}. Run this script as administrator (Windows) or with sudo (Linux).")
        summary.add("VMware defaults", "fail", "no write access to the config file")
        return EXIT_ERROR
    if writes and not ws.get("InstallPath"):
        ui.warn("VMware Workstation was not detected. The config can still be written and applies once it's installed.")
        if not (force or confirm("Continue anyway?", default=False)):
            summary.add("VMware defaults", "skip", "VMware not detected")
            return EXIT_ABORTED
    if writes and procs:
        ui.warn("VMware is running. Running VMs only read these defaults at their next power-on.")

    try:
        cfg = VmConfigFile.load(cfg_path)
    except PermissionError:
        ui.err(f"Permission denied reading {e(cfg_path)}. Run as administrator / with sudo.")
        summary.add("VMware defaults", "fail", "permission denied reading the config")
        return EXIT_ERROR
    except (OSError, UnicodeError) as exc:
        ui.err(f"Could not read {e(cfg_path)}: {e(exc)}")
        summary.add("VMware defaults", "fail", str(exc))
        return EXIT_ERROR
    if cfg.existed:
        ui.ok(f"Loaded {len(cfg.lines)} line(s); encoding={cfg.encoding}{' +BOM' if cfg.bom else ''}; "
              f"line endings={'CRLF' if cfg.newline == chr(13) + chr(10) else 'LF'}")
    else:
        ui.info("Config file does not exist yet; it will be created.")

    plan = plan_changes(cfg, settings, mode == "revert")
    ui.show(render_plan(plan, settings, "Revert plan" if mode == "revert" else "Settings plan"))
    pending = [c for c in plan if c.action != "ok"]

    code = EXIT_OK
    if mode == "check":
        if pending:
            ui.warn(f"{len(pending)} setting(s) not in place in the global config")
            summary.add("VMware defaults", "warn", f"{len(pending)} of {len(plan)} settings not in place")
            code = EXIT_NOT_COMPLIANT
        else:
            ui.ok("Global config has all the settings")
            summary.add("VMware defaults", "ok", "all settings in place")
    elif not pending:
        ui.ok("Nothing to change in the global config.")
        summary.add("VMware defaults", "ok", "already in place" if mode == "apply" else "nothing to remove")
    else:
        before_text = cfg.render() if cfg.existed else ""
        unmanaged_before = cfg.unmanaged_lines(settings)
        for c in pending:
            if c.action == "remove":
                cfg.remove(c.key)
            else:
                cfg.set(c.key, c.desired or "")
            ui.debug(f"{c.action} {c.key} -> {c.desired}")
        show_diff(before_text, cfg.render(), cfg_path.name)
        if dry_run:
            ui.info("\\[dry-run] nothing written to the global config.")
            summary.add("VMware defaults", "info", f"dry run: {len(pending)} change(s) planned")
        else:
            if not confirm(f"Write {len(pending)} change(s) to {e(cfg_path)}?", default=False):
                ui.warn("Declined; nothing written.")
                summary.add("VMware defaults", "skip", "declined at the prompt")
                return EXIT_ABORTED
            bak = None
            try:
                bak = backup_file(cfg_path)
                atomic_write_bytes(cfg_path, cfg.to_bytes())
                ui.ok(f"Wrote {e(cfg_path)}")
            except (OSError, UnicodeError) as exc:
                ui.err(f"Write failed for {e(cfg_path)}: {e(exc)}")
                ui.info("The write is atomic, so the original file was left unchanged.")
                if bak:
                    with contextlib.suppress(OSError):
                        bak.unlink()
                summary.add("VMware defaults", "fail", f"write failed: {exc}")
                return EXIT_ERROR
            if not verify_config(cfg_path, settings, mode == "revert", unmanaged_before):
                ui.err("Verification FAILED - rolling back.")
                restore_backup(cfg_path, bak, cfg.existed)
                summary.add("VMware defaults", "fail", "verification failed; rolled back")
                return EXIT_NOT_COMPLIANT
            ui.ok("Global config verified.")
            summary.add("VMware defaults", "ok", ("applied" if mode == "apply" else "reverted") +
                        f" and verified ({len(pending)} change(s)); backup {bak.name if bak else 'n/a (new file)'}")

    if scan_vms or fix_vms:
        if not scan_and_fix_vms(settings, fix_vms and mode == "apply", dry_run, list(vm_dirs)):
            summary.add("Per-VM fixes", "fail", "see errors above")
            code = EXIT_ERROR

    if mode != "revert":
        notes = []
        if "tools.upgrade.policy" in settings:
            notes.append("New VMs made by the wizard often get [bold]tools.upgrade.policy = \"useGlobal\"[/], which "
                         "follows the GUI checkbox rather than this file. Also uncheck [bold]Edit > Preferences > "
                         "Updates > \"Automatically update VMware Tools on a virtual machine\"[/].")
        notes.append("Easy Install still pushes VMware Tools into a new guest. In the New VM wizard choose "
                     "[bold]\"I will install the operating system later\"[/] and attach the ISO afterwards.")
        notes.append("Running VMs pick up changes at their next power-on (a guest reboot is not enough).")
        ui.show(Panel("\n\n".join(f"• {n}" for n in notes), title="Notes", border_style="cyan"))
    return code


# =========================================================================== #
# Windows hypervisor / WSL2 / VBS diagnostics
# =========================================================================== #
HV_FEATURES = {
    "Microsoft-Hyper-V-All": "Hyper-V (full feature)",
    "Microsoft-Hyper-V-Hypervisor": "Hyper-V hypervisor",
    "VirtualMachinePlatform": "Virtual Machine Platform (used by WSL2)",
    "HypervisorPlatform": "Windows Hypervisor Platform (WHP API)",
    "Microsoft-Windows-Subsystem-Linux": "Windows Subsystem for Linux",
    "Containers-DisposableClientVM": "Windows Sandbox",
}


def bcd_hypervisor_launchtype() -> Optional[str]:
    if not is_admin():
        return None
    try:
        out = run_cmd(["bcdedit", "/enum", "{current}"], timeout=30, encoding="mbcs").output
    except StepError as exc:
        ui.debug(f"bcdedit failed: {e(exc)}")
        return None
    m = re.search(r"^hypervisorlaunchtype\s+(\S+)", out, re.M | re.I)
    return m.group(1) if m else "Auto (not set)"


def gather_hypervisor_info() -> Dict[str, Any]:
    info: Dict[str, Any] = {}
    names = ",".join(f"'{n}'" for n in HV_FEATURES)
    script = (
        "$ErrorActionPreference = 'SilentlyContinue'; "
        "$cs = $null; $dg = $null; "
        "try { $cs = Get-CimInstance Win32_ComputerSystem -ErrorAction Stop } catch {}; "
        "try { $dg = Get-CimInstance -Namespace root\\Microsoft\\Windows\\DeviceGuard "
        "-ClassName Win32_DeviceGuard -ErrorAction Stop } catch {}; "
        "$feat = @{}; "
        f"foreach ($n in @({names})) {{ $f = $null; "
        "try { $f = Get-WindowsOptionalFeature -Online -FeatureName $n -ErrorAction Stop } catch {}; "
        "if ($f) { $feat[$n] = [string]$f.State } else { $feat[$n] = $null } }; "
        "[pscustomobject]@{ HypervisorPresent = $cs.HypervisorPresent; "
        "VBS = $dg.VirtualizationBasedSecurityStatus; Running = @($dg.SecurityServicesRunning); "
        "Features = $feat } | ConvertTo-Json -Depth 4 -Compress"
    )
    try:
        data = powershell_json(script) or {}
        info.update(data)
    except StepError as exc:
        ui.warn(f"Could not query Windows features: {e(exc)}")
    info["LaunchType"] = bcd_hypervisor_launchtype()
    try:
        import winreg
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                            r"SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity") as k:
            info["HVCI"] = int(winreg.QueryValueEx(k, "Enabled")[0])
    except (OSError, ImportError, ValueError):
        info["HVCI"] = None
    if shutil.which("wsl.exe") or shutil.which("wsl"):
        with contextlib.suppress(StepError):
            res = run_cmd(["wsl.exe", "--list", "--verbose"], timeout=30)
            lines = [ln.strip() for ln in res.output.splitlines() if ln.strip()]
            info["WSL"] = lines[1:] if res.rc == 0 and len(lines) > 1 else []
    return info


def show_hypervisor_status(summary: Summary) -> None:
    ui.section("Windows hypervisor (why VMware may run in Hyper-V mode)")
    if not WINDOWS:
        ui.info("Not Windows - skipped.")
        return
    info = gather_hypervisor_info()
    feats = info.get("Features") or {}
    t = Table(box=box.ROUNDED, header_style="bold", expand=True)
    t.add_column("Item", style="bold")
    t.add_column("State")
    t.add_column("Notes", style="dim", overflow="fold")
    hp = info.get("HypervisorPresent")
    t.add_row("Windows hypervisor running", "[yellow]YES[/]" if hp else ("[green]no[/]" if hp is False else "[dim]?[/]"),
              "When yes, VMware runs on top of it (Hyper-V/WHP mode) instead of its own monitor.")
    lt = info.get("LaunchType")
    t.add_row("Boot setting hypervisorlaunchtype", e(lt) if lt else "[dim]needs admin[/]",
              "'Off' stops the hypervisor from loading at boot; 'Auto' lets features start it.")
    for key, label in HV_FEATURES.items():
        state = feats.get(key)
        style = "yellow" if state == "Enabled" else "green" if state == "Disabled" else "dim"
        t.add_row(label, f"[{style}]{e(state) if state else ('needs admin' if not is_admin() else 'not present')}[/]", e(key))
    vbs = {0: "[green]off[/]", 1: "[cyan]enabled, not running[/]", 2: "[yellow]running[/]"}.get(info.get("VBS"), "[dim]?[/]")
    t.add_row("Virtualization-based security", vbs, "Core isolation / Credential Guard use the hypervisor too.")
    hvci = info.get("HVCI")
    t.add_row("Memory integrity (HVCI)", "[yellow]on[/]" if hvci == 1 else "[green]off[/]" if hvci == 0 else "[dim]not set[/]",
              "Windows Security > Device security > Core isolation.")
    wsl = info.get("WSL")
    if wsl is not None:
        t.add_row("WSL distros", e("; ".join(wsl)) if wsl else "[dim]none[/]", "WSL2 distros need the hypervisor.")
    ui.show(t)

    reasons = []
    if feats.get("VirtualMachinePlatform") == "Enabled":
        reasons.append("Virtual Machine Platform (WSL2)")
    if feats.get("Microsoft-Hyper-V-All") == "Enabled" or feats.get("Microsoft-Hyper-V-Hypervisor") == "Enabled":
        reasons.append("Hyper-V")
    if feats.get("Containers-DisposableClientVM") == "Enabled":
        reasons.append("Windows Sandbox")
    if info.get("VBS") == 2 or hvci == 1:
        reasons.append("virtualization-based security / memory integrity")
    if hp:
        why = ", ".join(reasons) if reasons else "a Windows feature that uses it"
        ui.show(Panel(
            f"The Windows hypervisor is running, started by [bold]{e(why)}[/]. That's why VMware detected Hyper-V "
            "even though the Hyper-V feature itself may be off: WSL2's Virtual Machine Platform loads the same hypervisor.\n\n"
            "VMware 16+ works fine on top of it, with some overhead; that's the mode where [bold]ulm.disableMitigations[/] "
            "helps. Nested virtualization (VT-x inside guests) isn't available in this mode.\n\n"
            "To get VMware's own, faster monitor back you'd have to stop the hypervisor at boot "
            "([bold]hypervisor off[/] command + reboot). That breaks WSL2, Docker Desktop (WSL backend), "
            "Windows Sandbox and memory integrity until you turn it back on ([bold]hypervisor auto[/]).",
            title="What this means", border_style="cyan"))
        summary.add("Windows hypervisor", "info", f"running ({why}) - VMware uses Hyper-V mode")
    elif hp is False:
        ui.ok("The Windows hypervisor is not running, so VMware uses its own monitor (fastest; mitigation setting has no effect).")
        summary.add("Windows hypervisor", "ok", "not running - VMware uses its own monitor")


def set_hypervisor_launch(mode: str, summary: Summary) -> int:
    ui.section(f"Windows hypervisor boot setting -> {mode}")
    if not WINDOWS:
        ui.err("This only applies to Windows.")
        return EXIT_ERROR
    current = bcd_hypervisor_launchtype()
    ui.info(f"Current hypervisorlaunchtype: [bold]{e(current)}[/]")
    target = "Off" if mode == "off" else "Auto"
    if current and current.lower().startswith(target.lower()):
        ui.ok("Already set; nothing to do.")
        summary.add("Hypervisor boot", "ok", f"already {target}")
        return EXIT_OK
    if mode == "off":
        ui.warn("After a reboot this stops WSL2, Docker Desktop (WSL backend), Windows Sandbox and memory integrity "
                "from working until you run [bold]hypervisor auto[/] and reboot again.")
    if not confirm(f"Set hypervisorlaunchtype to {target}?", default=False):
        summary.add("Hypervisor boot", "skip", "declined")
        return EXIT_ABORTED
    res = run_cmd(["bcdedit", "/set", "hypervisorlaunchtype", target.lower()], timeout=30, encoding="mbcs")
    if res.rc != 0:
        ui.err(f"bcdedit failed (exit {res.rc}): {e(res.output.strip())}")
        summary.add("Hypervisor boot", "fail", res.output.strip()[:200])
        return EXIT_ERROR
    after = bcd_hypervisor_launchtype()
    if after and after.lower().startswith(target.lower()):
        ui.ok(f"Verified: hypervisorlaunchtype = {e(after)}. [bold]Reboot[/] for it to take effect.")
        summary.add("Hypervisor boot", "ok", f"set to {target} (reboot needed)")
        return EXIT_OK
    ui.err(f"bcdedit reported success but the setting reads back as {e(after)}")
    summary.add("Hypervisor boot", "fail", f"reads back as {after}")
    return EXIT_NOT_COMPLIANT


# =========================================================================== #
# Windows 11 install bypass: autounattend.xml, ISO rebuild, Ventoy
# =========================================================================== #
WIN11_RAW_BASE = os.environ.get("WIN11_BYPASS_RAW",
                                "https://raw.githubusercontent.com/nutthawutkongsopa/win11-bypass/main").rstrip("/")
VENTOY_TEMPLATE_REL = "ventoy/script/win11-autounattend.xml"
VENTOY_CONTROL = {"VTOY_WIN11_BYPASS_CHECK": "1", "VTOY_WIN11_BYPASS_NRO": "1"}

# oscdimg.exe 2.56 (x64) from Microsoft's symbol server - no Windows ADK needed.
# See https://pete.akeo.ie/2025/06/downloading-oscdimgexe-from-microsoft.html
# It has no embedded signature (the ADK copy is catalog-signed), so it's checked against this pinned SHA-256.
OSCDIMG_URL = "https://msdl.microsoft.com/download/symbols/oscdimg.exe/688CABB065000/oscdimg.exe"
OSCDIMG_SHA256 = "2000160b2c5044691b2f9a0ac308e5207f273d4880a572457af16d05886ba861"
UNATTEND_NS = "urn:schemas-microsoft-com:unattend"


def validate_unattend(path: Path) -> List[str]:
    """Parse the answer file and return the commands it runs during setup (for review)."""
    try:
        root = ET.parse(str(path)).getroot()
    except (ET.ParseError, OSError) as exc:
        raise StepError(f"{path} is not valid XML: {exc}") from exc
    if root.tag != f"{{{UNATTEND_NS}}}unattend":
        raise StepError(f"{path} is not a Windows answer file (root element is {root.tag}).")
    cmds = []
    for el in root.iter():
        tag = el.tag.split("}")[-1]
        if tag in ("Path", "CommandLine") and el.text and el.text.strip():
            cmds.append(el.text.strip())
    return cmds


def get_unattend(explicit: Optional[Path], work: Path) -> Path:
    ui.section("autounattend.xml")
    cache = work / "win11-bypass" / "autounattend.xml"
    candidates = [p for p in (explicit, SCRIPT_DIR / "autounattend.xml", cache) if p]
    path = None
    for p in candidates:
        if p.is_file():
            path = p
            ui.ok(f"Using {e(p)}")
            break
        if p is explicit:
            raise StepError(f"--unattend file not found: {p}")
    if path is None:
        url = f"{WIN11_RAW_BASE}/autounattend.xml"
        ui.info(f"No local autounattend.xml; downloading it from {e(url)}")
        try:
            r = http_session().get(url, timeout=30)
        except requests.RequestException as exc:
            raise StepError(f"Could not download {url}: {exc}") from exc
        if not r.ok:
            raise StepError(f"Could not download {url}: HTTP {r.status_code}")
        tmp = cache.with_suffix(".part")
        cache.parent.mkdir(parents=True, exist_ok=True)
        tmp.write_bytes(r.content)
        try:
            validate_unattend(tmp)
        except StepError:
            tmp.unlink()
            raise
        os.replace(tmp, cache)
        ui.ok(f"Saved to {e(cache)} (reused next time)")
        path = cache
    cmds = validate_unattend(path)
    ui.ok(f"Valid Windows answer file; SHA-256 {sha256_file(path)[:16]}...")
    if cmds:
        t = Table(title="Commands this answer file runs during Windows setup", box=box.ROUNDED,
                  header_style="bold", expand=True)
        t.add_column("#", justify="right", style="dim")
        t.add_column("Command", overflow="fold")
        for i, c in enumerate(cmds, 1):
            t.add_row(str(i), e(c))
        ui.show(t)
    return path


def find_7zip() -> Optional[str]:
    exe = shutil.which("7z") or shutil.which("7z.exe")
    if exe:
        return exe
    for base in (os.environ.get("ProgramFiles"), os.environ.get("ProgramFiles(x86)")):
        if base and (Path(base) / "7-Zip" / "7z.exe").is_file():
            return str(Path(base) / "7-Zip" / "7z.exe")
    return None


def find_oscdimg(work: Path) -> Optional[str]:
    exe = shutil.which("oscdimg.exe") or shutil.which("oscdimg")
    if exe:
        return exe
    cached = work / "win11-bypass" / "oscdimg.exe"
    if cached.is_file():
        if sha256_file(cached) == OSCDIMG_SHA256:
            return str(cached)
        ui.warn(f"Cached {e(cached)} does not match the pinned SHA-256; ignoring it.")
    for base in (os.environ.get("ProgramFiles(x86)"), os.environ.get("ProgramFiles")):
        root = Path(base) / "Windows Kits" if base else None
        if root and root.is_dir():
            for p in root.rglob("oscdimg.exe"):
                if "amd64" in str(p).lower() or "x86" in str(p).lower():
                    return str(p)
    return None


def download_oscdimg(work: Path) -> Optional[str]:
    dest = work / "win11-bypass" / "oscdimg.exe"
    ui.warn("oscdimg.exe not found (it normally comes with the Windows ADK).")
    ui.info(f"It can be downloaded from Microsoft's symbol server (~140 KB): {e(OSCDIMG_URL)}")
    if not confirm("Download oscdimg.exe now?", default=True):
        return None
    part = dest.with_suffix(".part")
    dest.parent.mkdir(parents=True, exist_ok=True)
    try:
        # The symbol server only answers clients that look like a symbol client
        r = http_session().get(OSCDIMG_URL, timeout=60, headers={"User-Agent": "Microsoft-Symbol-Server/10.0.0.0"})
        if not r.ok:
            raise StepError(f"HTTP {r.status_code}")
        part.write_bytes(r.content)
    except (requests.RequestException, StepError) as exc:
        with contextlib.suppress(OSError):
            part.unlink()
        ui.err(f"Download failed: {e(exc)}")
        return None
    got = sha256_file(part)
    if got != OSCDIMG_SHA256:
        part.unlink()
        ui.err(f"SHA-256 mismatch - downloaded file discarded.\n expected {OSCDIMG_SHA256}\n got      {got}")
        return None
    os.replace(part, dest)
    ui.ok(f"oscdimg.exe downloaded and SHA-256 verified -> {e(dest)}")
    return str(dest)


def iso_label(path: Path) -> str:
    """Volume identifier from the ISO 9660 Primary Volume Descriptor (sector 16, offset 40, 32 bytes)."""
    with open(path, "rb") as f:
        f.seek(16 * 2048)
        pvd = f.read(2048)
    if len(pvd) < 72 or pvd[1:6] != b"CD001":
        return ""
    return pvd[40:72].decode("ascii", errors="replace").strip("\x00 ")


def mount_iso(path: Path) -> str:
    """Mount with Windows' built-in ISO support; returns the drive root like 'E:\\'."""
    data = powershell_json(
        f"$i = Mount-DiskImage -ImagePath {ps_quote(path)} -StorageType ISO -PassThru -ErrorAction Stop; "
        "Start-Sleep -Milliseconds 500; "
        "[pscustomobject]@{ Letter = [string]($i | Get-Volume).DriveLetter } | ConvertTo-Json -Compress")
    letter = (data or {}).get("Letter")
    if not letter:
        raise StepError(f"Mounted {path.name} but Windows didn't assign it a drive letter.")
    return f"{letter}:\\"


def dismount_iso(path: Path) -> None:
    with contextlib.suppress(StepError):
        powershell_json(f"Dismount-DiskImage -ImagePath {ps_quote(path)} | Out-Null; '{{}}'")


def select_iso() -> Optional[Path]:
    seen: Dict[str, Path] = {}
    for d in (Path.cwd(), SCRIPT_DIR, Path.home() / "Downloads"):
        with contextlib.suppress(OSError):
            for p in d.glob("*.iso"):
                if not p.stem.lower().endswith("-bypass"):
                    seen[str(p.resolve()).lower()] = p.resolve()
    isos = sorted(seen.values(), key=lambda p: p.name.lower())
    if isos:
        t = Table(title="ISOs found", box=box.ROUNDED, header_style="bold")
        t.add_column("#", justify="right")
        t.add_column("File")
        t.add_column("Size", justify="right")
        t.add_column("Modified")
        for i, p in enumerate(isos, 1):
            st = p.stat()
            t.add_row(str(i), e(p), fmt_size(st.st_size), dt.datetime.fromtimestamp(st.st_mtime).strftime("%Y-%m-%d"))
        t.add_row("0", "[dim]enter a path[/]", "", "")
        ui.show(t)
        n = ask_number("Which ISO?", 0, len(isos))
        if n is None:
            return None
        if n > 0:
            return isos[n - 1]
    ans = ask_text("Path to the Windows 11 ISO")
    return Path(os.path.expandvars(os.path.expanduser(ans.strip().strip('"').strip("'")))) if ans else None


def build_win11_iso(iso_in: Optional[Path], iso_out: Optional[Path], unattend_arg: Optional[Path],
                    work: Path, summary: Summary) -> int:
    ui.section("Windows 11 ISO: preflight")
    if not WINDOWS:
        ui.err("Rebuilding the ISO needs Windows (oscdimg.exe).")
        return EXIT_ERROR
    if iso_in is None:
        iso_in = select_iso()
        if iso_in is None:
            raise Aborted("No ISO selected.")
    iso_in = iso_in.resolve()
    if not iso_in.is_file():
        raise StepError(f"ISO not found: {iso_in}")
    iso_out = (iso_out or iso_in.with_name(f"{iso_in.stem}-bypass.iso")).resolve()
    if iso_out == iso_in:
        raise StepError("The output ISO must be different from the input.")
    label = iso_label(iso_in)
    ui.ok(f"Input:  {e(iso_in)} ({fmt_size(iso_in.stat().st_size)}, label {e(label or '?')})")
    ui.info(f"Output: {e(iso_out)}")
    if iso_out.exists() and not confirm(f"{e(iso_out.name)} exists. Overwrite it?", default=False):
        raise Aborted("Output exists; not overwritten.")

    free = shutil.disk_usage(iso_out.parent).free
    need = iso_in.stat().st_size * 2 + 512 * 1024 ** 2
    if free < need:
        raise StepError(f"Need about {fmt_size(need)} free on {iso_out.anchor}, have {fmt_size(free)}.")
    ui.ok(f"Free space OK ({fmt_size(free)} free, need ~{fmt_size(need)})")

    seven = find_7zip()
    ui.info(f"Extraction: {'7-Zip (' + e(seven) + ')' if seven else 'Windows ISO mount (7-Zip not found)'}")
    oscdimg = find_oscdimg(work) or download_oscdimg(work)
    if not oscdimg:
        raise StepError("oscdimg.exe isn't available. Install the Windows ADK (Deployment Tools) or allow the download.")
    ui.ok(f"oscdimg: {e(oscdimg)}")
    unattend = get_unattend(unattend_arg, work)
    if not confirm(f"Build {e(iso_out.name)} now?", default=True):
        raise Aborted("ISO build declined.")

    ui.section("Windows 11 ISO: build")
    staging = Path(tempfile.mkdtemp(prefix=".win11-bypass-", dir=str(iso_out.parent)))
    building = iso_out.with_name(iso_out.stem + ".building.iso")
    try:
        if seven:
            ui.info("Extracting with 7-Zip...")
            res = run_cmd([seven, "x", "-y", "-bso0", "-bsp0", f"-o{staging}", str(iso_in)], timeout=3600, stream=True)
            if res.rc != 0:
                raise StepError(f"7-Zip extraction failed (exit {res.rc}).")
        else:
            ui.info("Mounting the ISO and copying its files...")
            drive = mount_iso(iso_in)
            try:
                shutil.copytree(drive, staging, dirs_exist_ok=True)
            finally:
                dismount_iso(iso_in)
        ui.ok("ISO contents extracted")
        boot_dir = staging / "[BOOT]"  # 7-Zip's view of the El Torito images; not part of the file system
        if boot_dir.exists():
            rmtree(boot_dir)
        bios = staging / "boot" / "etfsboot.com"
        efi = staging / "efi" / "microsoft" / "boot" / "efisys.bin"
        if not efi.is_file():
            raise StepError(r"efi\microsoft\boot\efisys.bin not found - is this a Windows ISO?")
        if not (staging / "sources" / "install.wim").exists() and not (staging / "sources" / "install.esd").exists():
            ui.warn(r"sources\install.wim/.esd not found - this may not be a Windows install ISO.")
        shutil.copyfile(unattend, staging / "autounattend.xml")
        ui.ok("Added autounattend.xml to the ISO root")

        for p in (staging, building, bios, efi):
            if '"' in str(p):
                raise StepError(f"Path contains a double quote, which oscdimg can't handle: {p}")
        safe_label = re.sub(r"[^A-Za-z0-9_\-]", "_", label or "WIN11_BYPASS")[:32]
        # oscdimg resolves boot image paths relative to the current directory, so they must be absolute,
        # and its b"path" syntax must reach it verbatim - hence a raw command-line string.
        if bios.is_file():
            bootdata = f'-bootdata:2#p0,e,b"{bios}"#pEF,e,b"{efi}"'
        else:
            ui.warn(r"boot\etfsboot.com not found - the output will be UEFI-only.")
            bootdata = f'-bootdata:1#pEF,e,b"{efi}"'
        cmdline = f'"{oscdimg}" -m -o -u2 -udfver102 -l{safe_label} {bootdata} "{staging}" "{building}"'
        ui.info("Building the ISO with oscdimg (takes a few minutes)...")
        res = run_cmd(cmdline, timeout=3600, stream=True, encoding="mbcs")
        if res.rc != 0:
            raise StepError(f"oscdimg failed with exit code {res.rc}.")
        if not building.is_file() or building.stat().st_size < 100 * 1024 ** 2:
            raise StepError("oscdimg reported success but the output ISO is missing or far too small.")

        ui.section("Windows 11 ISO: verify")
        got_label = iso_label(building)
        if got_label.upper() == safe_label.upper():
            ui.ok(f"Volume label {e(got_label)}")
        else:
            ui.warn(f"Output volume label reads {e(got_label or '?')!r}, expected {e(safe_label)!r} (cosmetic).")
        if seven:
            res = run_cmd([seven, "l", "-slt", str(building), "autounattend.xml"], timeout=300)
            if "Path = autounattend.xml" not in res.output:
                raise StepError("autounattend.xml is not in the root of the output ISO.")
        else:
            drive = mount_iso(building)
            try:
                if not (Path(drive) / "autounattend.xml").is_file():
                    raise StepError("autounattend.xml is not in the root of the output ISO.")
            finally:
                dismount_iso(building)
        ui.ok("autounattend.xml is in the ISO root")
        if iso_out.exists():
            iso_out.unlink()
        os.replace(building, iso_out)
    finally:
        rmtree(staging)
        with contextlib.suppress(OSError):
            if building.exists():
                building.unlink()
    ui.ok(f"Done: [bold]{e(iso_out)}[/] ({fmt_size(iso_out.stat().st_size)})")
    ui.info("Use it in a VMware VM, copy it to a Ventoy USB, or write it with any USB tool.")
    summary.add("Windows 11 ISO", "ok", str(iso_out))
    return EXIT_OK


def find_ventoy(given: Optional[Path]) -> Path:
    if given:
        if not given.is_dir():
            raise StepError(f"Not a folder/drive: {given}")
        return given.resolve()
    roots: List[str] = []
    if WINDOWS:
        data = powershell_json("@(Get-Volume | Where-Object { $_.FileSystemLabel -eq 'Ventoy' -and $_.DriveLetter } "
                               "| ForEach-Object { [string]$_.DriveLetter }) | ConvertTo-Json -Compress")
        letters = data if isinstance(data, list) else ([data] if data else [])
        roots = [f"{d}:\\" for d in letters]
    elif LINUX and shutil.which("lsblk"):
        res = run_cmd(["lsblk", "-J", "-o", "LABEL,MOUNTPOINT"], timeout=20)
        with contextlib.suppress(ValueError):
            def walk(devs: List[Dict[str, Any]]) -> None:
                for d in devs:
                    if d.get("label") == "Ventoy" and d.get("mountpoint"):
                        roots.append(d["mountpoint"])
                    walk(d.get("children") or [])
            walk(json.loads(res.output).get("blockdevices", []))
    if not roots:
        raise StepError("No mounted partition labelled 'Ventoy' found. Plug in the USB or pass its drive/path.")
    if len(roots) == 1:
        ui.ok(f"Found Ventoy USB at {e(roots[0])}")
        return Path(roots[0])
    for i, r in enumerate(roots, 1):
        console.print(f"  [{i}] {e(r)}")
    n = ask_number("Which Ventoy USB?", 1, len(roots))
    if n is None:
        raise Aborted("No Ventoy USB selected.")
    return Path(roots[n - 1])


def _templates_of(entry: Dict[str, Any]) -> List[str]:
    t = entry.get("template")
    return [t] if isinstance(t, str) else list(t) if isinstance(t, list) else []


def ventoy_isos(root: Path) -> List[str]:
    out = []
    for dirpath, dirnames, files in os.walk(root, onerror=lambda exc: ui.debug(f"walk error: {e(exc)}")):
        rel_dir = Path(dirpath).relative_to(root)
        if rel_dir.parts and rel_dir.parts[0].lower() in ("ventoy", "system volume information", "$recycle.bin"):
            dirnames[:] = []
            continue
        for f in files:
            if f.lower().endswith(".iso") and re.search(r"win.*11", f, re.I):
                out.append("/" + (rel_dir / f).as_posix())
    return sorted(out)


def update_ventoy(action: str, root: Path, template: Optional[Path], summary: Summary) -> int:
    ui.section(f"Ventoy: {'configure' if action == 'apply' else 'remove'} Windows 11 bypass")
    tpl_ref = "/" + VENTOY_TEMPLATE_REL
    cfg_path = root / "ventoy" / "ventoy.json"
    tpl_dst = root / Path(VENTOY_TEMPLATE_REL)
    ui.info(f"Ventoy USB: [bold]{e(root)}[/]")
    if not (root / "ventoy").is_dir() and action == "apply":
        ui.info("No ventoy/ folder yet; it will be created (normal for a fresh Ventoy USB).")

    cfg: Dict[str, Any] = {}
    original_text = ""
    if cfg_path.is_file():
        original_text = cfg_path.read_text(encoding="utf-8-sig")
        if original_text.strip():
            try:
                cfg = json.loads(original_text)
            except ValueError as exc:
                raise StepError(f"{cfg_path} is not valid JSON ({exc}); fix or remove it first. Nothing was changed.")
            if not isinstance(cfg, dict):
                raise StepError(f"{cfg_path} does not contain a JSON object; nothing was changed.")
        ui.ok(f"Loaded {e(cfg_path)}")

    control = [c for c in (cfg.get("control") or [])
               if not (isinstance(c, dict) and any(k in c for k in VENTOY_CONTROL))]
    auto: List[Any] = []
    for a in cfg.get("auto_install") or []:
        if isinstance(a, dict) and tpl_ref in _templates_of(a):
            others = [t for t in _templates_of(a) if t != tpl_ref]
            if others:  # someone else's templates share this entry; keep those
                a = dict(a)
                a["template"] = others if len(others) > 1 else others[0]
                auto.append(a)
            continue
        auto.append(a)

    isos: List[str] = []
    if action == "apply":
        for k, v in VENTOY_CONTROL.items():
            control.append({k: v})
        isos = ventoy_isos(root)
        for iso in isos:
            existing = next((a for a in auto if isinstance(a, dict) and a.get("image") == iso), None)
            if existing is not None:
                existing["template"] = _templates_of(existing) + [tpl_ref]
            else:
                auto.append({"image": iso, "template": tpl_ref, "autosel": 1})
        if isos:
            ui.ok(f"Windows 11 ISOs that will get the answer file: {e(', '.join(isos))}")
        else:
            ui.warn("No Windows 11 ISO (name matching 'win*11') on the USB yet. The TPM/CPU bypass still works; "
                    "copy an ISO over and run this again to attach the answer file to it.")

    new_cfg = dict(cfg)
    for key, val in (("control", control), ("auto_install", auto)):
        if val:
            new_cfg[key] = val
        else:
            new_cfg.pop(key, None)
    new_text = json.dumps(new_cfg, indent=4, ensure_ascii=False) + "\n"
    show_diff(original_text, new_text, "ventoy.json")
    tpl_current = (tpl_dst.is_file() and template is not None and sha256_file(tpl_dst) == sha256_file(template))
    if new_cfg == cfg and (tpl_current if action == "apply" else not tpl_dst.exists()):
        ui.ok("Already in the requested state; nothing to change.")
        summary.add("Ventoy", "ok", "already configured" if action == "apply" else "nothing to remove")
        return EXIT_OK
    if not confirm(f"Write these changes to {e(root)}?", default=True):
        raise Aborted("Ventoy changes declined.")

    bak = backup_file(cfg_path) if cfg_path.exists() else None
    try:
        if action == "apply":
            assert template is not None
            tpl_dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(template, tpl_dst)
            if sha256_file(tpl_dst) != sha256_file(template):
                raise StepError(f"Copy of the answer file to {tpl_dst} does not match the source.")
            ui.ok(f"Copied answer file to {e(tpl_dst)} (verified)")
        elif tpl_dst.exists():
            tpl_dst.unlink()
            ui.ok(f"Removed {e(tpl_dst)}")
            with contextlib.suppress(OSError):
                tpl_dst.parent.rmdir()  # only if empty
        if new_cfg:
            atomic_write_bytes(cfg_path, new_text.encode("utf-8"))
        elif cfg_path.exists():
            cfg_path.unlink()
            ui.info("ventoy.json would be empty, so it was removed.")
    except (OSError, StepError) as exc:
        ui.err(f"Writing to the USB failed: {e(exc)}")
        if bak:
            restore_backup(cfg_path, bak, True)
        summary.add("Ventoy", "fail", str(exc))
        return EXIT_ERROR

    # Verify by re-reading
    check = json.loads(cfg_path.read_text(encoding="utf-8-sig")) if cfg_path.exists() else {}
    ctl_keys = {k for c in check.get("control", []) if isinstance(c, dict) for k in c}
    tpl_refs = [a.get("image") for a in check.get("auto_install", []) if isinstance(a, dict) and tpl_ref in _templates_of(a)]
    if action == "apply":
        good = all(k in ctl_keys for k in VENTOY_CONTROL) and sorted(tpl_refs) == isos and tpl_dst.is_file()
    else:
        good = not any(k in ctl_keys for k in VENTOY_CONTROL) and not tpl_refs and not tpl_dst.exists()
    if not good:
        ui.err("Verification failed after writing; rolling back ventoy.json.")
        restore_backup(cfg_path, bak, bak is not None)
        summary.add("Ventoy", "fail", "verification failed; rolled back")
        return EXIT_NOT_COMPLIANT
    ui.ok("Verified by re-reading ventoy.json")
    if action == "apply":
        ui.info("Needs a recent Ventoy release (1.0.83+ for the TPM/CPU bypass; the no-online-account option needs "
                "a newer one). Boot the ISO in normal mode, not WIMBoot.")
        summary.add("Ventoy", "ok", f"configured on {root}" + (f"; answer file on {len(isos)} ISO(s)" if isos else ""))
    else:
        summary.add("Ventoy", "ok", f"bypass settings removed from {root}" + (f"; backup {bak.name}" if bak else ""))
    return EXIT_OK


# =========================================================================== #
# Commands
# =========================================================================== #
def cmd_setup(args: argparse.Namespace, summary: Summary) -> int:
    work: Path = args.work_dir
    code = EXIT_OK
    if not args.skip_unlock:
        try:
            udir = ensure_unlocker(work, summary)
            before = run_patch_check(udir)
            summary.add("Patch status (before)", "info", before.text)
            if not do_unlock(udir, summary, before):
                code = EXIT_ERROR
        except Aborted as exc:
            ui.warn(f"{e(exc)}")
            summary.add("Unlock", "skip", str(exc))
        except StepError as exc:
            ui.err(f"{e(exc)}")
            summary.add("Unlocker", "fail", str(exc))
            code = EXIT_ERROR
    else:
        summary.add("Unlock", "skip", "--skip-unlock")

    if not args.skip_defaults:
        console.print()
        ui.info("Next: host-wide VMware defaults - side-channel mitigations off and no automatic VMware Tools installs, "
                "for all VMs. You'll see the plan and be asked before anything is written.")
        rc = run_defaults("apply", summary, scan_vms=True, fix_vms=args.fix_vms, vm_dirs=args.vm_dir)
        if rc not in (EXIT_OK, EXIT_ABORTED):
            code = code or rc
    else:
        summary.add("VMware defaults", "skip", "--skip-defaults")
    return code


def cmd_status(args: argparse.Namespace, summary: Summary) -> int:
    ui.section("VMware Workstation")
    ws = detect_workstation()
    if ws.get("InstallPath"):
        ui.ok(f"{e(ws.get('Product', 'VMware'))} {e(ws.get('ProductVersion', '?'))} at {e(ws['InstallPath'])}")
        summary.add("VMware install", "ok", f"{ws.get('ProductVersion', '?')} at {ws['InstallPath']}")
    else:
        ui.warn("VMware Workstation not detected.")
        summary.add("VMware install", "warn", "not detected")
    show_hypervisor_status(summary)

    udir = unlocker_dir(args.work_dir)
    if unlocker_tool(udir, "check").is_file():
        if is_admin():
            st = run_patch_check(udir)
            summary.add("Unlocker patch", {"patched": "ok", "unpatched": "info"}.get(st.state, "warn"), st.text)
        else:
            summary.add("Unlocker patch", "skip", "needs administrator rights")
    else:
        summary.add("Unlocker patch", "skip", f"Unlocker not downloaded yet ({udir})")
    rc = run_defaults("check", summary, scan_vms=True, vm_dirs=args.vm_dir)
    return EXIT_OK if rc in (EXIT_OK, EXIT_NOT_COMPLIANT) else rc


def cmd_unlock(args: argparse.Namespace, summary: Summary) -> int:
    udir = ensure_unlocker(args.work_dir, summary)
    before = run_patch_check(udir)
    return EXIT_OK if do_unlock(udir, summary, before) else EXIT_ERROR


def cmd_relock(args: argparse.Namespace, summary: Summary) -> int:
    udir = unlocker_dir(args.work_dir)
    if verify_unlocker_files(udir):
        ui.info("Unlocker not found locally; downloading it first.")
        udir = ensure_unlocker(args.work_dir, summary)
    return EXIT_OK if do_relock(args.work_dir, udir, summary) else EXIT_ERROR


def cmd_patch_status(args: argparse.Namespace, summary: Summary) -> int:
    udir = unlocker_dir(args.work_dir)
    if verify_unlocker_files(udir):
        udir = ensure_unlocker(args.work_dir, summary)
    st = run_patch_check(udir)
    summary.add("Patch status", {"patched": "ok", "unpatched": "info"}.get(st.state, "warn"), st.text)
    return EXIT_OK if st.state in ("patched", "unpatched", "notinstalled") else EXIT_ERROR


def cmd_defaults(args: argparse.Namespace, summary: Summary) -> int:
    mode = "apply" if args.apply else "revert" if args.revert else "check"
    return run_defaults(mode, summary, dry_run=args.dry_run, skip=args.skip, config_path=args.config_path,
                        scan_vms=args.scan_vms, fix_vms=args.fix_vms, vm_dirs=args.vm_dir, force=args.force)


def cmd_hypervisor(args: argparse.Namespace, summary: Summary) -> int:
    if args.action == "status":
        show_hypervisor_status(summary)
        return EXIT_OK
    return set_hypervisor_launch(args.action, summary)


def cmd_win11_iso(args: argparse.Namespace, summary: Summary) -> int:
    return build_win11_iso(args.iso, args.output, args.unattend, args.work_dir, summary)


def cmd_ventoy(args: argparse.Namespace, summary: Summary) -> int:
    template = get_unattend(args.unattend, args.work_dir)
    root = find_ventoy(args.drive)
    return update_ventoy("apply", root, template, summary)


def cmd_ventoy_remove(args: argparse.Namespace, summary: Summary) -> int:
    root = find_ventoy(args.drive)
    return update_ventoy("remove", root, None, summary)


def cmd_fetch(args: argparse.Namespace, summary: Summary) -> int:
    ui.section("GitHub release download")
    try:
        pattern = re.compile(args.asset_regex)
    except re.error as exc:
        raise StepError(f"Invalid asset regex: {exc}") from exc
    repo = parse_repo(args.repo)
    gh = GitHub()
    release, asset, newest = gh.find_asset(repo, pattern, args.prerelease)
    note = f"  [dim](newest release {e(newest)} has no matching asset)[/]" if newest and newest != release["tag_name"] else ""
    ui.ok(f"Found {e(asset['name'])} ({e(release['tag_name'])}){note}")
    path, verified = gh.download(asset, args.output_dir.resolve(), args.require_checksum, args.skip_existing)
    summary.add("Download", "ok" if verified else "warn",
                f"{path} ({'SHA-256 verified' if verified else 'no checksum published'})")
    if args.run:
        if not verified and not confirm("The file's checksum could not be verified. Run it anyway?", default=False):
            raise Aborted("Not running the unverified file.")
        launch_file(path)
        summary.add("Run", "ok", path.name)
    return EXIT_OK


MENU: List[Tuple[str, str, Callable[[argparse.Namespace], argparse.Namespace]]] = [
    ("Full setup", "Unlocker download + patch, then VMware defaults (recommended after installing VMware)",
     lambda a: _ns(a, func=cmd_setup, skip_unlock=False, skip_defaults=False, fix_vms=False)),
    ("Status report", "Read-only: hypervisor/WSL2, VMware, patch status, defaults",
     lambda a: _ns(a, func=cmd_status)),
    ("Unlock only", "Download/verify the Unlocker and patch VMware", lambda a: _ns(a, func=cmd_unlock)),
    ("Relock", "Remove the Unlocker patches", lambda a: _ns(a, func=cmd_relock)),
    ("Defaults: apply", "Write the host-wide defaults (and offer to fix existing VMs)",
     lambda a: _ns(a, func=cmd_defaults, apply=True, revert=False, dry_run=False, skip=[], config_path=None,
                   scan_vms=True, fix_vms=True, force=False)),
    ("Defaults: revert", "Remove the host-wide defaults",
     lambda a: _ns(a, func=cmd_defaults, apply=False, revert=True, dry_run=False, skip=[], config_path=None,
                   scan_vms=False, fix_vms=False, force=False)),
    ("Windows 11 ISO", "Rebuild a Win11 ISO that skips TPM/CPU checks and the online account",
     lambda a: _ns(a, func=cmd_win11_iso, iso=None, output=None, unattend=None)),
    ("Ventoy: set up", "Same bypass via Ventoy plugins, ISO unchanged",
     lambda a: _ns(a, func=cmd_ventoy, drive=None, unattend=None)),
    ("Ventoy: remove", "Undo the Ventoy configuration", lambda a: _ns(a, func=cmd_ventoy_remove, drive=None)),
    ("Hypervisor: off", "Stop the Windows hypervisor at boot (breaks WSL2 until turned back on)",
     lambda a: _ns(a, func=cmd_hypervisor, action="off")),
    ("Hypervisor: auto", "Restore the Windows default (WSL2 etc. work again)",
     lambda a: _ns(a, func=cmd_hypervisor, action="auto")),
]


def _ns(base: argparse.Namespace, **kw: Any) -> argparse.Namespace:
    d = vars(base).copy()
    d.setdefault("vm_dir", [])
    d.update(kw)
    return argparse.Namespace(**d)


def cmd_menu(args: argparse.Namespace, summary: Summary) -> int:
    t = Table(title="What do you want to do?", box=box.ROUNDED, header_style="bold", expand=True)
    t.add_column("#", justify="right", style="bold cyan")
    t.add_column("Action", style="bold", no_wrap=True)
    t.add_column("Description", style="dim")
    for i, (name, desc, _) in enumerate(MENU, 1):
        t.add_row(str(i), name, desc)
    t.add_row("0", "Exit", "")
    ui.show(t)
    n = ask_number("Choose", 0, len(MENU))
    if not n:
        return EXIT_OK
    name, _, make = MENU[n - 1]
    log.info("MENU choice: %s", name)
    sub = make(args)
    if needs_admin(sub) and not is_admin():
        ui.err("That action needs administrator/root rights. Re-run the script elevated.")
        return EXIT_ABORTED
    return sub.func(sub, summary)


# =========================================================================== #
# CLI plumbing
# =========================================================================== #
def needs_admin(args: argparse.Namespace) -> bool:
    f = getattr(args, "func", None)
    if f in (cmd_setup, cmd_unlock, cmd_relock, cmd_patch_status):
        return True
    if f is cmd_menu:
        return WINDOWS  # most menu actions need it; offer elevation once up front
    if f is cmd_defaults:
        return (args.apply or args.revert) and not args.dry_run and args.config_path is None
    if f is cmd_hypervisor:
        return True  # bcdedit needs admin even to read
    if f is cmd_status:
        return WINDOWS  # works without, but feature/bcdedit/patch checks need it
    return False


def relaunch_elevated(argv: List[str]) -> bool:
    import ctypes
    params = subprocess.list2cmdline([str(SCRIPT_PATH), "--cwd", os.getcwd(), "--pause-on-exit", *argv])
    log.info("Relaunching elevated: %s %s", sys.executable, params)
    rc = ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, params, str(SCRIPT_DIR), 1)  # type: ignore
    return rc > 32


def ensure_privileges(args: argparse.Namespace, argv: List[str]) -> Optional[int]:
    if not needs_admin(args) or is_admin():
        return None
    optional = args.func in (cmd_status, cmd_menu)
    if WINDOWS:
        ui.warn("This needs administrator rights" + (" for the full report." if optional else "."))
        if confirm("Relaunch elevated (UAC prompt)?", default=True):
            if relaunch_elevated(argv):
                ui.ok("The elevated copy opened in a new window; it writes its own log. This window can be closed.")
                return EXIT_OK
            ui.err("Elevation was cancelled or failed.")
        if optional:
            ui.info("Continuing without elevation; some checks will be skipped.")
            return None
        return EXIT_ABORTED
    ui.err("This needs root. Re-run with:")
    import shlex
    console.print(f"    [bold]sudo {e(shlex.join([sys.executable, str(SCRIPT_PATH), *argv]))}[/]")
    return None if optional else EXIT_ABORTED


class RichArgParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:  # type: ignore[override]
        console.print(f"[bold red]Error:[/] {e(message)}")
        console.print(f"[dim]Run [bold]{e(self.prog)} -h[/] for usage.[/]")
        sys.exit(EXIT_ERROR)


def build_parser() -> argparse.ArgumentParser:
    p = RichArgParser(prog=SCRIPT_PATH.name, description="Set up VMware Workstation on a fresh machine. "
                      "Run with no command for an interactive menu.",
                      formatter_class=argparse.RawDescriptionHelpFormatter,
                      epilog="Run '<command> -h' for a command's options. Exit codes: 0 OK, 1 error, "
                             "2 not compliant / verification failed, 3 aborted.")
    p.add_argument("--work-dir", type=Path, default=SCRIPT_DIR,
                   help="where downloads, the Unlocker and logs live (default: this script's folder)")
    p.add_argument("--log-dir", type=Path, help="log folder (default: <work-dir>/logs)")
    p.add_argument("--no-log", action="store_true", help="don't write a log file")
    p.add_argument("-v", "--verbose", action="store_true", help="show debug detail on screen (always in the log)")
    p.add_argument("--debug", action="store_true", help="full tracebacks on unexpected errors (implies -v)")
    p.add_argument("--version", action="version", version=f"%(prog)s {VERSION}")
    p.add_argument("--cwd", help=argparse.SUPPRESS)
    p.add_argument("--pause-on-exit", action="store_true", help=argparse.SUPPRESS)
    sub = p.add_subparsers(dest="command", metavar="command")

    def add(name: str, func: Callable, help_: str) -> argparse.ArgumentParser:
        sp = sub.add_parser(name, help=help_, description=help_)
        sp.set_defaults(func=func)
        return sp

    def vm_dir_opt(sp: argparse.ArgumentParser) -> None:
        sp.add_argument("--vm-dir", action="append", default=[], type=Path, metavar="DIR",
                        help="extra folder to search for .vmx files (repeatable)")

    sp = add("setup", cmd_setup, "Full workflow: Unlocker (download, check, patch) then VMware defaults")
    sp.add_argument("--skip-unlock", action="store_true", help="don't touch the Unlocker")
    sp.add_argument("--skip-defaults", action="store_true", help="don't set the VMware defaults")
    sp.add_argument("--fix-vms", action="store_true", help="also offer to fix existing VMs that override the defaults")
    vm_dir_opt(sp)

    sp = add("status", cmd_status, "Read-only report: hypervisor/WSL2, VMware, patch status, defaults")
    vm_dir_opt(sp)
    add("unlock", cmd_unlock, "Download/verify the Unlocker and patch VMware")
    add("relock", cmd_relock, "Remove the Unlocker patches (restore the original VMware files)")
    add("patch-status", cmd_patch_status, "Run the Unlocker's check only")

    sp = add("defaults", cmd_defaults, "Host-wide VMware defaults (mitigations off, no automatic Tools installs)")
    mode = sp.add_mutually_exclusive_group(required=True)
    mode.add_argument("--apply", action="store_true", help="write the settings (asks first)")
    mode.add_argument("--check", action="store_true", help="read-only; exit 2 if not in place")
    mode.add_argument("--revert", action="store_true", help="remove the managed keys (asks first)")
    sp.add_argument("--dry-run", action="store_true", help="with --apply/--revert: show the plan, write nothing")
    sp.add_argument("--skip", action="append", default=[], choices=list(SETTINGS), metavar="KEY",
                    help="leave one managed key alone (repeatable)")
    sp.add_argument("--config-path", type=Path, help="use a different global config file (testing)")
    sp.add_argument("--scan-vms", action="store_true", help="report VMs whose .vmx overrides the defaults")
    sp.add_argument("--fix-vms", action="store_true", help="with --apply: also fix those .vmx files (asks first)")
    sp.add_argument("--force", action="store_true", help="don't ask to continue when VMware isn't detected")
    vm_dir_opt(sp)

    sp = add("hypervisor", cmd_hypervisor, "Show or set the Windows hypervisor boot setting")
    sp.add_argument("action", nargs="?", default="status", choices=("status", "off", "auto"))

    sp = add("win11-iso", cmd_win11_iso, "Rebuild a Windows 11 ISO with the bypass answer file")
    sp.add_argument("iso", nargs="?", type=Path, help="input ISO (asks if omitted)")
    sp.add_argument("-o", "--output", type=Path, help="output ISO (default: <name>-bypass.iso)")
    sp.add_argument("--unattend", type=Path, help="use this autounattend.xml instead of the default one")

    sp = add("ventoy", cmd_ventoy, "Configure a Ventoy USB for the Windows 11 bypass")
    sp.add_argument("drive", nargs="?", type=Path, help="Ventoy drive/mount point (auto-detected if omitted)")
    sp.add_argument("--unattend", type=Path, help="use this autounattend.xml instead of the default one")

    sp = add("ventoy-remove", cmd_ventoy_remove, "Remove the Windows 11 bypass from a Ventoy USB")
    sp.add_argument("drive", nargs="?", type=Path, help="Ventoy drive/mount point (auto-detected if omitted)")

    sp = add("fetch", cmd_fetch, "Download a release asset from any GitHub repo")
    sp.add_argument("repo", help="owner/name or a GitHub URL")
    sp.add_argument("asset_regex", help="regex matched against asset file names")
    sp.add_argument("output_dir", nargs="?", default=Path("."), type=Path, help="where to save it (default: .)")
    sp.add_argument("--run", action="store_true", help="run the file after downloading")
    sp.add_argument("--prerelease", action="store_true", help="also consider pre-releases")
    sp.add_argument("--skip-existing", action="store_true", help="skip if the file is already there and matches")
    sp.add_argument("--require-checksum", action="store_true", help="refuse assets without a published SHA-256")
    return p


def main(argv: Optional[List[str]] = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    args = build_parser().parse_args(argv)
    if args.cwd:
        with contextlib.suppress(OSError):
            os.chdir(args.cwd)
    if not getattr(args, "func", None):
        args.func = cmd_menu
        args.vm_dir = []
    args.work_dir = args.work_dir.resolve()
    ui.verbose = args.verbose or args.debug
    if not args.no_log:
        setup_logging((args.log_dir or args.work_dir / "logs").resolve())

    title = args.command or "menu"
    console.print(Panel.fit(f"[bold]VMware Workstation setup[/]  v{VERSION}\nCommand: [bold magenta]{e(title)}[/]",
                            border_style="magenta"))
    admin = is_admin()
    log.info("vmware_setup.py %s | command=%s | argv=%s", VERSION, title, argv)
    log.info("Python %s (%s) | %s | admin=%s | cwd=%s | work=%s", sys.version.split()[0], sys.executable,
             sys.platform, admin, os.getcwd(), args.work_dir)
    ui.info(f"Running {'elevated' if WINDOWS else 'as root'}: " + ("[green]yes[/]" if admin else "[yellow]no[/]")
            + f"  ·  Python {e(sys.version.split()[0])}  ·  work folder {e(args.work_dir)}")
    if LOG_FILE:
        ui.info(f"Log file: {e(LOG_FILE)}")

    summary = Summary(f"Summary - {title}")
    code = EXIT_ERROR
    try:
        stop = ensure_privileges(args, argv)
        if stop is not None:
            code = stop
        else:
            args.work_dir.mkdir(parents=True, exist_ok=True)
            code = args.func(args, summary)
    except Aborted as exc:
        ui.warn(f"Stopped: {e(exc)}")
        code = EXIT_ABORTED
    except StepError as exc:
        ui.err(f"{e(exc)}")
        code = EXIT_ERROR
    except KeyboardInterrupt:
        console.print()
        ui.warn("Interrupted (Ctrl+C).")
        code = EXIT_INTERRUPTED
    except Exception as exc:  # last-resort safety net
        ui.err(f"Unexpected error: {e(type(exc).__name__)}: {e(exc)}")
        log.exception("Unexpected error")
        if args.debug:
            console.print_exception(show_locals=False)
        else:
            console.print("[dim]Re-run with --debug for a full traceback (it's also in the log file).[/]")
        code = EXIT_ERROR
    finally:
        if summary.rows:
            ui.section("Summary")
            ui.show(summary.render())
        counts = Table(box=box.SIMPLE, show_header=False)
        counts.add_column(style="bold")
        counts.add_column()
        counts.add_row("Warnings", f"[yellow]{len(ui.warnings)}[/]" if ui.warnings else "[green]0[/]")
        counts.add_row("Errors", f"[red]{len(ui.errors)}[/]" if ui.errors else "[green]0[/]")
        ui.show(counts)
        colour = "green" if code == EXIT_OK else "yellow" if code in (EXIT_NOT_COMPLIANT, EXIT_ABORTED) else "red"
        verdict = {EXIT_OK: "Finished without errors", EXIT_NOT_COMPLIANT: "Finished - not everything is in place",
                   EXIT_ABORTED: "Stopped before finishing", EXIT_INTERRUPTED: "Interrupted"}.get(code, "Stopped because of an error")
        console.print(f"[bold {colour}]{verdict} (exit code {code})[/]")
        log.info("FINISHED exit code %s - %s", code, verdict)
        if LOG_FILE:
            console.print(f"[dim]Full log: {e(LOG_FILE)}[/]")
        logging.shutdown()
        if args.pause_on_exit and interactive():
            with contextlib.suppress(EOFError, KeyboardInterrupt):
                input("\nPress Enter to close...")
    return code


if __name__ == "__main__":
    sys.exit(main())
