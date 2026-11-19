#!/usr/bin/env python3
"""
SetupShucker - unpack installers and split them by architecture.
Inno Setup · MSI · Electron · anything 7-Zip opens

Scan an installer, choose architecture,
Windows version, the values of the conditions it depends on, and which
features/components to include, watch the file list update live, then extract
that one install tree. For Inno Setup, Extract writes every architecture x Windows
version profile by default (untick "Every architecture and Windows version" on the
Target tab to extract only the one shown).

    python SetupShucker.py                       # pick the installer in the window
    python SetupShucker.py --no-splash           # skip the startup splash
    python SetupShucker.py kes_win.msi           # open and scan straight away
    python SetupShucker.py Setup.exe             # Inno Setup (uses innounp)
    python SetupShucker.py extracted_folder      # already extracted by innounp
    python SetupShucker.py vendor_setup.exe      # anything else (NSIS, SFX archives, ...):
                                                 # 7-Zip unpacks it into the main window and
                                                 # the payload is sorted by architecture;
                                                 # installers found inside are listed on the
                                                 # Inside tab, ready to open (Back returns)
    python SetupShucker.py some_folder           # any unpacked files: generic arch sort
    python SetupShucker.py electron_setup.exe    # electron-builder NSIS installer: one profile
                                                 # per embedded app package (app-64.7z /
                                                 # app-32.7z / app-arm64.7z)

Backends: Inno Setup and MSI read the installer's own rules; Electron installers
(electron-builder) are split by their per-arch app packages; anything else is
sorted generically by PE header and arch-named paths (split_generic.py).

Needs split_common.py, split_msi_arch.py, split_inno_arch.py, split_generic.py,
electron_extract.py, installer_detect.py, bundled_tools.py and splash_screen_tk.py
(optional) in the same folder, plus the helper tools in bin\\:
    bin\\innounp.exe          Inno Setup installers
    bin\\7z.exe, bin\\7z.dll  unpacking other .exe wrappers
    bin\\die\\diec.exe        identifying unknown files (optional)
Standard library only (tkinter).

Compiling (PyInstaller): the helper modules are picked up from the imports. Put
bin\\ (7z, innounp, die) and SetupShucker.ico in do.include\\ so they are bundled
into _MEIPASS; a bin\\ folder next to the .exe also works and wins over the
bundled one, so tools can be updated without rebuilding.

    pyinstaller --onefile --windowed --icon=SetupShucker.ico ^
        --add-data "SetupShucker.ico;." --add-data "bin;bin" SetupShucker.py
"""

import os
import queue
import shutil
import subprocess
import sys
import tempfile
import threading
import tkinter as tk
import webbrowser
from tkinter import filedialog, messagebox, ttk

# ===============================================================
#  EDIT ME GENTLY
# ===============================================================
SCRIPT_NAME = "SetupShucker"
SCRIPT_VERSION = "5.6"
SCRIPT_AUTHOR = "whalelinguini"
SCRIPT_URL = "https://github.com/honeybugserial"
SCRIPT_LIC = "Yes"
SCRIPT_TAGLINE = "unpack installers and split them by architecture"
SCRIPT_DESCRIPTION = ("SetupShucker unpacks Windows installers and sorts what is inside by "
                      "architecture. Inno Setup and MSI installers are read through their own "
                      "install rules, so every x86 / x64 / ARM64 and Windows-version profile "
                      "comes out exactly as the installer would lay it down. Electron "
                      "(electron-builder) installers give one clean app folder per embedded "
                      "package, and anything else 7-Zip can open is sorted by PE header and "
                      "arch-named paths.")

ABOUT = {
    "name":        SCRIPT_NAME,
    "version":     SCRIPT_VERSION,
    "author":      SCRIPT_AUTHOR,
    "description": SCRIPT_DESCRIPTION,
    "license":     SCRIPT_LIC,
    "url":         SCRIPT_URL,
}

APP_ICON = "SetupShucker.ico"
WINDOW_SIZE = "1280x800"
WINDOW_MIN = (980, 600)
SPLASH_SECONDS = 3.0      # startup splash (splash_screen_tk.py); 0 = off
# ===============================================================


# ── paths: source run, PyInstaller --onefile / --onedir, Nuitka ────────────────
# BASE_DIR     = next to the script / .exe   (writable: user-facing files)
# RESOURCE_DIR = where bundled read-only files land (_MEIPASS when frozen)
FROZEN = bool(getattr(sys, "frozen", False))
if FROZEN:
    BASE_DIR = os.path.dirname(os.path.abspath(sys.executable))
else:
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))
RESOURCE_DIR = getattr(sys, "_MEIPASS", None) or os.path.dirname(os.path.abspath(__file__))

# helper modules (split_*.py, electron_extract.py, ...) sit beside this script
for _p in (RESOURCE_DIR, BASE_DIR):
    if _p not in sys.path:
        sys.path.insert(0, _p)


def resource_path(name):
    """Absolute path to a bundled, read-only resource (icon, ...), or None.
    Tries _MEIPASS, this module's folder (Nuitka / source), then next to the exe."""
    bases = [getattr(sys, "_MEIPASS", None)]
    try:
        bases.append(os.path.dirname(os.path.abspath(__file__)))
    except NameError:                              # __file__ can be missing when frozen
        pass
    bases += [os.path.dirname(os.path.abspath(sys.executable)), BASE_DIR]
    seen = set()
    for base in bases:
        if base and base not in seen:
            seen.add(base)
            path = os.path.join(base, name)
            if os.path.isfile(path):
                return path
    return None


import electron_extract as electron  # noqa: E402
import installer_detect as detect  # noqa: E402
import split_common as common  # noqa: E402
import split_generic as generic  # noqa: E402
import split_inno_arch as inno  # noqa: E402
import split_msi_arch as msi  # noqa: E402
try:                                    # cosmetic: missing splash never blocks startup
    from splash_screen_tk import show_splash  # noqa: E402
except Exception:                       # pragma: no cover
    show_splash = None

AUTO, UNDECIDED, NOT_SET = "auto", "undecided", "not set"
ARCH_TEXT = {"x86": "x86  (32-bit Windows)", "x64": "x64  (64-bit Windows)",
             "arm64": "ARM64", "ia64": "Itanium"}
OLE_MAGIC = b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1"


def quick_kind(path):
    """'msi', 'inno', 'electron', 'generic' (a folder) or None, from the file itself.
    Electron needs a 7-Zip listing of the setup (a second or two, cached)."""
    if os.path.isdir(path):
        if os.path.isfile(os.path.join(path, "install_script.iss")):
            return "inno"
        return "electron" if electron.looks_like_electron(path) else "generic"
    if path.lower().endswith(".iss"):
        return "inno"
    with open(path, "rb") as f:
        head = f.read(8)
    if head == OLE_MAGIC:
        return "msi"
    if inno.looks_like_inno(path):
        return "inno"
    if electron.looks_like_electron(path):
        return "electron"
    return None


def open_project(path, log):
    kind = quick_kind(path)
    if kind == "msi":
        return msi.MsiProject(path, log=log)
    if kind == "inno":
        return inno.InnoProject(path, log=log)
    if kind == "electron":
        return electron.ElectronProject(path, log=log)
    # a folder, or anything else: 7-Zip unpacks it (if it can) and the payload is
    # sorted generically; installers inside are listed for the Inside tab
    return generic.GenericProject(path, log=log)


class App(tk.Tk):
    def __init__(self, path=None, splash_seconds=0.0):
        super().__init__()
        splash = bool(show_splash and splash_seconds > 0)
        if splash:
            self.withdraw()                         # main window stays hidden under the splash
        self.title(f"{SCRIPT_NAME} v{SCRIPT_VERSION} — {SCRIPT_TAGLINE}")
        icon = resource_path(APP_ICON)
        if icon:
            try:
                self.iconbitmap(default=icon)       # default= also covers dialogs
            except tk.TclError:
                pass
        self.geometry(WINDOW_SIZE)
        self.minsize(*WINDOW_MIN)

        self.proj = None
        self.bands = []
        self.prop_vars, self.prop_maps = {}, {}
        self.feat_override = {}
        self.toggleable = set()
        self.opt_vars = {}
        self.preview = None
        self.preview_fstates = {}
        self._pending = None
        self._busy = False
        self.stack = []                # parent projects when an inner installer is open
        self.last_output = None
        self.q = queue.Queue()

        self.src_var = tk.StringVar(value=path or "")
        self.arch_var = tk.StringVar()
        self.band_var = tk.IntVar(value=0)
        self.out_var = tk.StringVar()
        self.filter_var = tk.StringVar(value="All selected")
        self.opt_unknown_empty = tk.BooleanVar(value=False)
        self.opt_default = tk.BooleanVar(value=False)
        self.opt_prune = tk.BooleanVar(value=False)
        self.opt_skip_cond = tk.BooleanVar(value=False)
        self.opt_all = tk.BooleanVar(value=True)     # Inno: every arch x version
        self.all_label = None
        self.all_preview = []

        self._build()
        if splash:
            show_splash(self, seconds=splash_seconds)
            self.deiconify()
            self.lift()
            self.focus_force()
            self.after(50, lambda: self._pane.sashpos(0, 560))   # set while visible
        if path:
            self.after(100, self.scan)

    # ------------------------------------------------------------------ UI --
    def _build_menu(self):
        bar = tk.Menu(self, tearoff=False)
        m_file = tk.Menu(bar, tearoff=False)
        m_file.add_command(label="Exit", underline=1, accelerator="Alt+F4", command=self.on_exit)
        bar.add_cascade(label="File", underline=0, menu=m_file)
        m_help = tk.Menu(bar, tearoff=False)
        m_help.add_command(label=f"About {SCRIPT_NAME}", underline=0, command=self.show_about)
        bar.add_cascade(label="Help", underline=0, menu=m_help)
        self.config(menu=bar)
        self.protocol("WM_DELETE_WINDOW", self.on_exit)

    def on_exit(self):
        if self._busy and not messagebox.askyesno(
                "Exit", "Still working (unpacking or extracting).\n\nExit anyway?"):
            return
        self.destroy()

    def show_about(self):
        win = tk.Toplevel(self)
        win.title(f"About {SCRIPT_NAME}")
        win.transient(self)
        win.resizable(False, False)
        body = ttk.Frame(win, padding=(18, 14, 18, 10))
        body.pack(fill="both", expand=True)
        ttk.Label(body, text=ABOUT["name"], font=("TkDefaultFont", 16, "bold")).pack(anchor="w")
        ttk.Label(body, text=f"v{ABOUT['version']}  ·  {SCRIPT_TAGLINE}",
                  foreground="#555").pack(anchor="w", pady=(0, 10))
        ttk.Label(body, text=ABOUT["description"], wraplength=440,
                  justify="left").pack(anchor="w")
        grid = ttk.Frame(body)
        grid.pack(anchor="w", pady=(12, 0))
        rows = (("Author", ABOUT["author"]), ("License", ABOUT["license"]), ("URL", ABOUT["url"]))
        for r, (k, v) in enumerate(rows):
            ttk.Label(grid, text=k + ":", foreground="#555").grid(row=r, column=0, sticky="w",
                                                                   padx=(0, 8))
            lbl = ttk.Label(grid, text=v)
            lbl.grid(row=r, column=1, sticky="w")
            if k == "URL" and v:
                lbl.config(foreground="#0a58ca", cursor="hand2")
                lbl.bind("<Button-1>", lambda e, u=v: webbrowser.open(u))
        ok = ttk.Button(body, text="OK", command=win.destroy)
        ok.pack(anchor="e", pady=(14, 0))
        win.bind("<Return>", lambda e: win.destroy())
        win.bind("<Escape>", lambda e: win.destroy())
        win.update_idletasks()                      # centre over the main window
        x = self.winfo_rootx() + (self.winfo_width() - win.winfo_width()) // 2
        y = self.winfo_rooty() + (self.winfo_height() - win.winfo_height()) // 3
        win.geometry(f"+{max(x, 0)}+{max(y, 0)}")
        ok.focus_set()
        win.grab_set()

    def _build(self):
        self._build_menu()
        top = ttk.Frame(self, padding=(8, 8, 8, 4))
        top.pack(fill="x")
        self.btn_back = ttk.Button(top, text="◀ Back", command=self.go_back, state="disabled",
                                   width=8)
        self.btn_back.pack(side="left", padx=(0, 6))
        ttk.Label(top, text="Installer:").pack(side="left")
        ttk.Entry(top, textvariable=self.src_var).pack(side="left", fill="x", expand=True, padx=4)
        ttk.Button(top, text="Browse…", command=self.browse_src).pack(side="left")
        ttk.Button(top, text="Folder…", command=self.browse_folder).pack(side="left", padx=(4, 0))
        ttk.Button(top, text="Scan", command=self.scan).pack(side="left", padx=(4, 0))

        inforow = ttk.Frame(self, padding=(10, 0, 8, 4))
        inforow.pack(fill="x")
        self.btn_details = ttk.Button(inforow, text="Details…", command=self.show_details,
                                      state="disabled")
        self.btn_details.pack(side="right")
        self.info = ttk.Label(inforow, text="Open an installer (Inno Setup, MSI, Electron, "
                                            "NSIS, or anything 7-Zip can unpack) or a folder "
                                            "of unpacked files, and press Scan.",
                              foreground="#555")
        self.info.pack(side="left", fill="x", expand=True)

        pane = ttk.PanedWindow(self, orient="horizontal")
        pane.pack(fill="both", expand=True, padx=8)
        self.nb = ttk.Notebook(pane)
        pane.add(self.nb, weight=2)
        self.tab_target = ttk.Frame(self.nb, padding=10)
        self.tab_props = ttk.Frame(self.nb)
        self.tab_feats = ttk.Frame(self.nb, padding=6)
        self.nb.add(self.tab_target, text="Target")
        self.nb.add(self.tab_props, text="Conditions")
        self.tab_inside = ttk.Frame(self.nb, padding=6)
        self.nb.add(self.tab_feats, text="Features")
        self.nb.add(self.tab_inside, text="Inside")
        self._build_props_tab()
        self._build_feats_tab()
        self._build_inside_tab()
        right = ttk.Frame(pane)
        pane.add(right, weight=3)
        self._build_preview(right)
        self._pane = pane
        self.after(50, lambda: pane.sashpos(0, 560))

        bottom = ttk.Frame(self, padding=8)
        bottom.pack(fill="x")
        ttk.Label(bottom, text="Output folder:").grid(row=0, column=0, sticky="w")
        ttk.Entry(bottom, textvariable=self.out_var).grid(row=0, column=1, sticky="ew", padx=4)
        ttk.Button(bottom, text="Browse…", command=self.browse_out).grid(row=0, column=2)
        ttk.Button(bottom, text="Copy command line",
                   command=self.copy_cli).grid(row=0, column=3, padx=(12, 4))
        self.btn_extract = ttk.Button(bottom, text="Extract", command=self.extract,
                                      state="disabled")
        self.btn_extract.grid(row=0, column=4)
        self.btn_open_out = ttk.Button(bottom, text="Open output", state="disabled",
                                       command=lambda: self.last_output and
                                       _open_folder(self.last_output))
        self.btn_open_out.grid(row=0, column=5, padx=(4, 0))
        self.progress = ttk.Progressbar(bottom, mode="determinate")
        self.progress.grid(row=1, column=0, columnspan=6, sticky="ew", pady=(6, 0))
        self.status = ttk.Label(bottom, text="", foreground="#555")
        self.status.grid(row=2, column=0, columnspan=6, sticky="w")
        bottom.columnconfigure(1, weight=1)

    def _build_props_tab(self):
        self.props_help = _wrap(ttk.Label(self.tab_props, padding=(8, 8, 8, 4), justify="left"))
        self.props_help.pack(fill="x")
        holder = ttk.Frame(self.tab_props)
        holder.pack(fill="both", expand=True)
        self.prop_canvas = tk.Canvas(holder, highlightthickness=0)
        sb = ttk.Scrollbar(holder, orient="vertical", command=self.prop_canvas.yview)
        self.prop_frame = ttk.Frame(self.prop_canvas, padding=(8, 0))
        self.prop_frame.bind("<Configure>", lambda e: self.prop_canvas.configure(
            scrollregion=self.prop_canvas.bbox("all")))
        self.prop_canvas.create_window((0, 0), window=self.prop_frame, anchor="nw")
        self.prop_canvas.configure(yscrollcommand=sb.set)
        self.prop_canvas.pack(side="left", fill="both", expand=True)
        sb.pack(side="right", fill="y")
        self.prop_canvas.bind("<Enter>", lambda e: self._wheel(True))
        self.prop_canvas.bind("<Leave>", lambda e: self._wheel(False))
        ttk.Button(self.tab_props, text="Reset all to auto",
                   command=self.reset_props).pack(anchor="e", padx=8, pady=6)

    def _wheel(self, on):
        if on:
            self.bind_all("<MouseWheel>", lambda e: self.prop_canvas.yview_scroll(
                int(-e.delta / 120) or (-1 if e.delta > 0 else 1), "units"))
            self.bind_all("<Button-4>", lambda e: self.prop_canvas.yview_scroll(-3, "units"))
            self.bind_all("<Button-5>", lambda e: self.prop_canvas.yview_scroll(3, "units"))
        else:
            for ev in ("<MouseWheel>", "<Button-4>", "<Button-5>"):
                self.unbind_all(ev)

    def _build_feats_tab(self):
        self.feats_help = _wrap(ttk.Label(self.tab_feats, justify="left"))
        self.feats_help.pack(fill="x", pady=(0, 6))
        frame = ttk.Frame(self.tab_feats)
        frame.pack(fill="both", expand=True)
        self.feat_tree = ttk.Treeview(frame, columns=("include", "state", "files"),
                                      selectmode="browse")
        for col, txt in (("#0", "Name"), ("include", "Include"), ("state", "Result"),
                         ("files", "Files")):
            self.feat_tree.heading(col, text=txt)
        self.feat_tree.column("#0", width=240)
        self.feat_tree.column("include", width=70, anchor="center", stretch=False)
        self.feat_tree.column("state", width=90, anchor="center", stretch=False)
        self.feat_tree.column("files", width=60, anchor="e", stretch=False)
        sb = ttk.Scrollbar(frame, orient="vertical", command=self.feat_tree.yview)
        self.feat_tree.configure(yscrollcommand=sb.set)
        self.feat_tree.pack(side="left", fill="both", expand=True)
        sb.pack(side="right", fill="y")
        self.feat_tree.bind("<Button-1>", self.on_feat_click)
        self.feat_tree.tag_configure("off", foreground="#999")
        self.feat_tree.tag_configure("undecided", foreground="#b36b00")
        self.feat_tree.tag_configure("header", font=("TkDefaultFont", 9, "bold"))
        btns = ttk.Frame(self.tab_feats)
        btns.pack(fill="x", pady=(6, 0))
        ttk.Button(btns, text="All auto", command=self.feats_all_auto).pack(side="right")
        ttk.Button(btns, text="Force undecided ON",
                   command=lambda: self.feats_force_undecided(True)).pack(side="right", padx=4)
        ttk.Button(btns, text="Force undecided OFF",
                   command=lambda: self.feats_force_undecided(False)).pack(side="right")

    def _build_preview(self, parent):
        head = ttk.Frame(parent, padding=(6, 0))
        head.pack(fill="x")
        self.summary = ttk.Label(head, text="", font=("TkDefaultFont", 10, "bold"))
        self.summary.pack(side="left")
        cb = ttk.Combobox(head, textvariable=self.filter_var, state="readonly", width=18,
                          values=["All selected", "Undecided only", "Excluded"])
        cb.pack(side="right")
        cb.bind("<<ComboboxSelected>>", lambda e: self.fill_preview())
        ttk.Label(head, text="Show:").pack(side="right", padx=4)
        frame = ttk.Frame(parent, padding=(6, 4, 0, 0))
        frame.pack(fill="both", expand=True)
        self.files = ttk.Treeview(frame, columns=("dest", "key", "status"), show="headings")
        for col, txt, w in (("dest", "Destination", 420), ("key", "Source", 200),
                            ("status", "Status", 300)):
            self.files.heading(col, text=txt)
            self.files.column(col, width=w, stretch=(col != "key"))
        sy = ttk.Scrollbar(frame, orient="vertical", command=self.files.yview)
        sx = ttk.Scrollbar(frame, orient="horizontal", command=self.files.xview)
        self.files.configure(yscrollcommand=sy.set, xscrollcommand=sx.set)
        self.files.grid(row=0, column=0, sticky="nsew")
        sy.grid(row=0, column=1, sticky="ns")
        sx.grid(row=1, column=0, sticky="ew")
        frame.rowconfigure(0, weight=1)
        frame.columnconfigure(0, weight=1)
        self.files.tag_configure("undecided", foreground="#b36b00")
        self.files.tag_configure("excluded", foreground="#999")

    # ---------------------------------------------------------------- scan --
    def browse_src(self):
        p = filedialog.askopenfilename(filetypes=[
            ("Installers", "*.msi *.exe"), ("Windows Installer", "*.msi"),
            ("Inno Setup", "*.exe"), ("Inno script", "*.iss"), ("All files", "*.*")])
        if p:
            self.src_var.set(p)
            self.scan()

    def browse_folder(self):
        p = filedialog.askdirectory(title="Folder of unpacked files (or extracted by innounp)")
        if p:
            self.src_var.set(p)
            self.scan()

    def browse_out(self):
        p = filedialog.askdirectory()
        if p:
            self.out_var.set(p)

    def _log(self, msg):
        self.status.config(text=msg)
        self.update_idletasks()

    def scan(self, path=None, mode="new"):
        """Open `path` (default: the Installer box) in the background.
        mode 'new' replaces whatever is open; 'nested' (from the Inside tab) keeps
        the current one so Back can return to it."""
        if self._busy:
            return
        path = (path or self.src_var.get()).strip().strip('"')
        if not path:
            return
        if not os.path.exists(path):
            messagebox.showerror("Scan", f"Not found:\n{path}")
            return
        path = os.path.abspath(path)
        self._busy = True
        self.btn_extract.config(state="disabled")
        self.progress.config(mode="indeterminate")
        self.progress.start(12)
        self.config(cursor="watch")
        self._log(f"Scanning {os.path.basename(path) or path}…")

        def log(m):
            self.q.put(("status", str(m).strip()))

        def work():
            try:
                proj = open_project(path, log)
            except Exception as e:
                self.q.put(("scan_failed", path, str(e)))
                return
            if getattr(proj, "unpacked", False) and detect.die_available():
                log("Asking Detect It Easy what it is…")
                try:
                    proj.die_lines = detect.detect_with_die(path)
                except Exception as e:
                    proj.die_lines = [f"(Detect It Easy failed: {e})"]
            self.q.put(("scanned", path, proj, mode))
        threading.Thread(target=work, daemon=True).start()
        self.after(100, self._poll)

    def _drop_all(self):
        for p in [self.proj] + self.stack:
            if p:
                p.cleanup()
        self.proj, self.stack = None, []

    def _apply_project(self, proj, mode):
        if mode == "nested" and self.proj:
            self.stack.append(self.proj)           # keep the parent (and its files) for Back
        elif mode == "back":
            if self.proj:
                self.proj.cleanup()
        else:
            self._drop_all()
        self.proj = proj
        self.src_var.set(proj.path)
        self.bands = proj.bands()
        self.feat_override.clear()
        if self.stack:                              # inner installer: output next to the outer one
            top = self.stack[0].path
            base = top if os.path.isdir(top) else os.path.dirname(top)
            stem = os.path.splitext(os.path.basename(proj.path))[0]
            self.out_var.set(os.path.join(base, "_sorted", stem))
        else:
            base = proj.path if os.path.isdir(proj.path) else os.path.dirname(proj.path)
            self.out_var.set(getattr(proj, "default_output", None) or os.path.join(base, "_sorted"))
        info = proj.info_text()
        if self.stack:
            info = ("inside " + " › ".join(os.path.basename(p.path) for p in self.stack) +
                    "  ·  " + info)
        self.info.config(text=info)
        self.nb.tab(1, text=proj.decider_label)
        self.nb.tab(2, text=proj.feature_label)
        self.props_help.config(text=proj.decider_help)
        self.feats_help.config(text=proj.feature_help)
        self._fill_target()
        self._fill_props()
        self._fill_features()
        self._fill_inside()
        self.btn_back.config(state="normal" if self.stack else "disabled")
        self.btn_details.config(state="normal")
        self.btn_extract.config(state="normal")
        self.status.config(text=self._loaded_message(proj, mode))
        self.recompute()

    def _loaded_message(self, proj, mode):
        name = os.path.basename(proj.path) or proj.path
        if mode == "back":
            head = f"Back to {name}."
        elif getattr(proj, "unpacked", False):
            what = f"{proj.source_kind} installer" if proj.source_kind else "it"
            head = (f"Opened {name}: unpacked {what} with 7-Zip, {len(proj.items)} files, "
                    "sorted by PE header / path.")
        elif isinstance(proj, generic.GenericProject):
            head = f"Opened folder {name}: {len(proj.items)} files, sorted by PE header / path."
        else:
            head = f"Opened {name} as {proj.kind}."
        nested = getattr(proj, "nested", None)
        if nested is None:
            return head
        inst = [n for n in nested if n[4]]
        if inst:
            return head + (f"  {len(inst)} installer{'s' if len(inst) != 1 else ''} inside: "
                           "see the Inside tab.")
        return head + "  Nothing inside looks like another installer."

    def go_back(self):
        if self._busy or not self.stack:
            return
        self._apply_project(self.stack.pop(), "back")

    def show_details(self):
        p = self.proj
        if not p:
            return
        rows = [f"File: {p.path}", f"Read as: {p.kind}", "", p.info_text()]
        if self.stack:
            rows += ["", "Opened from: " + " › ".join(q.path for q in self.stack)]
        if getattr(p, "unpacked", False):
            rows += ["", f"Structure check: {p.source_kind or 'not a known installer type'}",
                     f"Unpacked (temporary) to: {p.root}"]
        lines = getattr(p, "die_lines", None)
        if lines:
            rows += ["", "Detect It Easy:"] + [f"    {ln}" for ln in lines[:12]]
        elif getattr(p, "unpacked", False) and not detect.die_available():
            rows += ["", "Detect It Easy: not available (bin\\die\\diec.exe)"]
        nested = getattr(p, "nested", None)
        if nested is not None:
            inst = [n for n in nested if n[4]]
            rows += ["", f"Installers inside: {len(inst)}"]
            rows += [f"    {n[2]:<16} {n[1]}" for n in inst[:15]]
            rows.append(f"Other programs inside: {len(nested) - len(inst)}")
        messagebox.showinfo(f"Details: {os.path.basename(p.path)}", "\n".join(rows))

    # ------------------------------------------------------------- Inside --
    def _build_inside_tab(self):
        self.inside_help = _wrap(ttk.Label(self.tab_inside, justify="left",
                                           text="Installers found inside what you opened "
                                                "are listed here."))
        self.inside_help.pack(fill="x", pady=(0, 6))
        frame = ttk.Frame(self.tab_inside)
        frame.pack(fill="both", expand=True)
        self.inside_tree = ttk.Treeview(frame, columns=("kind", "size"), selectmode="browse")
        self.inside_tree.heading("#0", text="File")
        self.inside_tree.heading("kind", text="Type")
        self.inside_tree.heading("size", text="Size")
        self.inside_tree.column("#0", width=260)
        self.inside_tree.column("kind", width=110, anchor="center", stretch=False)
        self.inside_tree.column("size", width=80, anchor="e", stretch=False)
        self.inside_tree.tag_configure("program", foreground="#777")
        sb = ttk.Scrollbar(frame, orient="vertical", command=self.inside_tree.yview)
        self.inside_tree.configure(yscrollcommand=sb.set)
        self.inside_tree.pack(side="left", fill="both", expand=True)
        sb.pack(side="right", fill="y")
        self.inside_tree.bind("<Double-1>", lambda e: self.open_nested())
        btns = ttk.Frame(self.tab_inside)
        btns.pack(fill="x", pady=(6, 0))
        self.show_programs = tk.BooleanVar(value=False)
        ttk.Checkbutton(btns, text="Also list plain programs (.exe)",
                        variable=self.show_programs,
                        command=self._fill_inside).pack(side="left")
        self.btn_open_nested = ttk.Button(btns, text="Open selected", state="disabled",
                                          command=self.open_nested)
        self.btn_open_nested.pack(side="right")
        self.btn_show_unpacked = ttk.Button(btns, text="Show unpacked files", state="disabled",
                                            command=lambda: self.proj and
                                            _open_folder(getattr(self.proj, "root", "")))
        self.btn_show_unpacked.pack(side="right", padx=4)
        self.inside_rows = []

    def _fill_inside(self):
        t = self.inside_tree
        t.delete(*t.get_children())
        self.inside_rows = []
        p = self.proj
        nested = getattr(p, "nested", None) if p else None
        self.btn_show_unpacked.config(state="normal" if getattr(p, "root", None) else "disabled")
        if nested is None:
            self.nb.tab(3, text="Inside")
            self.btn_open_nested.config(state="disabled")
            self.inside_help.config(text=(
                f"Nothing to list: {p.kind} installers are read through their own install "
                "rules, not unpacked generically." if p else
                "Installers found inside what you opened are listed here."))
            return
        name = os.path.basename(p.path) or p.path
        inst = [n for n in nested if n[4]]
        progs = [n for n in nested if not n[4]]
        rows = inst + (progs if self.show_programs.get() else [])
        for i, (path, rel, kind, size, is_inst) in enumerate(rows):
            t.insert("", "end", iid=str(i), text=rel, values=(kind, _size(size)),
                     tags=() if is_inst else ("program",))
        self.inside_rows = rows
        self.nb.tab(3, text=f"Inside ({len(inst)})" if inst else "Inside")
        if inst:
            msg = (f"Installers inside {name}, recognised by their structure (not just by "
                   "being an .exe). Open one to scan it here; ◀ Back returns to "
                   f"{name} without unpacking it again.")
        else:
            msg = f"Nothing inside {name} looks like another installer."
        if progs and not self.show_programs.get():
            msg += (f"  {len(progs)} plain program{'s' if len(progs) != 1 else ''} not listed "
                    "(tick below to show them; they can be opened the same way to try "
                    "unpacking them).")
        elif progs:
            msg += "  Plain programs are greyed: usually the app itself, not installers."
        self.inside_help.config(text=msg)
        if rows:
            t.selection_set("0")
            t.focus("0")
        self.btn_open_nested.config(state="normal" if rows else "disabled")

    def open_nested(self):
        sel = self.inside_tree.selection()
        if not sel or self._busy:
            return
        path = self.inside_rows[int(sel[0])][0]
        self.scan(path, mode="nested")

    def _fill_target(self):
        for w in self.tab_target.winfo_children():
            w.destroy()
        proj = self.proj
        arches = proj.arches()
        self.all_label = None
        if self.supports_all():
            box = ttk.LabelFrame(self.tab_target, text="What to extract", padding=8)
            box.pack(fill="x", pady=(0, 8))
            ttk.Checkbutton(box, variable=self.opt_all, command=self.recompute,
                            text="Every architecture and Windows version "
                                 "(one folder per profile)").pack(anchor="w")
            self.all_label = _wrap(ttk.Label(box, foreground="#555", justify="left"))
            self.all_label.pack(fill="x", pady=(4, 0))
        box = ttk.LabelFrame(self.tab_target, text="Architecture", padding=8)
        box.pack(fill="x")
        _wrap(ttk.Label(box, text=proj.arch_note(), foreground="#555")).pack(fill="x")
        if self.arch_var.get() not in arches:
            self.arch_var.set("x64" if "x64" in arches else arches[0])
        for a in arches:
            ttk.Radiobutton(box, text=ARCH_TEXT.get(a, a), value=a, variable=self.arch_var,
                            command=self.recompute).pack(anchor="w")

        box = ttk.LabelFrame(self.tab_target, text="Windows version", padding=8)
        box.pack(fill="x", pady=8)
        if len(self.bands) == 1:
            _wrap(ttk.Label(box, foreground="#555", text="Nothing in this installer "
                            "depends on the Windows version.")).pack(fill="x")
        else:
            _wrap(ttk.Label(box, foreground="#555", text=proj.band_hint())).pack(fill="x")
        self.band_var.set(len(self.bands) - 1)
        for i, band in enumerate(self.bands):
            ttk.Radiobutton(box, text=proj.band_text(band), value=i, variable=self.band_var,
                            command=self.recompute).pack(anchor="w")

        self.opt_vars = {}
        for key, label, values in proj.options():
            box = ttk.LabelFrame(self.tab_target, text=label, padding=8)
            box.pack(fill="x", pady=(0, 8))
            var = tk.StringVar(value=values[0])
            cb = ttk.Combobox(box, textvariable=var, values=values, state="readonly")
            cb.pack(anchor="w")
            cb.bind("<<ComboboxSelected>>", lambda e: self.recompute())
            self.opt_vars[key] = var

        box = ttk.LabelFrame(self.tab_target, text="Options", padding=8)
        box.pack(fill="x")
        for var, txt in ((self.opt_unknown_empty, proj.unknown_option),
                         (self.opt_default, proj.default_option),
                         (self.opt_skip_cond, "Leave out files that are still undecided"),
                         (self.opt_prune, "Drop wrong-arch binaries by PE header (at extract time)")):
            if txt is None:                       # option means nothing for this backend
                var.set(False)
                continue
            ttk.Checkbutton(box, text=txt, variable=var, command=self.recompute).pack(anchor="w")

        for note in proj.notes():
            _wrap(ttk.Label(self.tab_target, foreground="#555", padding=(0, 8),
                            text=note)).pack(fill="x")

    def _fill_props(self):
        for w in self.prop_frame.winfo_children():
            w.destroy()
        self.prop_vars.clear()
        self.prop_maps.clear()
        deciders = self.proj.deciders()
        if not deciders:
            ttk.Label(self.prop_frame, padding=8,
                      text="Nothing here: no conditions depend on values the script "
                           "cannot work out itself.").grid(row=0, column=0)
            return
        for r, d in enumerate(deciders):
            mapping = {d.auto_text: AUTO, UNDECIDED: UNDECIDED}
            if getattr(d, "allow_not_set", False):
                mapping[NOT_SET] = NOT_SET
            for val, note in d.choices:
                mapping[f"{val}   ({note})" if note else val] = val
            var = tk.StringVar(value=d.auto_text)
            self.prop_vars[d.name] = var
            self.prop_maps[d.name] = mapping
            ttk.Label(self.prop_frame, text=d.name, font=("TkDefaultFont", 9, "bold")
                      ).grid(row=2 * r, column=0, sticky="w", pady=(6, 0))
            free = getattr(d, "allow_not_set", False)       # MSI: any value can be typed
            cb = ttk.Combobox(self.prop_frame, textvariable=var, values=list(mapping),
                              width=26, state="normal" if free else "readonly")
            cb.grid(row=2 * r, column=1, sticky="w", padx=6, pady=(6, 0))
            cb.bind("<<ComboboxSelected>>", lambda e: self.recompute())
            if free:
                cb.bind("<KeyRelease>", lambda e: self.recompute(delay=600))
            ttk.Label(self.prop_frame, text=d.info, foreground="#666"
                      ).grid(row=2 * r + 1, column=0, columnspan=2, sticky="w")
        self.prop_canvas.yview_moveto(0)

    def reset_props(self):
        for name, var in self.prop_vars.items():
            var.set(next(iter(self.prop_maps[name])))
        self.recompute()

    def _fill_features(self):
        t = self.feat_tree
        t.delete(*t.get_children())
        self.toggleable = set()
        for iid, parent, text, n, toggle in self.proj.features():
            if parent and not t.exists(parent):
                parent = ""
            t.insert(parent, "end", iid=iid, text=text, open=True,
                     values=(AUTO if toggle else "", "", n),
                     tags=() if toggle else ("header",))
            if toggle:
                self.toggleable.add(iid)

    def on_feat_click(self, ev):
        if self.feat_tree.identify_column(ev.x) != "#1":
            return
        f = self.feat_tree.identify_row(ev.y)
        if not f or f not in self.toggleable:
            return
        nxt = {None: True, True: False, False: None}[self.feat_override.get(f)]
        if nxt is None:
            self.feat_override.pop(f, None)
        else:
            self.feat_override[f] = nxt
        self.recompute()
        return "break"

    def feats_all_auto(self):
        self.feat_override.clear()
        self.recompute()

    def feats_force_undecided(self, on):
        for f, (s, _) in self.preview_fstates.items():
            if s is None and f not in self.feat_override:
                self.feat_override[f] = on
        self.recompute()

    # ------------------------------------------------------------ compute --
    def supports_all(self):
        return bool(getattr(self.proj, "supports_all", False))

    def all_mode(self):
        return self.supports_all() and self.opt_all.get()

    def compute_all(self):
        return common.all_profiles(self.proj, self.values(), dict(self.feat_override),
                                 self.opts(), skip_undecided=self.opt_skip_cond.get())

    def values(self):
        out = {}
        for name, var in self.prop_vars.items():
            txt = var.get()
            val = self.prop_maps[name].get(txt, txt.strip())
            if val == AUTO or txt.startswith(AUTO + ":"):
                continue
            out[name] = None if val == UNDECIDED else ("" if val == NOT_SET else val)
        return out

    def opts(self):
        o = dict(unknown_empty=self.opt_unknown_empty.get(), default_only=self.opt_default.get(),
                 prune=self.opt_prune.get())
        for k, v in self.opt_vars.items():
            o[k] = v.get()
        return o

    def compute_profile(self):
        band = self.bands[self.band_var.get()]
        prof, fstates, errors = self.proj.compute(self.arch_var.get(), band, self.values(),
                                                  dict(self.feat_override), self.opts())
        if self.opt_skip_cond.get():
            for k in [k for k, s in prof.sel.items() if s.conditional]:
                s = prof.sel.pop(k)
                prof.dropped.append((s.key, "undecided (left out)"))
        return prof, fstates, errors

    def recompute(self, delay=150):
        if not self.proj:
            return
        if self._pending:
            self.after_cancel(self._pending)
        self._pending = self.after(delay, self._do_recompute)

    def _do_recompute(self):
        self._pending = None
        self.preview, self.preview_fstates, errors = self.compute_profile()
        p = self.preview
        und = sum(1 for s in p.sel.values() if s.conditional)
        text = (f"{p.label}  ·  {len(p.sel)} files  ·  {und} undecided  ·  "
                f"{len(p.dropped)} excluded")
        if self.all_label is not None:
            if self.all_mode():
                self.all_preview = self.compute_all()
                rows = [f"{q.label}   ({q.range_text()}, {len(q.sel)} files)"
                        for q in self.all_preview]
                self.all_label.config(text=(
                    f"Extract writes {len(rows)} folders:\n    " + "\n    ".join(rows) +
                    "\n\nThe Architecture / Windows version choices below only pick "
                    "which profile is shown in the preview."))
                text += f"   (preview; Extract writes all {len(rows)} profiles)"
            else:
                self.all_preview = []
                self.all_label.config(text="Off: Extract writes only the architecture and "
                                           "Windows version chosen below.")
        self.summary.config(text=text)
        for iid in self.toggleable:
            if not self.feat_tree.exists(iid):
                continue
            s, _ = self.preview_fstates.get(iid, (False, set()))
            inc = {None: AUTO, True: "on", False: "off"}[self.feat_override.get(iid)]
            res = {True: "on", False: "off", None: UNDECIDED}[s]
            self.feat_tree.item(iid, values=(inc, res, self.feat_tree.set(iid, "files")),
                                tags={True: (), False: ("off",), None: ("undecided",)}[s])
        if errors:
            self.status.config(text="Note: " + "; ".join(sorted(errors))[:300])
        self.fill_preview()

    def fill_preview(self):
        t = self.files
        t.delete(*t.get_children())
        p = self.preview
        if not p:
            return
        mode = self.filter_var.get()
        if mode == "Excluded":
            for key, why in p.dropped:
                t.insert("", "end", values=(self.proj.dest_of(key), key, why), tags=("excluded",))
            return
        for s in p.sel.values():
            if mode == "Undecided only" and not s.conditional:
                continue
            t.insert("", "end", values=(s.dest, s.key, s.why if s.conditional else "included"),
                     tags=(("undecided",) if s.conditional else ()))

    # ----------------------------------------------------------- outputs --
    def copy_cli(self):
        if not self.proj:
            return
        cmd, skipped = self.proj.cli_command(*self.cli_args())
        self.clipboard_clear()
        self.clipboard_append(cmd)
        msg = "Command line copied to the clipboard."
        if skipped:
            msg += "  (Forced-undecided values have no CLI equivalent: " + ", ".join(skipped) + ")"
        if self.opt_skip_cond.get() and isinstance(self.proj, msi.MsiProject):
            msg += "  ('Leave out undecided files' is GUI-only.)"
        self.status.config(text=msg)

    def cli_args(self):
        opts = self.opts()
        if self.supports_all():
            opts["skip_undecided"] = self.opt_skip_cond.get()
            if not self.opt_all.get():
                opts["single_band"] = self.band_var.get()
                return self.arch_var.get(), self.values(), self.feat_override, opts
            return None, self.values(), self.feat_override, opts
        return self.arch_var.get(), self.values(), self.feat_override, opts

    def extract(self):
        if self._busy or not self.proj:
            return
        out_root = self.out_var.get().strip()
        if not out_root:
            messagebox.showerror("Extract", "Choose an output folder.")
            return
        if self.all_mode():
            profs = self.compute_all()
            if not profs:
                messagebox.showerror("Extract", "Nothing to extract.")
                return
            existing = [q.label for q in profs if os.path.exists(os.path.join(out_root, q.label))]
            if existing and not messagebox.askyesno(
                    "Extract", f"{out_root}\nalready has: {', '.join(existing)}\n\nReplace them?"):
                return
            for lbl in existing:
                shutil.rmtree(os.path.join(out_root, lbl), ignore_errors=True)
        else:
            prof, _, _ = self.compute_profile()
            profs = [prof]
            pdir = os.path.join(out_root, prof.label)
            if os.path.exists(pdir):
                if not messagebox.askyesno("Extract", f"{pdir}\nalready exists. Replace it?"):
                    return
                shutil.rmtree(pdir)
        values = self.values()
        settings = [f"Source       : {self.proj.path}"]
        settings += [f"Set          : {k} = {'(undecided)' if v is None else repr(v)}"
                     for k, v in sorted(values.items())]
        settings += [f"Forced       : {f} {'on' if on else 'off'}"
                     for f, on in sorted(self.feat_override.items())]
        settings.append("Command line : " + self.proj.cli_command(*self.cli_args())[0])
        writer = common.write_profile

        self._busy = True
        self.btn_extract.config(state="disabled")
        self.progress.config(mode="indeterminate")
        self.progress.start(12)
        if self.all_mode():
            threading.Thread(target=self._worker_all, daemon=True,
                             args=(profs, out_root, self.opt_prune.get(), settings)).start()
        else:
            threading.Thread(target=self._worker, daemon=True,
                             args=(prof, pdir, self.opt_prune.get(), settings, writer)).start()
        self.after(100, self._poll)

    def _worker(self, prof, pdir, prune, settings, writer):
        work = tempfile.mkdtemp(prefix="splitter_")
        try:
            self.q.put(("status", "Extracting…"))
            located = self.proj.extract(work, log=lambda m: self.q.put(("status", m.strip())))
            if prune:
                common.prune_by_pe([prof], located)
            self.q.put(("start_copy", len(prof.sel)))
            writer(pdir, prof, located, settings,
                   progress=lambda i, n: self.q.put(("prog", i, n)))
            missing = sum(1 for s in prof.sel.values() if not located.get(s.key))
            self.q.put(("done", pdir, len(prof.sel), len(prof.pruned), missing))
        except Exception as e:
            self.q.put(("error", str(e)))
        finally:
            shutil.rmtree(work, ignore_errors=True)

    def _worker_all(self, profs, out_root, prune, settings):
        work = tempfile.mkdtemp(prefix="splitter_")
        try:
            self.q.put(("status", "Extracting…"))
            located = self.proj.extract(work, log=lambda m: self.q.put(("status", m.strip())))
            if prune:
                common.prune_by_pe(profs, located)
            total = sum(len(p.sel) for p in profs)
            self.q.put(("start_copy", total))
            common.write_all(out_root, profs, located, self.proj, settings,
                           progress=lambda i, n: self.q.put(("prog", i, n)))
            missing = sum(1 for p in profs for s in p.sel.values() if not located.get(s.key))
            pruned = sum(len(p.pruned) for p in profs)
            self.q.put(("done_all", out_root, [p.label for p in profs], total, pruned, missing))
        except Exception as e:
            self.q.put(("error", str(e)))
        finally:
            shutil.rmtree(work, ignore_errors=True)

    def _poll(self):
        try:
            while True:
                msg = self.q.get_nowait()
                kind = msg[0]
                if kind == "status":
                    self.status.config(text=msg[1])
                elif kind == "start_copy":
                    self.progress.stop()
                    self.progress.config(mode="determinate", maximum=max(msg[1], 1), value=0)
                    self.status.config(text="Copying files…")
                elif kind == "prog":
                    self.progress.config(value=msg[1])
                elif kind == "done":
                    _, pdir, n, pruned, missing = msg
                    self._finish()
                    text = f"Done: {n} files written to {pdir}"
                    if pruned:
                        text += f"  ({pruned} dropped by PE check)"
                    if missing:
                        text += f"  - {missing} missing, see _PROFILE.txt"
                    self._extracted(pdir, text)
                    return
                elif kind == "done_all":
                    _, out_root, labels, n, pruned, missing = msg
                    self._finish()
                    text = f"Done: {len(labels)} profiles, {n} files written to {out_root}"
                    if pruned:
                        text += f"  ({pruned} dropped by PE check)"
                    if missing:
                        text += f"  - {missing} missing, see _PROFILE.txt"
                    self._extracted(out_root, text + "  (" + ", ".join(labels) + ")")
                    return
                elif kind == "scanned":
                    _, path, proj, mode = msg
                    self._finish()
                    self._apply_project(proj, mode)
                    return
                elif kind == "scan_failed":
                    _, path, err = msg
                    self._finish()
                    name = os.path.basename(path) or path
                    first = err.strip().splitlines()[0] if err.strip() else "unknown error"
                    self.status.config(text=f"Could not open {name}: {first}"
                                       + ("  (still showing the previous one)" if self.proj
                                          else ""))
                    messagebox.showerror("Could not open", f"{name}\n\n{err}")
                    return
                elif kind == "error":
                    self._finish()
                    self.status.config(text="Failed.")
                    messagebox.showerror("Extract failed", msg[1])
                    return
        except queue.Empty:
            pass
        self.after(100, self._poll)

    def _extracted(self, folder, text):
        self.last_output = folder
        self.btn_open_out.config(state="normal")
        self.status.config(text=text + "   - Open output to see it.")

    def _finish(self):
        self._busy = False
        self.config(cursor="")
        self.progress.stop()
        self.progress.config(mode="determinate", value=0)
        self.btn_extract.config(state="normal" if self.proj else "disabled")

    def destroy(self):
        self._drop_all()
        super().destroy()


def _size(n):
    return f"{n / 1048576:,.1f} MB" if n >= 104858 else f"{n / 1024:,.0f} KB"


def _wrap(label):
    label.bind("<Configure>", lambda e: label.configure(wraplength=max(e.width - 12, 100)))
    return label


def _open_folder(path):
    try:
        if os.name == "nt":
            os.startfile(path)
        elif sys.platform == "darwin":
            subprocess.Popen(["open", path])
        else:
            subprocess.Popen(["xdg-open", path])
    except Exception:
        pass


def main():
    if sys.platform.startswith("win"):
        try:                                       # own taskbar group + icon, not python's
            import ctypes
            ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(
                f"{SCRIPT_AUTHOR}.{SCRIPT_NAME}.{SCRIPT_VERSION}")
        except Exception:
            pass
    args = [a for a in sys.argv[1:] if a != "--no-splash"]
    splash = 0.0 if "--no-splash" in sys.argv[1:] else SPLASH_SECONDS
    App(args[0] if args else None, splash_seconds=splash).mainloop()


if __name__ == "__main__":
    main()
