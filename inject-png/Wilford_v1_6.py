#!/usr/bin/env python3
"""
Wilford.py - hide/extract arbitrary payloads inside PNG files as custom 'puNk' chunks.

Usage:
    Wilford.py list    <file.png>
    Wilford.py inject  <in.png> <out.png> <payload> [--max-size SIZE]
    Wilford.py extract <in.png> <payload.out> [--all]

Changelog:
    v1.5  colored console output (help, listings, status, warnings, errors).
          Color auto-disables when output isn't a terminal, when NO_COLOR is
          set, and is forced on with FORCE_COLOR. No new dependencies.
          Fix: inject now writes the PNG signature to the output (previous
          versions produced a file missing its 8-byte header, so the result
          was not a valid PNG and could not be listed, extracted, or viewed).
    v1.4  streaming I/O, atomic output, disk-space and size preflight checks.
"""

from __future__ import annotations

import argparse
import binascii
import contextlib
import os
import re
import shutil
import struct
import sys
import tempfile
from pathlib import Path
from typing import BinaryIO

__version__ = "1.5"


# --------------------------------------------------------------------------- #
# Program name (frozen-aware)
# --------------------------------------------------------------------------- #

def _prog_name() -> str:
    """Best name to show in help/usage text.

    * Frozen by PyInstaller -> sys.argv[0] is the .exe path (e.g. Wilford.exe)
    * Run as `python Wilford.py` -> sys.argv[0] is the script path
    * Run via shebang -> sys.argv[0] is the invocation path

    In all three cases Path(...).name gives what the user actually typed.
    """
    try:
        name = Path(sys.argv[0]).name
    except (IndexError, TypeError):
        name = ""
    return name or "Wilford"


PROG = _prog_name()


# --------------------------------------------------------------------------- #
# Constants
# --------------------------------------------------------------------------- #

PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"
CHUNK_TYPE_END = b"IEND"
CHUNK_TYPE_PUNK = b"puNk"
MAX_CHUNK_SIZE = 2**31 - 1
BYTES_IN_KB = 1024
STREAM_BUF = 65536  # 64 KiB


class PngError(Exception):
    """Raised when the input is not valid/parseable PNG data."""


# --------------------------------------------------------------------------- #
# Color
#
# ANSI SGR codes, inserted only when the destination stream is a real terminal
# (and NO_COLOR isn't set). Every helper is a no-op when color is off, so the
# rest of the program can paint unconditionally. Help text is colored by
# inserting codes into already-laid-out strings, so column alignment is never
# affected (the codes are zero-width on screen).
# --------------------------------------------------------------------------- #

class _Sgr:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    MAGENTA = "\033[35m"
    CYAN = "\033[36m"


def _enable_windows_vt() -> None:
    """Turn on ANSI escape handling in legacy Windows consoles."""
    if sys.platform != "win32":
        return
    try:
        import ctypes

        kernel32 = ctypes.windll.kernel32
        enable_vt = 0x0004  # ENABLE_VIRTUAL_TERMINAL_PROCESSING
        for handle_id in (-11, -12):  # STDOUT, STDERR
            handle = kernel32.GetStdHandle(handle_id)
            mode = ctypes.c_uint32()
            if kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
                kernel32.SetConsoleMode(handle, mode.value | enable_vt)
    except Exception:
        pass


def _supports_color(stream) -> bool:
    if os.environ.get("NO_COLOR") is not None:
        return False
    if os.environ.get("FORCE_COLOR"):
        return True
    try:
        return bool(stream.isatty())
    except (AttributeError, ValueError):
        return False


_enable_windows_vt()
COLOR_STDOUT = _supports_color(sys.stdout)
COLOR_STDERR = _supports_color(sys.stderr)


def paint(text: str, *codes: str, err: bool = False) -> str:
    """Wrap text in SGR codes if color is enabled for the target stream."""
    enabled = COLOR_STDERR if err else COLOR_STDOUT
    if not enabled or not codes:
        return text
    return "".join(codes) + text + _Sgr.RESET


# help-text helpers (stdout) ------------------------------------------------- #

def _hdr(text: str) -> str:
    return paint(text, _Sgr.BOLD, _Sgr.CYAN)


def _example(tail: str) -> str:
    """One example command line: colored prog name, plain arguments.
    Any --flags in the tail get colored later by the help formatter."""
    return f"  {paint(PROG, _Sgr.CYAN)} {tail}"


def _comment(text: str) -> str:
    return "  " + paint("# " + text, _Sgr.DIM)


_OPTION_RE = re.compile(r"(?<![\w-])(--?[A-Za-z][\w-]*)")


def _color_options(text: str) -> str:
    """Green-ify option flags (-h, --all, --max-size, ...) in finished help
    text. Insertion is zero-width, so nothing shifts."""
    return _OPTION_RE.sub(lambda m: paint(m.group(1), _Sgr.GREEN), text)


# --------------------------------------------------------------------------- #
# I/O helpers
# --------------------------------------------------------------------------- #

def read_exact(f: BinaryIO, count: int, what: str) -> bytes:
    data = f.read(count)
    if len(data) != count:
        raise PngError(
            f"Unexpected end of file while reading {what} "
            f"(wanted {count} bytes, got {len(data)})"
        )
    return data


def _remaining_in_file(f: BinaryIO) -> int:
    try:
        return os.fstat(f.fileno()).st_size - f.tell()
    except (OSError, AttributeError, ValueError):
        return -1


def file_length(f: BinaryIO) -> int:
    pos = f.tell()
    f.seek(0, 2)
    length = f.tell()
    f.seek(pos)
    return length


def open_png(path: Path) -> BinaryIO:
    f = path.open("rb")
    try:
        sig = f.read(len(PNG_SIGNATURE))
        if sig != PNG_SIGNATURE:
            raise PngError(f"{path} is not a PNG file")
    except Exception:
        f.close()
        raise
    return f


@contextlib.contextmanager
def atomic_output(path: Path):
    """Write to a sibling temp file and atomically rename on success."""
    out_dir = path.parent
    f = tempfile.NamedTemporaryFile(
        mode="wb", delete=False, dir=out_dir,
        prefix=path.name + ".", suffix=".tmp",
    )
    tmp = Path(f.name)
    try:
        yield f
        f.close()
        os.replace(tmp, path)
        tmp = None
    finally:
        if not f.closed:
            f.close()
        if tmp is not None and tmp.exists():
            try:
                tmp.unlink()
            except OSError:
                pass


# --------------------------------------------------------------------------- #
# PNG chunk primitives (all streaming)
# --------------------------------------------------------------------------- #

def read_chunk_header(f: BinaryIO) -> tuple[int, bytes]:
    size = struct.unpack("!I", read_exact(f, 4, "chunk length"))[0]
    if size > MAX_CHUNK_SIZE:
        raise PngError(
            f"Chunk length {size} exceeds PNG maximum of {MAX_CHUNK_SIZE}"
        )
    remaining = _remaining_in_file(f)
    if remaining >= 0 and remaining < 8 + size:
        raise PngError(
            f"Chunk claims {size} bytes of content, but only "
            f"{max(0, remaining - 8)} bytes remain in the file"
        )
    chunk_type = read_exact(f, 4, "chunk type")
    return size, chunk_type


def stream_content(
    f: BinaryIO,
    size: int,
    chunk_type: bytes,
    sink: BinaryIO | None = None,
) -> bool:
    crc = binascii.crc32(chunk_type)
    remaining = size
    while remaining > 0:
        buf = f.read(min(remaining, STREAM_BUF))
        if not buf:
            raise PngError(
                f"Unexpected end of file mid-chunk ({remaining} bytes short)"
            )
        if sink is not None:
            sink.write(buf)
        crc = binascii.crc32(buf, crc)
        remaining -= len(buf)
    crc_bytes = read_exact(f, 4, "chunk CRC")
    return (crc & 0xFFFFFFFF) == struct.unpack("!I", crc_bytes)[0]


def copy_chunk(
    inf: BinaryIO, outf: BinaryIO, size: int, chunk_type: bytes
) -> bool:
    outf.write(struct.pack("!I", size))
    outf.write(chunk_type)
    crc = binascii.crc32(chunk_type)
    remaining = size
    while remaining > 0:
        buf = inf.read(min(remaining, STREAM_BUF))
        if not buf:
            raise PngError(
                f"Unexpected end of file mid-chunk ({remaining} bytes short)"
            )
        outf.write(buf)
        crc = binascii.crc32(buf, crc)
        remaining -= len(buf)
    crc_bytes = read_exact(inf, 4, "chunk CRC")
    outf.write(crc_bytes)
    return (crc & 0xFFFFFFFF) == struct.unpack("!I", crc_bytes)[0]


def _write_punk_chunk(outf: BinaryIO, src: BinaryIO, size: int) -> None:
    outf.write(struct.pack("!I", size))
    outf.write(CHUNK_TYPE_PUNK)
    crc = binascii.crc32(CHUNK_TYPE_PUNK)
    remaining = size
    while remaining > 0:
        buf = src.read(min(remaining, STREAM_BUF))
        if not buf:
            raise PngError(
                f"Payload file ended early ({remaining} bytes short)"
            )
        outf.write(buf)
        crc = binascii.crc32(buf, crc)
        remaining -= len(buf)
    outf.write(struct.pack("!I", crc & 0xFFFFFFFF))


# --------------------------------------------------------------------------- #
# Pretty-printing
# --------------------------------------------------------------------------- #

def _display(chunk_type: bytes) -> str:
    return chunk_type.decode("latin-1", errors="replace")


def human_size(n: int) -> str:
    value = float(n)
    for unit in ("B", "KiB", "MiB", "GiB"):
        if value < BYTES_IN_KB:
            return f"{int(value)} B" if unit == "B" else f"{value:.1f} {unit}"
        value /= BYTES_IN_KB
    return f"{value:.1f} TiB"


def parse_size(s: str) -> int:
    orig = s
    s = s.strip().upper()
    suffixes = [
        ("GIB", 1024**3), ("MIB", 1024**2), ("KIB", 1024),
        ("GB", 1024**3), ("MB", 1024**2), ("KB", 1024),
        ("G", 1024**3), ("M", 1024**2), ("K", 1024),
        ("B", 1),
    ]
    for suffix, mult in suffixes:
        if s.endswith(suffix):
            try:
                return int(float(s[: -len(suffix)]) * mult)
            except ValueError:
                break
    try:
        return int(s)
    except ValueError:
        raise argparse.ArgumentTypeError(
            f"invalid size: {orig!r} (try '512M', '1G', or a byte count)"
        )


# --------------------------------------------------------------------------- #
# Shared preflight checks
# --------------------------------------------------------------------------- #

def _check_paths(input_path: Path, output_path: Path) -> Path:
    if input_path.resolve() == output_path.resolve():
        raise PngError("Output file must be different from input file")
    out_dir = output_path.parent
    if not out_dir.exists():
        raise PngError(f"Output directory does not exist: {out_dir}")
    return out_dir


# --------------------------------------------------------------------------- #
# Commands
# --------------------------------------------------------------------------- #

def cmd_list(args: argparse.Namespace) -> int:
    with open_png(args.input) as f:
        end = file_length(f)
        while f.tell() < end:
            pos = f.tell()
            try:
                size, chunk_type = read_chunk_header(f)
                crc_ok = stream_content(f, size, chunk_type, sink=None)
            except PngError:
                f.seek(pos)
                print(paint(f"<trailing data, {end - pos} bytes>", _Sgr.YELLOW))
                break
            flag = "" if crc_ok else paint("  [bad CRC]", _Sgr.BOLD, _Sgr.RED)
            name = _display(chunk_type)
            if chunk_type == CHUNK_TYPE_PUNK:
                name = paint(name, _Sgr.BOLD, _Sgr.MAGENTA)  # the hidden-payload chunk
            else:
                name = paint(name, _Sgr.CYAN)
            size_txt = paint(f"{size} bytes", _Sgr.DIM)
            print(f"{name}: {size_txt}{flag}")
    return 0


def cmd_inject(args: argparse.Namespace) -> int:
    out_dir = _check_paths(args.input, args.output)

    try:
        payload_size = args.content.stat().st_size
        input_size = args.input.stat().st_size
    except OSError as e:
        raise PngError(f"Cannot read input/payload file: {e}")

    if payload_size == 0:
        raise PngError("Refusing to inject an empty payload")

    if payload_size > args.max_size:
        raise PngError(
            f"Payload is {human_size(payload_size)}, which exceeds the "
            f"--max-size limit of {human_size(args.max_size)}. "
            f"Raise it with --max-size BYTES (PNG spec ceiling: "
            f"{MAX_CHUNK_SIZE} bytes) if you really need a larger payload."
        )

    needed = input_size + payload_size + 128
    try:
        free = shutil.disk_usage(out_dir).free
    except OSError as e:
        raise PngError(f"Cannot check disk space in {out_dir}: {e}")
    if needed > free:
        raise PngError(
            f"Not enough disk space: output will need ~{human_size(needed)}, "
            f"but only {human_size(free)} is free in {out_dir}"
        )

    with open_png(args.input) as inf, \
         args.content.open("rb") as payload_src, \
         atomic_output(args.output) as outf:
        # open_png() consumed the 8-byte signature from the input; re-emit it
        # to the output so the result is a valid PNG.
        outf.write(PNG_SIGNATURE)
        end = file_length(inf)
        injected = False

        while inf.tell() < end:
            pos = inf.tell()
            try:
                size, chunk_type = read_chunk_header(inf)
            except PngError:
                inf.seek(pos)
                if not injected:
                    _write_punk_chunk(outf, payload_src, payload_size)
                    injected = True
                shutil.copyfileobj(inf, outf)
                break

            if not injected and chunk_type == CHUNK_TYPE_END:
                _write_punk_chunk(outf, payload_src, payload_size)
                injected = True

            copy_chunk(inf, outf, size, chunk_type)

        if not injected:
            _write_punk_chunk(outf, payload_src, payload_size)

    print(paint(
        f"Injected {human_size(payload_size)} into {args.output}",
        _Sgr.GREEN,
    ))
    return 0


def cmd_extract(args: argparse.Namespace) -> int:
    _check_paths(args.input, args.output)

    found = 0
    with open_png(args.input) as inf, atomic_output(args.output) as outf:
        end = file_length(inf)
        while inf.tell() < end:
            pos = inf.tell()
            try:
                size, chunk_type = read_chunk_header(inf)
            except PngError:
                print(
                    paint(f"Warning: stopping at malformed chunk at offset {pos}",
                          _Sgr.YELLOW, err=True),
                    file=sys.stderr,
                )
                break

            if chunk_type != CHUNK_TYPE_PUNK:
                inf.seek(size, 1)
                read_exact(inf, 4, "chunk CRC")
                continue

            crc_ok = stream_content(inf, size, chunk_type, sink=outf)
            if not crc_ok:
                print(
                    paint(f"Warning: puNk chunk #{found + 1} has a bad CRC",
                          _Sgr.BOLD, _Sgr.RED, err=True),
                    file=sys.stderr,
                )
            found += 1
            print(paint(f"Extracted {human_size(size)} from puNk chunk #{found}",
                        _Sgr.GREEN))

            if not args.all:
                break

    if found == 0:
        raise PngError(
            f"No {_display(CHUNK_TYPE_PUNK)} chunk found in {args.input}"
        )
    return 0


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #

DESCRIPTION = f"""\
{paint("Hide arbitrary payloads inside PNG images, or extract them again.", _Sgr.BOLD)}

PNG files are built from a stream of chunks (IHDR, IDAT, IEND, …). This tool
appends its own custom 'puNk' chunk just before IEND, which most PNG viewers
and editors ignore — so the image still renders normally while the payload
rides along untouched.

All I/O is streamed in 64 KiB blocks, so memory use is constant regardless of
payload size. Before writing, the tool checks that the output will fit on
disk; on any failure the partial output is removed.

{_hdr("MODES")}
  {paint("list", _Sgr.GREEN)}      Show every chunk in a PNG (with sizes and CRC status).
  {paint("inject", _Sgr.GREEN)}    Write a copy of a PNG with an extra puNk chunk holding a payload.
  {paint("extract", _Sgr.GREEN)}   Pull the payload back out of a PNG's puNk chunk.

Run '{paint(PROG, _Sgr.CYAN)} {paint("MODE", _Sgr.YELLOW)} -h' for mode-specific options and examples.
"""

EXAMPLES = "\n".join([
    _hdr("examples:"),
    _comment("See what chunks a PNG contains (and whether their CRCs are valid)"),
    _example("list photo.png"),
    "",
    _comment("Hide secret.zip inside a copy of photo.png"),
    _example("inject photo.png stego.png secret.zip"),
    "",
    _comment("Get secret.zip back out again"),
    _example("extract stego.png secret.zip"),
    "",
    _comment("A PNG can carry several payloads — pull them all out into one file"),
    _example("extract stego.png everything.bin --all"),
]) + "\n"


class ColorHelpFormatter(argparse.RawDescriptionHelpFormatter):
    """RawDescription formatter that adds color. Headings are colored as they're
    recorded; option flags and the 'usage:' prefix are colored by inserting
    zero-width codes into the finished text, so alignment is untouched."""

    def start_section(self, heading):
        if heading:
            heading = _hdr(heading)
        super().start_section(heading)

    def format_help(self):
        text = super().format_help()
        if COLOR_STDOUT:
            # Color is inserted only after argparse has laid everything out, so
            # the (zero-width) codes can't disturb wrapping or column alignment.
            text = _color_options(text)
            if text.startswith("usage:"):
                text = paint("usage:", _Sgr.BOLD, _Sgr.YELLOW) + text[len("usage:"):]
        return text


def _mode_parser(
    sub: argparse._SubParsersAction,
    name: str,
    summary: str,
    epilog: str,
) -> argparse.ArgumentParser:
    return sub.add_parser(
        name,
        help=summary,
        description=summary,
        epilog=epilog,
        formatter_class=ColorHelpFormatter,
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=PROG,
        description=DESCRIPTION,
        epilog=EXAMPLES,
        formatter_class=ColorHelpFormatter,
        add_help=True,
    )
    parser.add_argument(
        "--version", action="version",
        version=f"{paint(PROG, _Sgr.CYAN)} {paint('v' + __version__, _Sgr.BOLD)}",
    )
    sub = parser.add_subparsers(
        title="modes", dest="mode", metavar="MODE", required=True,
    )

    p = _mode_parser(
        sub, "list",
        "List every chunk in a PNG, with sizes and CRC status.",
        "\n".join([
            _hdr("examples:"),
            _example("list photo.png"),
            _example("list stego.png"),
        ]) + "\n",
    )
    p.add_argument("input", metavar="INPUT_PNG", type=Path,
                   help="PNG file to inspect")
    p.set_defaults(func=cmd_list)

    p = _mode_parser(
        sub, "inject",
        "Copy a PNG, adding a puNk chunk containing a payload file.",
        "The payload is streamed, so memory use stays tiny even for huge\n"
        "files. Free disk space and --max-size are checked before writing.\n"
        "\n"
        + "\n".join([
            _hdr("examples:"),
            _example("inject photo.png stego.png secret.zip"),
            _example("inject in.png out.png video.mp4 --max-size 1G"),
        ]) + "\n",
    )
    p.add_argument("input", metavar="INPUT_PNG", type=Path,
                   help="PNG to read from")
    p.add_argument("output", metavar="OUTPUT_PNG", type=Path,
                   help="PNG to write, with the payload embedded")
    p.add_argument("content", metavar="PAYLOAD_FILE", type=Path,
                   help="File whose bytes will be embedded in the output PNG")
    p.add_argument(
        "--max-size",
        type=parse_size,
        default=MAX_CHUNK_SIZE,
        metavar="SIZE",
        help=f"refuse payloads larger than SIZE (default: {MAX_CHUNK_SIZE} "
             f"bytes, the PNG spec ceiling). Accepts suffixes like 512M or 1G.",
    )
    p.set_defaults(func=cmd_inject)

    p = _mode_parser(
        sub, "extract",
        "Recover the payload embedded in a PNG's puNk chunk.",
        "\n".join([
            _hdr("examples:"),
            _example("extract stego.png secret.zip"),
            _example("extract stego.png everything.bin --all"),
        ]) + "\n",
    )
    p.add_argument("input", metavar="INPUT_PNG", type=Path,
                   help="PNG to read from")
    p.add_argument("output", metavar="OUTPUT_FILE", type=Path,
                   help="File to write the recovered payload to")
    p.add_argument("--all", action="store_true",
                   help="extract every puNk chunk (default: stop after the first)")
    p.set_defaults(func=cmd_extract)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    if argv is None:
        argv = sys.argv[1:]
    if not argv:
        parser.print_help(sys.stderr)
        return 2

    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except (PngError, OSError) as e:
        print(f"{paint('error:', _Sgr.BOLD, _Sgr.RED, err=True)} {e}", file=sys.stderr)
        return 1
    except MemoryError:
        print(
            f"{paint('error:', _Sgr.BOLD, _Sgr.RED, err=True)} out of memory — "
            "try a smaller file or a machine with more RAM "
            "(use --max-size to set a personal safety limit)",
            file=sys.stderr,
        )
        return 1
    except KeyboardInterrupt:
        print(paint("interrupted", _Sgr.DIM, err=True), file=sys.stderr)
        return 130


if __name__ == "__main__":
    sys.exit(main())
