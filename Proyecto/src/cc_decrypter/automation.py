"""Process CapCut draft media in place, publishing only a verified, complete file."""
import filecmp
import os
import shutil
import tempfile
import time
from pathlib import Path

from PySide6.QtCore import QLockFile

from .decoder import decode_file
from .discovery import VIDEO_SUFFIXES, probe_cryptor_type, resolve_drafts_folder
from .settings import load_drafts_folder


def drafts_root():
    root, missing = resolve_drafts_folder(load_drafts_folder())
    if missing or not root.is_dir():
        raise FileNotFoundError(f"No se encontró la carpeta de borradores: {missing or root}")
    return root


def media_files(root, *, combination_only=False):
    def report_error(error):
        raise error

    for directory, folders, names in os.walk(root, onerror=report_error):
        # Only generated project media is eligible for in-place replacement.
        # Keep the manual picker available for protected files elsewhere.
        parts = {part.casefold() for part in (root.name, *Path(directory).relative_to(root).parts)}
        eligible = {"combination"} if combination_only else {"resources", "combination", "preprocessed"}
        if not parts.intersection(eligible):
            continue
        for name in names:
            path = Path(directory) / name
            if path.suffix.lower() in VIDEO_SUFFIXES and ".alpha." not in name.lower():
                yield path


def signature(path):
    stat = path.stat()
    return stat.st_size, stat.st_mtime_ns, stat.st_ino


def export_copy(path, folder, report, progress=None, *, reuse_existing=False):
    initial = signature(path)
    with tempfile.TemporaryDirectory(dir=folder) as staging:
        decoded = Path(staging) / path.name
        decode_file(path, decoded, report, progress)
        if signature(path) != initial:
            raise OSError("CapCut modificó el archivo. Vuelve a ejecutar la automatización.")
        stem = path.stem + "_descifrado" if folder == path.parent else path.stem
        target = folder / f"{stem}{path.suffix}"
        number = 1
        while True:
            try:
                if os.name == "nt":
                    decoded.rename(target)  # Windows rejects an existing destination.
                else:
                    os.link(decoded, target)
                return target
            except FileExistsError:
                if reuse_existing and target.is_file() and filecmp.cmp(decoded, target, shallow=False):
                    return target
                number += 1
                target = folder / f"{stem} ({number}){path.suffix}"


def _write_open_clip(path, decoded, initial):
    """CapCut may share writes while denying renames. Lock the bytes during commit."""
    import ctypes
    import msvcrt
    from ctypes import wintypes

    backup = path.with_name(path.name + ".decrypt.restore")
    with path.open("r+b", buffering=0) as target:
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel.LockFile.argtypes = (wintypes.HANDLE, wintypes.DWORD, wintypes.DWORD,
                                    wintypes.DWORD, wintypes.DWORD)
        handle = msvcrt.get_osfhandle(target.fileno())
        if not kernel.LockFile(handle, 0, 0, 0xffffffff, 0xffffffff):
            raise ctypes.WinError(ctypes.get_last_error())
        if signature(path) != initial:
            raise OSError("CapCut modificó el archivo durante el proceso.")
        # Keep the original on disk until the entire decoded file is flushed.
        with backup.open("xb") as original:
            try:
                shutil.copyfileobj(target, original)
                original.flush()
                os.fsync(original.fileno())
            except BaseException:
                original.close()
                backup.unlink()
                raise
        try:
            with decoded.open("rb") as source:
                target.seek(0)
                shutil.copyfileobj(source, target)
                target.truncate()
                os.fsync(target.fileno())
        except BaseException:
            with backup.open("rb") as original:
                target.seek(0)
                shutil.copyfileobj(original, target)
                target.truncate()
                os.fsync(target.fileno())
            backup.unlink()
            raise
        backup.unlink()


def replace_protected(path, log, progress=None, *, wait_for_unlock=False):
    lock = QLockFile(str(path) + ".decrypt.lock")
    lock.setStaleLockTime(0)
    if not lock.tryLock(0):
        raise PermissionError("Otro proceso está trabajando en este archivo.")
    try:
        initial = signature(path)
        if probe_cryptor_type(path) != 1:
            return False
        with tempfile.NamedTemporaryFile(dir=path.parent, suffix=".decrypt.tmp", delete=False) as handle:
            temp = Path(handle.name)
        try:
            decode_file(path, temp, log, progress)
            attempt = 0
            while True:
                if initial != signature(path):
                    raise OSError("CapCut modificó el archivo durante el proceso.")
                try:
                    os.replace(temp, path)
                    break
                except PermissionError:
                    if os.name == "nt":
                        try:
                            _write_open_clip(path, temp, initial)
                            break
                        except OSError as error:
                            if getattr(error, "winerror", None) not in (5, 32, 33):
                                raise
                    if attempt >= 3:
                        if not wait_for_unlock:
                            raise
                        log("Pendiente: Windows bloquea la escritura. Reintentando en la carpeta original…")
                        time.sleep(2)
                    else:
                        time.sleep(0.2)
                    attempt += 1
            return True
        finally:
            temp.unlink(missing_ok=True)
    finally:
        lock.unlock()
