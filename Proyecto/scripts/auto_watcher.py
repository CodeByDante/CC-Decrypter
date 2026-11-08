"""Watch the configured CapCut drafts folder. Use start/stop to manage this instance."""
import logging
import os
import subprocess
import sys
import time
from pathlib import Path

from PySide6.QtCore import QCoreApplication, QLockFile, QStandardPaths

PROJECT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT / "src"))
from cc_decrypter.automation import drafts_root, export_copy, media_files, replace_protected
from cc_decrypter.discovery import probe_cryptor_type
from cc_decrypter.decoder import DecodeError

MODES = ("", "--escritorio", "--misma-carpeta")
MODE = next((mode for mode in MODES if mode and mode in sys.argv[1:]), "")
WATCH_ARGS = ["watch"] + ([MODE] if MODE else [])
LOGS = PROJECT / "logs" / MODE.removeprefix("--")


def watcher_lock():
    lock = QLockFile(str(LOGS / "watcher.lock"))
    lock.setStaleLockTime(0)
    return lock


def active_pid():
    if not (LOGS / "watcher.lock").exists():
        return None
    lock = watcher_lock()
    if lock.tryLock(0):
        lock.unlock()
        return None
    info = lock.getLockInfo()
    return info[0] if info else None


def watch():
    lock = watcher_lock()
    if not lock.tryLock(0):
        return
    stop = LOGS / f"watcher-{os.getpid()}.stop"
    logging.basicConfig(filename=LOGS / "watcher.log", level=logging.INFO,
                        format="%(asctime)s %(message)s", encoding="utf-8")
    logging.info("Vigilante iniciado")
    cache = {}
    last_error = None
    try:
        existing = {}
        started_ns = time.time_ns()
        try:
            for path in media_files(drafts_root(), combination_only=True):
                try:
                    stat = path.stat()
                    # On Windows, ctime is the creation time (Python 3.10/3.11).
                    created = getattr(stat, "st_birthtime_ns", stat.st_ctime_ns)
                    if os.name != "nt" or created < started_ns:
                        existing[path] = stat.st_ino
                except FileNotFoundError:
                    continue
        except FileNotFoundError:
            pass  # The projects folder may itself be created after startup.
        while not stop.exists():
            try:
                root = drafts_root()
                seen = set()
                for path in media_files(root, combination_only=True):
                    if stop.exists():
                        break
                    seen.add(path)
                    try:
                        stat = path.stat()
                        stamp = (stat.st_size, stat.st_mtime_ns, stat.st_ino)
                        # A draft can become visible long after startup. Apply the
                        # cutoff on every scan, even outside the initial inventory.
                        created = getattr(stat, "st_birthtime_ns", stat.st_ctime_ns)
                        if stat.st_mtime_ns < started_ns or (os.name == "nt" and created < started_ns):
                            continue
                        if path in existing:
                            if existing[path] == stamp[2]:
                                continue
                            del existing[path]
                        previous, retry = cache.get(path, (None, 0))
                        if previous != stamp:
                            # Require two consecutive identical observations before replacing a live clip.
                            cache[path] = (stamp, 0)
                            continue
                        if time.monotonic() < retry:
                            continue
                        if probe_cryptor_type(path) == 1:
                            def report(message):
                                if stop.exists():
                                    raise InterruptedError("Deteniendo vigilante")
                            if MODE:
                                folder = path.parent
                                if MODE == "--escritorio":
                                    location = QStandardPaths.writableLocation(QStandardPaths.DesktopLocation)
                                    if not location or not Path(location).is_dir():
                                        raise OSError("No se encontró la carpeta Escritorio.")
                                    folder = Path(location)
                                output = export_copy(path, folder, report, reuse_existing=True)
                                logging.info("Copia disponible: %s", output)
                                cache[path] = (stamp, float("inf"))
                                continue
                            if replace_protected(path, report):
                                logging.info("Completado: %s", path.name)
                        cache[path] = (stamp, time.monotonic() + 60)
                    except DecodeError as error:
                        logging.warning("%s: %s", path.name, error)
                        cache[path] = (stamp, float("inf"))
                    except (OSError, RuntimeError, ValueError) as error:
                        logging.warning("%s: %s", path.name, error)
                        if path in cache:
                            cache[path] = (cache[path][0], time.monotonic() + 30)
                cache = {path: item for path, item in cache.items() if path in seen}
                last_error = None
            except OSError as error:
                if str(error) != last_error:
                    logging.warning("%s", error)
                    last_error = str(error)
            time.sleep(1)
    finally:
        stop.unlink(missing_ok=True)
        lock.unlock()
        logging.info("Vigilante detenido")


def start_at_login(enabled):
    import winreg

    name = "CC Decrypter - Vigilante"
    name += {"": "", "--escritorio": " Escritorio", "--misma-carpeta": " Misma Carpeta"}[MODE]
    with winreg.CreateKey(winreg.HKEY_CURRENT_USER,
                          r"Software\Microsoft\Windows\CurrentVersion\Run") as key:
        if enabled:
            executable = Path(sys.executable).with_name("pythonw.exe")
            command = subprocess.list2cmdline([str(executable), str(Path(__file__).resolve()), *WATCH_ARGS])
            winreg.SetValueEx(key, name, 0, winreg.REG_SZ, command)
        else:
            try:
                winreg.DeleteValue(key, name)
            except FileNotFoundError:
                pass


def main(action):
    LOGS.mkdir(parents=True, exist_ok=True)
    if action == "watch":
        watch()
        return 0
    pid = active_pid()
    if action == "stop-mode":
        start_at_login(False)
        if pid:
            (LOGS / f"watcher-{pid}.stop").touch()
            for _ in range(100):
                if active_pid() != pid:
                    print("Vigilante desactivado.")
                    return 0
                time.sleep(0.05)
            print("Detención solicitada. El vigilante saldrá al terminar la operación en curso.")
            return 1
        else:
            print("El vigilante ya está detenido.")
        return 0
    if action not in ("start", "stop"):
        raise ValueError("Acción desconocida")
    switch = QLockFile(str(PROJECT / "logs" / "watcher-mode.lock"))
    if not switch.tryLock(10000):
        print("Hay otro cambio de modo en curso. Vuelve a intentar.")
        return 1
    try:
        failed = False
        for mode in MODES:
            if action == "start" and mode == MODE:
                continue
            args = [mode] if mode else []
            result = subprocess.run([sys.executable, str(Path(__file__).resolve()), "stop-mode", *args],
                                    stdout=subprocess.DEVNULL)
            failed |= result.returncode != 0
        if failed:
            print("Hay un vigilante pendiente de detenerse.")
            return 1
        if action == "stop":
            print("Todos los vigilantes están desactivados.")
            return 0
        return start_current()
    finally:
        switch.unlock()


def start_current():
    if active_pid():
        start_at_login(True)
        print("El vigilante ya está activo.")
        return 0
    process = subprocess.Popen([sys.executable, str(Path(__file__).resolve()), *WATCH_ARGS],
                               creationflags=subprocess.CREATE_NO_WINDOW,
                               stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL)
    for _ in range(100):
        time.sleep(0.05)
        if active_pid():
            start_at_login(True)
            print("Vigilante activo.")
            return 0
        if process.poll() is not None:
            break
    print("No se pudo iniciar el vigilante. Revisa logs/watcher.log.")
    return 1


if __name__ == "__main__":
    app = QCoreApplication(sys.argv)
    sys.exit(main(sys.argv[1] if len(sys.argv) > 1 else "watch"))
