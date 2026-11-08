# -*- coding: utf-8 -*-
import sys
import os
import time
from pathlib import Path

# Setup path to decoder
cc_src = Path(__file__).resolve().parent.parent / "src"
if cc_src.exists():
    sys.path.insert(0, str(cc_src))

from cc_decrypter.decoder import decode_file

def human_size(nbytes):
    for unit in ['B', 'KB', 'MB', 'GB']:
        if nbytes < 1024.0:
            return f"{nbytes:.1f} {unit}"
        nbytes /= 1024.0
    return f"{nbytes:.1f} TB"

def is_bdve_encrypted(file_path: Path) -> bool:
    try:
        if file_path.stat().st_size < 128:
            return False
        with open(file_path, "rb") as f:
            f.seek(max(0, file_path.stat().st_size - 128))
            tail = f.read()
        return b"bdve" in tail
    except Exception:
        return False

def progress_bar(percent, width=30):
    filled = int(width * percent / 100)
    bar = "#" * filled + "-" * (width - filled)
    return f"[{bar}] {percent}%"

def main():
    os.system("cls")
    print("-" * 65)
    print("  CAPCUT COMBINATION DECRYPTER")
    print("-" * 65)
    print()

    base_dir = Path(os.environ.get("LOCALAPPDATA", r"C:\Users\Gonzalo\AppData\Local")) / "CapCut" / "User Data" / "Projects" / "com.lveditor.draft"
    if not base_dir.exists():
        base_dir = Path(r"C:\Users\Gonzalo\AppData\Local\CapCut\User Data\Projects\com.lveditor.draft")

    print(f"Ruta: {base_dir}")
    print()

    comb_dirs = list(base_dir.rglob("combination"))
    if not comb_dirs:
        print("[!] No se encontraron carpetas combination.")
        print()
        return

    tasks = []
    for comb_dir in comb_dirs:
        mp4_files = [f for f in comb_dir.glob("*.mp4") if not f.name.endswith("_desencriptado.mp4") and not f.name.endswith(".alpha.mp4")]
        for video_file in mp4_files:
            if is_bdve_encrypted(video_file):
                tasks.append(video_file)

    total_tasks = len(tasks)
    print(f"Total videos detectados: {total_tasks}")
    print("-" * 65)
    print()

    if total_tasks == 0:
        print("No hay videos pendientes por desencriptar.")
        print()
        return

    total_decrypted = 0
    total_ready = 0
    start_time = time.time()

    for idx, video_file in enumerate(tasks, 1):
        file_sz = human_size(video_file.stat().st_size)
        project_name = video_file.parent.parent.parent.name
        clean_name = video_file.stem
        out_file = video_file.parent / f"{clean_name}_desencriptado.mp4"

        print(f"[{idx}/{total_tasks}] PROYECTO: {project_name}")
        print(f"Archivo: {video_file.name} ({file_sz})")
        print(f"Destino: combination\\{out_file.name}")

        if out_file.exists() and out_file.stat().st_size > 1000:
            print(f"{progress_bar(100)} (Ya estaba desencriptado)")
            print()
            total_ready += 1
            continue

        temp_out = video_file.parent / f"{clean_name}.tmp"
        try:
            t0 = time.time()
            print(f"{progress_bar(20)} Leyendo cabecera...", end="\r", flush=True)
            time.sleep(0.04)

            print(f"{progress_bar(60)} Desencriptando...", end="\r", flush=True)
            decode_file(video_file, temp_out)

            print(f"{progress_bar(90)} Guardando...", end="\r", flush=True)
            if temp_out.exists():
                if out_file.exists():
                    out_file.unlink()
                temp_out.rename(out_file)
                elapsed = time.time() - t0
                print(f"{progress_bar(100)} Completado en {elapsed:.2f}s        ")
                print()
                total_decrypted += 1
        except Exception as e:
            print(f"\n[ERROR] Fallo: {e}\n")
            if temp_out.exists():
                temp_out.unlink()

    total_time = time.time() - start_time
    print("-" * 65)
    print("RESUMEN:")
    print(f"- Desencriptados : {total_decrypted}")
    print(f"- Ya listos      : {total_ready}")
    print(f"- Tiempo total   : {total_time:.2f} segundos")
    print("-" * 65)
    print()

if __name__ == "__main__":
    main()