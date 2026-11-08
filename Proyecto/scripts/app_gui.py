# -*- coding: utf-8 -*-
import sys
import os
import time
from pathlib import Path
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QPushButton, QProgressBar, QListWidget, QListWidgetItem,
    QFrame, QGraphicsDropShadowEffect
)
from PySide6.QtCore import Qt, QThread, Signal
from PySide6.QtGui import QFont, QColor, QIcon

# Setup path to decoder
cc_src = Path(__file__).resolve().parents[1] / "src"
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

class DecryptWorker(QThread):
    progress_changed = Signal(int)
    item_status = Signal(str, str, str) # project, filename, status
    finished_all = Signal(int, int, float) # total_decrypted, total_skipped, elapsed_seconds
    log_message = Signal(str)

    def run(self):
        t_start = time.time()
        base_dir = Path(os.environ.get("LOCALAPPDATA", r"C:\Users\Gonzalo\AppData\Local")) / "CapCut" / "User Data" / "Projects" / "com.lveditor.draft"
        if not base_dir.exists():
            base_dir = Path(r"C:\Users\Gonzalo\AppData\Local\CapCut\User Data\Projects\com.lveditor.draft")

        comb_dirs = list(base_dir.rglob("combination"))
        tasks = []
        for comb_dir in comb_dirs:
            mp4_files = [f for f in comb_dir.glob("*.mp4") if not f.name.endswith("_desencriptado.mp4") and not f.name.endswith(".alpha.mp4")]
            for video_file in mp4_files:
                if is_bdve_encrypted(video_file):
                    tasks.append(video_file)

        total = len(tasks)
        if total == 0:
            self.progress_changed.emit(100)
            self.finished_all.emit(0, 0, 0.0)
            return

        decrypted_count = 0
        skipped_count = 0

        for i, video_file in enumerate(tasks, 1):
            project_name = video_file.parent.parent.parent.name
            clean_name = video_file.stem
            out_file = video_file.parent / f"{clean_name}_desencriptado.mp4"
            sz_str = human_size(video_file.stat().st_size)

            pct = int((i - 1) / total * 100)
            self.progress_changed.emit(pct)

            if out_file.exists() and out_file.stat().st_size > 1000:
                self.item_status.emit(project_name, video_file.name, f"Ya estaba listo ({sz_str})")
                skipped_count += 1
                continue

            self.item_status.emit(project_name, video_file.name, f"Desencriptando... ({sz_str})")
            temp_out = video_file.parent / f"{clean_name}.tmp"
            try:
                decode_file(video_file, temp_out)
                if temp_out.exists():
                    if out_file.exists():
                        out_file.unlink()
                    temp_out.rename(out_file)
                    decrypted_count += 1
                    self.item_status.emit(project_name, video_file.name, f"Completado con exito ({sz_str})")
            except Exception as e:
                self.item_status.emit(project_name, video_file.name, f"Fallo: {e}")
                if temp_out.exists():
                    temp_out.unlink()

            pct = int(i / total * 100)
            self.progress_changed.emit(pct)

        elapsed = time.time() - t_start
        self.progress_changed.emit(100)
        self.finished_all.emit(decrypted_count, skipped_count, elapsed)

class ModernDecryptApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("CapCut Auto Decrypter")
        self.setFixedSize(560, 480)
        self.setStyleSheet("""
            QMainWindow {
                background-color: #121418;
            }
            QLabel {
                color: #FFFFFF;
                font-family: 'Segoe UI', Arial, sans-serif;
            }
            QPushButton {
                background-color: #00D1B2;
                color: #0A0F14;
                font-size: 14px;
                font-weight: bold;
                border-radius: 8px;
                padding: 12px;
                font-family: 'Segoe UI', Arial, sans-serif;
            }
            QPushButton:hover {
                background-color: #00F0CE;
            }
            QPushButton:pressed {
                background-color: #00B89C;
            }
            QPushButton:disabled {
                background-color: #262C35;
                color: #555E6B;
            }
            QProgressBar {
                border: 1px solid #232931;
                border-radius: 6px;
                background-color: #1A1E24;
                height: 14px;
                text-align: center;
                color: transparent;
            }
            QProgressBar::chunk {
                background-color: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #00D1B2, stop:1 #0099FF);
                border-radius: 5px;
            }
            QListWidget {
                background-color: #181C22;
                border: 1px solid #262D36;
                border-radius: 8px;
                padding: 8px;
                color: #E2E8F0;
                font-family: 'Segoe UI', Consolas, sans-serif;
                font-size: 12px;
            }
            QListWidget::item {
                padding: 8px;
                border-bottom: 1px solid #202630;
                border-radius: 4px;
            }
            QListWidget::item:selected {
                background-color: #222933;
            }
        """)

        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        layout = QVBoxLayout(central_widget)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(16)

        # Header Card
        header_layout = QHBoxLayout()
        title_box = QVBoxLayout()
        title = QLabel("CapCut Combination Decrypter")
        title.setFont(QFont("Segoe UI", 16, QFont.Bold))
        subtitle = QLabel("Extrae tus clips combinados a MP4 estándar en segundos")
        subtitle.setStyleSheet("color: #7E8B9B; font-size: 12px;")
        title_box.addWidget(title)
        title_box.addWidget(subtitle)
        header_layout.addLayout(title_box)
        header_layout.addStretch()
        layout.addLayout(header_layout)

        # Progress Section
        prog_box = QVBoxLayout()
        prog_label_row = QHBoxLayout()
        self.status_label = QLabel("Listo para escanear y desencriptar")
        self.status_label.setStyleSheet("color: #00D1B2; font-weight: 600; font-size: 12px;")
        self.pct_label = QLabel("0%")
        self.pct_label.setStyleSheet("color: #7E8B9B; font-size: 12px; font-weight: bold;")
        prog_label_row.addWidget(self.status_label)
        prog_label_row.addStretch()
        prog_label_row.addWidget(self.pct_label)
        prog_box.addLayout(prog_label_row)

        self.progress_bar = QProgressBar()
        self.progress_bar.setValue(0)
        prog_box.addWidget(self.progress_bar)
        layout.addLayout(prog_box)

        # Activity List
        list_title = QLabel("Proyectos y Archivos detectados:")
        list_title.setStyleSheet("color: #A0AEC0; font-size: 12px; font-weight: bold;")
        layout.addWidget(list_title)

        self.list_widget = QListWidget()
        layout.addWidget(self.list_widget)

        # Bottom Button
        self.action_btn = QPushButton("🚀 Desencriptar Todos los Videos Ahora")
        self.action_btn.clicked.connect(self.start_process)
        layout.addWidget(self.action_btn)

        # Auto-start on launch for convenience
        self.worker = None
        self.start_process()

    def start_process(self):
        self.action_btn.setEnabled(False)
        self.action_btn.setText("Procesando proyectos...")
        self.status_label.setText("Escaneando carpetas...")
        self.status_label.setStyleSheet("color: #00D1B2; font-weight: bold; font-size: 12px;")
        self.progress_bar.setValue(0)
        self.list_widget.clear()

        self.worker = DecryptWorker()
        self.worker.progress_changed.connect(self.on_progress)
        self.worker.item_status.connect(self.on_item)
        self.worker.finished_all.connect(self.on_finished)
        self.worker.start()

    def on_progress(self, val):
        self.progress_bar.setValue(val)
        self.pct_label.setText(f"{val}%")

    def on_item(self, project, filename, status):
        # Update or add item
        found = False
        text = f"📁 {project}  ▸  {filename}\n     ↳ {status}"
        for i in range(self.list_widget.count()):
            item = self.list_widget.item(i)
            if filename in item.text():
                item.setText(text)
                found = True
                break
        if not found:
            self.list_widget.addItem(text)
        self.list_widget.scrollToBottom()

    def on_finished(self, decrypted, skipped, elapsed):
        self.action_btn.setEnabled(True)
        self.action_btn.setText("🔄 Volver a Escanear")
        if decrypted > 0:
            self.status_label.setText(f"¡Completado! {decrypted} video(s) desencriptados en {elapsed:.2f}s")
            self.status_label.setStyleSheet("color: #48BB78; font-weight: bold; font-size: 12px;")
        else:
            self.status_label.setText(f"Todos los videos ya estan listos ({skipped} revisados)")
            self.status_label.setStyleSheet("color: #00D1B2; font-weight: bold; font-size: 12px;")

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = ModernDecryptApp()
    window.show()
    sys.exit(app.exec())