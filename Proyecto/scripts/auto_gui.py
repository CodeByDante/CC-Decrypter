# -*- coding: utf-8 -*-
import sys
import time
from pathlib import Path
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QProgressBar, QListWidget, QFrame
)
from PySide6.QtCore import Qt, QThread, QStandardPaths, Signal
from PySide6.QtGui import QFont

# Setup path to decoder
cc_src = Path(__file__).resolve().parent.parent / "src"
if cc_src.exists():
    sys.path.insert(0, str(cc_src))

from cc_decrypter.automation import drafts_root, media_files, replace_protected, export_copy
from cc_decrypter.discovery import probe_cryptor_type



class AutoWorker(QThread):
    progress_changed = Signal(int)
    status_text = Signal(str)
    item_found = Signal(str, str, str)
    done_all = Signal(int, int, float)

    def __init__(self, desktop=False):
        super().__init__()
        self.desktop = desktop

    def run(self):
        start = time.monotonic()
        done = failed = 0
        self.progress_changed.emit(-1)
        try:
            root = drafts_root()
            if self.desktop:
                location = QStandardPaths.writableLocation(QStandardPaths.DesktopLocation)
                if not location or not Path(location).is_dir():
                    raise OSError("No se encontró la carpeta Escritorio.")
                folder = Path(location)
            tasks = []
            self.status_text.emit("Buscando clips en las carpetas combination…")
            for path in media_files(root, combination_only=True):
                if self.isInterruptionRequested():
                    return
                if probe_cryptor_type(path) is not None:
                    tasks.append(path)
            for index, path in enumerate(tasks, 1):
                if self.isInterruptionRequested():
                    return
                project = str(path.parent.relative_to(root))
                self.progress_changed.emit(-1)
                self.status_text.emit(f"Procesando archivo {index} de {len(tasks)}")
                def report(message):
                    if self.isInterruptionRequested():
                        raise InterruptedError("Proceso detenido.")
                    self.item_found.emit(project, path.name, message)
                try:
                    if probe_cryptor_type(path) not in (None, 1):
                        raise ValueError("Tipo de cifrado no compatible.")
                    def progress(percent):
                        self.progress_changed.emit(((index - 1) * 100 + min(percent, 99)) // len(tasks))
                    if self.desktop:
                        target = export_copy(path, folder, report, progress)
                        done += 1
                        report(f"Copia guardada en {target}")
                    elif replace_protected(path, report, progress, wait_for_unlock=True):
                        done += 1
                        report(f"Reemplazado en {path}")
                    else:
                        report("Ya procesado")
                except Exception as error:
                    failed += 1
                    self.item_found.emit(project, path.name, str(error))
                self.progress_changed.emit(index * 100 // len(tasks))
        except Exception as error:
            failed += 1
            self.item_found.emit("Búsqueda", "", str(error))
        self.progress_changed.emit(100)
        self.done_all.emit(done, failed, time.monotonic() - start)


class MinimalApp(QMainWindow):
    def __init__(self, desktop=False):
        super().__init__()
        self.setWindowTitle("CC Decrypter — Escritorio" if desktop else "CC Decrypter — Auto")
        self.setFixedSize(580, 420)
        
        # Estilo limpio: Fondo blanco, texto negro, bordes grises
        self.setStyleSheet("""
            QMainWindow {
                background-color: #FFFFFF;
            }
            QLabel {
                color: #111111;
                font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
            }
            QProgressBar {
                border: 1px solid #D0D0D0;
                border-radius: 4px;
                background-color: #F0F0F0;
                height: 18px;
                text-align: center;
                color: #111111;
                font-size: 11px;
                font-weight: bold;
            }
            QProgressBar::chunk {
                background-color: #111111;
                border-radius: 3px;
            }
            QListWidget {
                background-color: #FAFAFA;
                border: 1px solid #E0E0E0;
                border-radius: 6px;
                padding: 6px;
                color: #222222;
                font-family: "Consolas", "Segoe UI", monospace;
                font-size: 12px;
            }
            QListWidget::item {
                padding: 6px;
                border-bottom: 1px solid #EEEEEE;
            }
            QListWidget::item:selected, QListWidget::item:selected:!active {
                background-color: #DCEBFF;
                color: #142C4C;
            }
        """)

        central = QWidget()
        self.setCentralWidget(central)
        layout = QVBoxLayout(central)
        layout.setContentsMargins(28, 24, 28, 24)
        layout.setSpacing(14)

        # Header
        top_layout = QVBoxLayout()
        title = QLabel("CC Decrypter")
        title.setFont(QFont("Segoe UI", 18, QFont.Bold))
        title.setAlignment(Qt.AlignCenter)
        
        subtitle = QLabel("Guardando copias descifradas en el Escritorio" if desktop else
                          "Desencriptando automáticamente en su carpeta de origen")
        subtitle.setStyleSheet("color: #666666; font-size: 12px;")
        subtitle.setAlignment(Qt.AlignCenter)
        
        top_layout.addWidget(title)
        top_layout.addWidget(subtitle)
        layout.addLayout(top_layout)

        # Separator line
        sep = QFrame()
        sep.setFrameShape(QFrame.HLine)
        sep.setFrameShadow(QFrame.Plain)
        sep.setStyleSheet("color: #EAEAEA;")
        layout.addWidget(sep)

        # Info & Progress
        info_row = QHBoxLayout()
        self.status_lbl = QLabel("Iniciando...")
        self.status_lbl.setStyleSheet("font-weight: 600; font-size: 12px; color: #111111;")
        info_row.addWidget(self.status_lbl)
        info_row.addStretch()
        self.pct_lbl = QLabel("0%")
        self.pct_lbl.setStyleSheet("font-weight: bold; font-size: 12px; color: #555555;")
        info_row.addWidget(self.pct_lbl)
        layout.addLayout(info_row)

        self.bar = QProgressBar()
        self.bar.setValue(0)
        layout.addWidget(self.bar)

        # Task list
        list_lbl = QLabel("Archivos procesados:")
        list_lbl.setStyleSheet("font-size: 12px; font-weight: bold; color: #333333; margin-top: 6px;")
        layout.addWidget(list_lbl)

        self.list_widget = QListWidget()
        self.list_widget.setWordWrap(True)
        self.list_widget.setTextElideMode(Qt.ElideNone)
        layout.addWidget(self.list_widget)

        # Auto-run thread immediately
        self.worker = AutoWorker(desktop)
        self.worker.progress_changed.connect(self.on_progress)
        self.worker.status_text.connect(self.status_lbl.setText)
        self.worker.item_found.connect(self.on_item)
        self.worker.done_all.connect(self.on_done)
        self.worker.start()

    def on_progress(self, val):
        self.bar.setRange(0, 0 if val < 0 else 100)
        if val < 0:
            self.pct_lbl.setText("En curso")
            return
        self.bar.setValue(val)
        self.pct_lbl.setText(f"{val}%")

    def on_item(self, project, filename, state):
        found = False
        text = f"Proyecto: {project}\n  -> Archivo: {filename}\n  -> Estado : {state}"
        for i in range(self.list_widget.count()):
            item = self.list_widget.item(i)
            if item.data(Qt.UserRole) == (project, filename):
                item.setText(text)
                item.setToolTip(text)
                found = True
                break
        if not found:
            self.list_widget.addItem(text)
            item = self.list_widget.item(self.list_widget.count() - 1)
            item.setData(Qt.UserRole, (project, filename))
            item.setToolTip(text)
        self.list_widget.scrollToBottom()

    def on_done(self, count, failed, elapsed):
        if not count and not failed:
            self.status_lbl.setText("No hay archivos protegidos pendientes.")
        else:
            self.status_lbl.setText(f"Completados: {count} · Errores: {failed} · {elapsed:.1f} s")

    def closeEvent(self, event):
        if self.worker.isRunning():
            self.worker.requestInterruption()
            self.status_lbl.setText("Cerrando al terminar la operación actual…")
            self.worker.finished.connect(self.close)
            event.ignore()
        else:
            event.accept()


if __name__ == "__main__":
    app = QApplication(sys.argv)
    win = MinimalApp(desktop="--escritorio" in sys.argv)
    win.show()
    sys.exit(app.exec())
