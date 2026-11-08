import os
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from PySide6.QtWidgets import QApplication, QMessageBox
from cc_decrypter import gui
from cc_decrypter.automation import replace_protected
from cc_decrypter.decoder import CryptorParams, DecodeError, decode_bytes
from cc_decrypter.settings import save_drafts_folder, save_output_folder
from scripts.auto_gui import MinimalApp
from tests.test_decoder import bdve_footer, box, encrypt_bdve_payload


class ModeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication.instance() or QApplication([])

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        base = Path(tmp.name)
        self.enter_env = patch("cc_decrypter.settings.settings_path", return_value=base / "settings.json")
        self.enter_env.start()
        self.addCleanup(self.enter_env.stop)
        self.root = base / "drafts"
        self.output = base / "exports"
        self.path = self.root / "Project" / "Resources" / "combination" / "clip.mp4"
        self.path.parent.mkdir(parents=True)
        save_drafts_folder(self.root)
        save_output_folder(self.output)
        self.plain = box(b"ftyp", b"isom") + box(b"mdat", bytes(200000))
        params = CryptorParams(102303, 89230, 87)
        self.protected = encrypt_bdve_payload(self.plain, params) + bdve_footer(params)
        self.path.write_bytes(self.protected)

    def wait_for(self, predicate):
        deadline = time.monotonic() + 8
        while not predicate():
            self.app.processEvents()
            if time.monotonic() > deadline:
                self.fail("La operación no terminó a tiempo")
            time.sleep(0.01)
        self.app.processEvents()

    def test_manual_selection_exports_a_copy(self):
        window = gui.DecrypterWindow()
        self.wait_for(lambda: window.list.count() == 1)
        window.list.item(0).setSelected(True)
        with patch.object(QMessageBox, "exec", return_value=0):
            window.cta.click()
            self.wait_for(lambda: not window.busy)
        self.assertEqual(next(self.output.glob("*.mp4")).read_bytes(), self.plain)
        self.assertEqual(self.path.read_bytes(), self.protected)
        window.close()

    def test_automatic_window_decodes_in_place(self):
        window = MinimalApp()
        self.wait_for(lambda: not window.worker.isRunning())
        self.assertEqual(self.path.read_bytes(), self.plain)
        self.assertIn("Completados: 1", window.status_lbl.text())
        window.close()

    def test_desktop_mode_preserves_source_and_existing_destination(self):
        self.output.mkdir()
        existing = self.output / self.path.name
        existing.write_bytes(b"existing")
        with patch("scripts.auto_gui.QStandardPaths.writableLocation", return_value=str(self.output)):
            window = MinimalApp(desktop=True)
            self.wait_for(lambda: not window.worker.isRunning())
        self.assertEqual((self.output / "clip (2).mp4").read_bytes(), self.plain)
        self.assertEqual(existing.read_bytes(), b"existing")
        self.assertEqual(self.path.read_bytes(), self.protected)
        window.close()

    @unittest.skipUnless(os.name == "nt", "Windows file sharing")
    def test_capcut_can_hold_clip_open_during_replacement(self):
        with self.path.open("rb") as reader:
            self.assertTrue(replace_protected(self.path, lambda message: None))
            self.assertEqual(reader.read(), self.plain)
        self.assertEqual(list(self.path.parent.iterdir()), [self.path])

    def test_locked_target_is_preserved(self):
        with patch("cc_decrypter.automation.os.replace", side_effect=PermissionError):
            with self.assertRaises(PermissionError):
                replace_protected(self.path, lambda message: None)
        self.assertEqual(self.path.read_bytes(), self.protected)
        self.assertEqual(list(self.path.parent.iterdir()), [self.path])

    def test_automatic_mode_waits_for_original_to_be_released(self):
        replace = os.replace
        attempts = []
        def temporarily_locked(src, dst):
            if dst == self.path:
                attempts.append(dst)
                if len(attempts) <= 4:
                    raise PermissionError("en uso")
            replace(src, dst)
        denied = PermissionError("clip en uso")
        denied.winerror = 32
        with patch("cc_decrypter.automation.os.replace", side_effect=temporarily_locked), \
             patch("cc_decrypter.automation._write_open_clip", side_effect=denied):
            window = MinimalApp()
            self.wait_for(lambda: not window.worker.isRunning())
        self.assertEqual(self.path.read_bytes(), self.plain)
        self.assertEqual(len(attempts), 5)
        self.assertIn("Reemplazado en", window.list_widget.item(0).text())
        window.close()

    def test_unknown_profile_found_at_padding_boundaries(self):
        params = CryptorParams(147731, 45083, 87)
        payload = box(b"ftyp", b"isom") + box(b"mdat", bytes(450000))
        protected = encrypt_bdve_payload(payload, params) + bdve_footer(params)
        self.assertEqual(decode_bytes(protected), (payload, params))

    def test_audio_requires_matching_footer(self):
        params = CryptorParams(488065, 132216, 0x77)
        audio = bytes.fromhex("fff15080") + bytes(700)
        self.assertEqual(decode_bytes(encrypt_bdve_payload(audio, params) + bdve_footer(params)),
                         (audio, params))
        with self.assertRaises(DecodeError):
            decode_bytes(audio + bdve_footer(CryptorParams(99, 88, 1)))

    def test_all_watchers_skip_existing_and_decode_new_adts_audio(self):
        from scripts import auto_watcher as watcher

        # ADTS frames of 32 bytes, with both transitions between headers.
        frame = bytes.fromhex("fff15080041ffc") + bytes(25)
        audio = frame * 150
        params = CryptorParams(419, 159, 0xB1)
        protected = encrypt_bdve_payload(audio, params) + bdve_footer(params)
        for mode in watcher.MODES:
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as temp:
                base = Path(temp)
                folder = base / "drafts/project/Resources/combination"
                folder.mkdir(parents=True)
                old = folder / "anterior.aac"
                old.write_bytes(protected)
                hidden = base / "reaparece.aac"
                hidden.write_bytes(protected)
                os.utime(hidden, (1_600_000_000, 1_600_000_000))
                new = folder / "nuevo.aac"
                stop = base / f"watcher-{os.getpid()}.stop"
                count = 0

                def next_scan(_):
                    nonlocal count
                    count += 1
                    if count == 1:
                        old.touch()
                        hidden.rename(folder / hidden.name)
                        new.write_bytes(protected)
                    if count == 4:
                        stop.touch()

                with patch.object(watcher, "MODE", mode), patch.object(watcher, "LOGS", base), \
                     patch.object(watcher, "drafts_root", return_value=base / "drafts"), \
                     patch.object(watcher.QStandardPaths, "writableLocation", return_value=str(base)), \
                     patch.object(watcher.time, "sleep", side_effect=next_scan), \
                     patch.object(watcher.logging, "basicConfig"):
                    watcher.watch()
                self.assertEqual(old.read_bytes(), protected)
                self.assertFalse((folder / "anterior_descifrado.aac").exists())
                self.assertFalse((base / old.name).exists())
                self.assertEqual((folder / hidden.name).read_bytes(), protected)
                self.assertFalse((folder / "reaparece_descifrado.aac").exists())
                self.assertFalse(hidden.exists())
                output = {"": new, "--escritorio": base / new.name,
                          "--misma-carpeta": folder / "nuevo_descifrado.aac"}[mode]
                self.assertEqual(output.read_bytes(), audio)
                if mode:
                    self.assertEqual(new.read_bytes(), protected)
