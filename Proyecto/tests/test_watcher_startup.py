import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from scripts import auto_watcher as watcher


class StartupTests(unittest.TestCase):
    def test_mode_registration_removes_legacy_launchers(self):
        with tempfile.TemporaryDirectory() as temp:
            programs = Path(temp)
            startup = programs / "Startup"
            startup.mkdir()
            legacy = startup / "CapCut_AutoDecrypter_Background.lnk"
            legacy.touch()
            unrelated = startup / "other.lnk"
            unrelated.touch()
            registry = MagicMock()
            with patch.dict("sys.modules", winreg=registry), \
                 patch.object(watcher.QStandardPaths, "writableLocation", return_value=temp), \
                 patch.object(watcher, "MODE", "--escritorio"), \
                 patch.object(watcher, "WATCH_ARGS", ["watch", "--escritorio"]):
                watcher.start_at_login(True)
                self.assertFalse(legacy.exists())
                self.assertTrue(unrelated.exists())
                key = registry.CreateKey.return_value.__enter__.return_value
                registry.DeleteValue.assert_called_with(key, "CapCut_AutoDecrypter_Watcher")
                args = registry.SetValueEx.call_args.args
                self.assertEqual(args[1], "CC Decrypter - Vigilante Escritorio")
                self.assertTrue(args[4].endswith("watch --escritorio"))
                watcher.start_at_login(False)
                registry.DeleteValue.assert_called_with(key, "CC Decrypter - Vigilante Escritorio")
