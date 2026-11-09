"""Host orchestration checks without Docker, root privileges or network changes."""
import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch, MagicMock
import sys
import json

if sys.platform == "win32":
    sys.modules["fcntl"] = MagicMock()
spec = importlib.util.spec_from_file_location("installer", Path(__file__).parents[1] / "scripts/install-production.py")
installer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(installer)


class InstallerTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.root = Path(self.directory.name)
        self.secrets = self.root / ".secrets"
        self.secrets.mkdir()
        self.patches = [patch.object(installer, "ROOT", self.root), patch.object(installer, "SECRETS", self.secrets)]
        for item in self.patches:
            item.start()

    def tearDown(self):
        for item in self.patches:
            item.stop()
        self.directory.cleanup()

    def test_existing_environment_is_never_overwritten(self):
        (self.root / ".env").write_text("EXISTING=value")
        with self.assertRaises(RuntimeError):
            installer.prepare()
        self.assertEqual((self.root / ".env").read_text(), "EXISTING=value")

    def test_resume_never_regenerates_lost_keys(self):
        (self.secrets / "material-installed").write_text("1")
        with self.assertRaises(RuntimeError):
            installer.install_material()
        self.assertFalse((self.secrets / "keystore.json").exists())

    def test_interrupted_setup_recovers_original_issuer_without_prompting(self):
        material = self.secrets / "installer/material"
        material.mkdir(parents=True)
        (material.parent / "input.json").write_text(json.dumps({"domain": "original.example.com", "auditToken": "secret"}))
        with patch("builtins.input", side_effect=AssertionError("must not prompt")):
            settings = installer.prepare()
        self.assertEqual(settings["domain"], "original.example.com")
        self.assertNotIn("auditToken", settings)
        self.assertNotIn("secret", (self.secrets / "install-settings.json").read_text())

    def test_material_transfer_and_resume_preserve_operator_changes(self):
        material = self.secrets / "installer/material"
        material.mkdir(parents=True)
        for name in ("keystore.json", "manifest-root.pem", "manifest-root-public.pem", "production.env"):
            (material / name).write_text(name)
        with patch.object(installer.os, "chown", create=True):
            installer.install_material()
        self.assertFalse(material.exists())
        (self.secrets / "manifest-root.pem").unlink()
        (self.root / ".env").write_text("ROTATED=value")
        installer.install_material()
        self.assertFalse((self.secrets / "manifest-root.pem").exists())
        self.assertEqual((self.root / ".env").read_text(), "ROTATED=value")


if __name__ == "__main__":
    unittest.main()
