import contextlib
import hashlib
import io
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

from manager import Manager


class ManagerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name) / "config"
        self.doc = Path(self.tmp.name) / "doc"
        self.root.mkdir()
        self.doc.mkdir()
        (self.root / "soga.conf").write_text("node_id=1\n")
        (self.root / "anytls").mkdir()
        (self.root / "anytls/soga.conf").write_text("node_id=2\n")
        self.binary = Path(self.tmp.name) / "binary"
        self.binary.touch()
        self.app = Manager(self.root, self.binary, self.doc)
        self.calls = []

        def run(args, capture=False):
            args = list(map(str, args))
            self.calls.append(args)
            text = ""
            code = 0
            if args[-1:] == ["version"]:
                text = "soga-reconstructed 0.1.0 (independent reconstruction)\n"
            elif args[:2] == ["systemctl", "is-active"]:
                text = "active" if args[-1] == "soga.service" else "inactive"
            elif args[:2] == ["systemctl", "is-enabled"]:
                text = "enabled" if args[-1] == "soga.service" else "disabled"
            return subprocess.CompletedProcess(args, code, stdout=text)

        self.run_patch = mock.patch.object(self.app, "run", side_effect=run)
        self.run_patch.start()
        self.addCleanup(self.run_patch.stop)
        self.root_patch = mock.patch.object(Manager, "require_root")
        self.root_patch.start()
        self.addCleanup(self.root_patch.stop)
        self.app.release_cache["stable"] = {"tag_name": "build-new"}

    def test_menu_matches_requested_layout_and_actual_states(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            names = self.app.show()
        self.assertEqual(names, ["default", "anytls"])
        text = out.getvalue()
        for value in ("1. 安装/更新 soga", "2. 完全卸载 soga", "3. 切换 soga 安装分支",
                      "4. 更新管理脚本", "5. 新增 soga 实例", "6. 管理实例 [default]",
                      "7. 管理实例 [anytls]", "[已运行] [自启: 是]", "[未运行] [自启: 否]"):
            self.assertIn(value, text)
        self.assertIn(str(self.root / "anytls/soga.conf"), text)
        self.assertIn("重建版 0.1.0", text)

    def test_numeric_and_named_selection(self):
        for selection in ("7", "anytls"):
            with mock.patch("builtins.input", side_effect=[selection, "0"]), \
                    mock.patch.object(self.app, "instance_menu") as submenu, \
                    contextlib.redirect_stdout(io.StringIO()):
                self.app.menu()
            submenu.assert_called_once_with("anytls")

    def test_invalid_selection_does_not_call_backend(self):
        with mock.patch("builtins.input", side_effect=["999", "0"]), \
                mock.patch.object(self.app, "backend") as backend, \
                contextlib.redirect_stdout(io.StringIO()):
            self.app.menu()
        backend.assert_not_called()

    def test_start_and_follow_logs_use_selected_instance(self):
        with mock.patch("builtins.input", side_effect=["1", "", "7", "", "0"]), \
                contextlib.redirect_stdout(io.StringIO()):
            self.app.instance_menu("anytls")
        self.assertIn([str(self.binary), "instance", "-root", str(self.root), "start", "anytls"], self.calls)
        self.assertIn([str(self.binary), "instance", "-root", str(self.root), "log", "anytls", "-f"], self.calls)

    def test_default_delete_and_rename_are_rejected(self):
        with mock.patch("builtins.input", side_effect=["10", "", "11", "", "0"]), \
                mock.patch.object(self.app, "backend") as backend, \
                contextlib.redirect_stdout(io.StringIO()):
            self.app.instance_menu("default")
        backend.assert_not_called()

    def test_new_instance_keeps_quoted_parameters(self):
        with mock.patch("builtins.input", side_effect=["new-node", "node_id=3 webapi_key='a b=c'", "n"]), \
                mock.patch.object(self.app, "backend") as backend:
            self.app.new_instance()
        backend.assert_called_once_with("new", "new-node", "node_id=3", "webapi_key=a b=c")

    def test_branch_selection_and_no_preview(self):
        self.app.set_channel("preview")
        self.assertEqual(self.app.channel(), "preview")
        releases = [{"tag_name": "stable", "prerelease": False},
                    {"tag_name": "draft", "prerelease": True, "draft": True}]
        with mock.patch.object(self.app, "download", return_value=json.dumps(releases).encode()):
            self.assertIsNone(self.app.latest())
        with self.assertRaisesRegex(ValueError, "尚无"):
            self.app.update()

    def test_preview_selects_real_prerelease(self):
        self.app.set_channel("preview")
        releases = [{"tag_name": "stable", "prerelease": False},
                    {"tag_name": "preview-1", "prerelease": True, "draft": False}]
        with mock.patch.object(self.app, "download", return_value=json.dumps(releases).encode()):
            self.assertEqual(self.app.latest()["tag_name"], "preview-1")

    def test_update_notice_compares_installed_release(self):
        (self.doc / "build-info.json").write_text('{"tag":"build-old"}')
        self.assertIn("发现新版本", self.app.update_notice())
        (self.doc / "build-info.json").write_text('{"tag":"build-new"}')
        self.assertIn("已是", self.app.update_notice())

    def test_offline_menu_caches_error_and_remains_available(self):
        self.app.release_cache.clear()
        with mock.patch.object(self.app, "download", side_effect=OSError("offline")) as download:
            self.assertIn("无法", self.app.update_notice())
            self.assertIn("无法", self.app.update_notice())
        self.assertEqual(download.call_count, 1)
        self.assertEqual(self.app.instances(), ["default", "anytls"])

    def test_self_update_validates_checksum_before_replacing(self):
        destination = self.doc / "manager.py"
        destination.write_bytes(b"# old\n")
        data = b"# new manager\n"
        digest = hashlib.sha256(data).hexdigest()
        for expected, succeeds in (("0" * 64, False), (digest, True)):
            with mock.patch.object(self.app, "download",
                                   side_effect=[data, (expected + "  soga-manager.py\n").encode()]), \
                    contextlib.redirect_stdout(io.StringIO()):
                if succeeds:
                    self.app.self_update()
                else:
                    with self.assertRaisesRegex(ValueError, "SHA-256"):
                        self.app.self_update()
                    self.assertEqual(destination.read_bytes(), b"# old\n")
        self.assertEqual(destination.read_bytes(), data)

    def test_update_executes_installer_with_exact_tag(self):
        with mock.patch.object(self.app, "download", return_value=b"#!/bin/bash\nexit 0\n"):
            self.app.update("build-123")
        self.assertEqual(self.calls[-1][0], "bash")
        self.assertEqual(self.calls[-1][-1], "build-123")
        with self.assertRaises(ValueError):
            self.app.update("../escape")

    def test_instance_traversal_rejected(self):
        with self.assertRaises(ValueError):
            self.app.config_path("../other")

    def test_cli_dispatch(self):
        with mock.patch.object(self.app, "backend") as backend:
            self.app.cli(["restart", "anytls"])
        backend.assert_called_once_with("restart", "anytls")

    def test_purge_cancellation_and_path_guard(self):
        with self.assertRaisesRegex(ValueError, "非标准"):
            self.app.uninstall()
        self.app.root = Path("/etc/soga")
        with mock.patch("builtins.input", return_value="取消"), \
                contextlib.redirect_stdout(io.StringIO()):
            self.assertFalse(self.app.uninstall())
        self.assertFalse(self.calls)


class RealConfigurationTests(unittest.TestCase):
    def test_existing_binary_creates_edits_renames_and_removes_instance(self):
        binary = Path(__file__).resolve().parents[1] / "bin/soga-reconstructed-linux-amd64"
        self.assertTrue(binary.is_file(), "Build the amd64 program before running manager tests.")
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / "soga.conf").write_text("type=v2board\nnode_id=1\nwebapi_key=fixture\n")
            app = Manager(root, binary, root)
            app.backend("new", "anytls", "node_id=2")
            self.assertEqual(app.instances(), ["default", "anytls"])
            app.backend("config", "anytls", "node_id=3")
            self.assertIn("node_id=3", (root / "anytls/soga.conf").read_text())
            app.backend("rename", "anytls", "renamed")
            self.assertEqual(app.instances(), ["default", "renamed"])
            app.backend("remove", "renamed")
            self.assertEqual(app.instances(), ["default"])


if __name__ == "__main__":
    unittest.main()
