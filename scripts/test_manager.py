import contextlib
import hashlib
import io
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock
import urllib.error

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

    def test_instance_menu_matches_requested_text(self):
        output = io.StringIO()
        with mock.patch("builtins.input", return_value="0") as prompt, \
                contextlib.redirect_stdout(output):
            self.app.instance_menu("default")
        labels = ["返回上级", "启动", "停止", "重启", "重载配置", "查看服务状态详情",
                  "查看最近日志 (1000行)", "持续输出日志", "设置开机自启", "取消开机自启",
                  "快速配置 soga.conf", "编辑 soga.conf", "编辑 blockList", "编辑 whiteList",
                  "编辑 routes.toml", "编辑 dns.yml"]
        for i, label in enumerate(labels):
            self.assertIn("%d. %s" % (i, label), output.getvalue())
        self.assertEqual(output.getvalue().count("————————————————"), 4)
        self.assertEqual(prompt.call_args.args[0], "请输入选择 [0-15]: ")

    def test_all_instance_menu_choices_target_selected_instance(self):
        answers = [item for i in range(1, 16) for item in (str(i), "")] + ["0"]
        with mock.patch("builtins.input", side_effect=answers), \
                mock.patch.object(self.app, "backend") as backend, \
                mock.patch.object(self.app, "reload_instance") as reload, \
                mock.patch.object(self.app, "service_details") as status, \
                mock.patch.object(self.app, "quick_config") as quick, \
                mock.patch.object(self.app, "edit_file") as editor, \
                contextlib.redirect_stdout(io.StringIO()):
            self.app.instance_menu("anytls")
        self.assertEqual(backend.call_args_list, [
            mock.call("start", "anytls"), mock.call("stop", "anytls"),
            mock.call("restart", "anytls"), mock.call("log", "anytls"),
            mock.call("log", "anytls", "-f"), mock.call("enable", "anytls"),
            mock.call("disable", "anytls")])
        reload.assert_called_once_with("anytls")
        status.assert_called_once_with("anytls")
        quick.assert_called_once_with("anytls")
        self.assertEqual(editor.call_args_list, [
            mock.call("anytls", filename)
            for filename in ("soga.conf", "blockList", "whiteList", "routes.toml", "dns.yml")])

    def test_reload_signal_targets_only_selected_main_process(self):
        with contextlib.redirect_stdout(io.StringIO()):
            for name in ("default", "anytls"):
                self.app.reload_instance(name)
        self.assertEqual(self.calls[-2:], [
            ["systemctl", "kill", "--kill-whom=main", "--signal=HUP", "soga.service"],
            ["systemctl", "kill", "--kill-whom=main", "--signal=HUP", "soga@anytls.service"]])

    def test_editors_use_instance_directory_and_preserve_existing_file(self):
        import os
        before = (self.root / "anytls/soga.conf").read_bytes()
        with mock.patch.dict(os.environ, {"EDITOR": "fixture-editor -n", "VISUAL": ""}), \
                mock.patch("builtins.input", return_value="n"):
            for filename in ("soga.conf", "blockList", "whiteList", "routes.toml", "dns.yml"):
                self.app.edit_file("anytls", filename)
                target = self.root / "anytls" / filename
                self.assertEqual(self.calls[-1], ["fixture-editor", "-n", str(target)])
                self.assertTrue(target.is_file())
        self.assertEqual((self.root / "anytls/soga.conf").read_bytes(), before)
        with self.assertRaises(ValueError):
            self.app.edit_file("anytls", "../soga.conf")

    def test_quick_config_preserves_blanks_and_hides_secret(self):
        secret = "fixture-private-key"
        output = io.StringIO()
        with mock.patch("builtins.input", side_effect=["v2board", "vless", "", "https://panel.invalid", "7", "y"]), \
                mock.patch("getpass.getpass", return_value=secret), \
                mock.patch.object(self.app, "backend") as backend, \
                contextlib.redirect_stdout(output):
            self.app.quick_config("anytls")
        self.assertEqual(backend.call_args_list, [
            mock.call("config", "anytls", "type=v2board", "server_type=vless",
                      "webapi_url=https://panel.invalid", "webapi_key="+secret, "node_id=7"),
            mock.call("restart", "anytls")])
        self.assertNotIn(secret, output.getvalue())
        with mock.patch("builtins.input", return_value=""), \
                mock.patch("getpass.getpass", return_value=""), \
                mock.patch.object(self.app, "backend") as backend, \
                contextlib.redirect_stdout(io.StringIO()):
            self.app.quick_config("anytls")
        backend.assert_not_called()

    def test_backend_failure_does_not_print_config_secrets(self):
        with mock.patch.object(self.app, "run", side_effect=subprocess.CalledProcessError(1, ["webapi_key=secret"])):
            with self.assertRaises(ValueError) as caught:
                self.app.backend("config", "anytls", "webapi_key=secret")
        self.assertNotIn("secret", str(caught.exception))

    def test_inactive_service_status_is_displayed_without_false_failure(self):
        with mock.patch.object(self.app, "run", side_effect=subprocess.CalledProcessError(3, "systemctl")) as run:
            self.app.service_details("anytls")
        run.assert_called_once_with(["systemctl", "status", "--no-pager", "--full", "soga@anytls.service"])

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
        script = b"#!/bin/bash\nexit 0\n"
        sums = (hashlib.sha256(script).hexdigest() + "  soga-install.sh\n").encode()
        with mock.patch.object(self.app, "download", side_effect=[script, sums]) as download:
            self.app.update("build-123")
        self.assertEqual(download.call_args_list[0][0][0],
                         "https://github.com/Miku-programm/soga-v1/releases/download/build-123/soga-install.sh")
        self.assertEqual(self.calls[-1][:3], ["env", "SOGA_NO_MENU=1", "bash"])
        self.assertEqual(self.calls[-1][-1], "build-123")
        with self.assertRaises(ValueError):
            self.app.update("../escape")

    def test_update_rejects_installer_with_wrong_checksum(self):
        sums = ("0" * 64 + "  soga-install.sh\n").encode()
        with mock.patch.object(self.app, "download", side_effect=[b"#!/bin/bash\n", sums]):
            with self.assertRaisesRegex(ValueError, "SHA-256"):
                self.app.update("build-123")
        self.assertEqual(self.calls, [])

    def test_update_of_older_release_uses_installer_from_its_tag(self):
        missing = urllib.error.HTTPError("https://example.invalid", 404, "Not Found", {}, None)
        with mock.patch.object(self.app, "download", side_effect=[missing, b"#!/bin/bash\n"]) as download:
            self.app.update("build-9-1-44d9b76")
        self.assertEqual(download.call_args_list[-1][0][0],
                         "https://raw.githubusercontent.com/Miku-programm/soga-v1/build-9-1-44d9b76/install.sh")
        self.assertEqual(self.calls[-1][-1], "build-9-1-44d9b76")

    def test_captured_commands_run_on_python_36(self):
        seen = {}

        def fake(args, **kwargs):
            seen.update(kwargs)
            return subprocess.CompletedProcess(args, 0, stdout="")

        self.run_patch.stop()
        try:
            with mock.patch.object(subprocess, "run", side_effect=fake):
                self.app.run(["true"], capture=True)
        finally:
            self.run_patch.start()
        # Python 3.6 (EL7/EL8, Ubuntu 18.04) has neither keyword.
        self.assertNotIn("text", seen)
        self.assertNotIn("capture_output", seen)
        self.assertEqual(seen.get("encoding"), "utf-8")

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

    def test_uninstall_accepts_y_and_uppercase_y_only(self):
        self.app.root = Path("/etc/soga")
        for answer in ("y", "Y"):
            with mock.patch("builtins.input", return_value=answer) as prompt, \
                    mock.patch.object(Path, "exists", return_value=False), \
                    contextlib.redirect_stdout(io.StringIO()):
                self.assertTrue(self.app.uninstall())
            self.assertIn("输入 y", prompt.call_args.args[0])
        for answer in ("", "n", "卸载"):
            with mock.patch("builtins.input", return_value=answer), \
                    mock.patch.object(self.app, "run") as run, \
                    contextlib.redirect_stdout(io.StringIO()):
                self.assertFalse(self.app.uninstall())
            run.assert_not_called()

    def test_terminal_colors_and_plain_redirected_output(self):
        import os
        for tty in (True, False):
            output = io.StringIO()
            with contextlib.redirect_stdout(output), \
                    mock.patch.object(output, "isatty", return_value=tty), \
                    mock.patch.dict(os.environ, {"TERM": "xterm"}, clear=True):
                self.app.show()
            text = output.getvalue()
            if tty:
                for code in ("\033[32m", "\033[31m", "\033[0m"):
                    self.assertIn(code, text)
            else:
                self.assertNotIn("\033[", text)


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
