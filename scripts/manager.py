#!/usr/bin/env python3
"""Interactive management of the independently reconstructed soga service."""
import ast
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import urllib.request

VERSION = "0.1.0"
REPO = "Miku-programm/soga-v1"
NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]*$")


class Manager:
    def __init__(self, root=None, binary=None, doc=None):
        self.doc = Path(doc) if doc else Path(__file__).resolve().parent
        self.root = Path(root or "/etc/soga")
        self.binary = Path(binary) if binary else self.doc.parents[2] / "soga/soga"
        self.release_cache = {}

    @staticmethod
    def color(text, code):
        if sys.stdout.isatty() and os.environ.get("TERM") != "dumb" and "NO_COLOR" not in os.environ:
            return "\033[" + code + "m" + text + "\033[0m"
        return text

    def display(self, *items):
        text = " ".join(str(item) for item in items)
        text = re.sub(r"(?m)^(\s*\d+\.)", lambda m: self.color(m[0], "32"), text)
        for value, code in (("已运行", "32"), ("未运行", "31"), ("启动失败", "31"),
                            ("启动中", "33"), ("停止中", "33"), ("自启: 是", "32"),
                            ("自启: 否", "31")):
            text = text.replace("[" + value + "]", self.color("[" + value + "]", code))
        text = re.sub(r"(?m)^(.*soga 管理脚本 v[^\n]*)$", lambda m: self.color(m[0], "32"), text)
        text = re.sub(r"(?m)^(.*(?:发现新版本|暂时无法检查更新)[^\n]*)$", lambda m: self.color(m[0], "33"), text)
        print(text)

    def ask(self, prompt):
        return input(self.color(prompt, "33"))

    def run(self, args, capture=False):
        if capture:
            return subprocess.run([str(x) for x in args], text=True, encoding="utf-8",
                                  errors="replace", stdout=subprocess.PIPE,
                                  stderr=subprocess.DEVNULL, timeout=8)
        return subprocess.run([str(x) for x in args], check=True)

    def backend(self, action, *args):
        return self.run([self.binary, "instance", "-root", self.root, action, *args])

    @staticmethod
    def require_root():
        if os.geteuid() != 0:
            raise ValueError("请使用 root 或 sudo soga 执行管理操作。")

    @staticmethod
    def download(url):
        request = urllib.request.Request(url, headers={"User-Agent": "soga-reconstructed-manager"})
        with urllib.request.urlopen(request, timeout=8) as response:
            data = response.read(2 * 1024 * 1024 + 1)
        if len(data) > 2 * 1024 * 1024:
            raise ValueError("下载内容超过大小限制。")
        return data

    @staticmethod
    def valid_name(name):
        if not NAME.fullmatch(name):
            raise ValueError("实例名仅允许字母、数字、下划线和连字符。")
        return name

    def config_path(self, name):
        self.valid_name(name)
        return self.root / "soga.conf" if name == "default" else self.root / name / "soga.conf"

    def instances(self):
        names = []
        if (self.root / "soga.conf").is_file():
            names.append("default")
        if self.root.is_dir():
            names.extend(sorted(p.name for p in self.root.iterdir()
                                if p.name != "default" and NAME.fullmatch(p.name)
                                and p.is_dir() and not p.is_symlink()
                                and (p / "soga.conf").is_file()))
        return names

    def state(self, name):
        self.valid_name(name)
        unit = "soga.service" if name == "default" else "soga@" + name + ".service"
        try:
            active = self.run(["systemctl", "is-active", unit], capture=True).stdout.strip()
            enabled = self.run(["systemctl", "is-enabled", unit], capture=True).stdout.strip()
        except (OSError, subprocess.TimeoutExpired):
            return "未知", "未知"
        status = {"active": "已运行", "inactive": "未运行", "failed": "启动失败",
                  "activating": "启动中", "deactivating": "停止中"}.get(active, "未运行")
        return status, "是" if enabled == "enabled" else "否"

    def channel(self):
        try:
            value = (self.root / ".manager-channel").read_text().strip()
            return value if value in ("stable", "preview") else "stable"
        except FileNotFoundError:
            return "stable"

    def set_channel(self, channel):
        self.require_root()
        if channel not in ("stable", "preview"):
            raise ValueError("分支只能为 stable 或 preview。")
        self.root.mkdir(parents=True, mode=0o700, exist_ok=True)
        self.atomic_write(self.root / ".manager-channel", (channel + "\n").encode(), 0o600)
        self.release_cache.clear()

    def latest(self):
        channel = self.channel()
        if channel in self.release_cache:
            if isinstance(self.release_cache[channel], Exception):
                raise self.release_cache[channel]
            return self.release_cache[channel]
        base = "https://api.github.com/repos/" + REPO + "/releases"
        value = json.loads(self.download(base + ("/latest" if channel == "stable" else "?per_page=100")))
        if channel == "preview":
            value = next((r for r in value if r.get("prerelease") and not r.get("draft")), None)
        if value and (value.get("draft") or not isinstance(value.get("tag_name"), str)):
            raise ValueError("无效的发布信息。")
        self.release_cache[channel] = value
        return value

    def installed_tag(self):
        try:
            return json.loads((self.doc / "build-info.json").read_text()).get("tag", "")
        except (OSError, ValueError):
            return ""

    def program_version(self):
        if not self.binary.is_file():
            return "未安装"
        try:
            value = self.run([self.binary, "version"], capture=True)
            match = re.search(r"^soga-reconstructed (\S+)", value.stdout)
            return "重建版 " + match.group(1) if match else "未知"
        except (OSError, subprocess.TimeoutExpired):
            return "未知"

    def update_notice(self):
        try:
            release = self.latest()
            if not release:
                return "当前分支尚无发布版本"
            installed = self.installed_tag()
            if not installed:
                return "可安装版本: " + release["tag_name"] + "（本机发布标签未知）"
            if installed != release["tag_name"]:
                return "发现新版本: " + release["tag_name"]
            return "当前已是所选分支最新发布"
        except Exception as error:
            # An offline menu must remain usable; avoid repeated requests.
            self.release_cache[self.channel()] = error
            return "暂时无法检查更新"

    def show(self):
        names = self.instances()
        self.display("\n  soga 管理脚本 v%s  [soga: %s]" % (VERSION, self.program_version()))
        self.display("  " + self.update_notice())
        self.display("\n  0. 退出\n————————————————")
        self.display("  1. 安装/更新 soga\n  2. 完全卸载 soga")
        self.display("  3. 切换 soga 安装分支  [当前: %s]" %
              ("稳定版" if self.channel() == "stable" else "测试版"))
        self.display("————————————————\n  4. 更新管理脚本\n  5. 新增 soga 实例\n————————————————")
        for number, name in enumerate(names, 6):
            self.display("  %d. 管理实例 [%s]" % (number, name))
        self.display("\n  实例列表:")
        for name in names:
            active, enabled = self.state(name)
            self.display("    %-12s [%s] [自启: %s]  %s" % (name, active, enabled, self.config_path(name)))
        if not names:
            self.display("    暂无实例")
        return names

    @staticmethod
    def atomic_write(path, data, mode):
        descriptor, temporary = tempfile.mkstemp(prefix=".soga-manager-", dir=path.parent)
        try:
            with os.fdopen(descriptor, "wb") as output:
                output.write(data)
                output.flush()
                os.fsync(output.fileno())
            os.chmod(temporary, mode)
            os.replace(temporary, path)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)

    def update(self, tag=None):
        self.require_root()
        if tag is None:
            release = self.latest()
            if not release:
                raise ValueError("所选分支尚无可安装版本；请先发布该分支构建。")
            tag = release["tag_name"]
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", tag):
            raise ValueError("无效的发布标签。")
        script = self.download("https://raw.githubusercontent.com/" + REPO + "/main/install.sh")
        with tempfile.TemporaryDirectory(prefix="soga-update-") as folder:
            path = Path(folder) / "install.sh"
            path.write_bytes(script)
            self.run(["env", "SOGA_NO_MENU=1", "bash", path, tag])
        self.release_cache.clear()

    def self_update(self):
        self.require_root()
        release = self.latest()
        if not release:
            raise ValueError("所选分支尚无发布。")
        tag = release["tag_name"]
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", tag):
            raise ValueError("无效的发布标签。")
        base = "https://github.com/" + REPO + "/releases/download/" + tag + "/"
        data = self.download(base + "soga-manager.py")
        checksums = self.download(base + "SHA256SUMS").decode()
        hashes = [line.split()[0] for line in checksums.splitlines()
                  if len(line.split()) == 2 and line.split()[1] == "soga-manager.py"]
        if len(hashes) != 1 or hashlib.sha256(data).hexdigest() != hashes[0]:
            raise ValueError("管理脚本 SHA-256 校验失败，未替换原文件。")
        ast.parse(data.decode("utf-8"))
        self.atomic_write(self.doc / "manager.py", data, 0o644)
        self.display("管理脚本已更新；重新运行 soga 即可使用新版菜单。")

    def uninstall(self):
        self.require_root()
        if self.root != Path("/etc/soga") or self.root.is_symlink():
            raise ValueError("拒绝完全卸载非标准配置路径。")
        self.display("将停止并卸载本重建版，删除 %s 中的配置、证书和状态。" % self.root)
        if self.ask("输入 y 确认卸载，其他输入取消: ").strip().lower() != "y":
            return False
        self.run(["sh", self.doc / "uninstall.sh"])
        if self.root.exists():
            shutil.rmtree(self.root)
        self.display("完全卸载完成。")
        return True

    def new_instance(self):
        self.require_root()
        name = self.valid_name(self.ask("新实例名称: ").strip())
        changes = shlex.split(self.ask("配置参数（key=value，可留空继承 default）: ").strip())
        self.backend("new", name, *changes)
        if self.ask("立即启动并设置自启？[y/N]: ").strip().lower() == "y":
            self.backend("enable", name)
            self.backend("start", name)

    def instance_menu(self, name):
        self.valid_name(name)
        while name in self.instances():
            active, enabled = self.state(name)
            self.display("\n  实例 [%s] [%s] [自启: %s]\n  %s" %
                  (name, active, enabled, self.config_path(name)))
            self.display("  0. 返回\n  1. 启动\n  2. 停止\n  3. 重启\n  4. 开启自启\n"
                  "  5. 关闭自启\n  6. 查看日志\n  7. 实时日志\n  8. 查看配置\n"
                  "  9. 编辑配置\n  10. 重命名实例\n  11. 删除实例")
            choice = self.ask("请输入选择 [0-11]: ").strip()
            if choice == "0":
                return
            try:
                self.require_root()
                commands = {"1": "start", "2": "stop", "3": "restart", "4": "enable",
                            "5": "disable", "6": "log", "8": "config"}
                if choice in commands:
                    self.backend(commands[choice], name)
                elif choice == "7":
                    self.backend("log", name, "-f")
                elif choice == "9":
                    editor = shlex.split(os.environ.get("EDITOR", "vi"))
                    if not editor:
                        raise ValueError("EDITOR 为空。")
                    self.run([*editor, self.config_path(name)])
                    if self.ask("配置已保存，立即重启？[y/N]: ").strip().lower() == "y":
                        self.backend("restart", name)
                elif choice == "10":
                    if name == "default":
                        raise ValueError("default 实例不能重命名。")
                    new = self.valid_name(self.ask("新的实例名: ").strip())
                    self.backend("rename", name, new)
                    name = new
                elif choice == "11":
                    if name == "default":
                        raise ValueError("default 实例不能删除。")
                    if self.ask("输入实例名确认删除: ").strip() == name:
                        self.backend("remove", name)
                        return
                else:
                    self.display("无效选择。")
            except KeyboardInterrupt:
                self.display("\n已返回实例菜单。")
            except Exception as error:
                self.display("操作失败:", error)
            self.ask("按回车继续...")

    def menu(self):
        while True:
            names = self.show()
            value = self.ask("\n请输入选择 [0-%d] 或 [实例名]: " % (5 + len(names))).strip()
            try:
                if value == "0":
                    return
                # Numeric choices take precedence; other names are accepted.
                if value.isdigit() and 6 <= int(value) < 6 + len(names):
                    self.instance_menu(names[int(value) - 6])
                elif value in names and value not in ("1", "2", "3", "4", "5"):
                    self.instance_menu(value)
                elif value == "1":
                    self.update()
                elif value == "2":
                    if self.uninstall():
                        return
                elif value == "3":
                    option = self.ask("1. 稳定版  2. 测试版（GitHub 预发布）\n请选择 [1/2]: ").strip()
                    if option not in ("1", "2"):
                        raise ValueError("无效分支。")
                    self.set_channel("stable" if option == "1" else "preview")
                    self.display("安装分支已切换。选择「安装/更新」后生效。")
                elif value == "4":
                    self.self_update()
                elif value == "5":
                    self.new_instance()
                else:
                    self.display("无效选择。")
            except KeyboardInterrupt:
                self.display("\n已取消当前操作。")
            except Exception as error:
                self.display("操作失败:", error)

    def cli(self, args):
        if not args:
            self.menu()
            return
        action, rest = args[0], args[1:]
        if action in ("version", "-v", "--version"):
            self.display("soga 管理脚本 v%s [%s]" % (VERSION, self.program_version()))
        elif action == "list":
            for name in self.instances():
                active, enabled = self.state(name)
                self.display("%s\t%s\t自启: %s\t%s" % (name, active, enabled, self.config_path(name)))
        elif action in ("install", "update"):
            if len(rest) > 1:
                raise ValueError("用法: soga update [release-tag]")
            self.update(rest[0] if rest else None)
        elif action == "self-update":
            self.self_update()
        elif action == "uninstall":
            self.uninstall()
        elif action in ("new", "remove", "rename", "start", "stop", "restart",
                        "enable", "disable", "status", "log", "config"):
            self.require_root()
            self.backend(action, *rest)
        else:
            raise ValueError("未知命令；直接运行 soga 打开管理菜单。")


def main():
    try:
        Manager().cli(sys.argv[1:])
        return 0
    except (EOFError, KeyboardInterrupt):
        print("\n已退出。")
        return 0
    except Exception as error:
        print("操作失败:", error, file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
