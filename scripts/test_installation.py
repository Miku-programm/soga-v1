import os
from pathlib import Path
import pty
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class InstallationRegressionTests(unittest.TestCase):
    def shell(self, source, *args, env=None):
        return subprocess.run(["bash", "-c", source, "test", *map(str, args)],
                              capture_output=True, text=True, env=env, timeout=10)

    def test_real_systemctl_empty_listing_is_not_install_failure(self):
        with tempfile.TemporaryDirectory() as stage:
            Path(stage, "etc/systemd/system").mkdir(parents=True)
            # Use the real systemctl against an isolated filesystem root.
            result = self.shell("""
set -eu
. "$1/scripts/service-migration.sh"
stage=$2
systemctl() { command systemctl --root="$stage" "$@"; }
list_legacy_services list-unit-files --plain --no-legend 'soga-reconstructed@*.service'
echo CONTINUED
""", ROOT, stage)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("CONTINUED", result.stdout)

    def test_migration_empty_present_and_error_cases(self):
        for mode in ("empty", "present", "error", "stop-error"):
            result = self.shell("""
set -eu
. "$1/scripts/service-migration.sh"
mode=$2
systemctl() {
  case "$1" in
    list-*)
      case "$mode" in
        empty) return 1 ;;
        error) echo 'Failed to connect to bus' >&2; return 1 ;;
        *) echo 'soga-reconstructed@default.service enabled'
           echo 'unrelated.service enabled' ;;
      esac ;;
    disable)
      echo "STOP $*"
      [ "$mode" != stop-error ] || return 1 ;;
    daemon-reload) echo RELOAD ;;
  esac
}
retire_legacy_services
echo COMPLETED
""", ROOT, mode)
            if mode in ("error", "stop-error"):
                self.assertNotEqual(result.returncode, 0)
                self.assertNotIn("COMPLETED", result.stdout)
                self.assertIn("失败", result.stderr)
            else:
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn("COMPLETED", result.stdout)
                self.assertNotIn("unrelated.service", result.stdout)
                self.assertEqual(result.stdout.count("STOP"), int(mode == "present"))

    def test_existing_bash_command_hash_keeps_working_after_migration(self):
        with tempfile.TemporaryDirectory() as stage:
            old = Path(stage, "usr/local/bin")
            new = Path(stage, "usr/bin")
            old.mkdir(parents=True)
            new.mkdir(parents=True)
            for path, message in ((old / "soga", "OLD"), (new / "soga", "NEW")):
                path.write_text("#!/bin/sh\necho " + message + "\n")
                path.chmod(0o755)
            result = self.shell("""
set -eu
export PATH="$2/usr/local/bin:$2/usr/bin:$PATH"
soga
hash -t soga
cp "$1/scripts/soga-compat" "$2/usr/local/bin/soga"
soga
""", ROOT, stage)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue(result.stdout.endswith("NEW\n"))

    def test_menu_opens_only_for_interactive_direct_install(self):
        with tempfile.TemporaryDirectory() as directory:
            menu = Path(directory, "menu")
            menu.write_text("#!/bin/sh\necho MENU_OPENED\n")
            menu.chmod(0o755)
            script = '. "$1/install.sh"; open_install_menu "$2"'
            for extra, expected in (({}, True), ({"SOGA_NO_MENU": "1"}, False),
                                    ({"DESTDIR": directory}, False)):
                env = {k: v for k, v in os.environ.items() if k not in ("SOGA_NO_MENU", "DESTDIR")}
                env.update(extra)
                master, slave = pty.openpty()
                try:
                    child = subprocess.Popen(["bash", "-c", script, "test", str(ROOT), str(menu)],
                                             stdin=slave, stdout=slave, stderr=slave, env=env)
                    os.close(slave)
                    slave = None
                    self.assertEqual(child.wait(timeout=10), 0)
                    output = b""
                    while True:
                        try:
                            chunk = os.read(master, 4096)
                        except OSError:
                            break
                        if not chunk:
                            break
                        output += chunk
                    self.assertEqual(b"MENU_OPENED" in output, expected)
                finally:
                    if slave is not None:
                        os.close(slave)
                    os.close(master)
            result = self.shell(script, ROOT, menu)
            self.assertNotIn("MENU_OPENED", result.stdout)


if __name__ == "__main__":
    unittest.main()
