"""Exercise packaging failures with fake compilers; never modify real releases."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
import unittest

REPOSITORY = Path(__file__).resolve().parents[2]


@unittest.skipUnless(shutil.which("bash"), "Bash packaging tests require Bash")
class BuildTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="tknet build ö & ")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        shutil.copy(REPOSITORY / "build.sh", self.root)
        (self.root / "tools").mkdir()
        shutil.copy(REPOSITORY / "tools/check.sh", self.root / "tools")
        (self.root / "release-linux").mkdir()
        (self.root / "release-linux/TKNetUI").write_text("previous version")
        (self.root / "release-linux/previous-only.txt").write_text("old package")
        (self.root / "TKNetUI/Resources").mkdir(parents=True)
        (self.root / "TKNetUI/Resources/tknet-engine").write_text("cached engine")
        (self.root / "fake tools").mkdir()
        self.go = self.script("go", '''
import os, pathlib, sys, time
args = sys.argv[1:]
assert os.environ['GOOS'] == 'linux' and os.environ['GOARCH'] == 'amd64'
assert os.environ['CGO_ENABLED'] == '1', 'Do not change the configured DNS/CGO behavior'
root = pathlib.Path.cwd()
(root / 'go-started').touch()
if os.environ.get('HOLD_GO'):
    deadline = time.monotonic() + 5
    while not (root / 'release-go').exists():
        if time.monotonic() > deadline: sys.exit(9)
        time.sleep(.01)
failure = os.environ['FAILURE']
if failure == 'engine': sys.exit(1)
if failure == 'missing-engine': sys.exit(0)
output = pathlib.Path(args[args.index('-o') + 1])
assert output.parent.name.startswith('.tknet-build.')
output.write_text('' if failure == 'empty-engine' else 'new engine')
output.chmod(0o600 if failure == 'engine-not-executable' else 0o700)
''')
        self.dotnet = self.script("dotnet", '''
import json, os, pathlib, sys
args = sys.argv[1:]
engine = pathlib.Path(next(a.split('=', 1)[1] for a in args if a.startswith('-p:TkNetEnginePath=')))
assert engine.read_text() == 'new engine'
assert engine.parent.name.startswith('.tknet-build.')
assert args[args.index('-r') + 1] == 'linux-x64'
output = pathlib.Path(args[args.index('-o') + 1]); output.mkdir()
for name in ['TKNetUI', 'libSkiaSharp.so', 'libHarfBuzzSharp.so']:
    (output / name).write_text('new version' if name == 'TKNetUI' else 'native library')
(output / 'TKNetUI').chmod(0o700)
(pathlib.Path.cwd() / 'publish-args.json').write_text(json.dumps(args))
failure = os.environ['FAILURE']
if failure == 'publish': sys.exit(1)
if failure == 'missing-executable': (output / 'TKNetUI').unlink()
if failure == 'empty-executable': (output / 'TKNetUI').write_text('')
if failure == 'not-executable': (output / 'TKNetUI').chmod(0o600)
if failure == 'missing-native': (output / 'libSkiaSharp.so').unlink()
if failure == 'empty-native': (output / 'libHarfBuzzSharp.so').write_text('')
''')
        real_mv = shutil.which("mv")
        self.script("mv", '''
import os, pathlib, subprocess, sys
args = sys.argv[1:]
paths = [a for a in args if a not in ('--', '-T')]
source = pathlib.Path(paths[0])
failure = os.environ['FAILURE']
if failure in ('install', 'rollback') and source.name == 'publish': sys.exit(1)
if failure == 'rollback' and source.name == 'previous': sys.exit(1)
if failure == 'archive' and source.name == 'release-linux': sys.exit(1)
sys.exit(subprocess.run([REAL_MV] + args).returncode)
'''.replace("REAL_MV", repr(real_mv)))
        self.env = dict(os.environ, GO_BIN=str(self.go), DOTNET_BIN=str(self.dotnet), FAILURE="", CGO_ENABLED="1")
        self.env["PATH"] = str(self.root / "fake tools") + os.pathsep + os.environ.get("PATH", "")

    def script(self, name, body):
        path = self.root / "fake tools" / name
        path.write_text("#!" + sys.executable + "\n" + body)
        path.chmod(0o700)
        return path

    def run_build(self, failure="", **overrides):
        env = dict(self.env, FAILURE=failure, **overrides)
        return subprocess.run(["bash", str(self.root / "build.sh")], cwd=self.root.parent,
                              env=env, capture_output=True, text=True, timeout=10)

    def assert_preserved(self, result):
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual((self.root / "release-linux/TKNetUI").read_text(), "previous version")
        self.assertEqual((self.root / "TKNetUI/Resources/tknet-engine").read_text(), "cached engine")
        self.assertEqual(list(self.root.glob(".tknet-build.*")), [])

    def test_compiler_and_incomplete_output_failures_preserve_release(self):
        for failure in ["engine", "missing-engine", "empty-engine", "engine-not-executable", "publish",
                        "missing-executable", "empty-executable", "not-executable", "missing-native", "empty-native"]:
            with self.subTest(failure=failure):
                self.assert_preserved(self.run_build(failure))

    def test_success_replaces_complete_package_from_another_directory(self):
        result = self.run_build()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual((self.root / "release-linux/TKNetUI").read_text(), "new version")
        self.assertFalse((self.root / "release-linux/previous-only.txt").exists())
        self.assertTrue((self.root / "release-linux/libSkiaSharp.so").is_file())
        self.assertTrue((self.root / "release-linux/libHarfBuzzSharp.so").is_file())
        self.assertEqual((self.root / "TKNetUI/Resources/tknet-engine").read_text(), "cached engine")
        self.assertEqual(list(self.root.glob(".tknet-build.*")), [])

    def test_first_build_without_previous_release(self):
        shutil.rmtree(self.root / "release-linux")
        result = self.run_build()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((self.root / "release-linux/TKNetUI").read_text(), "new version")

    def test_failure_to_archive_preserves_release(self):
        self.assert_preserved(self.run_build("archive"))

    def test_failed_install_restores_previous_release(self):
        result = self.run_build("install")
        self.assert_preserved(result)
        self.assertIn("Previous release restored", result.stderr)

    def test_failed_rollback_retains_only_copy_for_recovery(self):
        result = self.run_build("rollback")
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.root / "release-linux").exists())
        self.assertFalse((self.root / ".tknet-build.lock").exists())
        stages = list(self.root.glob(".tknet-build.*"))
        self.assertEqual(len(stages), 1)
        self.assertEqual((stages[0] / "previous/TKNetUI").read_text(), "previous version")
        self.assertIn(str(stages[0]) + "/previous", result.stderr)

    def test_existing_lock_is_preserved_without_running_compilers(self):
        lock = self.root / ".tknet-build.lock"
        lock.mkdir(); (lock / "owner").write_text("another process")
        result = self.run_build()
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.root / "go-started").exists())
        self.assertEqual((lock / "owner").read_text(), "another process")
        self.assertEqual((self.root / "release-linux/TKNetUI").read_text(), "previous version")

    def test_two_concurrent_builds_do_not_mix_packages(self):
        process = subprocess.Popen(["bash", str(self.root / "build.sh")], cwd=self.root.parent,
                                   env=dict(self.env, HOLD_GO="1"), stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            deadline = time.monotonic() + 5
            while not (self.root / "go-started").exists():
                if process.poll() is not None or time.monotonic() > deadline:
                    self.fail("First build did not reach the staged compilation")
                time.sleep(.01)
            blocked = self.run_build()
            self.assertNotEqual(blocked.returncode, 0)
            self.assertTrue((self.root / ".tknet-build.lock").is_dir())
            (self.root / "release-go").touch()
            out, err = process.communicate(timeout=5)
            self.assertEqual(process.returncode, 0, out + err)
            self.assertEqual((self.root / "release-linux/TKNetUI").read_text(), "new version")
            self.assertFalse((self.root / ".tknet-build.lock").exists())
        finally:
            if process.poll() is None: process.kill()
            process.communicate()

    def test_missing_tool_fails_before_staging(self):
        result = self.run_build(GO_BIN=str(self.root / "absent"))
        self.assert_preserved(result)
        self.assertIn("Required build tool not found", result.stderr)

    def test_staging_failure_releases_lock(self):
        self.script("mktemp", "import sys\nsys.exit(1)\n")
        self.assert_preserved(self.run_build())

    def test_release_symlink_is_not_followed_or_replaced(self):
        (self.root / "release-linux").rename(self.root / "linked-release")
        (self.root / "release-linux").symlink_to(self.root / "linked-release", target_is_directory=True)
        self.assert_preserved(self.run_build())
        self.assertTrue((self.root / "release-linux").is_symlink())

    def test_quality_checks_use_custom_tools_and_release_lock(self):
        runner = self.script("check-tool", '''
import json, os, pathlib, sys
with (pathlib.Path.cwd() / 'check-calls.jsonl').open('a') as output:
    output.write(json.dumps(sys.argv[1:]) + '\\n')
if os.environ['FAILURE'] == 'checks': sys.exit(1)
''')
        env = dict(self.env, GO_BIN=str(runner), DOTNET_BIN=str(runner), PYTHON_BIN=str(runner))
        result = subprocess.run(["bash", str(self.root / "tools/check.sh")], cwd=self.root.parent,
                                env=env, capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        calls = [json.loads(line) for line in (self.root / "check-calls.jsonl").read_text().splitlines()]
        self.assertEqual(len(calls), 7)
        self.assertTrue(any("tests/TKNetUI.VisualChecks/TKNetUI.VisualChecks.csproj" in call for call in calls))
        self.assertFalse((self.root / ".tknet-build.lock").exists())
        env['FAILURE'] = 'checks'
        result = subprocess.run(["bash", str(self.root / "tools/check.sh")], env=env, capture_output=True, timeout=10)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.root / ".tknet-build.lock").exists())


if __name__ == "__main__":
    unittest.main()
