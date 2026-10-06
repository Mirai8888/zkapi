#!/usr/bin/env python3
"""Offline preparation regressions: patch-added files must pass exact-source checks,
and the companion test run must cover every crate the maintained patches change."""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


SCRIPTS = Path(__file__).resolve().parent


class Fixture:
    """Pinned fixture upstreams, a fixture checkout of this repository's scripts
    and patches, and a tree prepared from them by prepare-zkapi.sh."""

    def __init__(self, root, companion_files, protocol_files):
        """Each *_files maps a path to (original text or None for a file the
        patch adds, patched text)."""
        self.root = root
        global_config = root / "gitconfig"
        self.environment = dict(os.environ, GIT_CONFIG_GLOBAL=str(global_config),
                                GIT_CONFIG_NOSYSTEM="1", GIT_AUTHOR_NAME="Fixture",
                                GIT_AUTHOR_EMAIL="fixture@example.invalid",
                                GIT_COMMITTER_NAME="Fixture", GIT_COMMITTER_EMAIL="fixture@example.invalid")

        protocol = root / "protocol-upstream"
        protocol.mkdir()
        self.git(protocol, "init", "-q")
        self.write_originals(protocol, protocol_files, "unchanged protocol\n")
        self.git(protocol, "add", ".")
        self.git(protocol, "commit", "-qm", "fixture protocol")
        self.protocol_commit = self.git(protocol, "rev-parse", "HEAD")

        source = root / "companion-upstream"
        source.mkdir()
        self.git(source, "init", "-q")
        self.write_originals(source, companion_files, "unchanged companion\n")
        self.git(source, "add", ".")
        self.git(source, "-c", "protocol.file.allow=always", "submodule", "add", "-q", protocol.as_uri(), "protocol")
        self.git(source, "commit", "-qm", "fixture companion")
        self.companion_commit = self.git(source, "rev-parse", "HEAD")

        fixture_repo = root / "zkapi-clientd"
        self.scripts = fixture_repo / "zkapi-clientd/scripts"
        self.scripts.mkdir(parents=True)
        patches = fixture_repo / "zkapi-clientd/internal/zkapi"
        patches.mkdir(parents=True)
        packaging = fixture_repo / "zkapi-clientd/packaging"
        packaging.mkdir()
        for name in ("prepare-zkapi.sh", "verify-zkapi-source.py", "test-companion.sh"):
            shutil.copy2(SCRIPTS / name, self.scripts / name)
        (packaging / "zkapi-source.env").write_text(
            f"OA_COMPANION_COMMIT={self.companion_commit}\nOA_PROTOCOL_COMMIT={self.protocol_commit}\n")
        (patches / "companion.patch").write_text(self.patch(source, companion_files))
        (patches / "protocol-transport.patch").write_text(self.patch(protocol, protocol_files))
        # Clone the fixture revisions via an isolated Git URL rewrite. There
        # are no external downloads and no changes to the user's Git config.
        global_config.write_text(
            '[protocol "file"]\n\tallow = always\n'
            f'[url "{source.as_uri()}"]\n\tinsteadOf = https://github.com/ethereum/zkapi.git\n')
        self.prepared = root / "prepared"
        self.preparation = subprocess.run(["bash", str(self.scripts / "prepare-zkapi.sh"), str(self.prepared)],
                                          env=self.environment, text=True, capture_output=True, timeout=30)

    def git(self, path, *args):
        return subprocess.check_output(["git", "-C", str(path), *args],
                                       env=self.environment, stderr=subprocess.PIPE).decode().strip()

    @staticmethod
    def write_originals(directory, files, unchanged):
        (directory / "unchanged.txt").write_text(unchanged)
        for name, (original, _) in files.items():
            if original is not None:
                (directory / name).parent.mkdir(parents=True, exist_ok=True)
                (directory / name).write_text(original)

    def patch(self, directory, files):
        for name, (original, patched) in files.items():
            (directory / name).parent.mkdir(parents=True, exist_ok=True)
            (directory / name).write_text(patched)
            if original is None:
                self.git(directory, "add", "-N", name)
        return self.git(directory, "diff", "--binary", "HEAD") + "\n"


class PreparationTests(unittest.TestCase):
    def test_added_sources_are_verified_and_unexpected_changes_rejected(self):
        with tempfile.TemporaryDirectory(prefix="zkapi-prepare-test-") as directory:
            fixture = Fixture(
                Path(directory),
                {"main.txt": ("original companion\n", "patched companion\n"),
                 "withdrawal.txt": (None, "new withdrawal implementation\n")},
                {"transport.txt": ("original transport\n", "patched transport\n"),
                 "bridge.txt": (None, "new bridge implementation\n")})
            prepared, git = fixture.prepared, fixture.git
            result = fixture.preparation
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("Verified exact companion/protocol", result.stdout)
            self.assertEqual(git(prepared, "ls-files", "--others", "--exclude-standard"), "")
            self.assertEqual(git(prepared / "protocol", "ls-files", "--others", "--exclude-standard"), "")
            self.assertEqual((prepared / "withdrawal.txt").read_text(), "new withdrawal implementation\n")
            self.assertEqual((prepared / "protocol/bridge.txt").read_text(), "new bridge implementation\n")
            self.assertEqual(git(prepared, "ls-files", "--error-unmatch", "unchanged.txt"), "unchanged.txt")
            self.assertEqual(git(prepared / "protocol", "ls-files", "--error-unmatch", "unchanged.txt"), "unchanged.txt")

            # These patches change no crate, so there is nothing to test; the
            # companion test run refuses instead of reporting them tested.
            untested = subprocess.run(["bash", str(fixture.scripts / "test-companion.sh"), str(prepared)],
                                      env=fixture.environment, text=True, capture_output=True, timeout=30)
            self.assertNotEqual(untested.returncode, 0, untested.stdout + untested.stderr)
            self.assertIn("companion.patch changes no crate under crates/", untested.stderr)

            command = ["python3", str(fixture.scripts / "verify-zkapi-source.py"),
                       str(prepared), fixture.companion_commit, fixture.protocol_commit]
            for mutation in (prepared / "unexpected.txt", prepared / "protocol/bridge.txt"):
                mutation.write_text("unexpected source\n")
                rejected = subprocess.run(command, env=fixture.environment, text=True, capture_output=True, timeout=30)
                self.assertNotEqual(rejected.returncode, 0, "unexpected source was accepted")
                if mutation.name == "unexpected.txt":
                    mutation.unlink()

    def test_companion_tests_run_every_crate_the_patches_change(self):
        # The companion workspace excludes protocol/rust, so testing only the
        # companion crates would never run the patched protocol crates' tests.
        with tempfile.TemporaryDirectory(prefix="zkapi-companion-test-") as directory:
            root = Path(directory)
            fixture = Fixture(
                root,
                {"crates/wallet/src/lib.rs": ("original wallet\n", "patched wallet\n"),
                 "crates/wallet/src/routes.rs": ("original routes\n", "patched routes\n"),
                 "crates/bridge/tests/new.rs": (None, "new bridge test\n"),
                 "Cargo.lock": ("original lock\n", "patched lock\n")},
                {"rust/crates/client/src/journal.rs": ("original journal\n", "durable journal\n"),
                 "rust/crates/client/src/note_state.rs": ("original state\n", "durable state\n"),
                 "rust/crates/types/src/wire.rs": ("original wire\n", "patched wire\n"),
                 "README.md": ("original readme\n", "patched readme\n")})
            self.assertEqual(fixture.preparation.returncode, 0,
                             fixture.preparation.stdout + fixture.preparation.stderr)

            # A stand-in cargo records where and how it runs, and fails in one
            # chosen directory.
            bin_dir = root / "bin"
            bin_dir.mkdir()
            log = root / "cargo.log"
            fake_cargo = bin_dir / "cargo"
            fake_cargo.write_text('#!/bin/sh\nprintf \'%s\\t%s\\n\' "$(pwd -P)" "$*" >> "$FAKE_CARGO_LOG"\n'
                                  'test "$(pwd -P)" != "$FAKE_CARGO_FAIL_IN"\n')
            fake_cargo.chmod(0o755)
            prepared = Path(os.path.realpath(fixture.prepared))
            protocol_rust = prepared / "protocol/rust"

            def run_tests(fail_in=""):
                if log.exists():
                    log.unlink()
                environment = dict(fixture.environment, PATH=f"{bin_dir}{os.pathsep}{os.environ['PATH']}",
                                   FAKE_CARGO_LOG=str(log), FAKE_CARGO_FAIL_IN=fail_in)
                result = subprocess.run(["bash", str(fixture.scripts / "test-companion.sh"), str(fixture.prepared)],
                                        env=environment, text=True, capture_output=True, timeout=30)
                calls = [tuple(line.split("\t")) for line in log.read_text().splitlines()] if log.exists() else []
                return result, calls

            result, calls = run_tests()
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertEqual(calls, [
                (str(prepared), "test --release --locked -p bridge -p wallet"),
                (str(protocol_rust), "test --release --locked -p client -p types"),
            ])
            self.assertIn("Tested every crate changed by", result.stdout)

            # A failing protocol crate test fails the run.
            result, calls = run_tests(fail_in=str(protocol_rust))
            self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertEqual(len(calls), 2)

            # A failing companion crate test fails the run before the protocol crates.
            result, calls = run_tests(fail_in=str(prepared))
            self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertEqual(len(calls), 1)

            # A tree that is not exactly the pinned sources plus the patches is
            # refused before anything is tested.
            (fixture.prepared / "protocol/rust/crates/client/src/journal.rs").write_text("original journal\n")
            result, calls = run_tests()
            self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("differ from its maintained patch", result.stderr)
            self.assertEqual(calls, [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
