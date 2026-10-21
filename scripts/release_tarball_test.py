"""Tests for release_tarball.py: `python3 -I scripts/release_tarball_test.py` (CI runs it; standard library only).

Each tampered tarball holds the expected package/package.json plus something that could make npm read other content
than the checked manifest. All must be refused; the good one is rewritten unchanged in content.
"""

import io
import json
import os
import subprocess
import sys
import tarfile
import tempfile
import unittest

SCRIPT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "release_tarball.py")
NAME, VERSION = "@signupbouncer/better-auth", "0.2.1"
GOOD = json.dumps({"name": NAME, "version": VERSION, "publishConfig": {"access": "public", "provenance": True}})
HOSTILE = json.dumps(
    {"name": NAME, "version": VERSION, "publishConfig": {"https-proxy": "http://proxy.invalid:8080", "strict-ssl": False}}
)


def member(name, data=b"x", kind=tarfile.REGTYPE, link=""):
    return name, data.encode() if isinstance(data, str) else data, kind, link


def run(members):
    with tempfile.TemporaryDirectory() as d:
        src, dst = os.path.join(d, "in.tgz"), os.path.join(d, "out.tgz")
        with tarfile.open(src, "w:gz") as t:
            for name, data, kind, link in members:
                info = tarfile.TarInfo(name)
                info.type, info.linkname = kind, link
                info.size = len(data) if kind == tarfile.REGTYPE else 0
                t.addfile(info, io.BytesIO(data) if kind == tarfile.REGTYPE else None)
        result = subprocess.run(
            [sys.executable, "-I", SCRIPT, src, dst, NAME, VERSION], capture_output=True, text=True, check=False
        )
        out = None
        if result.returncode == 0:
            with tarfile.open(dst, "r:gz") as t:
                out = {m.name: t.extractfile(m).read() for m in t if m.isreg()}
        return result.returncode, result.stderr, out


class ReleaseTarball(unittest.TestCase):
    def test_good_package_is_rewritten_with_the_same_files(self):
        code, err, out = run([member("package/package.json", GOOD), member("package/esm/mod.js", "export {}")])
        self.assertEqual(code, 0, err)
        self.assertEqual(sorted(out), ["package/esm/mod.js", "package/package.json"])
        self.assertEqual(json.loads(out["package/package.json"]), json.loads(GOOD))

    def test_repeated_json_key_is_dropped_from_the_written_manifest(self):
        raw = (
            '{"name":"%s","version":"%s","publishConfig":{"registry":"https://other.invalid/"},'
            '"publishConfig":{"access":"public","provenance":true}}' % (NAME, VERSION)
        )
        code, err, out = run([member("package/package.json", raw)])
        self.assertEqual(code, 0, err)
        self.assertNotIn(b"other.invalid", out["package/package.json"])

    def test_refused(self):
        good = member("package/package.json", GOOD)
        cases = {
            "second top-level folder": [good, member("other/package.json", HOSTILE)],
            "same path twice": [good, member("package/package.json", HOSTILE)],
            "symlink manifest": [member("package/package.json", b"", tarfile.SYMTYPE, "/etc/passwd")],
            "hard link manifest": [
                member("package/x.json", GOOD),
                member("package/package.json", b"", tarfile.LNKTYPE, "package/x.json"),
            ],
            "dot part": [good, member("package/./package.json", HOSTILE)],
            "dot-dot part": [good, member("package/../package/package.json", HOSTILE)],
            "empty part": [good, member("package//x.js")],
            "drive prefix (astra review)": [good, member("package/z:package.json", HOSTILE)],
            "drive folder": [good, member("package/C:/package.json", HOSTILE)],
            "trailing newline": [good, member("package/x.js\n", HOSTILE)],
            "backslash": [good, member("package/a\\package.json", HOSTILE)],
            "absolute path": [good, member("/package/package.json", HOSTILE)],
            "space": [good, member("package/a b.js")],
            ".npmrc": [good, member("package/.npmrc", "registry=https://other.invalid/")],
            "hostile publishConfig": [member("package/package.json", HOSTILE)],
            "other package name": [member("package/package.json", GOOD.replace("better-auth", "client"))],
            "other version": [member("package/package.json", GOOD.replace(VERSION, "0.2.0"))],
            "placeholder": [good, member("package/README.md", "[FILL me]")],
            "no manifest": [member("package/esm/mod.js")],
        }
        for label, members in cases.items():
            with self.subTest(label):
                code, err, _ = run(members)
                self.assertEqual(code, 1, f"{label} was accepted")
                self.assertIn("release_tarball:", err)


if __name__ == "__main__":
    unittest.main()
