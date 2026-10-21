"""Checks the npm tarball the build job made, and writes a clean copy for `npm stage publish` (issue #3).

Used by the npm job in .github/workflows/publish.yml, the only job that can get an npm publishing token, so it treats
the tarball as untrusted. It never extracts to disk: it reads each member into memory and then writes a new tarball
from what it checked. npm therefore reads exactly the package.json checked here, and no second manifest, link or odd
path in the original can change what npm sees. npm applies package.json's publishConfig as configuration (registry,
proxy and TLS settings included), so publishConfig must be exactly what scripts/build_npm.ts writes.

    python3 -I release_tarball.py <in.tgz> <out.tgz> <package name> <version>

Refused: anything but regular files and directories (links, devices), a path outside `package/`, a path part with
any character other than letters, digits and . _ @ + - (so no colon, backslash, space or control character), an
empty, `.` or `..` part, the same path twice, any .npmrc, a "[FILL" placeholder, and a package.json whose name,
version or publishConfig differ from the expected ones.
"""

import io
import json
import re
import sys
import tarfile

EXPECTED_PUBLISH_CONFIG = {"access": "public", "provenance": True}
# npm pack's fixed timestamp (1985-10-26), so the clean copy is as reproducible as the original.
MTIME = 499162500
# An allowlist, not a blocklist: npm's tar reader rewrites some paths (it strips a Windows drive prefix such as "z:"
# even on Linux, and absolute roots), so a path it would read as another file must never pass. Every part after
# "package/" may hold only letters, digits and . _ @ + -, and none may be "." or "..".
SAFE_PART = re.compile(r"^[A-Za-z0-9._@+-]+$")


def fail(message: str) -> None:
    print(f"release_tarball: {message}", file=sys.stderr)
    sys.exit(1)


def safe_path(name: str) -> bool:
    parts = name.split("/")
    return (
        len(parts) >= 2
        and parts[0] == "package"
        and all(SAFE_PART.fullmatch(p) is not None and p not in (".", "..") for p in parts[1:])
    )


def main() -> None:
    if len(sys.argv) != 5:
        fail("usage: release_tarball.py <in.tgz> <out.tgz> <package name> <version>")
    src, dst, name, version = sys.argv[1:]
    files: dict[str, tuple[bytes, bool]] = {}
    with tarfile.open(src, "r:gz") as tar:
        for member in tar:
            if member.isdir():
                if member.name.rstrip("/") != "package" and not safe_path(member.name.rstrip("/")):
                    fail(f"directory outside package/: {member.name!r}")
                continue
            if not member.isreg():
                fail(f"not a regular file: {member.name!r}")
            if not safe_path(member.name):
                fail(f"unsafe path: {member.name!r}")
            if member.name in files:
                fail(f"path appears twice: {member.name!r}")
            if member.name.split("/")[-1] == ".npmrc":
                fail(f"the tarball holds an .npmrc: {member.name!r}")
            handle = tar.extractfile(member)
            data = handle.read() if handle else b""
            if b"[FILL" in data:
                fail(f"a [FILL ...] placeholder is left in {member.name!r}")
            files[member.name] = (data, bool(member.mode & 0o111))

    raw = files.get("package/package.json")
    if raw is None:
        fail("no package/package.json")
    try:
        manifest = json.loads(raw[0])
    except ValueError:
        fail("package/package.json is not JSON")
    if not isinstance(manifest, dict):
        fail("package/package.json is not an object")
    if manifest.get("name") != name or manifest.get("version") != version:
        fail(f"package.json says {manifest.get('name')!r} {manifest.get('version')!r}, expected {name!r} {version!r}")
    if manifest.get("publishConfig") != EXPECTED_PUBLISH_CONFIG:
        fail(f"publishConfig must be exactly {EXPECTED_PUBLISH_CONFIG!r}")
    # Written back from the parsed object: a key repeated in the original (where the last one wins) is gone.
    files["package/package.json"] = ((json.dumps(manifest, indent=2, ensure_ascii=False) + "\n").encode(), False)

    with tarfile.open(dst, "w:gz", format=tarfile.PAX_FORMAT) as out:
        for path in sorted(files):
            data, executable = files[path]
            info = tarfile.TarInfo(path)
            info.size = len(data)
            info.mode = 0o755 if executable else 0o644
            info.mtime = MTIME
            out.addfile(info, io.BytesIO(data))
    print(f"release_tarball: {len(files)} files checked and written to {dst}")


main()
