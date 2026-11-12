#!/usr/bin/env python3
"""把 .app 打成 ipa（Payload/<name>.app 结构 + 保留 unix 权限位）。

不要求 app 外面已经有 Payload/ 目录：直接拿 app 自己算前缀，
所以 build/Build/Products/Release-iphoneos/TRX.app 和 <x>/Payload/TRX.app 都能打。

用法: python tools/make_ipa.py --app <TRX.app> --out <x.ipa>
"""

import argparse
import os
import plistlib
import zipfile

MACHO_MAGICS = (b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe", b"\xca\xfe\xba\xbe")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--app", required=True)
    parser.add_argument("--out", required=True)
    args = parser.parse_args()

    app = os.path.abspath(args.app)
    out = os.path.abspath(args.out)
    name = os.path.basename(app)
    if not name.endswith(".app"):
        raise SystemExit("not an .app bundle: %s" % name)

    prefix = "Payload/" + name + "/"
    exe = plistlib.load(open(os.path.join(app, "Info.plist"), "rb"))["CFBundleExecutable"]

    entries = []          # (zip path, absolute path)
    executables = set()
    for base, _dirs, files in os.walk(app):
        for f in sorted(files):
            full = os.path.join(base, f)
            rel = os.path.relpath(full, app).replace(os.sep, "/")
            arc = prefix + rel
            entries.append((arc, full))
            try:
                with open(full, "rb") as fh:
                    magic = fh.read(4)
            except OSError:
                continue
            if rel == exe or magic in MACHO_MAGICS:
                executables.add(arc)

    if not entries:
        raise SystemExit("app bundle is empty: %s" % app)

    if os.path.exists(out):
        os.remove(out)
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as zf:
        for arc, full in entries:
            info = zipfile.ZipInfo(arc)
            info.external_attr = (0o100755 if arc in executables else 0o100644) << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            with open(full, "rb") as fh:
                zf.writestr(info, fh.read())

    size = os.path.getsize(out)
    print("wrote %s  %.2f MB  (%d files, %d executables)" % (
        out, size / 1048576, len(entries), len(executables)))
    if size < 1024 * 1024:
        print("[WARN] ipa 只有 %d 字节 —— 打包大概率是空的" % size)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
