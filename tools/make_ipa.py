#!/usr/bin/env python3
"""把 .app 打成 ipa（Payload/ 结构 + 保留 unix 权限位，等价于 macOS 的 zip -qry）。

用法: python tools/make_ipa.py --app <TRX.app> --out <x.ipa>
"""

import argparse
import os
import plistlib
import zipfile


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--app", required=True)
    parser.add_argument("--out", required=True)
    args = parser.parse_args()

    app = os.path.abspath(args.app)
    out = os.path.abspath(args.out)
    name = os.path.basename(app)
    # app 在 <root>/Payload/<name>.app，zip 里必须保留 Payload/ 这一层
    root = os.path.dirname(os.path.dirname(app))

    exe = plistlib.load(open(os.path.join(app, "Info.plist"), "rb"))["CFBundleExecutable"]
    executables = {("Payload/%s/%s" % (name, exe))}
    for base, _dirs, files in os.walk(app):
        for f in files:
            full = os.path.join(base, f)
            try:
                with open(full, "rb") as fh:
                    magic = fh.read(4)
            except OSError:
                continue
            if magic in (b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe", b"\xca\xfe\xba\xbe"):
                rel = os.path.relpath(full, root).replace(os.sep, "/")
                executables.add(rel)

    if os.path.exists(out):
        os.remove(out)

    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as zf:
        for base, _dirs, files in os.walk(root):
            for f in sorted(files):
                full = os.path.join(base, f)
                rel = os.path.relpath(full, root).replace(os.sep, "/")
                if not rel.startswith("Payload/"):
                    continue
                info = zipfile.ZipInfo(rel)
                info.external_attr = (0o100755 if rel in executables else 0o100644) << 16
                info.compress_type = zipfile.ZIP_DEFLATED
                with open(full, "rb") as fh:
                    zf.writestr(info, fh.read())

    print("wrote %s  %.2f MB  (%d executables)" % (out, os.path.getsize(out) / 1048576, len(executables)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
