#!/usr/bin/env python3
"""对比"未签名 app"与"签名后 app"，定位完整性校验为什么不过。

用法:
    python tools/diagnose_signed.py --unsigned <Payload/TRX.app> --signed <Payload/TRX.app>
"""

import argparse
import base64
import hashlib
import json
import os
import plistlib
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from integrity_pack import macho_text_range, find_integrity_section  # noqa: E402


def sha256(b):
    return hashlib.sha256(b).digest()


def exe_of(app):
    return plistlib.load(open(os.path.join(app, "Info.plist"), "rb"))["CFBundleExecutable"]


def read_manifest(app):
    exe = os.path.join(app, exe_of(app))
    data = open(exe, "rb").read()
    sec = find_integrity_section(data)
    if not sec:
        return None, data, None
    off, size = sec
    blob = data[off:off + size]
    if blob[:8] != b"3105IGV1":
        return None, data, None
    length = struct.unpack_from("<I", blob, 8)[0]
    body = blob[12:12 + length]
    sig = blob[12 + length:12 + length + 64]
    return json.loads(body), data, sig


def walk(app):
    out = {}
    root = app
    for base, _dirs, files in os.walk(root):
        for f in files:
            full = os.path.join(base, f)
            rel = os.path.relpath(full, root).replace(os.sep, "/")
            out[rel] = full
    return out


def text_hash(data):
    span = macho_text_range(data)
    if span:
        return ("macho", sha256(data[span[0]:span[1]]), span)
    return ("raw", sha256(data), None)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--unsigned", required=True)
    ap.add_argument("--signed", required=True)
    args = ap.parse_args()

    u_app = os.path.abspath(args.unsigned)
    s_app = os.path.abspath(args.signed)

    m, u_exe, _sig = read_manifest(u_app)
    if not m:
        print("! 未签名包里没有找到 __DATA,__integrity 清单")
        return 1
    print("=== 未签名包的清单 ===")
    print("  files:", len(m["files"]), " skip:", m["skip"])
    recorded = base64.b64decode(m["text"])

    # 未签名主二进制：验证清单里的 text hash 是按哪个范围算的
    span = macho_text_range(u_exe)
    h_from_text = sha256(u_exe[span[0]:span[1]])
    fs = struct.unpack_from("<Q", u_exe, 0)[0]  # placeholder
    print("  __text 起始偏移:", span[0], " 结束:", span[1])
    print("  hash(__text..__TEXT.filesize):", h_from_text.hex()[:16], "match:", h_from_text == recorded)
    # 旧范围：从 0 到 __TEXT.filesize
    text_filesize = span[1]
    h_from_zero = sha256(u_exe[0:text_filesize])
    print("  hash(0..__TEXT.filesize)     :", h_from_zero.hex()[:16], "match:", h_from_zero == recorded)
    print("  => 该包使用", "新范围(__text 起)" if h_from_text == recorded else ("旧范围(文件 0 起)" if h_from_zero == recorded else "未知范围"))

    # 文件差异
    u_files = walk(u_app)
    s_files = walk(s_app)
    only_signed = sorted(set(s_files) - set(u_files))
    only_unsigned = sorted(set(u_files) - set(s_files))
    print()
    print("=== 文件集合差异 ===")
    print("  仅签名包有:", only_signed or "无")
    print("  仅未签名包有:", only_unsigned or "无")

    # 逐文件对比
    print()
    print("=== 逐文件哈希（清单 vs 签名后实际） ===")
    expected = {e["p"]: (bool(e["k"]), base64.b64decode(e["h"])) for e in m["files"]}
    bad = []
    skipped = m["skip"]
    for rel in sorted(set(u_files) & set(s_files)):
        if any(rel == s or (s.endswith("/") and rel.startswith(s)) for s in skipped):
            continue
        u_data = open(u_files[rel], "rb").read()
        s_data = open(s_files[rel], "rb").read()
        u_kind, u_hash, _ = text_hash(u_data)
        s_kind, s_hash, _ = text_hash(s_data)
        exp = expected.get(rel)
        status = []
        if exp is None:
            status.append("清单外")
        else:
            status.append("manifest-ok" if exp[1] == s_hash else "MANIFEST-MISMATCH")
        if u_hash != s_hash:
            status.append("签名改动了内容")
        if status != ["manifest-ok"]:
            bad.append((rel, status, u_kind, len(u_data), len(s_data)))
            print("  %-58s %s  size %d->%d" % (rel, ",".join(status), len(u_data), len(s_data)))

    if not any(b[1] != ["manifest-ok"] for b in bad):
        print("  （除签名产物外全部一致）")

    # Info.plist 关键字段
    print()
    print("=== Info.plist 差异（关键字）===")
    u_info = plistlib.load(open(os.path.join(u_app, "Info.plist"), "rb"))
    s_info = plistlib.load(open(os.path.join(s_app, "Info.plist"), "rb"))
    keys = sorted(set(u_info) | set(s_info))
    diff = [(k, u_info.get(k), s_info.get(k)) for k in keys if u_info.get(k) != s_info.get(k)]
    if not diff:
        print("  无差异")
    for k, a, b in diff:
        print("  %-42s %r -> %r" % (k, a, b))
    print("  Info.plist 在 skip 列表里:", any("Info.plist" == s for s in skipped))
    return 0


if __name__ == "__main__":
    sys.exit(main())
