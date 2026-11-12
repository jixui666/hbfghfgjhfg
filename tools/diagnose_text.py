#!/usr/bin/env python3
"""逐 section 对比未签名/签名后的主二进制，定位哪一块被动了。

用法: python tools/diagnose_text.py --unsigned <TRX.app> --signed <TRX.app>
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
from integrity_pack import find_integrity_section  # noqa: E402


def sha(b):
    return hashlib.sha256(b).digest()


def sections_of(data):
    """返回 [(seg, sect, offset_in_file, size)] 以及 __TEXT 的 (fileoff, filesize)。"""
    out = []
    text = None
    ncmds = struct.unpack_from("<I", data, 16)[0]
    sizeofcmds = struct.unpack_from("<I", data, 20)[0]
    cur = 32
    limit = min(len(data), 32 + sizeofcmds)
    for _ in range(ncmds):
        if cur + 8 > limit:
            break
        cmd, cmdsize = struct.unpack_from("<II", data, cur)
        if cmd == 0x19 and cur + 72 <= limit:
            segname = data[cur + 8:cur + 24].split(b"\0")[0].decode(errors="replace")
            fileoff, filesize = struct.unpack_from("<QQ", data, cur + 40)
            nsects = struct.unpack_from("<I", data, cur + 64)[0]
            if segname == "__TEXT":
                text = (fileoff, filesize)
            sec = cur + 72
            for _ in range(nsects):
                sectname = data[sec:sec + 16].split(b"\0")[0].decode(errors="replace")
                sseg = data[sec + 16:sec + 32].split(b"\0")[0].decode(errors="replace")
                addr, size = struct.unpack_from("<QQ", data, sec + 32)
                offset = struct.unpack_from("<I", data, sec + 48)[0]
                out.append((sseg, sectname, addr, size, offset))
                sec += 80
        if cmdsize == 0:
            break
        cur += cmdsize
    return out, text


def manifest_text(app):
    exe = os.path.join(app, plistlib.load(open(os.path.join(app, "Info.plist"), "rb"))["CFBundleExecutable"])
    data = open(exe, "rb").read()
    sec = find_integrity_section(data)
    if not sec:
        return None, data
    off, size = sec
    blob = data[off:off + size]
    if blob[:8] != b"3105IGV1":
        return None, data
    n = struct.unpack_from("<I", blob, 8)[0]
    return json.loads(blob[12:12 + n]), data


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--unsigned", required=True)
    ap.add_argument("--signed", required=True)
    args = ap.parse_args()

    u_app, s_app = os.path.abspath(args.unsigned), os.path.abspath(args.signed)
    m, u_data = manifest_text(u_app)
    _, s_data = manifest_text(s_app)
    if not m:
        print("未签名包没有清单")
        return 1
    recorded = base64.b64decode(m["text"])

    print("=== 主二进制 ===")
    print("  unsigned size:", len(u_data), "  signed size:", len(s_data),
          "  delta:", len(s_data) - len(u_data))
    u_secs, u_text = sections_of(u_data)
    s_secs, s_text = sections_of(s_data)
    print("  __TEXT (fileoff,filesize):", u_text, "->", s_text)

    def span(data, text_seg, secs):
        for seg, sect, addr, size, off in secs:
            if sect == "__text":
                return (off, text_seg[0] + text_seg[1])
        return None

    us = span(u_data, u_text, u_secs)
    ss = span(s_data, s_text, s_secs)
    print("  哈希范围:", us, "->", ss)
    if us and ss:
        uh = sha(u_data[us[0]:us[1]])
        sh = sha(s_data[ss[0]:ss[1]])
        print("  unsigned hash:", uh.hex()[:16], " match manifest:", uh == recorded)
        print("  signed   hash:", sh.hex()[:16], " match manifest:", sh == recorded)

    print()
    print("=== __TEXT 内 section 逐个对比 ===")
    m1 = {(seg, sect): (addr, size, off) for seg, sect, addr, size, off in u_secs if seg == "__TEXT"}
    m2 = {(seg, sect): (addr, size, off) for seg, sect, addr, size, off in s_secs if seg == "__TEXT"}
    for key in sorted(set(m1) | set(m2)):
        a, b = m1.get(key), m2.get(key)
        if a is None or b is None:
            print("  %-24s 只在一边: %s" % (key[1], "signed" if a is None else "unsigned"))
            continue
        part_a = u_data[a[2]:a[2] + a[1]]
        part_b = s_data[b[2]:b[2] + b[1]]
        same = sha(part_a) == sha(part_b)
        flag = "" if same else "  <== CHANGED"
        print("  %-24s addr %#x->%#x size %d->%d off %d->%d%s" % (
            key[1], a[0], b[0], a[1], b[1], a[2], b[2], flag))

    # 主二进制不在 manifest.files 里，但 text hash 必须一致
    if us and ss:
        uh, sh = sha(u_data[us[0]:us[1]]), sha(s_data[ss[0]:ss[1]])
        if uh != sh:
            print()
            print("!! 签名改动了被哈希的区间，前 4 个不同字节位置：")
            n = 0
            for i in range(min(us[1] - us[0], ss[1] - ss[0])):
                if u_data[us[0] + i] != s_data[ss[0] + i]:
                    print("   offset %#x: %02x -> %02x" % (us[0] + i, u_data[us[0] + i], s_data[ss[0] + i]))
                    n += 1
                    if n >= 4:
                        break
    return 0


if __name__ == "__main__":
    sys.exit(main())
