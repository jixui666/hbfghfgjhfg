#!/usr/bin/env python3
"""验证"重签不会误判、真正被篡改一定会被抓到"。

模拟 codesign 的核心动作：往 load commands 尾部插一个 LC_CODE_SIGNATURE，
并改 ncmds / sizeofcmds —— 这一步会改写 mach header 与前 16 KB，
但不会碰 __TEXT,__text 之后的内容。

期望：
  1. 打包后 verify 通过
  2. 模拟重签后 verify 仍然通过（说明哈希范围选对了）
  3. 改 __text 里一个字节后 verify 失败（说明代码段仍被保护）

用法: python tools/selftest_resign.py --app <TRX.app>
"""

import argparse
import os
import struct
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
PACKER = os.path.join(HERE, "integrity_pack.py")


def run(args):
    proc = subprocess.run([sys.executable, PACKER] + args, capture_output=True, text=True)
    return proc.returncode, (proc.stdout + proc.stderr).strip()


def simulate_codesign(path: str) -> bool:
    data = bytearray(open(path, "rb").read())
    ncmds, sizeofcmds = struct.unpack_from("<II", data, 16)
    insert_at = 32 + sizeofcmds

    # 确认插进去的位置还在 __text 之前（属于可以变化的 load-commands 区域）
    text_start = None
    cursor = 32
    limit = 32 + sizeofcmds
    for _ in range(ncmds):
        c, sz = struct.unpack_from("<II", data, cursor)
        if c == 0x19:
            segname = data[cursor + 8:cursor + 24].split(b"\0")[0]
            if segname == b"__TEXT":
                nsects = struct.unpack_from("<I", data, cursor + 64)[0]
                sec = cursor + 72
                for _ in range(nsects):
                    if data[sec:sec + 16].split(b"\0")[0] == b"__text":
                        text_start = struct.unpack_from("<I", data, sec + 48)[0]
                    sec += 80
        if sz == 0:
            break
        cursor += sz
    if text_start is None or insert_at + 16 > text_start:
        print("    没有足够的 load-commands padding，跳过模拟重签")
        return False

    lc = struct.pack("<IIII", 0x1D, 16, len(data), 0x100)   # LC_CODE_SIGNATURE
    data[insert_at:insert_at + 16] = lc
    struct.pack_into("<I", data, 16, ncmds + 1)
    struct.pack_into("<I", data, 20, sizeofcmds + 16)
    open(path, "wb").write(data)
    return True


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--app", required=True)
    parser.add_argument("--profile", default="strict", choices=["strict", "sideload"])
    args = parser.parse_args()

    app = os.path.abspath(args.app)
    exe = os.path.join(app, "TRX")
    if not os.path.exists(exe):
        import plistlib
        exe = os.path.join(app, plistlib.load(open(os.path.join(app, "Info.plist"), "rb"))["CFBundleExecutable"])

    failures = []

    code, out = run(["--app", app, "--profile", args.profile])
    print("[1] pack                  :", "OK" if code == 0 else "FAIL", "|", out.splitlines()[-1])
    if code != 0:
        return 1

    code, out = run(["--app", app, "--profile", args.profile, "--verify"])
    print("[2] verify before resign  :", "OK" if code == 0 else "FAIL", "|", out.splitlines()[-1])
    if code != 0:
        failures.append("clean verify failed")

    if simulate_codesign(exe):
        code, out = run(["--app", app, "--profile", args.profile, "--verify"])
        print("[3] verify after 'resign' :", "OK" if code == 0 else "FAIL", "|", out.splitlines()[-1])
        if code != 0:
            failures.append("resign triggered a false positive (hash range still includes load commands)")

    # 改 __text 内的一个字节 → 必须被抓到
    data = bytearray(open(exe, "rb").read())
    original = bytes(data)
    ncmds, sizeofcmds = struct.unpack_from("<II", data, 16)
    cursor, target = 32, None
    for _ in range(ncmds):
        c, sz = struct.unpack_from("<II", data, cursor)
        if c == 0x19:
            segname = data[cursor + 8:cursor + 24].split(b"\0")[0]
            if segname == b"__TEXT":
                nsects = struct.unpack_from("<I", data, cursor + 64)[0]
                sec = cursor + 72
                for _ in range(nsects):
                    if data[sec:sec + 16].split(b"\0")[0] == b"__text":
                        target = struct.unpack_from("<I", data, sec + 48)[0] + 64
                    sec += 80
        if sz == 0:
            break
        cursor += sz
    if target:
        data[target] ^= 0xFF
        open(exe, "wb").write(data)
        code, out = run(["--app", app, "--profile", args.profile, "--verify"])
        print("[4] verify after __text edit:", "DETECTED" if code != 0 else "MISSED")
        if code == 0:
            failures.append("__text tampering not detected")
        open(exe, "wb").write(original)

    print()
    if failures:
        print("FAILED:", "; ".join(failures))
        return 1
    print("ALL RESIGN TESTS PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
