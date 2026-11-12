#!/usr/bin/env python3
"""integrity_pack.py 的离线自测（不需要 macOS / Xcode）。

构造一个合成 Mach-O（含 __TEXT 与 __DATA,__integrity 占位段）+ 一个假 .app 树，
然后验证：
  1. 打包成功、--verify 通过
  2. 改资源文件 → --verify 失败
  3. 改主二进制 __TEXT → --verify 失败
  4. 多塞一个文件 → --verify 失败
  5. 恢复后 → 重新通过

用法: python tools/selftest_integrity.py
"""

import os
import plistlib
import shutil
import struct
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
PACKER = os.path.join(HERE, "integrity_pack.py")

TEXT_OFF = 0x400
TEXT_SIZE = 0x100
INTEGRITY_OFF = 0x500
INTEGRITY_SIZE = 128 * 1024


def section64(sectname, segname, addr, size, offset, flags):
    return struct.pack(
        "<16s16sQQIIIIIIII",
        sectname.encode(), segname.encode(), addr, size, offset, 4, 0, 0, flags, 0, 0, 0,
    )


def segment64(name, vmaddr, vmsize, fileoff, filesize, sections):
    cmdsize = 72 + 80 * len(sections)
    head = struct.pack(
        "<II16sQQQQiiII",
        0x19, cmdsize, name.encode(), vmaddr, vmsize, fileoff, filesize, 7, 7, len(sections), 0,
    )
    return head + b"".join(sections)


def build_macho():
    text_seg = segment64(
        "__TEXT", 0x100000000, INTEGRITY_OFF, 0, INTEGRITY_OFF,
        [section64("__text", "__TEXT", 0x100000000 + TEXT_OFF, TEXT_SIZE, TEXT_OFF, 0x80000400)],
    )
    data_seg = segment64(
        "__DATA", 0x100100000, INTEGRITY_SIZE, INTEGRITY_OFF, INTEGRITY_SIZE,
        [section64("__integrity", "__DATA", 0x100100000, INTEGRITY_SIZE, INTEGRITY_OFF, 0)],
    )
    sizeofcmds = len(text_seg) + len(data_seg)
    header = struct.pack("<IiiIIIII", 0xFEEDFACF, 0x0100000C, 0, 2, 2, sizeofcmds, 0, 0)

    out = bytearray(INTEGRITY_OFF + INTEGRITY_SIZE)
    out[0:len(header)] = header
    out[32:32 + len(text_seg)] = text_seg
    out[32 + len(text_seg):32 + sizeofcmds] = data_seg
    # __text 内容（模拟代码）
    for i in range(TEXT_SIZE):
        out[TEXT_OFF + i] = (i * 37 + 11) & 0xFF
    # __integrity 占位（全零，pack 时会写入）
    return bytes(out)


def make_app(root):
    app = os.path.join(root, "Test.app")
    os.makedirs(os.path.join(app, "Frameworks", "F.framework"), exist_ok=True)
    os.makedirs(os.path.join(app, "Resources"), exist_ok=True)

    with open(os.path.join(app, "Test"), "wb") as fh:
        fh.write(build_macho())
    with open(os.path.join(app, "Frameworks", "F.framework", "F"), "wb") as fh:
        fh.write(build_macho())
    with open(os.path.join(app, "Resources", "a.txt"), "w") as fh:
        fh.write("hello integrity\n")
    with open(os.path.join(app, "Info.plist"), "wb") as fh:
        plistlib.dump({
            "CFBundleExecutable": "Test",
            "CFBundleIdentifier": "com.test.integrity",
            "CFBundleShortVersionString": "1.0",
            "CFBundleVersion": "1",
        }, fh)
    return app


def run(args):
    proc = subprocess.run([sys.executable, PACKER] + args, capture_output=True, text=True)
    return proc.returncode, proc.stdout + proc.stderr


def main() -> int:
    work = tempfile.mkdtemp(prefix="integrity-selftest-")
    failures = []
    try:
        app = make_app(work)
        exe = os.path.join(app, "Test")

        code, out = run(["--app", app])
        print("[1] pack:", "OK" if code == 0 else "FAIL")
        print("    " + out.strip().replace("\n", "\n    "))
        if code != 0:
            return 1

        code, out = run(["--app", app, "--verify"])
        print("[2] verify clean tree:", "OK" if code == 0 else "FAIL", "|", out.strip().splitlines()[-1])
        if code != 0:
            failures.append("clean verify failed")

        # 3) 改资源
        target = os.path.join(app, "Resources", "a.txt")
        original = open(target, "rb").read()
        open(target, "wb").write(original + b"tampered")
        code, out = run(["--app", app, "--verify"])
        print("[3] verify after resource edit:", "DETECTED" if code != 0 else "MISSED")
        if code == 0:
            failures.append("resource tampering not detected")
        open(target, "wb").write(original)

        code, _ = run(["--app", app, "--verify"])
        print("[4] verify restored:", "OK" if code == 0 else "FAIL")
        if code != 0:
            failures.append("restore did not verify")

        # 5) 改主二进制 __TEXT
        data = bytearray(open(exe, "rb").read())
        data[TEXT_OFF + 8] ^= 0xFF
        open(exe, "wb").write(data)
        code, out = run(["--app", app, "--verify"])
        print("[5] verify after __TEXT edit:", "DETECTED" if code != 0 else "MISSED")
        if code == 0:
            failures.append("__TEXT tampering not detected")

        # 6) 多塞文件
        open(os.path.join(app, "Resources", "injected.dylib"), "wb").write(b"\x00" * 32)
        code, out = run(["--app", app, "--verify"])
        print("[6] verify after injected file:", "DETECTED" if code != 0 else "MISSED")
        if code == 0:
            failures.append("injected file not detected")

        print()
        if failures:
            print("FAILED:", "; ".join(failures))
            return 1
        print("ALL SELF-TESTS PASSED")
        return 0
    finally:
        shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
