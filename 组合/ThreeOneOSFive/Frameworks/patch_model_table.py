#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
patch_model_table.py —— 把 libapptracecore 内置机型白名单中的两个 iPhone 槽位
替换为 iPhone 14 Pro / 14 Pro Max，使 darkSword 策略接受该机型。

替换内容（等长，无长度描述符问题）：
  0x646B1F "iPhone17,1" (iPhone 16)      -> "iPhone15,2" (iPhone 14 Pro)
  0x646B2A "iPhone17,2" (iPhone 16 Plus) -> "iPhone15,3" (iPhone 14 Pro Max)

若想牺牲别的槽位，改 PATCHES 字典即可（可用的其他 iPhone 槽位偏移：
  0x646AD6 iPhone16,1 | 0x646AE1 iPhone16,2 | 0x646AFE iPhone17,3
  0x646B09 iPhone17,4 | 0x646B14 iPhone17,5）
"""
import hashlib
import os
import shutil
import sys
import zipfile

PATCHES = {
    0x646B1F: b"iPhone15,2\x00",  # 原 iPhone17,1
    0x646B2A: b"iPhone15,3\x00",  # 原 iPhone17,2
}
OLD = {
    0x646B1F: b"iPhone17,1\x00",
    0x646B2A: b"iPhone17,2\x00",
}

BINS = [
    r"G:\xm\新建文件夹 (3)\新建文件夹\26.1-27源码\3105\ThreeOneOSFive\Frameworks\libapptracecore.framework\libapptracecore",
]
IPAS = [
    r"G:\xm\新建文件夹 (3)\新建文件夹\26.1-27源码\3105\dist\7T-unsigned.ipa",
    r"G:\xm\新建文件夹 (3)\新建文件夹\cool-admin-midway-8.x\ipa\7T.ipa",
    r"G:\xm\新建文件夹 (3)\新建文件夹\26.1-27源码\7T.ipa",
    r"G:\xm\新建文件夹 (3)\新建文件夹\13-26.1\测试.ipa",
]

def md5(b):
    return hashlib.md5(b).hexdigest()[:10]

def patch_bytes(d):
    for off, new in PATCHES.items():
        old = OLD[off]
        cur = d[off:off + len(old)]
        if cur == new:
            print(f"  @0x{off:X} 已是 {new!r}（已打过）")
            continue
        if cur != old:
            raise SystemExit(
                f"  @0x{off:X} 内容不符：期望 {old!r}，实际 {cur!r}，中止"
            )
        d[off:off + len(new)] = new
        print(f"  @0x{off:X} {old!r} -> {new!r}")
    return d

def patch_file(path):
    print(f"== {path}")
    d = bytearray(open(path, "rb").read())
    patch_bytes(d)
    bak = path + ".bak"
    if not os.path.exists(bak):
        shutil.copyfile(path, bak)
        print(f"  备份 -> {bak}")
    open(path, "wb").write(d)
    print(f"  完成 md5={md5(bytes(d))}")

def patch_ipa(path):
    print(f"== {path}")
    zin = zipfile.ZipFile(path, "r")
    names = [n for n in zin.namelist()
             if n.endswith("libapptracecore.framework/libapptracecore")]
    if not names:
        print("  未找到 libapptracecore，跳过")
        return
    items = {}
    for n in zin.namelist():
        items[n] = zin.read(n)
    zin.close()
    bak = path + ".bak"
    if not os.path.exists(bak):
        shutil.copyfile(path, bak)
        print(f"  备份 -> {bak}")
    for n in names:
        d = bytearray(items[n])
        patch_bytes(d)
        items[n] = bytes(d)
        print(f"  替换条目 {n} md5={md5(bytes(d))}")
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as zout:
        for n, data in items.items():
            zout.writestr(n, data)
    print("  重新打包完成")

if __name__ == "__main__":
    for p in BINS:
        patch_file(p)
    for p in IPAS:
        if os.path.isfile(p):
            patch_ipa(p)
        else:
            print(f"跳过（不存在）: {p}")
    print("ALL DONE")
