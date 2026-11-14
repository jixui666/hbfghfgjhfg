#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
patch_model_table_add.py —— 在 libapptracecore 机型白名单中【新增】两条
（不替换任何现有条目）：

  + "iPhone15,2"（iPhone 14 Pro）
  + "iPhone15,3"（iPhone 14 Pro Max）

实现：
  1. 新字符串写入 __TEXT 空闲区 0x64A32E（原为节间对齐填充 0x00，218 字节）
  2. 跳板代码写入 0x64A344：
       append(新串1) -> append(新串2) -> 原拷贝调用(条数 17->19) -> b 回 0x5A7A40
  3. 0x5A7A28 原拷贝调用起点改为 b <跳板>
  4. 两处清理循环计数 0x198(17*0x18) -> 0x1C8(19*0x18)
"""
import hashlib
import os
import shutil
import struct
import sys
import zipfile

BIN = r"G:\xm\新建文件夹 (3)\新建文件夹\26.1-27源码\3105\ThreeOneOSFive\Frameworks\libapptracecore.framework\libapptracecore"

# 空闲区选点：__TEXT 段尾（最后一个 section __eh_frame 0x660A18 之后、
# 段末 0x664000 之前）为纯 0x00 填充，共约 0x35E8 字节，不在任何 section 内，
# 不会被 unwind/objc 运行时引用。
# 注意：不要选 0x64A32E——那是 __unwind_info 段内填充，会破坏异常展开表。
S1 = 0x661000          # "iPhone15,2\0"
S2 = 0x66100B          # "iPhone15,3\0"
T  = 0x661020          # 跳板代码起点
COPY_CALL_SITE = 0x5A7A28   # 原“拷贝到静态表”调用序列起点
RET_ADDR = 0x5A7A40        # 原拷贝调用返回点（清理循环）

def rd(data, a):
    return struct.unpack('<I', data[a:a+4])[0]

def wr(data, a, v):
    struct.pack_into('<I', data, a, v)

def add_imm_from(data, src_off, new_imm):
    """复制一条 add xN,sp/#xN 指令并替换 imm12"""
    v = rd(data, src_off)
    return (v & ~(0xFFF << 10)) | ((new_imm & 0xFFF) << 10)

def adrp_page_from(data, src_off, new_page):
    """复制一条 adrp 指令并替换 21 位页号"""
    v = rd(data, src_off)
    v &= ~((3 << 29) | (0x7FFFF << 5))
    v |= ((new_page & 3) << 29) | (((new_page >> 2) & 0x7FFFF) << 5)
    return v

def emit_adrp(insns, rd_reg, target_addr):
    """在跳板内生成一条指向 target_addr 所在页的 adrp（PC 相对，须按新地址计算）"""
    addr = T + len(insns) * 4
    imm = ((target_addr >> 12) - ((addr & ~0xFFF) >> 12)) & 0x1FFFFF
    if imm & 0x100000:
        imm -= 0x200000
    insns.append(
        0x90000000 | ((imm & 3) << 29) | (((imm >> 2) & 0x7FFFF) << 5) | rd_reg
    )

def mov_imm16_from(data, src_off, new_imm16):
    v = rd(data, src_off)
    return (v & ~(0xFFFF << 5)) | ((new_imm16 & 0xFFFF) << 5)

def bl_to(dst, src):
    off = dst - src
    return 0x94000000 | ((off >> 2) & 0x3FFFFFF)

def b_to(dst, src):
    off = dst - src
    return 0x14000000 | ((off >> 2) & 0x3FFFFFF)

def apply(data):
    data = bytearray(data)
    # 0) 校验原始字节与空闲区
    assert data[0x646B1F:0x646B1F+11] == b"iPhone17,1\x00", "原始字符串1不符"
    assert data[0x646B2A:0x646B2A+11] == b"iPhone17,2\x00", "原始字符串2不符"
    assert data[S1:S1+22] == b"\x00"*22, "空闲区不是全零"
    assert data[T:T+80] == b"\x00"*80, "跳板区不是全零"
    # __unwind_info 不得被改动（防止异常展开崩溃），记录原始头
    assert data[0x64A194:0x64A194+16] == data[0x64A194:0x64A194+16]
    # 1) 写入新字符串
    data[S1:S1+11] = b"iPhone15,2\x00"
    data[S2:S2+11] = b"iPhone15,3\x00"
    # 2) 跳板指令
    insns = []
    #   add x19, sp, #0x1A0            (slot18)
    insns.append(add_imm_from(data, 0x5A7A30, 0x1A0))
    #   adrp x1, S1 所在页
    emit_adrp(insns, 1, S1)
    #   add x1, x1, #(S1 & 0xFFF)       (S1)
    insns.append(add_imm_from(data, 0x5A79AC, S1 & 0xFFF))
    #   mov x0, x19
    insns.append(rd(data, 0x5A79B0))
    #   bl 0x5EC8
    addr = T + len(insns)*4
    insns.append(bl_to(0x5EC8, addr))
    #   add x19, sp, #0x1B8            (slot19)
    insns.append(add_imm_from(data, 0x5A7A30, 0x1B8))
    #   adrp x1, S2 所在页
    emit_adrp(insns, 1, S2)
    #   add x1, x1, #(S2 & 0xFFF)       (S2)
    insns.append(add_imm_from(data, 0x5A79AC, S2 & 0xFFF))
    #   mov x0, x19
    insns.append(rd(data, 0x5A79B0))
    #   bl 0x5EC8
    addr = T + len(insns)*4
    insns.append(bl_to(0x5EC8, addr))
    #   adrp x0, 0x6CA290 所在页 ; add x0,x0,#0x290 ; add x19,sp,#8 ; add x1,sp,#8
    emit_adrp(insns, 0, 0x6CA290)
    insns.append(rd(data, 0x5A7A2C))
    insns.append(rd(data, 0x5A7A30))
    insns.append(rd(data, 0x5A7A34))
    #   mov w2, #0x13                  (19 条)
    insns.append(mov_imm16_from(data, 0x5A7A38, 0x13))
    #   bl 0x58E70C
    addr = T + len(insns)*4
    insns.append(bl_to(0x58E70C, addr))
    #   b RET_ADDR
    addr = T + len(insns)*4
    insns.append(b_to(RET_ADDR, addr))
    for i, v in enumerate(insns):
        wr(data, T + i*4, v)
    # 3) 0x5A7A28: adrp -> b <跳板>
    wr(data, COPY_CALL_SITE, b_to(T, COPY_CALL_SITE))
    # 4) 清理计数 17 -> 19
    for a in (0x5A7A40, 0x5A7A94):
        v = rd(data, a)
        data[a:a+4] = struct.pack('<I', (v & ~(0xFFFF << 5)) | (0x1C8 << 5))
    return bytes(data)

def main():
    # 源：原版备份（未打过替换补丁）
    src = BIN + ".bak"
    if not os.path.exists(src):
        sys.exit("找不到原版备份 libapptracecore.bak")
    raw = open(src, "rb").read()
    patched = apply(raw)
    print("二进制补丁完成，md5 =", hashlib.md5(patched).hexdigest()[:10])
    open(BIN, "wb").write(patched)

    ipas = [
        r"G:\xm\新建文件夹 (3)\新建文件夹\26.1-27源码\3105\dist\7T-unsigned.ipa",
        r"G:\xm\新建文件夹 (3)\新建文件夹\cool-admin-midway-8.x\ipa\7T.ipa",
        r"G:\xm\新建文件夹 (3)\新建文件夹\26.1-27源码\7T.ipa",
        r"G:\xm\新建文件夹 (3)\新建文件夹\13-26.1\测试.ipa",
    ]
    for ip in ipas:
        if not os.path.isfile(ip):
            print("跳过(不存在):", ip)
            continue
        src_ipa = ip + ".bak"
        if not os.path.exists(src_ipa):
            print("跳过(无.bak):", ip)
            continue
        zin = zipfile.ZipFile(src_ipa, "r")
        items = {n: zin.read(n) for n in zin.namelist()}
        zin.close()
        for n, b in items.items():
            if n.endswith("libapptracecore.framework/libapptracecore"):
                items[n] = patched
                print("替换条目:", n)
        with zipfile.ZipFile(ip, "w", zipfile.ZIP_DEFLATED) as zout:
            for n, b in items.items():
                zout.writestr(n, b)
        print("重新打包:", ip)

if __name__ == "__main__":
    main()
