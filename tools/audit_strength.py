import hashlib
import json
import math
import os
import re
import struct
import sys
import zipfile

ROOT = r"G:\xm\新建文件夹 (3)\新建文件夹\26.1-27源码\3105"
IPA = os.path.join(ROOT, "ThreeOneOSFive", "JSQ-unsigned.ipa")
sys.path.insert(0, os.path.join(ROOT, "tools"))
from integrity_pack import find_integrity_section, macho_text_range  # noqa: E402

z = zipfile.ZipFile(IPA)
exe = z.read("Payload/JSQ.app/JSQ")
pubhex = open(os.path.join(ROOT, "tools", "integrity_pubkey.hex")).read().strip()
pub = bytes.fromhex(pubhex)
fp = hashlib.sha256(pub).digest()[:8]

# 段表
ncmds = struct.unpack_from("<I", exe, 16)[0]
off, segs, secs = 32, [], []
for _ in range(ncmds):
    cmd, cs = struct.unpack_from("<II", exe, off)
    if cmd == 0x19:
        name = exe[off + 8:off + 24].split(b"\0")[0].decode()
        fo, fs = struct.unpack_from("<QQ", exe, off + 40)
        segs.append((name, fo, fs))
        ns = struct.unpack_from("<I", exe, off + 64)[0]
        s = off + 72
        for _ in range(ns):
            sn = exe[s:s + 16].split(b"\0")[0].decode()
            sfo = struct.unpack_from("<I", exe, s + 48)[0]
            ssz = struct.unpack_from("<Q", exe, s + 40)[0]
            secs.append((name, sn, sfo, ssz))
            s += 80
    off += cs


def where(needle):
    hits = [m.start() for m in re.finditer(re.escape(needle), exe)]
    out = []
    for h in hits:
        seg = next((n for n, fo, fs in segs if fo <= h < fo + fs), "?")
        sec = next(("%s,%s" % (n, sn) for n, sn, sfo, _ in secs if sfo <= h < sfo + 4096), "")
        out.append("%#x in %s%s" % (h, seg, (" " + sec) if sec else ""))
    return out


print("=== 1) 基本 ===")
print("  JSQ %.2f MB" % (len(exe) / 1048576))
print("  segments:", [(n, hex(fo), fs) for n, fo, fs in segs if fs])
print("  __pubkey section:", [s for s in secs if s[1] == "__pubkey"] or "无")

print()
print("=== 2) 公钥 / 指纹 落在哪个段（决定能否被换掉）===")
print("  公钥   出现位置:", where(pub) or "未找到")
print("  指纹   出现位置:", where(fp) or "未以连续 8 字节出现（说明被拆成立即数指令）")

print()
print("=== 3) 明文特征扫描 ===")
needles = [b"forgetcx", b"api27", b"k7m3q9x2", b"3105-v2-enc", b"3105-v2-mac", b"3105.blob.",
           b"ZX2dTqYepmVGRZPE", b"DXsZEcu5BurQg1TH", b"WIx1sxGK9vHybdRx", b"8gicinLCfhFSLbZj",
           b"418afba10ac2c0b08e043de48e547ecf", b"d3351c8c6578f2da099135923c0071a1",
           b"db4f76d0877feb1371b7a3eef3d15a85", b"e95f92340225fbd30bb983821e881941",
           b"https://", b"-----BEGIN"]
hits = [n.decode() for n in needles if n in exe]
print("  命中:", hits or "NONE")

print()
print("=== 4) 符号表 ===")
if any(True for _ in [0]):
    pass
sym = None
off = 32
for _ in range(ncmds):
    cmd, cs = struct.unpack_from("<II", exe, off)
    if cmd == 0x2:
        sym = struct.unpack_from("<IIII", exe, off + 8)
    off += cs
if sym:
    so, ns, stro, _ = sym
    names = []
    for i in range(ns):
        strx, ntype, _nsect, _nd, _v = struct.unpack_from("<IBBHQ", exe, so + i * 16)
        if ntype & 0xE0:
            continue
        e = exe.find(b"\0", stro + strx)
        names.append(exe[stro + strx:e].decode("utf-8", "replace"))
    leaks = [n for n in names if any(k in n for k in
             ("GeneratedSecrets", "SecureBox", "IntegrityGuard", "V2Protocol", "Integrity"))]
    print("  symtab %d, 安全层符号 %d" % (len(names), len(leaks)))

print()
print("=== 5) 高熵常量块 ===")
def ent(b):
    if not b:
        return 0.0
    c = [0] * 256
    for x in b:
        c[x] += 1
    return -sum((v / len(b)) * math.log2(v / len(b)) for v in c if v)

runs, i = [], 0
while i < len(exe) - 64:
    if ent(exe[i:i + 64]) > 7.5:
        j = i
        while j < len(exe) - 64 and ent(exe[j:j + 64]) > 7.5:
            j += 16
        if j - i >= 96:
            runs.append((i, j - i))
        i = j
    else:
        i += 16
print("  >=96 字节:", len(runs), [("%#x" % o, sz) for o, sz in runs[:6]])

print()
print("=== 6) 清单 ===")
so, ssz = find_integrity_section(exe)
blob = exe[so:so + ssz]
n = struct.unpack_from("<I", blob, 8)[0]
man = json.loads(blob[12:12 + n])
print("  files=%d  allow_extra_macho=%s" % (len(man["files"]), man.get("allow_extra_macho")))
print("  skip=%s" % man["skip"])
for e in man["files"]:
    print("     k=%d %s" % (e["k"], e["p"]))
span = macho_text_range(exe)
actual = hashlib.sha256(exe[span[0]:span[1]]).digest()
import base64
print("  text 哈希一致:", base64.b64decode(man["text"]) == actual, "  range:", span)

print()
print("=== 7) txt 解密（验证 key 仍走 SecureBox）===")
for rel, key, iv in [("shell.txt", "WIx1sxGK9vHybdRx", "8gicinLCfhFSLbZj"),
                     ("links.txt", "ZX2dTqYepmVGRZPE", "DXsZEcu5BurQg1TH")]:
    raw = base64.b64decode(z.read("Payload/JSQ.app/" + rel).strip())
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        dec = Cipher(algorithms.AES(key.encode()), modes.CBC(iv.encode())).decryptor()
        out = dec.update(raw) + dec.finalize()
        pad = out[-1]
        print("  %-10s %d B -> %r" % (rel, len(raw), out[:-pad].decode("utf-8", "replace")[:60]))
    except Exception as exc:
        print("  %-10s 解密失败: %s" % (rel, exc))
