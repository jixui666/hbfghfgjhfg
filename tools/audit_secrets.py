import base64
import hashlib
import math
import os
import re
import struct
import zipfile

IPA = r"G:\xm\新建文件夹 (3)\新建文件夹\26.1-27源码\3105\JSQ-unsigned.ipa"
OUT = r"G:\xm\新建文件夹 (3)\新建文件夹\26.1-27源码\3105\ipa\_audit"

os.makedirs(OUT, exist_ok=True)
z = zipfile.ZipFile(IPA)
exe = z.read("Payload/JSQ.app/JSQ")
open(os.path.join(OUT, "JSQ"), "wb").write(exe)
shell = z.read("Payload/JSQ.app/shell.txt")
links = z.read("Payload/JSQ.app/links.txt")

print("=== 1) 二进制基本信息 ===")
print("  JSQ: %.2f MB" % (len(exe) / 1048576))
ncmds = struct.unpack_from("<I", exe, 16)[0]
off, sym, text = 32, None, None
for _ in range(ncmds):
    cmd, cs = struct.unpack_from("<II", exe, off)
    if cmd == 0x2:
        sym = struct.unpack_from("<IIII", exe, off + 8)
    if cmd == 0x19:
        seg = exe[off + 8:off + 24].split(b"\0")[0]
        if seg == b"__TEXT":
            text = (struct.unpack_from("<Q", exe, off + 40)[0], struct.unpack_from("<Q", exe, off + 48)[0])
    off += cs
print("  symtab entries:", sym[1] if sym else 0)
print("  __TEXT (fileoff, filesize):", text)
if sym:
    so, ns, stro, strs = sym
    names = []
    for i in range(ns):
        strx, ntype, _nsect, _ndesc, _val = struct.unpack_from("<IBBHQ", exe, so + i * 16)
        if ntype & 0xE0:
            continue
        e = exe.find(b"\0", stro + strx)
        names.append(exe[stro + strx:e].decode("utf-8", "replace"))
    app_syms = [n for n in names if any(k in n for k in
                ("GeneratedSecrets", "SecureBox", "IntegrityGuard", "V2Protocol", "ProtocolCrypto",
                 "LocalLinkProvider", "ShellConfig", "ApptraceLinksCipher"))]
    print("  usable symbols:", len(names), " 安全层残留:", len(app_syms))
    for n in sorted(set(app_syms))[:6]:
        print("     ", n)

print()
print("=== 2) 明文扫描（域名 / 路径 / 密钥 / HKDF info）===")
needles = [b"forgetcx", b"api27", b"k7m3q9x2", b"vv.", b"tronscan", b"3105-v2-enc", b"3105-v2-mac",
           b"3105.blob.", b"ZX2dTqYepmVGRZPE", b"DXsZEcu5BurQg1TH", b"WIx1sxGK9vHybdRx",
           b"8gicinLCfhFSLbZj", b"418afba10ac2c0b08e043de48e547ecf", b"d3351c8c6578f2da099135923c0071a1",
           b"db4f76d0877feb1371b7a3eef3d15a85", b"e95f92340225fbd30bb983821e881941", b"https://api"]
hits = []
for n in needles:
    for m in re.finditer(re.escape(n), exe):
        hits.append((m.start(), n.decode()))
print("  hits in JSQ  :", hits if hits else "NONE")
for label, blob in (("shell.txt", shell), ("links.txt", links)):
    h2 = [(n.decode()) for n in needles if n in blob]
    print("  hits in %-10s: %s" % (label, h2 if h2 else "NONE (应该是密文)"))

print()
print("=== 3) 两个 txt 的密文 ===")
print("  shell.txt (%d bytes): %s" % (len(shell), shell.decode().strip()))
print("  links.txt (%d bytes): %s" % (len(links), links.decode().strip()))
for label, blob in (("shell", shell), ("links", links)):
    try:
        raw = base64.b64decode(blob.strip())
        print("  %-5s base64 -> %d bytes (16 的倍数: %s)" % (label, len(raw), len(raw) % 16 == 0))
    except Exception as exc:
        print("  %-5s base64 decode failed: %s" % (label, exc))

print()
print("=== 4) 高熵数据块（找 SecureBox 的静态数组）===")
def entropy(b):
    if not b:
        return 0.0
    counts = [0] * 256
    for x in b:
        counts[x] += 1
    e = 0.0
    for c in counts:
        if c:
            p = c / len(b)
            e -= p * math.log2(p)
    return e

window = 64
runs = []
i = 0
data_span = exe[text[0]:text[1]] if text else exe
while i < len(data_span):
    if entropy(data_span[i:i + window]) > 7.5:
        j = i
        while j < len(data_span) and entropy(data_span[j:j + window]) > 7.5:
            j += 16
        if j - i >= 128:
            runs.append((i, j - i))
        i = j
    else:
        i += 16
print("  高熵段 >=128 字节:", len(runs))
for off_, size in runs[:12]:
    print("     offset %#08x  %d bytes  entropy=%.2f" % (off_, size, entropy(data_span[off_:off_ + size])))
