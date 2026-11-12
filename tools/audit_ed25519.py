import os
import re
import zipfile

from cryptography.hazmat.primitives import serialization

IPA = r"G:\xm\新建文件夹 (3)\新建文件夹\26.1-27源码\3105\JSQ-unsigned.ipa"
KEY = os.path.join(os.path.expanduser("~"), ".3105", "integrity_ed25519.key")

z = zipfile.ZipFile(IPA)
exe = z.read("Payload/JSQ.app/JSQ")

print("=== A) ipa 文件清单 ===")
keys = [n for n in z.namelist() if re.search(r"\.(key|pem|p12|cer|mobileprovision)$", n, re.I)]
print("  密钥/证书类文件:", keys or "无")

print()
print("=== B) 二进制里搜私钥痕迹 ===")
patterns = {
    "PEM 头 '-----BEGIN'": b"-----BEGIN",
    "'BEGIN PRIVATE KEY'": b"BEGIN PRIVATE KEY",
    "PKCS8 Ed25519 私钥 DER 前缀": bytes.fromhex("302e020100300506032b657004220420"),
    "SPKI Ed25519 公钥 DER 前缀": bytes.fromhex("302a030506032b6570032100".replace("0305", "0506")),
    "文件名 integrity_ed25519": b"integrity_ed25519",
    "路径 .3105/integrity": b".3105/integrity",
    "环境变量 INTEGRITY_PRIVATE_KEY_PEM": b"INTEGRITY_PRIVATE_KEY_PEM",
}
for label, needle in patterns.items():
    print("  %-42s %s" % (label, "FOUND" if needle in exe else "not found"))

print()
print("=== C) 用真实私钥做决定性检查 ===")
if not os.path.exists(KEY):
    print("  本机没有私钥文件，跳过")
else:
    pem = open(KEY, "rb").read()
    priv = serialization.load_pem_private_key(pem, password=None)
    seed = priv.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )
    pub = priv.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    print("  私钥 seed (32B):", seed.hex())
    print("  公钥     (32B):", pub.hex())
    print("  私钥 seed 出现在 ipa 二进制里:", seed in exe, "<-- 必须是 False")
    print("  公钥        出现在 ipa 二进制里:", pub in exe, "<-- 应该是 True（编译期常量）")
    if pub in exe:
        at = [m.start() for m in re.finditer(re.escape(pub), exe)]
        print("  公钥出现位置:", ["%#x" % x for x in at])

print()
print("=== D) 二进制里所有 32 字节高熵片段里是否可能夹带私钥 ===")
print("  （单靠熵无法区分；上面 C 段用真实私钥做了精确匹配，足够定论）")
