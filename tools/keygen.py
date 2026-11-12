#!/usr/bin/env python3
"""生成完整性清单签名用的 Ed25519 密钥对。

- 私钥：写到 ~/.3105/integrity_ed25519.key（0600），或由环境变量
        INTEGRITY_PRIVATE_KEY_HEX 提供（CI 用 secret）。绝不进仓库。
- 公钥：写到 tools/integrity_pubkey.hex（32 字节 hex），gen_secrets.py 会把它
        编进主二进制 —— 公钥属于 __TEXT，被 textHash 保护。

用法:
    python tools/keygen.py            # 生成（已存在则拒绝覆盖）
    python tools/keygen.py --force    # 覆盖
"""

import os
import stat
import sys

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
PUB = os.path.join(HERE, "integrity_pubkey.hex")
KEY_DIR = os.path.join(os.path.expanduser("~"), ".3105")
KEY = os.path.join(KEY_DIR, "integrity_ed25519.key")


def import_from_env() -> bool:
    """CI：从 INTEGRITY_PRIVATE_KEY_PEM 还原私钥并导出公钥，不落仓库。"""
    pem = os.environ.get("INTEGRITY_PRIVATE_KEY_PEM", "").strip()
    if not pem:
        return False
    os.makedirs(KEY_DIR, exist_ok=True)
    with open(KEY, "wb") as fh:
        fh.write(pem.encode() + b"\n")
    os.chmod(KEY, stat.S_IRUSR | stat.S_IWUSR)
    priv = serialization.load_pem_private_key(open(KEY, "rb").read(), password=None)
    pub_raw = priv.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    with open(PUB, "w") as fh:
        fh.write(pub_raw.hex())
    print("imported private key from INTEGRITY_PRIVATE_KEY_PEM")
    print("public hex :", pub_raw.hex())
    return True


def main() -> int:
    force = "--force" in sys.argv
    if import_from_env():
        return 0

    if os.path.exists(KEY) and not force:
        print("private key already exists:", KEY)
        print("use --force to replace (all previously built ipa will stop validating)")
        if not os.path.exists(PUB):
            priv = serialization.load_pem_private_key(open(KEY, "rb").read(), password=None)
            open(PUB, "w").write(priv.public_key().public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex())
            print("recovered public key ->", PUB)
        return 0

    os.makedirs(KEY_DIR, exist_ok=True)
    priv = Ed25519PrivateKey.generate()
    pem = priv.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    with open(KEY, "wb") as fh:
        fh.write(pem)
    os.chmod(KEY, stat.S_IRUSR | stat.S_IWUSR)

    pub_raw = priv.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    with open(PUB, "w") as fh:
        fh.write(pub_raw.hex())

    print("private key :", KEY, "(chmod 600, keep it out of git)")
    print("public key  :", PUB)
    print("public hex  :", pub_raw.hex())
    print()
    print("next: python tools/gen_secrets.py   # 把公钥编进 GeneratedSecrets")
    return 0


if __name__ == "__main__":
    sys.exit(main())
