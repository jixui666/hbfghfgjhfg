#!/usr/bin/env python3
"""把完整性清单 + Ed25519 签名写进主二进制的 __DATA,__integrity 段。

链路:
    __TEXT(代码 + 公钥)  <-- SHA-256 -->  清单(本脚本写入)  <-- Ed25519 -->  构建机私钥
                                          ^
                                          +-- 逐个文件 SHA-256 --> Bundle 内所有文件

用法:
    # 构建后打补丁
    python tools/integrity_pack.py --app build/Build/Products/Release-iphoneos/TRX.app

    # 只校验（不需要私钥）
    python tools/integrity_pack.py --app ... --verify

    # 重签场景（Sideloadly 会改 Info.plist）改用放宽的豁免列表
    python tools/integrity_pack.py --app ... --profile sideload
"""

import argparse
import base64
import hashlib
import json
import os
import struct
import sys

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

MAGIC = b"3105IGV1"
SIG_LEN = 64

STRICT_SKIP = [
    "_CodeSignature/",
    "SC_Info/",
    "embedded.mobileprovision",
    "PkgInfo",
    ".DS_Store",
]
SIDELOAD_SKIP = STRICT_SKIP + [
    "Info.plist",
    "Watch/",
]

PROFILES = {"strict": STRICT_SKIP, "sideload": SIDELOAD_SKIP}


# ---------------------------------------------------------------- mach-o

def thin_text_size(data: bytes, offset: int = 0):
    """返回 (text_fileoff, text_filesize)，offset 是 Mach-O 在文件里的起点。"""
    if offset + 32 > len(data):
        return None
    magic = struct.unpack_from("<I", data, offset)[0]
    if magic != 0xFEEDFACF:
        return None
    ncmds = struct.unpack_from("<I", data, offset + 16)[0]
    sizeofcmds = struct.unpack_from("<I", data, offset + 20)[0]
    cursor = offset + 32
    limit = min(len(data), offset + 32 + sizeofcmds)
    for _ in range(ncmds):
        if cursor + 8 > limit:
            break
        cmd, cmdsize = struct.unpack_from("<II", data, cursor)
        if cmd == 0x19 and cursor + 72 <= limit:            # LC_SEGMENT_64
            name = data[cursor + 8:cursor + 24].split(b"\0")[0]
            fileoff, filesize = struct.unpack_from("<QQ", data, cursor + 40)
            if name == b"__TEXT":
                return (fileoff, filesize)
        if cmdsize == 0:
            break
        cursor += cmdsize
    return None


def macho_text_range(data: bytes):
    """对 FAT/thin 都返回 __TEXT 在文件中的字节区间。"""
    if len(data) < 8:
        return None
    magic = struct.unpack_from("<I", data, 0)[0]
    if magic == 0xFEEDFACF:
        hit = thin_text_size(data, 0)
        return (hit[0], hit[0] + hit[1]) if hit else None
    if magic == 0xCAFEBABE:                                  # FAT, big endian
        count = struct.unpack_from(">I", data, 4)[0]
        if count == 0:
            return None
        off = struct.unpack_from(">I", data, 8 + 8)[0]
        hit = thin_text_size(data, off)
        return (hit[0], hit[0] + hit[1]) if hit else None
    return None


def find_integrity_section(data: bytes):
    """在 __DATA 段里找 __integrity：返回 (file_offset, size)。"""
    if len(data) < 32:
        return None
    if struct.unpack_from("<I", data, 0)[0] != 0xFEEDFACF:
        return None
    ncmds = struct.unpack_from("<I", data, 16)[0]
    sizeofcmds = struct.unpack_from("<I", data, 20)[0]
    cursor = 32
    limit = min(len(data), 32 + sizeofcmds)
    for _ in range(ncmds):
        if cursor + 8 > limit:
            break
        cmd, cmdsize = struct.unpack_from("<II", data, cursor)
        if cmd == 0x19 and cursor + 72 <= limit:
            segname = data[cursor + 8:cursor + 24].split(b"\0")[0]
            nsects = struct.unpack_from("<I", data, cursor + 64)[0]
            sec = cursor + 72
            for _ in range(nsects):
                sectname = data[sec:sec + 16].split(b"\0")[0]
                # section_64: sectname(0) segname(16) addr(32) size(40) offset(48) ...
                addr, size = struct.unpack_from("<QQ", data, sec + 32)
                offset = struct.unpack_from("<I", data, sec + 48)[0]
                if segname == b"__DATA" and sectname == b"__integrity":
                    return (offset, size)
                sec += 80
        if cmdsize == 0:
            break
        cursor += cmdsize
    return None


# ---------------------------------------------------------------- hashing

def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def hash_bundle_file(path: str):
    with open(path, "rb") as fh:
        data = fh.read()
    span = macho_text_range(data)
    if span:
        return (True, sha256(data[span[0]:span[1]]))
    return (False, sha256(data))


def iter_bundle(app: str, skip):
    root = os.path.abspath(app)
    out = []
    for base, dirs, files in os.walk(root):
        dirs.sort()
        for name in sorted(files):
            full = os.path.join(base, name)
            rel = os.path.relpath(full, root).replace(os.sep, "/")
            if any(rel == s or (s.endswith("/") and rel.startswith(s)) for s in skip):
                continue
            out.append((rel, full))
    return out


# ---------------------------------------------------------------- keys

def load_private_key(args):
    hex_key = args.key_hex or os.environ.get("INTEGRITY_PRIVATE_KEY_HEX", "")
    if hex_key:
        raw = bytes.fromhex(hex_key.strip())
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        if len(raw) == 32:
            return Ed25519PrivateKey.from_private_bytes(raw)
        return serialization.load_der_private_key(raw, password=None)
    path = args.key_path or os.path.join(os.path.expanduser("~"), ".3105", "integrity_ed25519.key")
    if not os.path.exists(path):
        raise SystemExit("private key not found: %s (run tools/keygen.py)" % path)
    with open(path, "rb") as fh:
        return serialization.load_pem_private_key(fh.read(), password=None)


def load_public_key(args):
    hex_key = args.pubkey_hex or os.environ.get("INTEGRITY_PUBLIC_KEY_HEX", "")
    if not hex_key:
        here = os.path.dirname(os.path.abspath(__file__))
        pub_file = os.path.join(here, "integrity_pubkey.hex")
        if os.path.exists(pub_file):
            hex_key = open(pub_file).read().strip()
    if not hex_key:
        raise SystemExit("public key not found (tools/integrity_pubkey.hex)")
    return Ed25519PublicKey.from_public_bytes(bytes.fromhex(hex_key.strip()))


# ---------------------------------------------------------------- pack

def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--app", required=True, help="path to .app bundle")
    parser.add_argument("--executable", default=None, help="main executable name (default: from Info.plist)")
    parser.add_argument("--profile", default="strict", choices=sorted(PROFILES.keys()))
    parser.add_argument("--key-path", default=None)
    parser.add_argument("--key-hex", default=None)
    parser.add_argument("--pubkey-hex", default=None)
    parser.add_argument("--verify", action="store_true", help="only verify an already-packed bundle")
    parser.add_argument("--skip", action="append", default=[], help="extra skip prefixes")
    args = parser.parse_args()

    app = os.path.abspath(args.app)
    if not os.path.isdir(app):
        raise SystemExit("not a directory: %s" % app)

    skip = list(PROFILES[args.profile]) + args.skip

    exe_name = args.executable
    if not exe_name:
        import plistlib
        with open(os.path.join(app, "Info.plist"), "rb") as fh:
            exe_name = plistlib.load(fh)["CFBundleExecutable"]
    exe_path = os.path.join(app, exe_name)
    with open(exe_path, "rb") as fh:
        exe_data = fh.read()

    span = macho_text_range(exe_data)
    if not span:
        raise SystemExit("main executable is not a thin/fat arm64 Mach-O")

    text_digest = sha256(exe_data[span[0]:span[1]])

    files = []
    for rel, full in iter_bundle(app, skip):
        if rel == exe_name:
            continue                      # 主二进制只校验 __TEXT（__DATA 会被本脚本改写）
        is_macho, digest = hash_bundle_file(full)
        files.append({"p": rel, "k": 1 if is_macho else 0, "h": base64.b64encode(digest).decode()})

    manifest = {
        "v": 1,
        "text": base64.b64encode(text_digest).decode(),
        "files": files,
        "skip": skip,
    }
    json_bytes = json.dumps(manifest, separators=(",", ":"), sort_keys=True).encode("utf-8")

    section = find_integrity_section(exe_data)
    if not section:
        raise SystemExit(
            "main executable has no __DATA,__integrity section.\n"
            "add to OTHER_LDFLAGS: -sectcreate __DATA __integrity ThreeOneOSFive/Security/integrity.section"
        )
    sec_off, sec_size = section
    need = 12 + len(json_bytes) + SIG_LEN
    if need > sec_size:
        raise SystemExit("integrity section too small: need %d, have %d" % (need, sec_size))

    if args.verify:
        payload = exe_data[sec_off:sec_off + sec_size]
        if payload[:8] != MAGIC:
            print("FAIL: section magic missing (never packed)")
            return 1
        length = struct.unpack_from("<I", payload, 8)[0]
        embedded_json = payload[12:12 + length]
        signature = payload[12 + length:12 + length + SIG_LEN]
        pub = load_public_key(args)
        try:
            pub.verify(signature, embedded_json)
        except Exception:
            print("FAIL: signature invalid")
            return 1
        if embedded_json != json_bytes:
            print("FAIL: manifest differs from current bundle content")
            print("      embedded files:", len(json.loads(embedded_json)["files"]))
            print("      actual files  :", len(files))
            return 1
        print("OK: %d files, __TEXT %s, signature valid" % (len(files), text_digest.hex()[:16]))
        return 0

    private_key = load_private_key(args)
    signature = private_key.sign(json_bytes)
    if len(signature) != SIG_LEN:
        raise SystemExit("unexpected signature length")

    blob = MAGIC + struct.pack("<I", len(json_bytes)) + json_bytes + signature
    patched = bytearray(exe_data)
    patched[sec_off:sec_off + sec_size] = blob + b"\x00" * (sec_size - len(blob))
    with open(exe_path, "wb") as fh:
        fh.write(patched)

    # 自检：__TEXT 未被改动
    with open(exe_path, "rb") as fh:
        again = fh.read()
    span2 = macho_text_range(again)
    if not span2 or sha256(again[span2[0]:span2[1]]) != text_digest:
        raise SystemExit("FATAL: __TEXT changed while writing the payload")

    print("packed %s" % exe_name)
    print("  files        : %d" % len(files))
    print("  manifest     : %d bytes" % len(json_bytes))
    print("  section      : %d bytes (used %d)" % (sec_size, len(blob)))
    print("  __TEXT sha256: %s" % text_digest.hex())
    print("  signature    : %s..." % signature.hex()[:32])
    for entry in files[:8]:
        print("    %s %s" % ("M" if entry["k"] else "R", entry["p"]))
    if len(files) > 8:
        print("    ... %d more" % (len(files) - 8))
    return 0


if __name__ == "__main__":
    sys.exit(main())
