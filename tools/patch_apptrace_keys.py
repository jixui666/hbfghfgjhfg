#!/usr/bin/env python3
"""Rotate the AES key/IV baked into apptrace.framework's Mach-O.

The binary contains two 16-byte constants used by `CCCrypt`:

    0x13c3e0  IV     adrp x5,#0x13c000 ; add x5,x5,#0x3e0
    0x13c420  KEY    adrp x3,#0x13c000 ; add x3,x3,#0x420

with the call set up as `CCCrypt(1 /*kCCDecrypt*/, 0 /*AES128*/, 1 /*PKCS7*/,
key, 16, iv, …)`, i.e. they decrypt whatever the 127.0.0.1:8888 link endpoint
returns. Only those two constants are touched; everything else is left alone.

Usage:
    python tools/patch_apptrace_keys.py                 # random new key/iv
    python tools/patch_apptrace_keys.py --key HEX --iv HEX
    python tools/patch_apptrace_keys.py --check         # show current values

The .bak next to a patched binary is never modified, so `--restore` puts the
original back.
"""

import argparse
import hashlib
import os
import secrets
import shutil
import sys

KEY_OFFSET = 0x13C420
IV_OFFSET = 0x13C3E0
ORIGINAL_KEY = bytes.fromhex("418afba10ac2c0b08e043de48e547ecf")
ORIGINAL_IV = bytes.fromhex("d3351c8c6578f2da099135923c0071a1")

DEFAULT_TARGETS = [
    "ThreeOneOSFive/Frameworks/apptrace.framework/apptrace",
    "dist/_u_x/Payload/7T.app/Frameworks/apptrace.framework/apptrace",
]


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()[:16]


def patch(path: str, key: bytes, iv: bytes, restore: bool) -> None:
    with open(path, "rb") as handle:
        data = bytearray(handle.read())
    if len(data) < KEY_OFFSET + 16:
        print(f"  {path}: too small, skipped")
        return

    current_key = bytes(data[KEY_OFFSET:KEY_OFFSET + 16])
    current_iv = bytes(data[IV_OFFSET:IV_OFFSET + 16])
    print(f"  {path}")
    print(f"    before key={current_key.hex()} iv={current_iv.hex()} sha={digest(bytes(data))}")

    if restore:
        data[KEY_OFFSET:KEY_OFFSET + 16] = ORIGINAL_KEY
        data[IV_OFFSET:IV_OFFSET + 16] = ORIGINAL_IV
    else:
        data[KEY_OFFSET:KEY_OFFSET + 16] = key
        data[IV_OFFSET:IV_OFFSET + 16] = iv

    backup = path + ".bak"
    if not os.path.exists(backup):
        shutil.copy2(path, backup)
        print(f"    backup -> {backup}")

    with open(path, "wb") as handle:
        handle.write(data)
    with open(path, "rb") as handle:
        check = handle.read()
    print(f"    after  key={check[KEY_OFFSET:KEY_OFFSET + 16].hex()} "
          f"iv={check[IV_OFFSET:IV_OFFSET + 16].hex()} sha={digest(check)}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--key", help="16-byte key as 32 hex chars")
    parser.add_argument("--iv", help="16-byte iv as 32 hex chars")
    parser.add_argument("--path", action="append", help="binary to patch (repeatable)")
    parser.add_argument("--check", action="store_true", help="only print current values")
    parser.add_argument("--restore", action="store_true", help="put the original constants back")
    args = parser.parse_args()

    targets = args.path or DEFAULT_TARGETS

    if args.check or args.restore:
        key = iv = b""
    else:
        if args.key:
            key = bytes.fromhex(args.key)
            if len(key) != 16:
                print("--key must be 16 bytes", file=sys.stderr)
                return 2
        else:
            key = secrets.token_bytes(16)
        if args.iv:
            iv = bytes.fromhex(args.iv)
            if len(iv) != 16:
                print("--iv must be 16 bytes", file=sys.stderr)
                return 2
        else:
            iv = secrets.token_bytes(16)
        print(f"new key={key.hex()} iv={iv.hex()}")
        print("keep these: they must match what the app encrypts for the binary")

    for path in targets:
        if not os.path.exists(path):
            print(f"  {path}: missing")
            continue
        patch(path, key, iv, args.restore)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
