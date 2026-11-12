#!/usr/bin/env python3
"""把构建期机密写进 GitHub Actions Secrets（用仓库公钥做 sealed box 加密）。

用法:
    python tools/push_secrets.py                  # 上传 SECRETS_JSON + INTEGRITY_ED25519_KEY_PEM
    python tools/push_secrets.py --repo o/r

需要 GITHUB_TOKEN 环境变量（repo scope / fine-grained 的 Secrets: write）。
"""

import base64
import json
import os
import sys
import urllib.request

from nacl import encoding, public


def api(path, token, method="GET", payload=None):
    url = "https://api.github.com" + path
    data = None
    headers = {
        "Authorization": "Bearer " + token,
        "Accept": "application/vnd.github+json",
        "User-Agent": "3105-secrets",
    }
    if payload is not None:
        data = json.dumps(payload).encode()
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    with urllib.request.urlopen(req, timeout=30) as resp:
        body = resp.read()
        return json.loads(body) if body else {}


def encrypt(public_key_b64: str, secret_value: bytes) -> str:
    pk = public.PublicKey(public_key_b64.encode(), encoding.Base64Encoder())
    box = public.SealedBox(pk)
    return base64.b64encode(box.encrypt(secret_value)).decode()


def main() -> int:
    token = os.environ.get("GITHUB_TOKEN", "").strip()
    if not token:
        print("missing GITHUB_TOKEN")
        return 2

    repo = "jixui666/hbfghfgjhfg"
    if "--repo" in sys.argv:
        repo = sys.argv[sys.argv.index("--repo") + 1]

    here = os.path.dirname(os.path.abspath(__file__))
    root = os.path.dirname(here)

    payloads = {}

    secrets_json = os.path.join(here, "secrets.json")
    if os.path.exists(secrets_json):
        payloads["SECRETS_JSON"] = open(secrets_json, "rb").read()
    else:
        print("[skip] tools/secrets.json 不存在")

    key_path = os.path.join(os.path.expanduser("~"), ".3105", "integrity_ed25519.key")
    if os.path.exists(key_path):
        payloads["INTEGRITY_ED25519_KEY_PEM"] = open(key_path, "rb").read()
    else:
        print("[skip] 私钥不存在，先跑 tools/keygen.py")

    if not payloads:
        print("nothing to upload")
        return 1

    pk = api("/repos/%s/actions/secrets/public-key" % repo, token)
    key_id = pk["key_id"]
    for name, value in payloads.items():
        encrypted = encrypt(pk["key"], value)
        api("/repos/%s/actions/secrets/%s" % (repo, name), token,
            method="PUT", payload={"encrypted_value": encrypted, "key_id": key_id})
        print("uploaded %-28s %d bytes" % (name, len(value)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
