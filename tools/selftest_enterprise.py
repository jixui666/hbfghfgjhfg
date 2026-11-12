import os
import shutil
import subprocess
import sys
import zipfile

ROOT = r"G:\xm\新建文件夹 (3)\新建文件夹\26.1-27源码\3105"
UNSIGNED = os.path.join(ROOT, "JSQ-unsigned.ipa")
ENTERPRISE = r"C:\Users\Administrator\Downloads\cmwdohian12jbfm7u6cu320fd-cmwdohiap12jffm7ufqpx225a-cmvl70uqx01yiq8nxt6n3rd3l.enterprise.signed.ipa"
WORK = os.path.join(ROOT, "ipa", "_sim")

shutil.rmtree(WORK, ignore_errors=True)
os.makedirs(WORK, exist_ok=True)

# 1) 干净的未签名 app
zipfile.ZipFile(UNSIGNED).extractall(os.path.join(WORK, "u"))
app = os.path.join(WORK, "u", "Payload", "JSQ.app")

# 2) 用 enterprise profile 打清单
r = subprocess.run([sys.executable, os.path.join(ROOT, "tools/integrity_pack.py"),
                    "--app", app, "--profile", "enterprise"], capture_output=True, text=True)
print("[1] pack enterprise:", "OK" if r.returncode == 0 else "FAIL")
print("   ", (r.stdout + r.stderr).strip().splitlines()[0])

# 3) 把企业签平台注入的东西原样搬进来，模拟企业签
zipfile.ZipFile(ENTERPRISE).extractall(os.path.join(WORK, "e"))
ent_app = os.path.join(WORK, "e", "Payload", "JSQ.app")
injected = [
    "Frameworks/QNSpecialLock.dylib",
    "Frameworks/SDWebIOImage.framework/SDWebIOImage",
    "Frameworks/SDWebIOImage.framework/Info.plist",
    "Frameworks/UMComon.framework/UMComon",
    "Frameworks/UMComon.framework/Info.plist",
    "channel",
    "embedded.mobileprovision",
    "_CodeSignature/CodeResources",
]
for rel in injected:
    src = os.path.join(ent_app, rel)
    dst = os.path.join(app, rel)
    os.makedirs(os.path.dirname(dst), exist_ok=True)
    shutil.copy2(src, dst)
# Info.plist 也按企业签改（改 MinimumOSVersion，验证 sideload/enterprise 的豁免）
import plistlib
info_path = os.path.join(app, "Info.plist")
d = plistlib.load(open(info_path, "rb"))
d["MinimumOSVersion"] = "10.0"
plistlib.dump(d, open(info_path, "wb"))
print("[2] 模拟企业签：注入 3 个 dylib/framework + channel + 签名产物 + 改 Info.plist")

# 4) 按 enterprise 校验
r = subprocess.run([sys.executable, os.path.join(ROOT, "tools/integrity_pack.py"),
                    "--app", app, "--profile", "enterprise", "--verify"],
                   capture_output=True, text=True)
out = (r.stdout + r.stderr).strip()
print("[3] verify enterprise:", "PASS" if r.returncode == 0 else "FAIL")
print("   ", out.splitlines()[-1])

# 5) 清单内文件被动 → 仍要被抓
target = os.path.join(app, "shell.txt")
data = open(target, "rb").read()
open(target, "wb").write(data[:-1] + bytes([data[-1] ^ 0xFF]))
r = subprocess.run([sys.executable, os.path.join(ROOT, "tools/integrity_pack.py"),
                    "--app", app, "--profile", "enterprise", "--verify"],
                   capture_output=True, text=True)
print("[4] 改 shell.txt 后:", "DETECTED" if r.returncode != 0 else "MISSED")
open(target, "wb").write(data)

# 6) 干净 app + strict profile 再注入 → 必须被拦（证明 strict 仍然拒绝注入）
clean = os.path.join(WORK, "c")
zipfile.ZipFile(UNSIGNED).extractall(clean)
app2 = os.path.join(clean, "Payload", "JSQ.app")
subprocess.run([sys.executable, os.path.join(ROOT, "tools/integrity_pack.py"),
                "--app", app2, "--profile", "strict"], capture_output=True, text=True)
for rel in injected:
    src = os.path.join(ent_app, rel)
    dst = os.path.join(app2, rel)
    os.makedirs(os.path.dirname(dst), exist_ok=True)
    shutil.copy2(src, dst)
r = subprocess.run([sys.executable, os.path.join(ROOT, "tools/integrity_pack.py"),
                    "--app", app2, "--profile", "strict", "--verify"],
                   capture_output=True, text=True)
print("[5] strict 包 + 注入后:", "REJECTED（符合预期）" if r.returncode != 0 else "PASS（不应该）")
if r.returncode != 0:
    print("   ", (r.stdout + r.stderr).strip().splitlines()[-1])

shutil.rmtree(WORK, ignore_errors=True)
