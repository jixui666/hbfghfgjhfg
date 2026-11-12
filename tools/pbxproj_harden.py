#!/usr/bin/env python3
"""把加固改动写进 Xcode 工程（幂等，可重复执行）。

做三件事:
  1. 把 Security/ 下三个 Swift 文件加入编译（PBXFileReference + PBXBuildFile + Sources）
  2. OTHER_LDFLAGS 追加 -sectcreate __DATA __integrity <placeholder>，为主二进制预留
     存放完整性清单的段
  3. Release 打开 strip / postprocess，并降低 Swift 反射元数据（去掉类名/属性名）

用法:
    python tools/pbxproj_harden.py            # 应用
    python tools/pbxproj_harden.py --check    # 只检查是否已经应用
"""

import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
PBX = os.path.join(ROOT, "ThreeOneOSFive.xcodeproj", "project.pbxproj")
SECTION = os.path.join(ROOT, "ThreeOneOSFive", "Security", "integrity.section")

PREFIX = "3105S"
GROUP_ID = PREFIX + "105"

SOURCES = [
    ("3105S101", "3105S201", "SecureBox.swift", "SecureBox.swift"),
    ("3105S102", "3105S202", "IntegrityGuard.swift", "IntegrityGuard.swift"),
    ("3105S103", "3105S203", "Secrets.generated.swift", "Generated/Secrets.generated.swift"),
]

LDFLAGS_BLOCK = """\t\t\t\tOTHER_LDFLAGS = (
\t\t\t\t\t"$(inherited)",
\t\t\t\t\t"-lz",
\t\t\t\t\t"-sectcreate",
\t\t\t\t\t"__DATA",
\t\t\t\t\t"__integrity",
\t\t\t\t\t"$(SRCROOT)/ThreeOneOSFive/Security/integrity.section",
\t\t\t\t);"""

HARDEN_BLOCK = """\t\t\t\tDEPLOYMENT_POSTPROCESSING = YES;
\t\t\t\tSTRIP_INSTALLED_PRODUCT = YES;
\t\t\t\tSWIFT_REFLECTION_METADATA_LEVEL = without-availability;
"""


def make_placeholder():
    size = 128 * 1024
    if os.path.exists(SECTION) and os.path.getsize(SECTION) == size:
        return False
    os.makedirs(os.path.dirname(SECTION), exist_ok=True)
    with open(SECTION, "wb") as fh:
        fh.write(b"3105IGV1" + b"\x00" * (size - 8))
    return True


def apply(text):
    changed = []

    # 1) file references
    if SOURCES[0][0] not in text:
        refs = "".join(
            "\t\t%s /* %s */ = {isa = PBXFileReference; lastKnownFileType = sourcecode.swift; "
            "path = %s; sourceTree = \"<group>\"; };\n" % (ref, name, rel)
            for ref, _bf, name, rel in SOURCES
        )
        text = text.replace(
            "/* Begin PBXFileReference section */\n",
            "/* Begin PBXFileReference section */\n" + refs,
            1,
        )
        changed.append("file references")

    # 2) build files
    if SOURCES[0][1] not in text:
        builds = "".join(
            "\t\t%s /* %s in Sources */ = {isa = PBXBuildFile; fileRef = %s; };\n" % (bf, name, ref)
            for ref, bf, name, _rel in SOURCES
        )
        text = text.replace(
            "/* Begin PBXBuildFile section */\n",
            "/* Begin PBXBuildFile section */\n" + builds,
            1,
        )
        changed.append("build files")

    # 3) group
    if GROUP_ID not in text:
        children = "".join("\t\t\t\t%s /* %s */,\n" % (ref, name) for ref, _bf, name, _rel in SOURCES)
        group = (
            "\t\t%s /* Security */ = {\n"
            "\t\t\tisa = PBXGroup;\n"
            "\t\t\tchildren = (\n%s\t\t\t);\n"
            "\t\t\tpath = Security;\n"
            "\t\t\tsourceTree = \"<group>\";\n"
            "\t\t};\n"
        ) % (GROUP_ID, children)
        text = text.replace("/* Begin PBXGroup section */\n",
                            "/* Begin PBXGroup section */\n" + group, 1)
        # 挂到主 group（与 helpers 同级）
        text = text.replace("\t\t\t\t3105A405 /* helpers */,\n",
                            "\t\t\t\t%s /* Security */,\n\t\t\t\t3105A405 /* helpers */,\n" % GROUP_ID, 1)
        changed.append("group")

    # 4) sources phase
    missing = [bf for _ref, bf, _n, _r in SOURCES if bf not in text.split("PBXSourcesBuildPhase")[1][:8000]]
    if missing:
        anchor = re.search(r"(isa = PBXSourcesBuildPhase;.*?files = \(\n)((?:.*?\n)*?)(\t\t\t\);\n)",
                           text, re.S)
        if anchor:
            body = anchor.group(2)
            add = "".join("\t\t\t\t%s /* in Sources */,\n" % bf for bf in missing)
            text = text[:anchor.end(2)] + add + text[anchor.end(2):]
            changed.append("sources phase")

    # 5) linker flags
    if "-sectcreate" not in text:
        text = text.replace('\t\t\t\tOTHER_LDFLAGS = "-lz";', LDFLAGS_BLOCK)
        changed.append("linker flags")

    # 6) strip / reflection
    if "STRIP_INSTALLED_PRODUCT" not in text:
        text = text.replace("\t\t\t\tMARKETING_VERSION = 2.0;\n",
                            "\t\t\t\tMARKETING_VERSION = 2.0;\n" + HARDEN_BLOCK)
        changed.append("strip / reflection")

    return text, changed


def main() -> int:
    with open(PBX, encoding="utf-8", newline="") as fh:
        original = fh.read()

    if "--check" in sys.argv:
        missing = [m for m in ["3105S101", "3105S201", "-sectcreate",
                               "STRIP_INSTALLED_PRODUCT", "SWIFT_REFLECTION_METADATA_LEVEL"]
                   if m not in original]
        print("applied:", not missing, "missing:", missing)
        return 0 if not missing else 1

    if make_placeholder():
        print("created placeholder:", SECTION)

    text, changed = apply(original)
    if text == original:
        print("nothing to do — project already hardened")
        return 0

    size = len(original.encode("utf-8"))
    backup = PBX + ".before-harden"
    if not os.path.exists(backup):
        with open(backup, "w", encoding="utf-8", newline="") as fh:
            fh.write(original)

    with open(PBX, "w", encoding="utf-8", newline="") as fh:
        fh.write(text)

    print("patched:", ", ".join(changed))
    print("size: %d -> %d bytes" % (size, len(text.encode("utf-8"))))
    print("backup:", backup)
    return 0


if __name__ == "__main__":
    sys.exit(main())
