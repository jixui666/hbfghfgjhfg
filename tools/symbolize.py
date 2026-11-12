#!/usr/bin/env python3
"""用 dSYM 把崩溃日志里的 imageOffset 符号化。

崩溃日志的 imageOffset 是相对 image base（= __TEXT.vmaddr）的偏移，
dSYM 的 DWARF 文件里保留着完整符号表，所以：

    addr = __TEXT.vmaddr + imageOffset
    找 value <= addr 的最近符号

用法:
    python tools/symbolize.py --dsym <.../TRX.app.dSYM/Contents/Resources/DWARF/TRX> --offsets 595156,596096,597348
"""

import argparse
import bisect
import struct
import sys


def macho_symbols(path):
    data = open(path, "rb").read()
    if len(data) < 32 or struct.unpack_from("<I", data, 0)[0] != 0xFEEDFACF:
        raise SystemExit("not a 64-bit mach-o: %s" % path)
    ncmds = struct.unpack_from("<I", data, 16)[0]
    off = 32
    symtab = None
    text_vmaddr = None
    for _ in range(ncmds):
        cmd, cmdsize = struct.unpack_from("<II", data, off)
        if cmd == 0x2:
            symtab = struct.unpack_from("<IIII", data, off + 8)
        elif cmd == 0x19:
            segname = data[off + 8:off + 24].split(b"\0")[0]
            vmaddr = struct.unpack_from("<Q", data, off + 24)[0]
            if segname == b"__TEXT":
                text_vmaddr = vmaddr
        off += cmdsize
    if not symtab:
        raise SystemExit("no symtab in dSYM (should never happen)")

    symoff, nsyms, stroff, strsize = symtab
    out = []
    for i in range(nsyms):
        strx, ntype, nsect, ndesc, value = struct.unpack_from("<IBBHQ", data, symoff + i * 16)
        if ntype & 0xE0 or value == 0:      # skip stabs
        # N_SECT (0x0e) + N_EXT
            continue
        if (ntype & 0x0E) != 0x0E:
            continue
        end = data.find(b"\0", stroff + strx)
        name = data[stroff + strx:end].decode("utf-8", "replace")
        if name:
            out.append((value, name))
    out.sort()
    return out, (text_vmaddr or 0)


def demangle(name):
    """把 Swift 的 $s3TRX10V2ProtocolO... 粗略转成可读形式。"""
    if not name.startswith("_$s") and not name.startswith("$s"):
        return name
    body = name[3:] if name.startswith("_$s") else name[2:]
    parts = []
    i = 0
    digits = ""
    while i < len(body) and body[i].isdigit():
        digits += body[i]
        i += 1
    if digits:
        n = int(digits)
        module = body[i:i + n]
        parts.append(module)
        i += n
    token = ""
    while i < len(body):
        ch = body[i]
        if ch.isdigit():
            digits = ""
            while i < len(body) and body[i].isdigit():
                digits += body[i]
                i += 1
            n = int(digits)
            nxt = body[i:i + n]
            parts.append(nxt)
            i += n
        elif ch == "O":
            parts.append(".")
            i += 1
        else:
            token += ch
            i += 1
    return " ".join(p for p in parts if p)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dsym", required=True)
    ap.add_argument("--offsets", required=True, help="comma separated imageOffsets from the crash log")
    args = ap.parse_args()

    symbols, text_vmaddr = macho_symbols(args.dsym)
    values = [s[0] for s in symbols]
    print("dSYM symbols: %d   __TEXT.vmaddr: %#x" % (len(symbols), text_vmaddr))
    for raw in args.offsets.split(","):
        image_offset = int(raw.strip(), 0)
        addr = text_vmaddr + image_offset
        i = bisect.bisect_right(values, addr) - 1
        if i < 0:
            print("  offset %-8d addr %#x  -> (before first symbol)" % (image_offset, addr))
            continue
        value, name = symbols[i]
        print("  offset %-8d addr %#x  %s +%d" % (image_offset, addr, demangle(name), addr - value))


if __name__ == "__main__":
    sys.exit(main())
