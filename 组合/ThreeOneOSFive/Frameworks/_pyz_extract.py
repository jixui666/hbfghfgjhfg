import struct, zlib, marshal, re, sys, os

data = open(sys.argv[1], 'rb').read()
assert data[:4] == b'PYZ\x00'
p = 4
# PYZ header: magic(4) + python version magic(4) + flags(4) + toc position (4 for old; new uses 8? modern: codemagic(4) flag(4) tocpos(8))
# skip: 'PYZ\0' then '\xcb\r\r\n' = marshal magic? '\x00>\xee\xbe' hmm
# Modern PyInstaller (v5+): PYZ header: 4 bytes magic, then TOC at end; actual layout:
#   struct: magic(4)  # b'PYZ\x00'
#   python_marshal_magic(4)
#   flags(4)
#   toc_pos(8)
# try both
for tocspec in ('old', 'new'):
    try:
        if tocspec == 'new':
            toc_pos = struct.unpack('<Q', data[12:20])[0]
            toc = data[20:toc_pos]
            start = 20
        else:
            toc_pos = struct.unpack('<I', data[12:16])[0]
            toc = data[16:16+toc_pos]
            start = 16 + toc_pos
        # toc: entries: len(4) + name + pos(4) + cmpr_len(4) + unc_len(4) + cmpr_flag(4) + typecode...
        i = 0
        entries = []
        ok = True
        while i < len(toc):
            ln = struct.unpack('<I', toc[i:i+4])[0]
            if ln == 0 or ln > 200:
                ok = False
                break
            name = toc[i+4:i+4+ln].decode()
            i += 4 + ln
            pos, clen, ulen, cflag = struct.unpack('<IIII', toc[i:i+16])
            i += 16
            # typecode char
            typecode = toc[i:i+1]
            i += 1
            entries.append((name, pos, clen, ulen, cflag))
        if not ok or not entries:
            continue
        print(f'TOC format {tocspec}: {len(entries)} entries, toc at {toc_pos}')
        for name, pos, clen, ulen, cflag in entries:
            if pos + clen > len(data):
                ok = False
                break
        if not ok:
            continue
        outdir = sys.argv[2]
        os.makedirs(outdir, exist_ok=True)
        for name, pos, clen, ulen, cflag in entries:
            blob = data[pos:pos+clen]
            try:
                if cflag:
                    content = zlib.decompress(blob)
                else:
                    content = blob
                if content[:4] in (b'\xe3\x00\x00\x00', b'\x99\x01\x00\x00', b'\xa9\x01\x00\x00') or content[:1] in (b'\xe3', b'\xcb'):
                    # marshal code object
                    content = marshal.loads(content)
                    src = 'marshal'
                else:
                    src = 'raw'
            except Exception as e:
                src = f'err:{e}'
                content = None
            fn = os.path.join(outdir, name.replace('/', '_').replace('\\', '_'))
            try:
                if isinstance(content, bytes):
                    open(fn, 'wb').write(content)
                else:
                    open(fn + '.info', 'w').write(str(type(content)))
            except Exception:
                pass
        print('done')
        break
    except Exception as e:
        print(tocspec, 'failed:', e)
