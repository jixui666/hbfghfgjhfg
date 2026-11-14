import sys

path = sys.argv[1]
data = open(path, 'rb').read()
patterns = {
    '步骤': '步骤'.encode('utf-8'),
    '上传': '上传'.encode('utf-8'),
    '导出': '导出'.encode('utf-8'),
    '打洞': '打洞'.encode('utf-8'),
    '成功': '成功'.encode('utf-8'),
    'data.xml': b'data.xml',
    'keychain': b'keychain',
    '8888': b'8888',
    '127.0.0.1': b'127.0.0.1',
    'https://': b'https://',
    'http://': b'http://',
}
print(path, 'size=', len(data))
for name, pat in patterns.items():
    idxs = []
    start = 0
    while True:
        i = data.find(pat, start)
        if i < 0:
            break
        idxs.append(i)
        start = i + 1
    print(f'{name}: {len(idxs)} hits', [hex(i) for i in idxs[:20]])
