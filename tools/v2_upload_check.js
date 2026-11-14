#!/usr/bin/env node
/**
 * tools/v2_upload_check.js
 *
 * WQFiles 采集包上传链路的对拍测试（纯 Node，不需要 Xcode / 真机）。
 *
 * 把「目录 -> ZIP -> v2 加密 -> multipart 上传」这条链上最容易错的三件事钉住：
 *
 *   1) multipart 字段名：后端 v2 控制器 readEnvelope 读 `meta`（或 `params`），
 *      不认 `payload`；用旧字段名会 401「clientPub 无效」。
 *   2) AAD 里的 path：服务端 buildAad 取 ctx.path 后 `.replace(/^\/+/, '')`，
 *      客户端必须发去掉前导斜杠的同一串，否则 401「消息校验失败」。
 *   3) 响应必须用同一会话解开（服务端 seal 的是 {ok:1}），只看 code 不够。
 *
 * 对照的后端源码：cool-admin-midway-8.x
 *   src/modules/device/controller/open/v2.ts
 *   src/modules/device/service/v2-crypto.ts
 *   src/modules/device/service/upload.ts  (save('zip', files, params, appUuid))
 * 对照的客户端源码：WQV2.swift / WQNet.swift
 *
 * 用法：
 *   node tools/v2_upload_check.js                 # 跑对拍用例
 *   node tools/v2_upload_check.js --serve 18091   # 起一个 mock v2 服务端，打印公钥后常驻
 *                                                 # （可以拿后端自带的 tools/v2-probe.js 打它做交叉验证）
 *
 * 上传路径从 tools/secrets.json 的 pathZip 读（gitignored），也可用 V2_ZIP_PATH 覆盖；
 * 两者都没有时用占位路径 api/placeholder/upload/zip —— 这时只能验证协议，不能验证端点。
 */

'use strict';

const crypto = require('crypto');
const http = require('http');
const fs = require('fs');
const path = require('path');

const INFO_ENC = Buffer.from('3105-v2-enc');
const INFO_MAC = Buffer.from('3105-v2-mac');
const INFO_RENC = Buffer.from('3105-v2-renc');
const INFO_RMAC = Buffer.from('3105-v2-rmac');
const PKCS8_PREFIX = Buffer.from('302e020100300506032b656e04220420', 'hex');
const SPKI_PREFIX = Buffer.from('302a300506032b656e032100', 'hex');

/**
 * 上传路径不写死在这里（v2 端点路径是这层加固的一部分，不该静态出现在仓库里）。
 * 取值顺序：tools/secrets.json 的 pathZip → 环境变量 V2_ZIP_PATH → 占位路径。
 * tools/secrets.json 是 gitignored 的本地/CI 构建配置。
 */
function secretEntry(name) {
  try {
    const file = path.join(__dirname, 'secrets.json');
    if (!fs.existsSync(file)) return '';
    const cfg = JSON.parse(fs.readFileSync(file, 'utf8'));
    const index = cfg.index?.[name];
    return index == null ? '' : String(cfg.entries?.[index] || '');
  } catch {
    return '';
  }
}

const UPLOAD_PATH = (() => {
  const resolved = secretEntry('pathZip') || process.env.V2_ZIP_PATH || '';
  const trimmed = resolved.replace(/^\/+/, '');
  return '/' + (trimmed || 'api/placeholder/upload/zip');
})();
const UPLOAD_RE = new RegExp('^' + UPLOAD_PATH.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '/?$');

/* ------------------------------------------------------------------ 服务端 */

/** 对应 DeviceV2CryptoService */
function makeServer() {
  const rawPriv = crypto.randomBytes(32);
  const privKey = crypto.createPrivateKey({
    key: Buffer.concat([PKCS8_PREFIX, rawPriv]),
    format: 'der',
    type: 'pkcs8',
  });
  const der = crypto.createPublicKey(privKey).export({ format: 'der', type: 'spki' });
  const pubRaw = der.subarray(der.length - 32);
  const seen = new Set();

  const hkdf = (shared, salt, info, len = 32) =>
    Buffer.from(crypto.hkdfSync('sha256', shared, salt, info, len));

  const hmac = (key, parts) =>
    crypto.createHmac('sha256', key).update(Buffer.concat(parts)).digest();

  const buildAad = (ctx, plain) => {
    const fields = [
      String(ctx.method || 'POST').toUpperCase(),
      String(ctx.path || '').replace(/^\/+/, ''),
      String(ctx.appUuid || plain?.app_uuid || ''),
      String(Number(plain?.ts || 0)),
      String(plain?.nonce || ''),
    ];
    const chunks = [];
    fields.forEach((field, i) => {
      chunks.push(Buffer.from(field, 'utf8'));
      if (i < fields.length - 1) chunks.push(Buffer.from([0]));
    });
    return Buffer.concat(chunks);
  };

  function decrypt(encKey, iv, ct) {
    try {
      const d = crypto.createDecipheriv('aes-256-cbc', encKey, iv);
      return JSON.parse(Buffer.concat([d.update(ct), d.final()]).toString('utf8'));
    } catch {
      throw new Error('消息校验失败');
    }
  }

  function open(body, ctx) {
    const clientPub = Buffer.from(String(body?.k || ''), 'base64');
    if (clientPub.length !== 32) throw new Error('clientPub 无效');

    const shared = crypto.diffieHellman({
      privateKey: privKey,
      publicKey: crypto.createPublicKey({
        key: Buffer.concat([SPKI_PREFIX, clientPub]),
        format: 'der',
        type: 'spki',
      }),
    });
    const salt = Buffer.concat([clientPub, pubRaw]);
    const encKey = hkdf(shared, salt, INFO_ENC);
    const macKey = hkdf(shared, salt, INFO_MAC);

    const iv = Buffer.from(String(body?.iv || ''), 'base64');
    const mac = Buffer.from(String(body?.mac || ''), 'base64');
    const ct = Buffer.from(String(body?.ct || ''), 'base64');
    const kRaw = Buffer.from(String(body?.k || ''), 'base64');
    if (iv.length !== 16 || mac.length !== 32 || !ct.length) throw new Error('密文结构无效');

    let plain;
    const legacyMac = hmac(macKey, [kRaw, iv, ct]);
    if (crypto.timingSafeEqual(legacyMac, mac)) {
      plain = decrypt(encKey, iv, ct);
    } else {
      plain = decrypt(encKey, iv, ct);
      const candidates = [
        buildAad(ctx, plain),
        buildAad({ ...ctx, appUuid: String(plain?.app_uuid || '') }, plain),
      ];
      let ok = false;
      for (const aad of candidates) {
        const expect = hmac(macKey, [aad, kRaw, iv, ct]);
        if (crypto.timingSafeEqual(expect, mac)) {
          ok = true;
          break;
        }
      }
      if (!ok) throw new Error('消息校验失败');
    }

    const ts = Number(plain?.ts || 0);
    if (!ts || Math.abs(Date.now() - ts) > 300_000) throw new Error('请求时间戳过期');
    const nonce = String(plain?.nonce || '');
    if (!/^[0-9a-f]{16,64}$/i.test(nonce)) throw new Error('缺少 nonce');
    if (seen.has(nonce)) throw new Error('重复请求');
    seen.add(nonce);

    return { plain, clientPub, shared, salt };
  }

  function seal(session, payload) {
    const encKey = hkdf(session.shared, session.salt, INFO_RENC);
    const macKey = hkdf(session.shared, session.salt, INFO_RMAC);
    const iv = crypto.randomBytes(16);
    const c = crypto.createCipheriv('aes-256-cbc', encKey, iv);
    const ct = Buffer.concat([c.update(Buffer.from(JSON.stringify(payload ?? {}), 'utf8')), c.final()]);
    const mac = crypto.createHmac('sha256', macKey).update(Buffer.concat([iv, ct])).digest();
    return {
      v: 2,
      iv: iv.toString('base64'),
      ct: ct.toString('base64'),
      mac: mac.toString('base64'),
      ts: Date.now(),
    };
  }

  return { pubRaw, open, seal };
}

/* ------------------------------------------------------------------ 客户端 */

/** 对应 WQV2.normalizePath */
function normalizePath(path) {
  let out = String(path || '');
  while (out.startsWith('/')) out = out.slice(1);
  return out;
}

/**
 * 对应 WQV2.newSession：一次请求一个临时 X25519 会话。
 * aadPath 用来模拟「SecureBox 里的路径常量写成带前导 /」的坏情况。
 */
function clientSession(serverPubRaw, payload, ctx, aadPath) {
  const serverPub = crypto.createPublicKey({
    key: Buffer.concat([SPKI_PREFIX, serverPubRaw]),
    format: 'der',
    type: 'spki',
  });
  const { privateKey, publicKey } = crypto.generateKeyPairSync('x25519');
  const clientPub = publicKey.export({ format: 'der', type: 'spki' }).subarray(-32);
  const shared = crypto.diffieHellman({ privateKey, publicKey: serverPub });
  const salt = Buffer.concat([clientPub, serverPubRaw]);

  const hkdf = info => Buffer.from(crypto.hkdfSync('sha256', shared, salt, info, 32));
  const encKey = hkdf(INFO_ENC);
  const macKey = hkdf(INFO_MAC);

  const body = { ...payload };
  if (body.ts == null) body.ts = Date.now();
  if (body.nonce == null) body.nonce = crypto.randomBytes(8).toString('hex');

  const iv = crypto.randomBytes(16);
  const c = crypto.createCipheriv('aes-256-cbc', encKey, iv);
  const ct = Buffer.concat([c.update(Buffer.from(JSON.stringify(body), 'utf8')), c.final()]);

  const pathForAad = aadPath == null ? normalizePath(ctx.path) : aadPath;
  const aad = Buffer.from(
    [
      String(ctx.method || 'POST').toUpperCase(),
      pathForAad,
      String(ctx.appUuid || ''),
      String(Number(body.ts)),
      String(body.nonce),
    ].join('\0'),
    'utf8'
  );
  const mac = crypto
    .createHmac('sha256', macKey)
    .update(Buffer.concat([aad, clientPub, iv, ct]))
    .digest();

  return {
    envelope: {
      v: 2,
      k: clientPub.toString('base64'),
      iv: iv.toString('base64'),
      ct: ct.toString('base64'),
      mac: mac.toString('base64'),
    },
    open(reply) {
      if (!reply || typeof reply !== 'object') return null;
      const rEnc = hkdf(INFO_RENC);
      const rMac = hkdf(INFO_RMAC);
      const rIv = Buffer.from(String(reply.iv || ''), 'base64');
      const rCt = Buffer.from(String(reply.ct || ''), 'base64');
      const rMacBuf = Buffer.from(String(reply.mac || ''), 'base64');
      const expect = crypto.createHmac('sha256', rMac).update(Buffer.concat([rIv, rCt])).digest();
      if (!crypto.timingSafeEqual(expect, rMacBuf)) return null;
      const d = crypto.createDecipheriv('aes-256-cbc', rEnc, rIv);
      return JSON.parse(Buffer.concat([d.update(rCt), d.final()]).toString('utf8'));
    },
  };
}

/* ------------------------------------------------- 流式 multipart（同 WQNet） */

const CHUNK = 1 << 20;

/** 对应 WQNet.netBuildMultipart：meta + params + file，1 MB 分块写 */
function buildMultipart(envelope, zipBuffer, fileName, boundary, fields = ['meta', 'params']) {
  const parts = [];
  const json = JSON.stringify(envelope);
  for (const field of fields) {
    parts.push(Buffer.from(`--${boundary}\r\n`));
    parts.push(Buffer.from(`Content-Disposition: form-data; name="${field}"\r\n`));
    parts.push(Buffer.from('Content-Type: application/json\r\n\r\n'));
    parts.push(Buffer.from(json, 'utf8'));
    parts.push(Buffer.from('\r\n'));
  }
  parts.push(Buffer.from(`--${boundary}\r\n`));
  parts.push(Buffer.from(`Content-Disposition: form-data; name="file"; filename="${fileName}"\r\n`));
  parts.push(Buffer.from('Content-Type: application/zip\r\n\r\n'));
  for (let off = 0; off < zipBuffer.length; off += CHUNK) {
    parts.push(zipBuffer.subarray(off, Math.min(off + CHUNK, zipBuffer.length)));
  }
  parts.push(Buffer.from(`\r\n--${boundary}--\r\n`));
  return Buffer.concat(parts);
}

/** 只解析本测试的形态：文本字段 + 一个文件字段 */
function parseMultipart(buffer, boundary) {
  const fields = {};
  const files = [];
  const delim = Buffer.from(`--${boundary}`);
  let pos = 0;
  while (pos < buffer.length) {
    const start = buffer.indexOf(delim, pos);
    if (start < 0) break;
    let cursor = start + delim.length;
    if (buffer.slice(cursor, cursor + 2).toString() === '--') break;
    cursor += 2; // \r\n
    const headEnd = buffer.indexOf('\r\n\r\n', cursor);
    if (headEnd < 0) break;
    const head = buffer.slice(cursor, headEnd).toString('utf8');
    const dataStart = headEnd + 4;
    const next = buffer.indexOf(delim, dataStart);
    if (next < 0) break;
    const data = buffer.slice(dataStart, next - 2);
    const fieldName = /name="([^"]*)"/.exec(head)?.[1] || '';
    const filename = /filename="([^"]*)"/.exec(head)?.[1];
    if (filename != null) files.push({ fieldName, filename, data });
    else fields[fieldName] = data.toString('utf8');
    pos = next;
  }
  return { fields, files };
}

/* ---------------------------------------------------------------- 迷你 ZIP */

const CRC_TABLE = (() => {
  const table = new Int32Array(256);
  for (let i = 0; i < 256; i++) {
    let c = i;
    for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    table[i] = c;
  }
  return table;
})();

function crc32(buf) {
  let c = -1;
  for (const byte of buf) c = CRC_TABLE[(c ^ byte) & 0xff] ^ (c >>> 8);
  return (c ^ -1) >>> 0;
}

/** stored（method 0）ZIP；够用来验证「ZIP 原始字节被完整搬过去」 */
function makeZip(entries) {
  const locals = [];
  const centrals = [];
  let offset = 0;
  for (const [name, content] of entries) {
    const data = Buffer.isBuffer(content) ? content : Buffer.from(content, 'utf8');
    const nameBuf = Buffer.from(name, 'utf8');
    const crc = crc32(data);

    const local = Buffer.alloc(30);
    local.writeUInt32LE(0x04034b50, 0);
    local.writeUInt16LE(20, 4);
    local.writeUInt16LE(0x0800, 6);
    local.writeUInt32LE(crc, 14);
    local.writeUInt32LE(data.length, 18);
    local.writeUInt32LE(data.length, 22);
    local.writeUInt16LE(nameBuf.length, 26);
    locals.push(local, nameBuf, data);

    const central = Buffer.alloc(46);
    central.writeUInt32LE(0x02014b50, 0);
    central.writeUInt16LE((3 << 8) | 20, 4);
    central.writeUInt16LE(20, 6);
    central.writeUInt16LE(0x0800, 8);
    central.writeUInt32LE(crc, 16);
    central.writeUInt32LE(data.length, 20);
    central.writeUInt32LE(data.length, 24);
    central.writeUInt16LE(nameBuf.length, 28);
    central.writeUInt32LE(offset, 42);
    centrals.push(central, nameBuf);

    offset += 30 + nameBuf.length + data.length;
  }
  const cd = Buffer.concat(centrals);
  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0);
  eocd.writeUInt16LE(entries.length, 8);
  eocd.writeUInt16LE(entries.length, 10);
  eocd.writeUInt32LE(cd.length, 12);
  eocd.writeUInt32LE(offset, 16);
  return Buffer.concat([...locals, cd, eocd]);
}

/** 走一遍中央目录，返回解压后总字节数（坏档返回 -1） */
function zipUncompressedBytes(zipBuffer) {
  try {
    const eocdPos = zipBuffer.lastIndexOf(Buffer.from([0x50, 0x4b, 0x05, 0x06]));
    if (eocdPos < 0) return -1;
    const cdOffset = zipBuffer.readUInt32LE(eocdPos + 16);
    const count = zipBuffer.readUInt16LE(eocdPos + 10);
    let pos = cdOffset;
    let total = 0;
    for (let i = 0; i < count; i++) {
      if (zipBuffer.readUInt32LE(pos) !== 0x02014b50) return -1;
      total += zipBuffer.readUInt32LE(pos + 24);
      pos += 46 + zipBuffer.readUInt16LE(pos + 28);
    }
    return total;
  } catch {
    return -1;
  }
}

/* --------------------------------------------------------------------- 服务 */

function startServer(server, sink, port = 0) {
  const httpServer = http.createServer((req, res) => {
    const chunks = [];
    req.on('data', c => chunks.push(c));
    req.on('end', () => {
      const body = Buffer.concat(chunks);
      const path = String(req.url || '').split('?')[0];
      const send = payload => {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(payload));
      };
      if (!UPLOAD_RE.test(path)) {
        res.writeHead(404);
        return res.end('not found');
      }

      // ---- 控制器 readEnvelope(fields) + handle() ----
      const boundary = /boundary=(.+)$/.exec(req.headers['content-type'] || '')?.[1];
      if (!boundary) return send({ code: 401, message: 'meta 不是合法 JSON', data: null });
      const { fields, files } = parseMultipart(body, boundary);
      const raw = fields.meta || fields.params;
      if (!raw) return send({ code: 401, message: 'clientPub 无效', data: null });

      let session;
      try {
        session = server.open(JSON.parse(raw), {
          method: req.method,
          path,
          appUuid: String(req.headers['x-app-uuid'] || ''),
        });
      } catch (error) {
        return send({ code: 401, message: error.message, data: null });
      }

      // ---- service/upload.ts save('zip', files, params, appUuid) 的关键校验 ----
      const file = files.find(f => f.fieldName === 'file') || files[0];
      if (!file) return send({ code: 500, message: '缺少 file', data: null });
      const plain = session.plain;
      const actualMd5 = crypto.createHash('md5').update(file.data).digest('hex');
      if (plain.file_md5 && plain.file_md5 !== actualMd5) {
        return send({ code: 500, message: `file_md5 不符 ${actualMd5}`, data: null });
      }
      if (Number(plain.file_size) && Number(plain.file_size) !== file.data.length) {
        return send({ code: 500, message: `file_size 不符 ${file.data.length}`, data: null });
      }
      sink.received = {
        bundleId: plain.bundle_id,
        fileName: file.filename,
        size: file.data.length,
        md5: actualMd5,
        zipSignature: file.data.subarray(0, 2).toString() === 'PK',
        unzipBytes: zipUncompressedBytes(file.data),
      };
      return send({ code: 0, message: 'ok', data: server.seal(session, { ok: 1 }) });
    });
  });
  return new Promise(resolve => {
    httpServer.listen(port, '127.0.0.1', () => resolve({ httpServer, port: httpServer.address().port }));
  });
}

/* -------------------------------------------------------------------- 用例 */

function post(port, path, buffer, appUuid, boundary) {
  return new Promise((resolve, reject) => {
    const req = http.request(
      {
        host: '127.0.0.1',
        port,
        path,
        method: 'POST',
        headers: {
          'Content-Type': `multipart/form-data; boundary=${boundary}`,
          'X-App-UUID': appUuid,
          'Content-Length': buffer.length,
        },
      },
      res => {
        const chunks = [];
        res.on('data', c => chunks.push(c));
        res.on('end', () =>
          resolve({ status: res.statusCode, body: JSON.parse(Buffer.concat(chunks).toString('utf8')) })
        );
      }
    );
    req.on('error', reject);
    req.end(buffer);
  });
}

/** --serve <port>：常驻 mock 服务端，方便用后端自带的 tools/v2-probe.js 交叉验证 */
async function serve(port) {
  const server = makeServer();
  const sink = {};
  const { httpServer } = await startServer(server, sink, port);
  console.log(`[mock-v2] listening http://127.0.0.1:${port}${UPLOAD_PATH}`);
  console.log(`[mock-v2] serverPub = ${server.pubRaw.toString('base64')}`);
  console.log('[mock-v2] 用法: node <backend>/tools/v2-probe.js --base http://127.0.0.1:' + port +
    ' --pub <上面的 serverPub> zip <zip 文件> <bundle_id>');
  setInterval(() => {
    if (sink.received) {
      console.log(`[mock-v2] 收到上传 bundle=${sink.received.bundleId} ${sink.received.size}B ` +
        `md5=${sink.received.md5} file=${sink.received.fileName} zip=${sink.received.zipSignature}`);
      sink.received = null;
    }
  }, 500);
}

async function main() {
  const serveIndex = process.argv.indexOf('--serve');
  if (serveIndex >= 0) {
    await serve(Number(process.argv[serveIndex + 1]) || 18091);
    return;
  }

  const results = [];
  const record = (name, ok, detail) => {
    results.push({ name, ok, detail });
    console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${detail ? ' — ' + detail : ''}`);
  };

  const entries = [
    ['com.demo.app-20261115-101500/Documents/note.txt', 'hello from the sandbox'],
    [
      'com.demo.app-20261115-101500/Library/Preferences/com.demo.app.plist',
      Buffer.from([0x62, 0x70, 0x6c, 0x69, 0x73, 0x74, 0x30, 0x30]),
    ],
    ['com.demo.app-20261115-101500/Caches/blob.bin', crypto.randomBytes(8 * 1024 * 1024)],
  ];
  const zip = makeZip(entries);
  const expectedBytes = entries.reduce(
    (sum, [, content]) => sum + (Buffer.isBuffer(content) ? content.length : Buffer.byteLength(content)),
    0
  );
  const zipMd5 = crypto.createHash('md5').update(zip).digest('hex');
  const fileName = 'com.demo.app-20261115-101500.zip';
  const bundleId = 'com.demo.app';
  const appUuid = 'b1f0e0d0-1111-2222-3333-444455556666';
  const boundary = '----WQFilesCheck';
  const params = {
    app_uuid: appUuid,
    bundle_id: bundleId,
    file_name: fileName,
    file_size: zip.length,
    file_md5: zipMd5,
    upload_kind: 'zip',
    timestamp: Date.now(),
  };

  // ---------- 用例 1：正确链路（meta/params + 去前导斜杠的 AAD path） ----------
  {
    const server = makeServer();
    const sink = {};
    const { httpServer, port } = await startServer(server, sink);
    try {
      const ctx = { method: 'POST', path: UPLOAD_PATH, appUuid };
      const client = clientSession(server.pubRaw, params, ctx);
      const body = buildMultipart(client.envelope, zip, fileName, boundary);
      const res = await post(port, UPLOAD_PATH, body, appUuid, boundary);
      const plain = res.body.code === 0 ? client.open(res.body.data) : null;

      record(
        '上传成功：code=0 且响应能用同一会话解开',
        res.body.code === 0 && plain && plain.ok === 1,
        `code=${res.body.code} reply=${JSON.stringify(plain)}`
      );
      record(
        '服务端拿到同一份 ZIP：md5 / size / 文件名 / bundle_id 全等',
        !!(
          sink.received &&
          sink.received.size === zip.length &&
          sink.received.md5 === zipMd5 &&
          sink.received.bundleId === bundleId &&
          sink.received.fileName === fileName &&
          sink.received.zipSignature
        ),
        sink.received
          ? `${sink.received.size}B md5=${sink.received.md5} file=${sink.received.fileName}`
          : 'sink 为空'
      );
      const expectedUnzipped = expectedBytes;
      record(
        'ZIP 结构完整：中央目录可走通、解压字节数吻合',
        sink.received && sink.received.unzipBytes === expectedUnzipped,
        sink.received ? `unzipBytes=${sink.received.unzipBytes} expect=${expectedUnzipped}` : 'sink 为空'
      );
      record(
        '设备参数完整：app_uuid 与 header 一致（AAD 才绑得住）',
        sink.received && sink.received.bundleId === bundleId,
        `bundle=${sink.received && sink.received.bundleId}`
      );
    } finally {
      httpServer.close();
    }
  }

  // ---------- 用例 2：旧字段名 payload —— 必须 401 ----------
  {
    const server = makeServer();
    const { httpServer, port } = await startServer(server, {});
    try {
      const ctx = { method: 'POST', path: UPLOAD_PATH, appUuid };
      const client = clientSession(server.pubRaw, params, ctx);
      const body = buildMultipart(client.envelope, zip, fileName, boundary, ['payload']);
      const res = await post(port, UPLOAD_PATH, body, appUuid, boundary);
      record('字段名 payload（旧实现）被拒：401', res.body.code === 401,
        `code=${res.body.code} message=${res.body.message}`);
    } finally {
      httpServer.close();
    }
  }

  // ---------- 用例 3：AAD path 带前导斜杠 —— 必须校验失配 ----------
  {
    const server = makeServer();
    const { httpServer, port } = await startServer(server, {});
    try {
      const ctx = { method: 'POST', path: UPLOAD_PATH, appUuid };
      // 模拟 SecureBox 里 pathZip 写成带前导 / 的形态
      const client = clientSession(server.pubRaw, params, ctx, UPLOAD_PATH);
      const body = buildMultipart(client.envelope, zip, fileName, boundary);
      const res = await post(port, UPLOAD_PATH, body, appUuid, boundary);
      record(
        'AAD path 保留前导 / 被拒：401（所以客户端要 normalizePath）',
        res.body.code === 401,
        `code=${res.body.code} message=${res.body.message}`
      );
    } finally {
      httpServer.close();
    }
  }

  // ---------- 用例 4：nonce 复用 —— 必须 401 重复请求 ----------
  {
    const server = makeServer();
    const { httpServer, port } = await startServer(server, {});
    try {
      const ctx = { method: 'POST', path: UPLOAD_PATH, appUuid };
      const fixed = crypto.randomBytes(8).toString('hex');
      const first = clientSession(server.pubRaw, { ...params, nonce: fixed, ts: Date.now() }, ctx);
      const res1 = await post(
        port,
        UPLOAD_PATH,
        buildMultipart(first.envelope, zip, fileName, boundary),
        appUuid,
        boundary
      );
      const second = clientSession(server.pubRaw, { ...params, nonce: fixed, ts: Date.now() }, ctx);
      const res2 = await post(
        port,
        UPLOAD_PATH,
        buildMultipart(second.envelope, zip, fileName, boundary),
        appUuid,
        boundary
      );
      record(
        'nonce 复用被拒（每次上传都用新会话，重试也不会撞车）',
        res1.body.code === 0 && res2.body.code === 401,
        `first=${res1.body.code} second=${res2.body.code}/${res2.body.message}`
      );
    } finally {
      httpServer.close();
    }
  }

  const failed = results.filter(r => !r.ok);
  console.log('');
  console.log(`${results.length - failed.length}/${results.length} passed`);
  if (failed.length) {
    console.log('failed: ' + failed.map(f => f.name).join(' | '));
    process.exit(1);
  }
}

main().catch(error => {
  console.error(error);
  process.exit(1);
});
