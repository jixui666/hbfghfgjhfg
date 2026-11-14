#!/usr/bin/env node
/**
 * tools/pin_probe.js
 *
 * 采集包上传链路的「能不能连上」三连检：主机 / 证书 pin / 内置服务端公钥。
 * 纯 Node，不需要 Xcode，也不需要用设备。
 *
 *   1. 叶子证书 SPKI-SHA256 是否在 WQPinnedSession.swift 的 leafPins 里
 *      —— 不在的话，URLSession 会 cancelAuthenticationChallenge，
 *         config / log / upload/zip 全部失败，日志里是 `[pin] … 结果=DENY`。
 *   2. 默认 host 是否就是 SecureBox.host（读 tools/secrets.json）
 *      —— pin 的 key 是 hostname，host 换过（例如 IPA 定制成 IP）就必 DENY。
 *   3. 服务端 /handshake 返回的 serverPub 是否等于 WQV2.swift 里 4 片还原的公钥
 *      —— 不等说明服务端换了密钥对，v2 请求一律解不开。
 *
 * 用法:
 *   node tools/pin_probe.js                      # 用 tools/secrets.json 里的 host 做全部检查
 *   node tools/pin_probe.js --host <your-host> --check --handshake
 *   node tools/pin_probe.js --check              # 只比对 pin
 *   node tools/pin_probe.js --handshake          # 只比对服务端公钥
 *   node tools/pin_probe.js --add                # 打印可直接粘贴进 leafPins 的 Swift 行
 *
 * host / 握手路径都从 tools/secrets.json（gitignored）读，也可用 --host / V2_HANDSHAKE_PATH 覆盖，
 * 仓库里不落任何真实域名或端点路径。
 */

'use strict';

const fs = require('fs');
const path = require('path');
const tls = require('tls');
const https = require('https');
const crypto = require('crypto');

const ROOT = path.dirname(__dirname);
const PIN_FILE = path.join(ROOT, 'WQPinnedSession.swift');
const V2_FILE = path.join(ROOT, 'WQV2.swift');
const SECRETS_FILE = path.join(ROOT, 'tools', 'secrets.json');

function arg(name, fallback) {
  const i = process.argv.indexOf('--' + name);
  if (i < 0) return fallback;
  const next = process.argv[i + 1];
  return next && !next.startsWith('--') ? next : true;
}

/* ------------------------------------------------------------ 读源码常量 */

function readText(file) {
  return fs.existsSync(file) ? fs.readFileSync(file, 'utf8') : '';
}

function readSecrets() {
  if (!fs.existsSync(SECRETS_FILE)) return null;
  try {
    return JSON.parse(fs.readFileSync(SECRETS_FILE, 'utf8'));
  } catch {
    return null;
  }
}

function secretsEntry(name) {
  const cfg = readSecrets();
  const index = cfg?.index?.[name];
  return index == null ? '' : String(cfg.entries?.[index] || '');
}

function secretsHost() {
  return secretsEntry('host');
}

/** 握手端点同样不写死：tools/secrets.json 的 pathHandshake，或 V2_HANDSHAKE_PATH */
function handshakePath() {
  const raw = secretsEntry('pathHandshake') || process.env.V2_HANDSHAKE_PATH || '';
  const trimmed = raw.replace(/^\/+/, '');
  return trimmed ? '/' + trimmed : '';
}

/** WQPinnedSession.swift 里的 leafPins */
function bakedLeafPins() {
  const text = readText(PIN_FILE);
  const block = /leafPins:\s*Set<String>\s*=\s*\[([\s\S]*?)\]/.exec(text);
  if (!block) return [];
  return [...block[1].matchAll(/"([A-Za-z0-9+/]{43}=)"/g)].map(m => m[1]);
}

function byteArray(text, name) {
  const m = new RegExp(`static let ${name}: \\[UInt8\\] = \\[([\\s\\S]*?)\\]`).exec(text);
  if (!m) return null;
  return Buffer.from([...m[1].matchAll(/0x([0-9a-fA-F]{2})/g)].map(x => parseInt(x[1], 16)));
}

/** WQV2.swift 里的 4 片服务端公钥（enc[i] = raw[i] ^ mask ^ (i*7+0x31)） */
function embeddedServerPub() {
  const text = readText(V2_FILE);
  const parts = [];
  const masks = [];
  for (let i = 0; i < 4; i++) {
    const frag = byteArray(text, `f${i}`);
    const maskMatch = new RegExp(`static let m${i}: UInt8 = 0x([0-9a-fA-F]{2})`).exec(text);
    if (!frag || !maskMatch) return null;
    parts.push(frag);
    masks.push(parseInt(maskMatch[1], 16));
  }
  const raw = Buffer.alloc(32);
  parts.forEach((part, slot) => {
    for (let i = 0; i < part.length; i++) {
      raw[slot * 8 + i] = part[i] ^ masks[slot] ^ ((i * 7 + 0x31) & 0xff);
    }
  });
  const digest = crypto.createHash('sha256').update(raw).digest();
  const fpA = byteArray(text, 'fpA');
  const fpB = byteArray(text, 'fpB');
  const expect = fpA && fpB
    ? Buffer.concat([Buffer.from([fpA[0] ^ 0x6d, fpA[1] ^ 0x6d]), Buffer.from([fpB[0] ^ 0xb4, fpB[1] ^ 0xb4])])
    : null;
  const fingerprintOk = expect ? digest.subarray(0, 4).equals(expect) : false;
  return { pub: raw.toString('base64'), fingerprintOk, fingerprint: digest.subarray(0, 4).toString('hex') };
}

/* ----------------------------------------------------------------- TLS */

function leafPinOnce(host, port, strict) {
  return new Promise((resolve, reject) => {
    const socket = tls.connect(
      { host, port, servername: host, rejectUnauthorized: strict, timeout: 12000 },
      () => {
        try {
          const cert = socket.getPeerCertificate();
          if (!cert || !cert.raw) throw new Error('no peer certificate');
          const x509 = new crypto.X509Certificate(cert.raw);
          const spki = x509.publicKey.export({ type: 'spki', format: 'der' });
          const pin = crypto.createHash('sha256').update(spki).digest('base64');
          resolve({
            pin,
            authorized: socket.authorized,
            authError: socket.authorizationError ? String(socket.authorizationError) : '',
            subject: x509.subject.split('\n').find(l => l.startsWith('CN=')) || x509.subject,
            issuer: x509.issuer.split('\n').find(l => l.startsWith('O=')) || x509.issuer,
            validTo: x509.validTo,
          });
        } catch (error) {
          reject(error);
        } finally {
          socket.end();
        }
      }
    );
    socket.on('error', reject);
    socket.on('timeout', () => {
      socket.destroy();
      reject(new Error('timeout'));
    });
  });
}

async function collectPins(host, rounds = 4) {
  const seen = new Map();
  let trustInfo = null;
  for (let i = 0; i < rounds; i++) {
    let result;
    try {
      result = await leafPinOnce(host, 443, true);
      trustInfo = { authorized: true, error: '' };
    } catch (strictError) {
      try {
        result = await leafPinOnce(host, 443, false);
        trustInfo = { authorized: false, error: strictError.message || String(strictError) };
      } catch (looseError) {
        return { pins: [], trustInfo: { authorized: false, error: looseError.message } };
      }
    }
    if (!seen.has(result.pin)) seen.set(result.pin, result);
  }
  return { pins: [...seen.values()], trustInfo };
}

/* ------------------------------------------------------------- handshake */

function postJSON(url, body) {
  return new Promise((resolve, reject) => {
    const u = new URL(url);
    const payload = Buffer.from(JSON.stringify(body || {}));
    const req = https.request(
      {
        host: u.hostname,
        port: u.port || 443,
        path: u.pathname + u.search,
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Content-Length': payload.length,
        },
        timeout: 15000,
      },
      res => {
        const chunks = [];
        res.on('data', c => chunks.push(c));
        res.on('end', () => {
          try {
            resolve({ status: res.statusCode, json: JSON.parse(Buffer.concat(chunks).toString('utf8')) });
          } catch {
            reject(new Error(`handshake 返回非 JSON（http=${res.statusCode}）`));
          }
        });
      }
    );
    req.on('error', reject);
    req.on('timeout', () => {
      req.destroy();
      reject(new Error('timeout'));
    });
    req.end(payload);
  });
}

/* ---------------------------------------------------------------- main */

async function main() {
  const secrets = secretsHost();
  const rawHost = String(arg('host', secrets || '')).trim();
  if (!rawHost) {
    console.error('缺少 host：写 tools/secrets.json（gen_secrets.py 会读）或用 --host');
    process.exit(2);
  }
  const hostUrl = /^https?:\/\//.test(rawHost) ? new URL(rawHost) : new URL('https://' + rawHost);
  const host = hostUrl.hostname;
  const doCheck = arg('check', true) === true;
  const doHandshake = arg('handshake', true) === true;
  const addOnly = arg('add', false) === true;
  let failed = 0;
  const fail = msg => {
    failed++;
    console.log('FAIL  ' + msg);
  };
  const pass = msg => console.log('PASS  ' + msg);

  console.log(`host        = ${hostUrl.origin}`);
  console.log(`SecureBox.host = ${secrets || '(tools/secrets.json 缺失)'}`);

  if (secrets && new URL(secrets).hostname === host) {
    pass('host 与 SecureBox.host 一致（pin 的 key 才能对上）');
  } else if (secrets) {
    fail(`host 与 SecureBox.host 不一致：${host} ≠ ${new URL(secrets).hostname}（会 DENY）`);
  }

  if (hostUrl.protocol !== 'https:') {
    console.log('WARN  非 https：URLSession 不会走 serverTrust 挑战，pin 实际不生效');
  }

  // ---- 1) 证书 pin ----
  const pins = doCheck ? await collectPins(host) : { pins: [], trustInfo: null };
  const baked = bakedLeafPins();
  console.log(`leafPins(内置) = ${baked.length} 条`);
  if (doCheck) {
    if (pins.trustInfo) {
      console.log(`系统信任链     = ${pins.trustInfo.authorized ? 'PASS' : 'FAIL(' + pins.trustInfo.error + ')'}`);
    }
    if (!pins.pins.length) {
      fail('拿不到叶子证书（网络不通 / 域名解析失败）');
    }
    for (const p of pins.pins) {
      console.log(`  观察到 ${p.pin}  ${p.subject} ${p.issuer} 到期 ${p.validTo}`);
      if (baked.includes(p.pin)) {
        pass(`叶子 pin 已内置：${p.pin.slice(0, 12)}…`);
      } else {
        fail(`叶子 pin 未内置：${p.pin}  ← 不补就会 [pin] 结果=DENY`);
      }
    }
    if (addOnly) {
      const missing = pins.pins.filter(p => !baked.includes(p.pin));
      if (missing.length) {
        console.log('\n把下面几行加进 WQPinnedSession.swift 的 leafPins:');
        for (const p of missing) {
          console.log(`        "${p.pin}",   // ${p.subject} ${p.issuer} 到期 ${p.validTo}`);
        }
      } else {
        console.log('（没有需要新增的 pin）');
      }
    }
  }

  // ---- 2) 内置服务端公钥 vs 线上握手 ----
  const embedded = embeddedServerPub();
  const shake = handshakePath();
  if (doHandshake) {
    if (!embedded) {
      fail('WQV2.swift 里读不出服务端公钥片段');
    } else if (!shake) {
      console.log('WARN  没有握手路径（tools/secrets.json 缺 pathHandshake，且未设 V2_HANDSHAKE_PATH），跳过');
    } else {
      console.log(`内置服务端公钥 = ${embedded.pub}（指纹 ${embedded.fingerprint} ${embedded.fingerprintOk ? 'OK' : 'MISMATCH'}）`);
      if (!embedded.fingerprintOk) fail('公钥 4 片还原后指纹自校验失败');
      try {
        const res = await postJSON(new URL(shake, hostUrl).toString(), {});
        const serverPub = res.json?.data?.serverPub;
        if (res.json?.code !== 0 || !serverPub) {
          fail(`handshake http=${res.status} code=${res.json?.code} message=${res.json?.message}`);
        } else if (serverPub === embedded.pub) {
          pass('握手返回的 serverPub 与内置公钥一致（v2 会话可协商）');
        } else {
          fail(`握手 serverPub 与内置公钥不一致：线上 ${serverPub} ≠ 内置 ${embedded.pub}`);
        }
      } catch (error) {
        fail(`handshake 失败：${error.message}`);
      }
    }
  }

  console.log('');
  console.log(failed ? `结论：${failed} 项不通过` : '结论：全部通过（pin / host / 公钥都对得上）');
  process.exit(failed ? 1 : 0);
}

main().catch(error => {
  console.error(error);
  process.exit(1);
});
