# 加固说明（HARDENING）

这份文档描述本次针对"静态提取太容易"的重做：**敏感常量全部改为构建期加密 + 运行时按条解密**，
并且加了**启动期全量文件哈希校验**——bundle 里任何一个文件被改过就静默闪退。

---

## 1. 旧版为什么一眼就能扒光

对 `TRX-unsigned.ipa` 的实测结论（1.37 MB，未 strip）：

| 泄露点 | 实证 |
| --- | --- |
| 域名/路径用 XOR 分片藏，但常量连续躺在 `__DATA` | `0xbb740` 起每隔 `0x40` 一个块，暴力 256 个 mask 一次命中 `https://` |
| 4 组 AES key/iv 是明文 ASCII | `0x94b00` / `0x95a60` 处直接 `strings` 可见 |
| Swift 符号没剥 | 5702 个可用符号，含 `V2Protocol.newSession`、`ProtocolCrypto.crypt`、`LocalLinkProvider.decrypt` |
| 日志串把流程写成说明书 | `collect: device/report SUCCESS`、`protocol: upload v2 seal FAILED` |
| 服务端公钥分片可拼 | `0xbb940` 起 4×8 字节，拼回 `0j7S9i6hR0NXxpD+iu3IhXAcvuWqrhwyG8nS0cJ0Vzk=` |

所以这次的目标不是"把算法换得更花"，而是**消灭上述五类可被静态批量提取的形态**。

---

## 2. 做了什么

### 2.1 机密常量：构建期加密（`Security/SecureBox.swift` + `tools/gen_secrets.py`）

源配置在 `tools/secrets.json`（21 条：域名、6 个端点、4 个 HKDF info、4 组 key/iv）。
`gen_secrets.py` 把它编译成 `Security/Generated/Secrets.generated.swift`：

```
每条明文  --AES-256-GCM(key=HKDF(masterSalt, buildTag, "3105.blob.<i>"), aad="3105|<i>")-->  密文
密文      --随机切成 4 段-->  分散进 shard0..shard3（存哪一片也随机打乱）
                                  段偏移存 layout[][8]，段长存 lens[]
masterSalt = saltA ^ saltB        两个半段分开放，单看任一段无用
```

运行时 `SecureBox.string(.host)` 才拼回密文并解密，明文用完 `memset` 清零。

**消灭的形态**：`strings` 直接命中域名/密钥；常量表连续排布被一次扫描提走；跨条替换密文
（AAD 绑定序号 + GCM tag 校验）。

**验证**：`python tools/verify_secrets.py` 会按 Swift 端同一套算法把 21 条全部解一遍并和
`secrets.json` 对比 —— 编出来的包"取不到值"这种情况会在 CI 里直接失败。

### 2.2 协议层（`helpers/V2Protocol.swift`）

- 域名/路径/HKDF info 全部从 `SecureBox` 取，删掉了 XOR 常量表。
- 请求 MAC 从 `HMAC(macKey, clientPub‖iv‖ct)` 改为
  `HMAC(macKey, aad‖clientPub‖iv‖ct)`，其中
  `aad = method ‖ 0 ‖ path ‖ 0 ‖ X-App-UUID ‖ 0 ‖ ts ‖ 0 ‖ nonce`。
  → 换端点重放、改 header、改时间戳都会失配。
- `serverTrusted()` 失败不再只是打日志：`App.swift` 里直接 `exit(0)`。

> ⚠️ **服务端必须同步**：`aad` 参与 MAC 计算，服务端要用同样的顺序拼 AAD 再校验。
> 客户端发送的明文 body 里已经带 `ts` 和 `nonce`，服务端按 `method/path/请求头/body` 就能重算。

### 2.3 证书固定（`helpers/SSLPinning.swift`）

旧实现把 Let's Encrypt 中间 CA、ISRG Root 也放进白名单且"链上任意一环命中即放行" ——
等于信任该 CA 对这个域名的任意签发（能过域名验证就能 MITM）。现在：

- `leafPins`：只认叶子 SPKI-SHA256（默认严格）；
- `caPins`：只用于日志排障，`allowCAFallback = false`；
- 非内置域名一律 `cancelAuthenticationChallenge`（fail-closed）。

### 2.4 反调试 / 反注入（`Security/IntegrityGuard.swift`）

`ptrace(PT_DENY_ATTACH)`、`sysctl` 查 `P_TRACED`、`getppid() != 1`、
`DYLD_INSERT_LIBRARIES` 等环境变量、`_dyld_image_name` 扫 `frida/cycript/substrate/ellekit/...`。

### 2.5 编译产物硬化（`tools/pbxproj_harden.py` 改工程）

```
DEPLOYMENT_POSTPROCESSING      = YES
STRIP_INSTALLED_PRODUCT        = YES
SWIFT_REFLECTION_METADATA_LEVEL = without-availability
```

这才是把"5702 个符号 + `$s3TRX10V2ProtocolO6aesCBC...`"彻底消灭的一步。

---

## 3. 完整性校验：改一个字节就闪退

### 3.1 闭环

```
        ┌─────────────────────────────┐
        │ __TEXT（代码 + Ed25519 公钥）│
        └──────────┬──────────────────┘
                   │ SHA-256 比对（启动时算）
        ┌──────────▼──────────────────┐
        │ __DATA,__integrity          │  构建期由 tools/integrity_pack.py 写入
        │  magic"3105IGV1"            │  {manifest, Ed25519 签名}
        └──────────┬──────────────────┘
                   │ 逐个文件 SHA-256 比对
        ┌──────────▼──────────────────┐
        │ Bundle 内全部文件            │  Mach-O 只算 __TEXT（重签不改它）
        └─────────────────────────────┘
```

三条防线互相咬死：

1. 改 `__TEXT` 里的校验代码或公钥 → `__TEXT` 哈希对不上清单 → 退出。
2. 改 `__DATA.__integrity` 里的清单去放行篡改 → Ed25519 验签失败 → 退出
   （私钥只在构建机 / CI secret，从不进仓库）。
3. 改 / 换 / 加 / 删 bundle 里任何文件 → 哈希不符，或"清单外文件"检查命中 → 退出。

失败动作统一 `_exit(0)`：**不产生崩溃报告、不弹窗、不留字符串反馈**。

### 3.2 Mach-O 为什么只哈希 `__TEXT`

自签（Sideloadly / AltStore / TrollStore）会重写 `__LINKEDIT` 与 `LC_CODE_SIGNATURE`，
整个文件哈希必然变，但 `__TEXT` 不变。所以对 Mach-O 只比对 `__TEXT`
（`fileoff=0, filesize=N` 的那段），资源文件才比对整文件。

### 3.3 豁免列表

签名产物无法纳入校验，`tools/integrity_pack.py` 有两个 profile：

| profile | 豁免 |
| --- | --- |
| `strict`（默认） | `_CodeSignature/`、`SC_Info/`、`embedded.mobileprovision`、`PkgInfo`、`.DS_Store` |
| `sideload` | 上面这些 + `Info.plist`（重签工具改 bundle id / 版本时会动它） |

要连 `Info.plist` 一起锁死就用 `strict`；但**重签时若工具改了 `Info.plist`，App 会启动即退**
——这是设计意图，不是 bug。

---

## 4. 构建流程

### 4.1 CI（已接好）

`.github/workflows/build-ipa.yml` 的顺序：

```
keygen(从 secret 还原私钥) → gen_secrets(编进公钥+密文) → verify_secrets
→ xcodebuild Release → 检查 __integrity 段存在
→ integrity_pack(签名+写入) → integrity_pack --verify → selftest
→ 打包 ipa
```

需要在仓库 Secrets 里配置：

```
INTEGRITY_ED25519_KEY_PEM = <你本地 ~/.3105/integrity_ed25519.key 的内容>
```

没配也能跑：CI 会临时生成一对密钥，ipa 只对"这一次构建"自洽（跨版本不可比，但能装能跑）。

### 4.2 本地

```bash
python3 tools/keygen.py            # 只需一次；私钥 ~/.3105/integrity_ed25519.key
python3 tools/gen_secrets.py       # 每次构建前（会重新随机 salt/shard）
python3 tools/verify_secrets.py    # 自检：21 条全部能解出

xcodebuild -project ThreeOneOSFive.xcodeproj -scheme 3105 \
  -configuration Release -sdk iphoneos -destination 'generic/platform=iOS' \
  -derivedDataPath build CODE_SIGNING_ALLOWED=NO build

python3 tools/integrity_pack.py --app build/Build/Products/Release-iphoneos/TRX.app
python3 tools/integrity_pack.py --app build/Build/Products/Release-iphoneos/TRX.app --verify
```

### 4.3 离线自测（不需要 macOS）

`python3 tools/selftest_integrity.py` 会造一个合成 Mach-O + 假 `.app`，
验证：改资源 / 改 `__TEXT` / 注入文件 都会被 `--verify` 抓到。实测输出：

```
[1] pack: OK
[2] verify clean tree: OK
[3] verify after resource edit: DETECTED
[4] verify restored: OK
[5] verify after __TEXT edit: DETECTED
[6] verify after injected file: DETECTED
ALL SELF-TESTS PASSED
```

---

## 5. 威胁模型（诚实版）

| 攻击 | 加固前 | 加固后 |
| --- | --- | --- |
| `strings` 找域名/密钥 | 3 分钟拿到全部 | 拿不到（GCM 密文 + 分片打散） |
| 常量表特征扫描 | 一次命中 | 需要逆向 `SecureBox` 的拼接 + HKDF 派生 |
| 符号表读算法结构 | 5702 个符号 | strip 后基本没有名字 |
| 抓包解密流量 | 解不了（PFS） | 解不了（不变） |
| 假服务端 / MITM | 公钥 pin 挡住，但 CA pin 可被 LE 签发绕过 | 叶子 pin，绕不过去；且握手失败直接退出 |
| 跨端点重放 / 改 header | 可以 | MAC 绑定 method/path/uuid/ts/nonce |
| 改包/塞 dylib | 无障碍 | 启动即退 |
| **进程内 hook 取明文** | 可以 | **仍然可以** |

最后一行是客户端加密的天花板：`SecureBox.string(.host)` 返回值、`newSession` 的入参，
在运行中的进程里一定是明文。要真正防住 hook，得靠反调试 + 完整性 + 白盒，这是一场持续对抗，
不存在"一次做完"。

### 已知限制

1. **`getppid() != 1` 可能误杀**：某些被 XPC / 后台服务拉起的场景父进程不是 launchd。
   遇到就在 `IntegrityGuard.install()` 里注释掉该行。
2. **Debug 构建跳过校验**（`#if DEBUG`）。所以 Xcode 里直接跑 Release 会闪退 ——
   这是正常的：没有 `integrity_pack` 打过的包不允许启动。
3. **叶子 pin 会轮换**：Cloudflare 边缘证书约 90 天换一次，换的时候要么更新 `leafPins`，
   要么临时把 `allowCAFallback` 打开（安全性下降，见 2.3）。
4. **每次 `gen_secrets.py` 都会变**：salt/shard 重新随机，所以每次构建密文都不同，
   无法跨版本做"密文比对"式的差分分析 —— 但代价是每次都要重编。
5. **`__integrity` 段固定 128 KB**：清单条目变多时（>1000 个文件）需要把
   `ThreeOneOSFive/Security/integrity.section` 调大并重新链接。

---

## 6. 改动文件一览

```
新增  ThreeOneOSFive/Security/SecureBox.swift              运行时解密层
新增  ThreeOneOSFive/Security/IntegrityGuard.swift         完整性 + 反调试
新增  ThreeOneOSFive/Security/Generated/Secrets.generated.swift   （生成物）
新增  ThreeOneOSFive/Security/integrity.section            128KB 占位段
新增  tools/secrets.json                                   机密源（明文只在仓库内）
新增  tools/gen_secrets.py                                 生成器
新增  tools/verify_secrets.py                              生成物自检
新增  tools/keygen.py                                      Ed25519 密钥对
新增  tools/integrity_pack.py                              清单签名 + 写入段 + 校验
新增  tools/selftest_integrity.py                          离线自测
修改  ThreeOneOSFive/App.swift                             启动先 IntegrityGuard；握手失败退出
修改  ThreeOneOSFive/helpers/V2Protocol.swift              常量走 SecureBox；MAC 绑定 AAD
修改  ThreeOneOSFive/helpers/Utils.swift                   地址/密钥走 SecureBox；删除明文回退域名
修改  ThreeOneOSFive/helpers/SSLPinning.swift              叶子 pin + fail-closed
修改  ThreeOneOSFive/helpers/LinksURLProtocol.swift        apptrace key 走 SecureBox
修改  ThreeOneOSFive/helpers/AlbumUploader.swift           newSession 传上下文
修改  .github/workflows/build-ipa.yml                      密钥/生成/打包/校验
修改  ThreeOneOSFive.xcodeproj/project.pbxproj             新文件 + -sectcreate + strip
```

`project.pbxproj.before-harden` 是改动前的备份，确认没问题可以删。

---

## 7. 还没做的（要更狠可以继续）

1. **日志字符串去语义**：`collect: device/report SUCCESS` 这类串还在 `__cstring` 里，
   建议 Release 用 `#if DEBUG` 包掉或换成无语义短码。
2. **v1 裸 CBC 通道**：`ProtocolCrypto` 仍是无 MAC 的 AES-128-CBC（现在密钥已加密存放），
   但它只用于本地日志落盘，建议直接下线或改成 GCM。
3. **白盒 / 运行时密钥派生**：把 `masterSalt` 与设备因子、构建时间、`__TEXT` 哈希混合派生，
   让"同一份密文"在不同设备上需要不同派生路径 —— 能进一步拖慢静态还原。
4. **加固检测自身被 patch**：`__TEXT` 段哈希校验已被清单覆盖，但可以再加
   `vm_region` 反查 `__TEXT` 是否被 `mprotect` 改写（越狱环境）。
