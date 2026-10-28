# runProbe 补全：KVC 虚拟 asset 送入 PhotosServices 私有管线

## 本轮交付（commit f34be2b，已 push jixui main，CI 构建 7T-unsigned.ipa）

### 改动文件
1. **ThreeOneOSFive-Bridging-Header.h**：新增 5 个 PhotosServices 私有管线 objc_msgSend 封装声明
2. **AppIconHelper.m**：实现 5 个精确签名 objc_msgSend forwarder（ARM64 变参转发会丢浮点/整型寄存器参数，故逐方法钉死签名）
3. **PhotosTraversalProbe.swift**：新增 `submitVirtualInputIntoPrivatePipeline`，替换 runProbe 的 `(symbol TBD)`

### 私有管线调用链（对应已逆向确认的 IMP）
```
KVC alloc 非 nil 虚拟 PHAsset
  → PHCEIRContextInitWithRequest (PHContentEditingInputRequestContext
     initWithRequestID:managerID:asset:options:useRAWAsUnadjustedBase:resultHandler: IMP 0x23e340)
  → PHCEIRContextStart (start IMP 0x23bad4)
  → resultHandler 里 PHCEIRResultImageSandboxToken (IMP 0x27cb70)
  → sandbox_extension_consume → 枚举 /var/mobile/Media/PhotoData
```

### bridging header / .m 新增 C 封装
| 函数 | selector / IMP | 签名 |
|---|---|---|
| PHCEIRContextInitWithRequest | initWithRequestID:managerID:asset:options:useRAWAsUnadjustedBase:resultHandler: 0x23e340 | @,:,i,Q,@,@,B,@? → id |
| PHCEIRContextStart | start 0x23bad4 | v,@,: |
| PHCEIRContextProcessAndReturn | processAndReturnResultsWithRequest: 0x23acec | v,@,@ |
| PHCEIRResultImageSandboxToken | imageSandboxExtensionToken 0x27cb70 | @,: |
| PHImageManagerRequestCEI | requestContentEditingInputForAsset:withOptions:completionHandler: 桩0x3d7500 | v,@,@,@,@? |

## 关键设计决策（用户拍板）
- **asset 用 KVC 注入虚拟 PHAsset**（用户 interaction_ask 答复）：`NSClassFromString("PHAsset") as? NSObject.Type` + alloc → KVC 注入 localIdentifier/mediaType/mediaSubtypes，保证非 nil、可被 context 解引用。
- resultHandler 用 `@convention(block)` 闭包（以 ObjC block 传给 C 函数 id 参数），参数用 `AnyObject?` 接收（实际 ObjC 传 PHContentEditingInputResult），避免类型强转崩溃。

## 诚实标注边界（未伪装为已验证）
1. **虚拟 asset 的资源读取**：context 内部会经 `assetResourcesForAsset:`(0x3b7380) 读 asset 的真实资源。纯 KVC 虚拟 asset 大概率过不了这一步（PHAsset 资源在内部不可注入），可能导致 context 静默失败、不触发 MCM 签发。这是**本方案能否真正触发签发的核心待验证点**——需真机 log2_19 确认。
2. **resultHandler block 签名**：私有 context 的 resultHandler 实际期望 `void(^)(PHContentEditingInputResult*, NSDictionary*)`，我以 `AnyObject?` 接收避免类型崩溃，但若 context 未真正启动，handler 不会被调用。
3. **ARC 生命周期**：C 封装返回的 ctx 由 Swift 接管，但 ctx 内部异步引用链依赖 PhotosServices 保持。研究场景可接受。

## 下一步真机验证
- 用户装 CI 产物 `7T-unsigned.ipa`（f34be2b）→ 真机跑 → 回传新 log2_19
- 观察日志关键词：
  - `photo-probe: virtual PHAsset built` → 虚拟 asset 构造成功
  - `photo-probe: submitted to PHContentEditingInputRequestContext (start)` → context 触发
  - `imageSandboxExtensionToken=…` → **MCM 已签发 token（成功标志）**
  - 或 `pipeline result nil` / `PHAsset class unavailable` → context 未启动/资产未过
  - 相册枚举：`/var/mobile/Media/PhotoData: N entries`（成功）vs `not enumerable errno=1`（EPERM 依旧）

## 与本段已修复项的关系
- ADRP 修复（fb08996）已真机验证：log2_18 resolved 6546 桩、29 目标桩全 PRESENT，本段全部方法/IMP 均来自权威桩表。
- 本补全使 runProbe 首次从"仅构造虚拟 input + 日志观测"推进到"送入私有 context + start 触发"，是触发链路的真实实现。
