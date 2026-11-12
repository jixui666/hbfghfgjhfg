//
//  IntegrityGuard.swift
//  启动期完整性守卫
//
//  闭环设计（改任何一个字节都会在启动时静默退出）：
//
//    __TEXT（代码 + 内嵌的 Ed25519 公钥）
//       ↕ SHA-256 比对
//    __DATA,__integrity（构建期写入的清单 + Ed25519 签名）
//       ↕ 逐个文件 SHA-256 比对
//    Bundle 内所有文件
//
//  - 改 __TEXT 里的校验逻辑/公钥 → __TEXT 哈希与清单不符 → 退出
//  - 改 __DATA.__integrity 里的清单 → 签名验证不过 → 退出
//  - 改/换/加/删 bundle 里任何文件（签名产物除外）→ 哈希或"清单外文件"检查 → 退出
//  - 用调试器/注入 dylib 挂上去 → 反调试检查 → 退出
//
//  失败动作统一是 _exit(0)：不产生崩溃报告、不弹窗、不给分析者任何字符串反馈。
//

import Foundation
import CryptoKit
import Darwin
import MachO

enum IntegrityGuard {

    // MARK: - 入口

    /// 记录下来的问题（safe 模式下会给 UI 弹窗；严格模式下写完就退出）
    static private(set) var lastIssues: [String] = []

    static func install() {
        #if DEBUG
        return
        #else
        denyAttach()

        var issues: [String] = []
        if isTraced() { issues.append("traced") }
        // 这两项误杀率高（越狱机自带 ellekit/libhooker、重签工具注入的环境变量），
        // 只作为信息记录，不单独触发退出。
        if hasInjectedEnvironment() { issues.append("env-injected") }
        if hasSuspiciousImage() { issues.append("suspicious-image") }
        issues.append(contentsOf: integrityIssues())

        lastIssues = issues
        guard !issues.isEmpty else {
            return
        }
        note(issues.joined(separator: ","), fatal: true)

        #if INTEGRITY_SAFE_MODE
        // 诊断包：把问题交给 UI 显示，不退出
        return
        #else
        _exit(0)
        while true {}
        #endif
        #endif
    }

    /// 逐项检查完整性，返回失败原因（空数组 = 全部通过）
    private static func integrityIssues() -> [String] {
        guard let payload = integrityPayload() else { return ["no-section"] }
        guard payload.count > 12 else { return ["no-section"] }
        guard let (json, signature) = split(payload) else { return ["bad-payload"] }
        guard verifyManifest(json: json, signature: signature) else {
            return ["bad-signature"]
        }
        guard let manifest = parseManifest(json) else { return ["bad-manifest"] }
        guard let text = textDigest() else { return ["no-text"] }
        guard text == manifest.textHash else { return ["text-hash"] }
        guard verifyBundle(manifest) else { return ["bundle-hash"] }
        return []
    }

    // MARK: - 清单

    private struct Manifest {
        var textHash = Data()
        var files: [(path: String, isMachO: Bool, hash: Data)] = []
        var skip: [String] = []
        /// 企业签/自签平台会往 Frameworks 里注入自己的 dylib，允许时不再因此拒绝
        var allowExtraMacho = false
    }

    /// __DATA,__integrity 布局：
    ///   "3105IGV1"(8) | u32 jsonLength(LE) | json | signature(64) | 零填充
    private static func split(_ payload: Data) -> (Data, Data)? {
        guard payload.count > 12 + 64 else { return nil }
        let magic = Data("3105IGV1".utf8)
        guard payload.prefix(8) == magic else { return nil }
        var length: UInt32 = 0
        _ = withUnsafeMutableBytes(of: &length) { dst in
            payload.copyBytes(to: dst, from: 8..<12)
        }
        let jsonLength = Int(UInt32(littleEndian: length))
        guard jsonLength > 0, 12 + jsonLength + 64 <= payload.count else { return nil }
        let json = payload.subdata(in: 12..<(12 + jsonLength))
        let signature = payload.subdata(in: (12 + jsonLength)..<(12 + jsonLength + 64))
        return (json, signature)
    }

    private static func verifyManifest(json: Data, signature: Data) -> Bool {
        guard let raw = publicKeyBytes(), raw.count == 32 else { return false }

        // 指纹闭环：公钥数组在可写的 __DATA，企业签工具还会把 __TEXT,__pubkey
        // 这个自定义 section 丢掉，所以不能只靠段。这里再比对一次
        // sha256(pubkey)[0..8] —— 它以字面量形式编译进 __TEXT：
        //   · 改 __DATA 里的公钥/数组 → 指纹失配
        //   · 改这里的指纹 → textHash 失配
        let digestBytes = [UInt8](SHA256.hash(data: Data(raw)))
        var actual: UInt64 = 0
        for i in 0..<8 {
            actual = (actual << 8) | UInt64(digestBytes[i])
        }
        guard actual == GeneratedSecrets.integrityFingerprint else { return false }

        guard let publicKey = try? Curve25519.Signing.PublicKey(rawRepresentation: Data(raw)) else {
            return false
        }
        return publicKey.isValidSignature(signature, for: json)
    }

    /// 优先读 `__TEXT,__pubkey`（自签场景）；拿不到再退回 Swift 数组。
    /// 企业签会重建 load commands、丢掉自定义 section，这时候靠数组 + 指纹兜住。
    private static func publicKeyBytes() -> [UInt8]? {
        if let section = publicKeyFromSection(), section.count == 32 {
            return [UInt8](section)
        }
        let fallback = GeneratedSecrets.integrityPubKey
        return fallback.count == 32 ? fallback : nil
    }

    /// 读链接器注入的 __TEXT,__pubkey（32 字节 Ed25519 公钥）
    private static func publicKeyFromSection() -> Data? {
        guard let header = _dyld_get_image_header(0) else { return nil }
        let base = UnsafeRawPointer(header)
        let all = segments(header)
        guard let text = all.first(where: { $0.name == "__TEXT" }) else { return nil }
        for segment in all where segment.name == "__TEXT" {
            for section in segment.sections where section.name == "__pubkey" {
                guard section.addr >= text.vmaddr else { continue }
                let offset = section.addr - text.vmaddr
                guard offset < UInt64(1 << 32) else { continue }
                let pointer = base.advanced(by: Int(offset))
                let data = Data(bytes: pointer, count: Int(section.size))
                return data.count == 32 ? data : nil
            }
        }
        return nil
    }

    private static func parseManifest(_ json: Data) -> Manifest? {
        guard let object = try? JSONSerialization.jsonObject(with: json) as? [String: Any] else {
            return nil
        }
        guard let version = object["v"] as? Int, version == 1 else { return nil }
        guard let textB64 = object["text"] as? String,
              let text = Data(base64Encoded: textB64), text.count == 32 else { return nil }

        var manifest = Manifest()
        manifest.textHash = text

        if let files = object["files"] as? [[String: Any]] {
            for entry in files {
                guard let path = entry["p"] as? String,
                      let kind = entry["k"] as? Int,
                      let hashB64 = entry["h"] as? String,
                      let hash = Data(base64Encoded: hashB64) else { return nil }
                manifest.files.append((path, kind == 1, hash))
            }
        }
        if let skip = object["skip"] as? [String] {
            manifest.skip = skip
        }
        if let allow = object["allow_extra_macho"] as? Bool {
            manifest.allowExtraMacho = allow
        }
        return manifest
    }

    // MARK: - 自身 __TEXT

    private static func textDigest() -> Data? {
        guard let header = _dyld_get_image_header(0) else { return nil }
        let base = UnsafeRawPointer(header)
        guard let text = segments(header).first(where: { $0.name == "__TEXT" }) else { return nil }
        // 从 __text section 开始，跳过 mach header + load commands：
        // 重签会在 load commands 里插 LC_CODE_SIGNATURE，那 16 KB 必然变化。
        guard let textSection = text.sections.first(where: { $0.name == "__text" }) else { return nil }
        guard textSection.addr >= text.vmaddr else { return nil }
        let start = textSection.addr - text.vmaddr
        guard start < text.filesize else { return nil }
        let count = Int(text.filesize - start)
        guard count > 0, count < 512_000_000 else { return nil }
        let data = Data(bytes: base.advanced(by: Int(start)), count: count)
        return Data(SHA256.hash(data: data))
    }

    private static func integrityPayload() -> Data? {
        guard let header = _dyld_get_image_header(0) else { return nil }
        let base = UnsafeRawPointer(header)
        let all = segments(header)
        guard let text = all.first(where: { $0.name == "__TEXT" }) else { return nil }
        for segment in all {
            for section in segment.sections where section.name == "__integrity" {
                guard section.addr >= text.vmaddr else { continue }
                let offset = section.addr - text.vmaddr
                guard offset < UInt64(1 << 32) else { continue }
                let pointer = base.advanced(by: Int(offset))
                return Data(bytes: pointer, count: Int(section.size))
            }
        }
        return nil
    }

    // MARK: - Bundle 全量校验

    /// 主二进制不参与逐文件比对：它的 `__TEXT` 由 textDigest 单独校验，
    /// 打包时也不会写进 manifest.files。这里必须显式跳过，否则会被
    /// "清单外的 Mach-O" 这条规则判成注入。
    private static var mainExecutableName: String {
        Bundle.main.executableURL?.lastPathComponent ?? ""
    }

    private static func verifyBundle(_ manifest: Manifest) -> Bool {
        let mainExe = mainExecutableName
        let root = Bundle.main.bundleURL
        guard let enumerator = FileManager.default.enumerator(
            at: root,
            includingPropertiesForKeys: [.isRegularFileKey],
            options: [.skipsHiddenFiles]
        ) else { return false }

        var actual: [String: (Bool, Data)] = [:]
        for case let url as URL in enumerator {
            var isDirectory: ObjCBool = false
            guard FileManager.default.fileExists(atPath: url.path, isDirectory: &isDirectory) else {
                return false
            }
            if isDirectory.boolValue { continue }
            // iOS 上 Bundle.main.bundleURL 可能是 /var/...，而枚举返回 /private/var/...
            // （/var 是指向 /private/var 的符号链接）。按路径前缀比较会全部失败，
            // 所以统一 resolve 符号链接后再按 pathComponents 比。
            guard let relative = relativePath(of: url, root: root) else {
                continue
            }
            if isSkipped(relative, manifest.skip) { continue }
            if relative == mainExe { continue }
            guard let hashed = hashFile(url) else {
                return false
            }
            actual[relative] = hashed
        }

        // 清单里每个文件都必须存在且哈希一致
        for expected in manifest.files {
            guard let got = actual[expected.path] else {
                return false
            }
            if got.0 != expected.isMachO || got.1 != expected.hash {
                return false
            }
        }
        // 清单外多出来的文件：非 Mach-O 一律放行（重签工具会塞 _CodeSignature 等）；
        // Mach-O 默认拒绝（注入 dylib），但 enterprise/sideload 包允许
        // —— 企业签平台必然往 Frameworks 里塞锁/统计库，拒绝就装不上。
        if !manifest.allowExtraMacho {
            for (key, value) in actual where !manifest.files.contains(where: { $0.path == key }) {
                if value.0 {
                    return false
                }
            }
        }
        return true
    }

    /// 相对 app 根目录的路径；符号链接（/var vs /private/var）已归一。
    private static func relativePath(of url: URL, root: URL) -> String? {
        let target = url.resolvingSymlinksInPath().pathComponents
        let base = root.resolvingSymlinksInPath().pathComponents
        guard target.count > base.count, Array(target.prefix(base.count)) == base else {
            return nil
        }
        return target.dropFirst(base.count).joined(separator: "/")
    }

    private static func isSkipped(_ relative: String, _ skip: [String]) -> Bool {
        for rule in skip {
            if relative == rule { return true }
            // 目录规则（以 / 结尾）在任意层级生效：Frameworks/x.framework/_CodeSignature/…
            if rule.hasSuffix("/") && relative.contains(rule) { return true }
            // "Info.plist" 指所有层级的 Info.plist：重签工具会把主 app 和每个 framework
            // 的 MinimumOSVersion 一起改，只豁免根目录那份是不够的。
            if rule == "Info.plist" && (relative == rule || relative.hasSuffix("/" + rule)) {
                return true
            }
        }
        return false
    }

    /// Mach-O 只对 __TEXT 段做哈希：重签名会改写 __LINKEDIT/LC_CODE_SIGNATURE，
    /// 但不会动 __TEXT，所以自签之后依然能通过校验。
    private static func hashFile(_ url: URL) -> (Bool, Data)? {
        guard let data = try? Data(contentsOf: url, options: .mappedIfSafe) else { return nil }
        if let machO = machOTextRange(data) {
            let slice = data.subdata(in: machO)
            return (true, Data(SHA256.hash(data: slice)))
        }
        return (false, Data(SHA256.hash(data: data)))
    }

    private static func machOTextRange(_ data: Data) -> Range<Int>? {
        guard data.count > 32 else { return nil }
        var magic: UInt32 = 0
        _ = withUnsafeMutableBytes(of: &magic) { data.copyBytes(to: $0, from: 0..<4) }
        switch magic {
        case 0xFEEDFACF:                 // MH_MAGIC_64（小端读出的值）
            return thinTextRange(data, offset: 0)
        case 0xBEBAFECA:                 // FAT_MAGIC（CA FE BA BE 小端读出的值）
            // FAT（big endian 头）：取第一个架构
            guard data.count > 8 else { return nil }
            var countBE: UInt32 = 0
            _ = withUnsafeMutableBytes(of: &countBE) { data.copyBytes(to: $0, from: 4..<8) }
            let count = Int(UInt32(bigEndian: countBE))
            guard count > 0 else { return nil }
            var archOffset = 8
            var offsetBE: UInt32 = 0
            _ = withUnsafeMutableBytes(of: &offsetBE) {
                data.copyBytes(to: $0, from: archOffset + 8..<archOffset + 12)
            }
            return thinTextRange(data, offset: Int(UInt32(bigEndian: offsetBE)))
        default:
            return nil
        }
    }

    private static func thinTextRange(_ data: Data, offset: Int) -> Range<Int>? {
        guard offset >= 0, offset + 32 <= data.count else { return nil }
        var ncmds: UInt32 = 0
        var sizeofcmds: UInt32 = 0
        _ = withUnsafeMutableBytes(of: &ncmds) { data.copyBytes(to: $0, from: offset + 16..<offset + 20) }
        _ = withUnsafeMutableBytes(of: &sizeofcmds) {
            data.copyBytes(to: $0, from: offset + 20..<offset + 24)
        }
        var cursor = offset + 32
        var remaining = Int(ncmds)
        let limit = min(data.count, offset + 32 + Int(sizeofcmds))
        while remaining > 0 && cursor + 8 <= limit {
            var cmd: UInt32 = 0
            var cmdsize: UInt32 = 0
            _ = withUnsafeMutableBytes(of: &cmd) { data.copyBytes(to: $0, from: cursor..<cursor + 4) }
            _ = withUnsafeMutableBytes(of: &cmdsize) {
                data.copyBytes(to: $0, from: cursor + 4..<cursor + 8)
            }
            if cmd == 0x19 && cursor + 72 <= limit {
                // LC_SEGMENT_64：只认 __TEXT，并且只从 __text section 开始算。
                // 不能从文件 0 开始：codesign 重签必须往 load commands 里插
                // LC_CODE_SIGNATURE，ncmds/sizeofcmds 会变，前 16 KB 就不同了。
                let segname = machOName(data, at: cursor + 8)
                if segname == "__TEXT" {
                    var fileoff: UInt64 = 0
                    var filesize: UInt64 = 0
                    var nsects: UInt32 = 0
                    _ = withUnsafeMutableBytes(of: &fileoff) {
                        data.copyBytes(to: $0, from: cursor + 40..<cursor + 48)
                    }
                    _ = withUnsafeMutableBytes(of: &filesize) {
                        data.copyBytes(to: $0, from: cursor + 48..<cursor + 56)
                    }
                    _ = withUnsafeMutableBytes(of: &nsects) {
                        data.copyBytes(to: $0, from: cursor + 64..<cursor + 68)
                    }
                    var section = cursor + 72
                    for _ in 0..<Int(nsects) {
                        if machOName(data, at: section) == "__text" {
                            var sectionOffset: UInt32 = 0
                            _ = withUnsafeMutableBytes(of: &sectionOffset) {
                                data.copyBytes(to: $0, from: section + 48..<section + 52)
                            }
                            let start = offset + Int(sectionOffset)
                            let end = offset + Int(fileoff + filesize)
                            guard start < end, end <= data.count else { return nil }
                            return start..<end
                        }
                        section += 80
                    }
                    return nil
                }
            }
            let step = Int(cmdsize)
            guard step > 0 else { return nil }
            cursor += step
            remaining -= 1
        }
        return nil
    }

    /// 读 Mach-O 里 16 字节定长名字（segname / sectname）
    private static func machOName(_ data: Data, at offset: Int, length: Int = 16) -> String {
        guard offset >= 0, offset + length <= data.count else { return "" }
        // 注意：这里必须直接从 Data 切片转数组。
        // 早先写成 withUnsafeMutableBytes(of: &array) —— 那拿到的是 Array 变量本身
        // （8 字节指针）而不是元素存储区，往里写 16 字节会踩坏栈，返回地址变成垃圾
        // （崩溃日志里 vmRegionInfo 是一个野地址就是这么来的）。
        let bytes = [UInt8](data[offset..<(offset + length)])
        let trimmed = bytes.prefix(while: { $0 != 0 })
        return String(decoding: trimmed, as: UTF8.self)
    }

    // MARK: - 反调试 / 反注入

    private static func isTraced() -> Bool {
        var info = kinfo_proc()
        var mib: [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid()]
        var size = MemoryLayout<kinfo_proc>.stride
        let result = mib.withUnsafeMutableBufferPointer { buffer in
            sysctl(buffer.baseAddress, 4, &info, &size, nil, 0)
        }
        guard result == 0 else { return false }
        return (info.kp_proc.p_flag & 0x0000_0800) != 0   // P_TRACED
    }

    private static func denyAttach() {
        // iOS SDK 的 Darwin 模块不导出 ptrace，运行时用 dlsym 从 libSystem 取。
        // PT_DENY_ATTACH = 31
        typealias PtraceFn = @convention(c) (
            CInt, Int32, UnsafeMutableRawPointer?, UnsafeMutableRawPointer?
        ) -> CInt
        guard let symbol = dlsym(UnsafeMutableRawPointer(bitPattern: -2), "ptrace") else { return }
        let call = unsafeBitCast(symbol, to: PtraceFn.self)
        _ = call(31, 0, nil, nil)
    }

    private static func hasInjectedEnvironment() -> Bool {
        let environment = ProcessInfo.processInfo.environment
        let keys = ["DYLD_INSERT_LIBRARIES", "DYLD_FRAMEWORK_PATH", "DYLD_LIBRARY_PATH"]
        for key in keys {
            if let value = environment[key], !value.isEmpty { return true }
        }
        return false
    }

    private static func hasSuspiciousImage() -> Bool {
        let needles = ["frida", "cycript", "substrate", "libhooker", "ellekit",
                       "sslkillswitch", "injector", "libblackjack"]
        let count = _dyld_image_count()
        for index in 0..<count {
            guard let name = _dyld_get_image_name(index) else { continue }
            let lowered = String(cString: name).lowercased()
            for needle in needles where lowered.contains(needle) {
                return true
            }
        }
        return false
    }

    // MARK: - 退出

    /// 校验不过就静默退出：不落盘、不弹窗、不留可供分析的文件。
    private static func die(_ reason: String) -> Never {
        note(reason, fatal: true)
        _exit(0)
        while true {}
    }

    /// 只写系统日志（设备上的 Console 可见，沙盒里不留任何文件）。
    private static func note(_ reason: String, fatal: Bool = false) {
        NSLog("[IG] %@%@", reason, fatal ? " (fatal)" : "")
    }



    // MARK: - 内存中的段表

    private struct SectionInfo {
        let name: String
        let addr: UInt64
        let size: UInt64
    }

    private struct SegmentInfo {
        let name: String
        let vmaddr: UInt64
        let filesize: UInt64
        let sections: [SectionInfo]
    }

    private static func segments(_ header: UnsafePointer<mach_header>) -> [SegmentInfo] {
        let base = UnsafeRawPointer(header)
        var result: [SegmentInfo] = []
        var cursor = base.advanced(by: 32)
        let count = Int(header.pointee.ncmds)
        for _ in 0..<count {
            let command = cursor.load(as: load_command.self)
            if command.cmd == 0x19 {
                let segment = cursor.load(as: segment_command_64.self)
                var sections: [SectionInfo] = []
                var sectionCursor = cursor.advanced(by: 72)
                for _ in 0..<Int(segment.nsects) {
                    let section = sectionCursor.load(as: section_64.self)
                    var rawName = section.sectname
                    let name = withUnsafeBytes(of: &rawName) { bytes -> String in
                        guard let address = bytes.baseAddress else { return "" }
                        return String(cString: address.assumingMemoryBound(to: CChar.self))
                    }
                    sections.append(SectionInfo(name: name, addr: section.addr, size: section.size))
                    sectionCursor = sectionCursor.advanced(by: 80)
                }
                var rawSegmentName = segment.segname
                let segmentName = withUnsafeBytes(of: &rawSegmentName) { bytes -> String in
                    guard let address = bytes.baseAddress else { return "" }
                    return String(cString: address.assumingMemoryBound(to: CChar.self))
                }
                result.append(SegmentInfo(
                    name: segmentName,
                    vmaddr: segment.vmaddr,
                    filesize: segment.filesize,
                    sections: sections
                ))
            }
            let step = Int(command.cmdsize)
            guard step > 0 else { break }
            cursor = cursor.advanced(by: step)
        }
        return result
    }
}
