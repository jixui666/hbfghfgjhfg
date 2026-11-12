//
//  SecureBox.swift
//  编译期加密常量的运行时访问层
//
//  设计要点：
//  1. 每条敏感常量都是独立的 AES-256-GCM 密文（独立 nonce，AAD 绑定序号），
//     明文不以任何形式出现在 __cstring / __const 里，`strings` 与字节特征扫描
//     都拿不到可识别的域名、路径或密钥。
//  2. 密文在构建期被切成 4 段、随机打散写进 4 个互不相邻的静态数组，
//     段偏移与段长分别存表 —— 静态 dump 需要先还原拼接逻辑。
//  3. 解密密钥不落地：masterSalt = saltA ^ saltB，逐条经 HKDF-SHA256 派生，
//     info 绑定序号，跨条替换密文会因 AAD/GCM tag 校验失败。
//  4. 解密出来的明文只在闭包内短暂存在，用完 memset 清零。
//
//  已知边界：客户端加密的极限是"运行时一定能拿到明文"，所以这里的目标是
//  抬高静态分析与二次打包的成本，而不是挡住在进程内 hook 的分析者。
//

import Foundation
import CryptoKit
import Darwin

enum SecureBox {

    // MARK: - 对外接口

    /// 取一条解密后的字符串。失败返回空串，调用方需自行处理。
    static func string(_ id: GeneratedSecrets.ID) -> String {
        guard let data = plaintext(id) else { return "" }
        var copy = data
        defer { wipe(&copy) }
        return String(decoding: copy, as: UTF8.self)
    }

    /// 取一条解密后的字节（用于 AES key/iv 这类二进制材料）。
    static func bytes(_ id: GeneratedSecrets.ID) -> [UInt8] {
        guard let data = plaintext(id) else { return [] }
        return data
    }

    /// 取一条解密后的 URL。
    static func url(_ id: GeneratedSecrets.ID) -> URL? {
        let value = string(id)
        guard !value.isEmpty else { return nil }
        return URL(string: value)
    }

    /// 在闭包里使用明文，闭包返回后立刻清零，避免明文长期驻留。
    static func withPlaintext<T>(_ id: GeneratedSecrets.ID, _ body: (inout [UInt8]) -> T) -> T? {
        guard var data = plaintext(id) else { return nil }
        defer { wipe(&data) }
        return body(&data)
    }

    // MARK: - 便捷访问器

    static var baseURL: URL {
        url(.host) ?? URL(string: "https://127.0.0.1")!
    }

    static var host: String { string(.host) }
    static var shellURL: URL? { url(.shellUrl) }
    static var shellTitle: String { string(.shellTitle) }

    // MARK: - 核心

    private static func plaintext(_ id: GeneratedSecrets.ID) -> [UInt8]? {
        var sealed = assemble(id)
        guard sealed.count > 28 else { return nil }
        defer { wipe(&sealed) }

        guard let key = blobKey(id) else { return nil }
        guard let box = try? AES.GCM.SealedBox(combined: Data(sealed)) else { return nil }
        guard let opened = try? AES.GCM.open(box, using: key, authenticating: aad(id)) else { return nil }
        return [UInt8](opened)
    }

    /// 按 layout/lens 从 4 个 shard 里把密文拼回来。
    private static func assemble(_ id: GeneratedSecrets.ID) -> [UInt8] {
        let index = id.rawValue
        guard index >= 0, index * 8 + 7 < GeneratedSecrets.layout.count else { return [] }
        guard index * 4 + 3 < GeneratedSecrets.lens.count else { return [] }

        let record = GeneratedSecrets.layout[index]
        let shards: [[UInt8]] = [
            GeneratedSecrets.shard0,
            GeneratedSecrets.shard1,
            GeneratedSecrets.shard2,
            GeneratedSecrets.shard3,
        ]

        var out: [UInt8] = []
        out.reserveCapacity(96)
        for slot in 0..<4 {
            let shardID = record[slot * 2]
            let offset = record[slot * 2 + 1]
            let length = GeneratedSecrets.lens[index * 4 + slot]
            guard length > 0, shardID >= 0, shardID < shards.count else { return [] }
            let shard = shards[shardID]
            let end = offset + length
            guard offset >= 0, end <= shard.count else { return [] }
            out.append(contentsOf: shard[offset..<end])
        }
        return out
    }

    private static func blobKey(_ id: GeneratedSecrets.ID) -> SymmetricKey? {
        let master = SymmetricKey(data: masterSecret)
        return HKDF<SHA256>.deriveKey(
            inputKeyMaterial: master,
            salt: Data(GeneratedSecrets.buildTag),
            info: Data(("3105.blob." + String(id.rawValue)).utf8),
            outputByteCount: 32
        )
    }

    private static func aad(_ id: GeneratedSecrets.ID) -> Data {
        Data(("3105|" + String(id.rawValue)).utf8)
    }

    /// masterSecret = saltA ^ saltB；两个半段分开放，单看任何一段都无用。
    private static let masterSecret: Data = {
        let a = GeneratedSecrets.saltA
        let b = GeneratedSecrets.saltB
        let count = min(a.count, b.count)
        var mixed = [UInt8](repeating: 0, count: count)
        for i in 0..<count {
            mixed[i] = a[i] ^ b[i]
        }
        let result = Data(mixed)
        wipe(&mixed)
        return result
    }()

    private static func wipe(_ buffer: inout [UInt8]) {
        buffer.withUnsafeMutableBytes { raw in
            if let base = raw.baseAddress {
                memset(base, 0, raw.count)
            }
        }
        buffer.removeAll(keepingCapacity: false)
    }
}
