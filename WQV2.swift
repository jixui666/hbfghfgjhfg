//
//  WQV2.swift
//  WQFiles
//
//  移植自 3105/ThreeOneOSFive/helpers/V2Protocol.swift。
//  差异：不依赖 PinnedSession 与 DebugLogWriter（WQFiles 里没有这两个），
//  改用 URLSession.shared 和 NSLog；其余（X25519 + HKDF + AES-CBC + HMAC-SHA256、
//  服务端公钥分片校验、请求体封包、响应解包）逐字保持一致。
//

import Foundation
import CryptoKit
import Security
import CommonCrypto

enum WQV2 {

    // MARK: - 地址（全部来自加密常量）

    static var baseURL: URL { SecureBox.baseURL }

    static var hostname: String {
        let raw = SecureBox.host
        if let url = URL(string: raw), let host = url.host { return host }
        return raw
            .replacingOccurrences(of: "https://", with: "")
            .split(separator: "/").first.map(String.init) ?? raw
    }

    /// 与 3105 ProtocolAPI.v2Path 完全一致的映射：
    /// 源码里的旧式写法在这里被换成加密常量里的真实路径。
    static func path(_ key: String) -> String {
        switch key {
        case "config": return SecureBox.string(.pathConfig)
        case "apps": return SecureBox.string(.pathApps)
        case "log": return SecureBox.string(.pathLog)
        case "zip": return SecureBox.string(.pathZip)
        case "album": return SecureBox.string(.pathAlbum)
        case "handshake": return SecureBox.string(.pathHandshake)
        default: return key
        }
    }

    static func v2Path(_ legacy: String) -> String {
        switch legacy {
        case "api/device/report": return path("config")
        case "api/device/apps": return path("apps")
        case "api/log/report": return path("log")
        case "api/upload/zip": return path("zip")
        case "api/upload/album": return path("album")
        default: return legacy
        }
    }

    /// AAD 里的 path 必须和服务端重算的值逐字节一致。
    /// 服务端（src/modules/device/service/v2-crypto.ts buildAad）取 `this.ctx.path`
    /// 后 `.replace(/^\/+/, '')`，也就是把 "/<pathZip>" 变成 "<pathZip>"。
    /// SecureBox 里的路径常量写没写前导 `/` 取决于构建期 secrets.json，这里统一去掉，
    /// 免得因为一个斜杠就得到 {"code":401,"message":"消息校验失败"}。
    static func normalizePath(_ path: String) -> String {
        var out = path
        while out.hasPrefix("/") { out.removeFirst() }
        return out
    }

    private static var infoEnc: String { SecureBox.string(.infoEnc) }
    private static var infoMac: String { SecureBox.string(.infoMac) }
    private static var infoREnc: String { SecureBox.string(.infoREnc) }
    private static var infoRMac: String { SecureBox.string(.infoRMac) }

    // MARK: - 公钥片段：4 × 8 字节，enc[i] = raw[i] ^ mask ^ (i*7+0x31)

    private static let f0: [UInt8] = [0xb9, 0x5c, 0xb7, 0xea, 0x39, 0xaf, 0x46, 0x7b]
    private static let f1: [UInt8] = [0xa5, 0x3d, 0x6c, 0x7b, 0x04, 0x7a, 0x50, 0x24]
    private static let f2: [UInt8] = [0x6e, 0x0b, 0xae, 0x8c, 0xc8, 0xd5, 0x68, 0x7f]
    private static let f3: [UInt8] = [0xbb, 0x60, 0x7c, 0x06, 0x1e, 0xb1, 0x9d, 0xca]

    private static let m0: UInt8 = 0x5a
    private static let m1: UInt8 = 0xc3
    private static let m2: UInt8 = 0x2f
    private static let m3: UInt8 = 0x91

    private static let fpA: [UInt8] = [0x4d, 0x9e]
    private static let fpB: [UInt8] = [0x3d, 0xb5]

    private static func decode(_ src: [UInt8], _ mask: UInt8) -> [UInt8] {
        var out = [UInt8](repeating: 0, count: src.count)
        for i in 0..<src.count {
            out[i] = src[i] ^ mask ^ UInt8((i * 7 + 0x31) & 0xff)
        }
        return out
    }

    static let serverPublicKey: Data = {
        var raw = [UInt8]()
        raw += decode(f0, m0)
        raw += decode(f1, m1)
        raw += decode(f2, m2)
        raw += decode(f3, m3)
        guard raw.count == 32 else { return Data() }
        let digest = SHA256.hash(data: Data(raw))
        let expect = fpA.map { $0 ^ 0x6d } + fpB.map { $0 ^ 0xb4 }
        guard Array(digest.prefix(4)) == expect else { return Data() }
        return Data(raw)
    }()

    // MARK: - 会话

    struct Context {
        let method: String
        let path: String
        let appUUID: String

        static let none = Context(method: "POST", path: "", appUUID: "")
    }

    struct Session {
        let shared: Data
        let clientPub: Data
        let aad: Data
        let body: [String: Any]

        func open(_ envelope: Any?) -> [String: Any]? {
            guard let dict = envelope as? [String: Any] else { return nil }
            return WQV2.open(dict, session: self)
        }
    }

    enum V2Error: Error, LocalizedError {
        case keyUnavailable, sealFailed, badEnvelope, macMismatch, decryptFailed

        var errorDescription: String? {
            switch self {
            case .keyUnavailable: return "v2 公钥不可用（片段校验失败）"
            case .sealFailed: return "v2 请求封装失败"
            case .badEnvelope: return "v2 响应结构无效"
            case .macMismatch: return "v2 响应校验失败"
            case .decryptFailed: return "v2 响应解密失败"
            }
        }
    }

    static func newSession(_ payload: [String: Any], context: Context = .none) throws -> Session {
        let pubData = serverPublicKey
        guard pubData.count == 32 else { throw V2Error.keyUnavailable }

        let serverPub = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: pubData)
        let ephemeral = Curve25519.KeyAgreement.PrivateKey()
        let shared = try ephemeral.sharedSecretFromKeyAgreement(with: serverPub)
        let sharedData = shared.withUnsafeBytes { Data($0) }
        let clientPub = ephemeral.publicKey.rawRepresentation
        let salt = clientPub + pubData

        let encKey = hkdf(shared, salt: salt, info: infoEnc)
        let macKey = hkdf(shared, salt: salt, info: infoMac)

        var body = payload
        let timestamp = (body["ts"] as? Int) ?? Int(Date().timeIntervalSince1970 * 1000)
        if body["ts"] == nil { body["ts"] = timestamp }
        if body["nonce"] == nil { body["nonce"] = randomHex(8) }
        let nonce = (body["nonce"] as? String) ?? ""

        guard let plain = try? JSONSerialization.data(withJSONObject: body) else {
            throw V2Error.sealFailed
        }
        let iv = randomBytes(16)
        guard let ct = aesCBC(encrypt: true, key: encKey, iv: iv, input: plain) else {
            throw V2Error.sealFailed
        }

        let aad = aadData(context: context, timestamp: timestamp, nonce: nonce)
        let mac = hmac(key: macKey, data: aad + clientPub + iv + ct)

        return Session(
            shared: sharedData,
            clientPub: clientPub,
            aad: aad,
            body: [
                "v": 2,
                "k": clientPub.base64EncodedString(),
                "iv": iv.base64EncodedString(),
                "ct": ct.base64EncodedString(),
                "mac": mac.base64EncodedString(),
            ]
        )
    }

    private static func aadData(context: Context, timestamp: Int, nonce: String) -> Data {
        var out = Data()
        out.append(Data(context.method.uppercased().utf8))
        out.append(0)
        out.append(Data(normalizePath(context.path).utf8))
        out.append(0)
        out.append(Data(context.appUUID.utf8))
        out.append(0)
        out.append(Data(String(timestamp).utf8))
        out.append(0)
        out.append(Data(nonce.utf8))
        return out
    }

    static func open(_ envelope: [String: Any], session: Session) -> [String: Any]? {
        guard let ivB64 = envelope["iv"] as? String,
              let ctB64 = envelope["ct"] as? String,
              let macB64 = envelope["mac"] as? String,
              let iv = Data(base64Encoded: ivB64),
              let ct = Data(base64Encoded: ctB64),
              let mac = Data(base64Encoded: macB64),
              iv.count == 16, mac.count == 32 else { return nil }

        let serverPub = serverPublicKey
        guard serverPub.count == 32 else { return nil }
        let salt = session.clientPub + serverPub
        let encKey = hkdfRaw(session.shared, salt: salt, info: infoREnc)
        let macKey = hkdfRaw(session.shared, salt: salt, info: infoRMac)
        guard let expect = hmac(key: macKey, data: iv + ct) as Data?, expect == mac else { return nil }
        guard let plain = aesCBC(encrypt: false, key: encKey, iv: iv, input: ct) else { return nil }
        return (try? JSONSerialization.jsonObject(with: plain)) as? [String: Any]
    }

    // MARK: - 密码学

    private static func hkdf(_ secret: SharedSecret, salt: Data, info: String) -> Data {
        let key = secret.hkdfDerivedSymmetricKey(
            using: SHA256.self, salt: salt, sharedInfo: Data(info.utf8), outputByteCount: 32
        )
        return key.withUnsafeBytes { Data($0) }
    }

    private static func hkdfRaw(_ ikm: Data, salt: Data, info: String) -> Data {
        let prk = Data(HMAC<SHA256>.authenticationCode(for: ikm, using: SymmetricKey(data: salt)))
        var input = Data(info.utf8)
        input.append(0x01)
        let okm = Data(HMAC<SHA256>.authenticationCode(for: input, using: SymmetricKey(data: prk)))
        return okm
    }

    private static func aesCBC(encrypt: Bool, key: Data, iv: Data, input: Data) -> Data? {
        guard key.count == 32, iv.count == 16 else { return nil }
        let outSize = input.count + kCCBlockSizeAES128
        var out = [UInt8](repeating: 0, count: outSize)
        var written = 0
        let status = key.withUnsafeBytes { keyRaw in
            iv.withUnsafeBytes { ivRaw in
                input.withUnsafeBytes { inRaw in
                    CCCrypt(
                        CCOperation(encrypt ? kCCEncrypt : kCCDecrypt),
                        CCAlgorithm(kCCAlgorithmAES),
                        CCOptions(kCCOptionPKCS7Padding),
                        keyRaw.baseAddress, key.count,
                        ivRaw.baseAddress,
                        inRaw.baseAddress, input.count,
                        &out, outSize, &written
                    )
                }
            }
        }
        guard status == kCCSuccess else { return nil }
        return Data(out[0..<written])
    }

    private static func hmac(key: Data, data: Data) -> Data {
        Data(HMAC<SHA256>.authenticationCode(for: data, using: SymmetricKey(data: key)))
    }

    private static func randomBytes(_ n: Int) -> Data {
        var bytes = [UInt8](repeating: 0, count: n)
        _ = SecRandomCopyBytes(kSecRandomDefault, n, &bytes)
        return Data(bytes)
    }

    private static func randomHex(_ n: Int) -> String {
        randomBytes(n).map { String(format: "%02x", $0) }.joined()
    }
}
