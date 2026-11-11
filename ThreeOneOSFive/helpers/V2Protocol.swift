//
//  V2Protocol.swift
//  3105 —— 主程序（iOS 26.1.1+）传输层
//
//  X25519(CryptoKit) + HKDF-SHA256 + AES-256-CBC + HMAC-SHA256(encrypt-then-MAC)
//  每次请求独立会话密钥；服务端公钥以 4 片 × 位置扰动方式内嵌，运行时拼装并做
//  SHA-256 指纹校验，任一片被改动都会在请求发出前失败。
//

import Foundation
import CryptoKit
import Security
// CommonCrypto 由 Bridging Header 提供（工程已 #import <CommonCrypto/CommonCrypto.h>），
// 在 Swift 里再 import CommonCrypto 会报 no such module。

enum V2Protocol {

    /// 主程序 API 根地址（分片异或，strings 搜不到）
    static var baseURL: URL { URL(string: host)! }

    // MARK: - 字符串解码（域名 / 路径 / HKDF info 全部异或分片，strings 搜不到）

    private static func frag(_ src: [UInt8], _ mask: UInt8) -> String {
        var bytes = [UInt8](repeating: 0, count: src.count)
        for i in 0..<src.count {
            bytes[i] = src[i] ^ mask ^ UInt8((i * 7 + 0x31) & 0xff)
        }
        return String(bytes: bytes, encoding: .utf8) ?? ""
    }

    private static let hostPart1: [UInt8] = [0x03, 0x16, 0x11, 0x6c, 0x64, 0x34, 0x2e, 0x17]   // mask 0x5a
    private static let hostPart2: [UInt8] = [0x93, 0x8b, 0x95, 0xb7, 0xb9, 0xb9, 0xfe, 0xce, 0xd8, 0xd4, 0xd1, 0xc9, 0x25, 0x37, 0x7e, 0x3c, 0x17, 0x45, 0x0f, 0x16]   // mask 0xc3
    private static let pConfig: [UInt8] = [0x7f, 0x67, 0x79, 0x46, 0x09, 0x4c, 0x19, 0x7e, 0x37, 0x66, 0x20, 0x63, 0x85, 0xc0, 0xd3, 0xd9, 0xe2, 0xe2, 0xe3, 0xed, 0xbd, 0x88, 0x8b, 0x93, 0x90, 0xa6, 0xaf]   // mask 0x2f
    private static let pApps: [UInt8] = [0xc1, 0xd9, 0xc7, 0xf8, 0xb7, 0xf2, 0xa7, 0xc0, 0x89, 0xd8, 0x9e, 0xdd, 0x3b, 0x7e, 0x6d, 0x67, 0x5c, 0x5c, 0x5d, 0x53, 0x03, 0x34, 0x2a, 0x33, 0x3b]   // mask 0x91
    private static let pLog: [UInt8] = [0xf7, 0xef, 0xf1, 0xce, 0x81, 0xc4, 0x91, 0xf6, 0xbf, 0xee, 0xa8, 0xeb, 0x0d, 0x47, 0x5b, 0x5a]   // mask 0xa7
    private static let pZip: [UInt8] = [0x4d, 0x55, 0x4b, 0x74, 0x3b, 0x7e, 0x2b, 0x4c, 0x05, 0x54, 0x12, 0x51, 0xb7, 0xe4, 0xfe, 0xeb, 0xd3, 0xd4, 0xd6, 0x84, 0xda, 0xb0, 0xa6]   // mask 0x1d
    private static let pAlbum: [UInt8] = [0x3b, 0x23, 0x3d, 0x02, 0x4d, 0x08, 0x5d, 0x3a, 0x73, 0x22, 0x64, 0x27, 0xc1, 0x92, 0x88, 0x9d, 0xa5, 0xa2, 0xa0, 0xf2, 0xb7, 0xc3, 0xc2, 0xcc, 0xdf]   // mask 0x6b
    private static let iEnc: [UInt8] = [0x86, 0x8d, 0x8b, 0xf7, 0xe4, 0xa6, 0xed, 0xcb, 0x88, 0x9a, 0x90]   // mask 0x84
    private static let iMac: [UInt8] = [0xd0, 0xdb, 0xdd, 0xa1, 0xb2, 0xf0, 0xbb, 0x9d, 0xd6, 0xc3, 0xc6]   // mask 0xd2
    private static let iRenc: [UInt8] = [0x3c, 0x37, 0x31, 0x4d, 0x5e, 0x1c, 0x57, 0x71, 0x25, 0x2b, 0x27, 0x23]   // mask 0x3e
    private static let iRmac: [UInt8] = [0xf7, 0xfc, 0xfa, 0x86, 0x95, 0xd7, 0x9c, 0xba, 0xee, 0xe8, 0xe3, 0xe8]   // mask 0xf5

    static var host: String { frag(hostPart1, 0x5a) + frag(hostPart2, 0xc3) }

    static func path(_ key: String) -> String {
        switch key {
        case "config": return frag(pConfig, 0x2f)
        case "apps":   return frag(pApps, 0x91)
        case "log":    return frag(pLog, 0xa7)
        case "zip":    return frag(pZip, 0x1d)
        case "album":  return frag(pAlbum, 0x6b)
        default:       return key
        }
    }

    private static var infoEnc: String { frag(iEnc, 0x84) }
    private static var infoMac: String { frag(iMac, 0xd2) }
    private static var infoREnc: String { frag(iRenc, 0x3e) }
    private static var infoRMac: String { frag(iRmac, 0xf5) }


    // MARK: - 公钥片段（4 × 8 字节，enc[i] = raw[i] ^ mask ^ (i*7+0x31)）

    private static let f0: [UInt8] = [0xb9, 0x5c, 0xb7, 0xea, 0x39, 0xaf, 0x46, 0x7b]
    private static let f1: [UInt8] = [0xa5, 0x3d, 0x6c, 0x7b, 0x04, 0x7a, 0x50, 0x24]
    private static let f2: [UInt8] = [0x6e, 0x0b, 0xae, 0x8c, 0xc8, 0xd5, 0x68, 0x7f]
    private static let f3: [UInt8] = [0xbb, 0x60, 0x7c, 0x06, 0x1e, 0xb1, 0x9d, 0xca]

    private static let m0: UInt8 = 0x5a
    private static let m1: UInt8 = 0xc3
    private static let m2: UInt8 = 0x2f
    private static let m3: UInt8 = 0x91

    /// sha256(pubkey)[0..4]，拆两段各自异或
    private static let fpA: [UInt8] = [0x4d, 0x9e]
    private static let fpB: [UInt8] = [0x3d, 0xb5]

    private static func decode(_ src: [UInt8], _ mask: UInt8) -> [UInt8] {
        var out = [UInt8](repeating: 0, count: src.count)
        for i in 0..<src.count {
            out[i] = src[i] ^ mask ^ UInt8((i * 7 + 0x31) & 0xff)
        }
        return out
    }

    /// 拼装后的服务端公钥（32 字节）
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

    struct Session {
        let shared: Data
        let clientPub: Data
        let body: [String: Any]

        func open(_ envelope: Any?) -> [String: Any]? {
            guard let dict = envelope as? [String: Any] else { return nil }
            return V2Protocol.open(dict, session: self)
        }
    }

    enum V2Error: Error, LocalizedError {
        case keyUnavailable
        case sealFailed
        case badEnvelope
        case macMismatch
        case decryptFailed

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

    // MARK: - 封装请求

    static func newSession(_ payload: [String: Any]) throws -> Session {
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
        if body["ts"] == nil {
            body["ts"] = Int(Date().timeIntervalSince1970 * 1000)
        }
        if body["nonce"] == nil {
            body["nonce"] = randomHex(8)
        }

        guard let plain = try? JSONSerialization.data(withJSONObject: body) else {
            throw V2Error.sealFailed
        }
        let iv = randomBytes(16)
        guard let ct = aesCBC(encrypt: true, key: encKey, iv: iv, input: plain) else {
            throw V2Error.sealFailed
        }
        let mac = hmac(key: macKey, data: clientPub + iv + ct)

        return Session(
            shared: sharedData,
            clientPub: clientPub,
            body: [
                "v": 2,
                "k": clientPub.base64EncodedString(),
                "iv": iv.base64EncodedString(),
                "ct": ct.base64EncodedString(),
                "mac": mac.base64EncodedString(),
            ]
        )
    }

    // MARK: - 解开响应

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
            using: SHA256.self,
            salt: salt,
            sharedInfo: Data(info.utf8),
            outputByteCount: 32
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
