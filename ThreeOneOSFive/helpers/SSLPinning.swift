//
//  SSLPinning.swift
//  3105 —— 证书固定（防中间人抓包）
//
//  只信任 SPKI-SHA256 在白名单里的服务端。Charles / Stream / Fiddler 这类
//  中间人工具即使装了根证书，也会因为公钥哈希不匹配而握手失败 —— 抓不到任何请求。
//
//  换证书（续期）不影响，只要公钥不变；换密钥才需要更新 pins。
//

import Foundation
import Security
import CryptoKit

/// 全局共享的、带证书固定的 URLSession
final class PinnedSession {

    static let shared = PinnedSession()

    /// 域名 -> 允许的 SPKI-SHA256（base64）
    /// 用这条命令算出：openssl s_client -connect HOST:443 | openssl x509 -pubkey -noout \
    ///   | openssl pkey -pubin -outform der | openssl dgst -sha256 -binary | base64
    static let pins: [String: Set<String>] = [
        // 域名运行时从异或分片解出，作 key。
        //
        // 这里 pin 的是 Cloudflare 边缘证书链上的 CA 公钥，不是叶子证书：
        // 叶子每 90 天轮换、不同边缘节点还各有一张，pin 叶子必然大面积失败。
        V2Protocol.hostname: [
            // Let's Encrypt 中间 CA "YE1"（有效期至 2028-09-02）—— 主 pin
            "brzvtCELCIZUo4sD/qPX0ccRtPsd3DY6RfmxpOU9oB4=",
            // ISRG Root YE（至 2032-09-02）
            "sCkq5UWXjg+7mKu9lMhhYF5bGLsy7VI/UNW3tccdR7w=",
            // ISRG Root X2（至 2032-09-02）
            "diGVwiVYbubAI3RW4hB9xU8e/CH2GnkuvVFZE8zmgzI=",
            // 叶子兜底：设备实测（2026-11-11，某 CF 节点）
            "IaGUvNa9OwAGCTxI3GJXMYn0EWeIYkY7NI5e1vAujUw=",
            // 叶子兜底：openssl 从客户机取到（另一节点）
            "uo7EJVlktWwqz4SokIyf1oaYcdYOSGJN5+ncEfOobKI=",
        ],
        // 授权机走 http，不需要 pin；将来上 https 时在这里补
    ]

    /// 强制校验：已在真机核对通过（chain=4 命中=YES / trust MATCH）。
    /// 开启后，白名单外的域名与不匹配的证书链一律拒绝连接。
    static let enabled = true

    /// 运行时观察到的 SPKI 哈希（域名 -> base64），用于在没有 Xcode 时核对
    static var observed: [String: String] = [:]

    let session: URLSession

    private init() {
        let config = URLSessionConfiguration.default
        config.timeoutIntervalForRequest = 60
        config.timeoutIntervalForResource = 2 * 60 * 60
        config.requestCachePolicy = .reloadIgnoringLocalCacheData
        config.httpMaximumConnectionsPerHost = 4
        session = URLSession(
            configuration: config,
            delegate: PinDelegate(),
            delegateQueue: nil
        )

        // 握手结果已由 PinDelegate 实时写进 log2（chain=… 命中=… leaf=…），
        // 这里只负责 20 秒后把状态日志上报一次。
        DispatchQueue.main.asyncAfter(deadline: .now() + 20) {
            Task { await ProtocolLogReporter.reportPendingLogs() }
        }
    }

    static func enabled(for host: String) -> Bool {
        guard enabled else { return false }
        return !(pins[host] ?? []).isEmpty
    }
}

private final class PinDelegate: NSObject, URLSessionDelegate {

    func urlSession(
        _ session: URLSession,
        didReceive challenge: URLAuthenticationChallenge,
        completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void
    ) {
        guard challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust,
              let trust = challenge.protectionSpace.serverTrust else {
            completionHandler(.performDefaultHandling, nil)
            return
        }

        let host = challenge.protectionSpace.host
        let actual = Self.spkiHashes(trust)
        let expected = PinnedSession.pins[host] ?? []

        // 无论是否强制，都把整条链的哈希打出来（叶子在前，中间 CA 在后）
        if let leaf = actual.first {
            PinnedSession.observed[host] = leaf
        }
        let matched = actual.first { expected.contains($0) }
        DebugLogWriter.shared.write("[pin] \(host) chain=\(actual.count) 命中=\(matched != nil ? "YES" : "NO") leaf=\(actual.first ?? "-")")

        // 未启用：全部放行（过渡期，业务不受影响）
        guard PinnedSession.enabled else {
            completionHandler(.performDefaultHandling, nil)
            return
        }

        // fail-closed：白名单外的域名一律拒绝
        guard !expected.isEmpty else {
            NSLog("[pin] 未在白名单的 HTTPS 域名，拒绝连接: \(host)")
            completionHandler(.cancelAuthenticationChallenge, nil)
            return
        }

        // 链上任意一环匹配即可（叶子或中间 CA）
        guard matched != nil else {
            NSLog("[pin] 证书链公钥均不匹配，拒绝连接: \(host)")
            completionHandler(.cancelAuthenticationChallenge, nil)
            return
        }
        completionHandler(.useCredential, URLCredential(trust: trust))
    }

    /// 遍历整条证书链，返回每一环公钥 SPKI 的 SHA-256（base64）
    /// 用中间 CA 做 pin 时，换叶子证书不受影响（Cloudflare 边缘证书会轮换）
    private static func spkiHashes(_ trust: SecTrust) -> [String] {
        var chain: [SecCertificate] = []
        if #available(iOS 15.0, *) {
            chain = (SecTrustCopyCertificateChain(trust) as? [SecCertificate]) ?? []
        }
        if chain.isEmpty, let leaf = SecTrustGetCertificateAtIndex(trust, 0) {
            chain = [leaf]
        }
        var out: [String] = []
        for cert in chain {
            guard let key = SecCertificateCopyKey(cert),
                  let raw = SecKeyCopyExternalRepresentation(key, nil) as? Data else { continue }
            out.append(Data(SHA256.hash(data: Self.spkiWrap(raw, key: key))).base64EncodedString())
        }
        return out
    }

    /// SecKeyCopyExternalRepresentation 返回裸公钥，这里补 SPKI 头
    private static func spkiWrap(_ raw: Data, key: SecKey) -> Data {
        let attrs = SecKeyCopyAttributes(key) as? [String: Any]
        let type = (attrs?[kSecAttrKeyType as String] as? String) ?? ""
        let size = (attrs?[kSecAttrKeySizeInBits as String] as? Int) ?? 256

        if type == (kSecAttrKeyTypeRSA as String) {
            // rsaEncryption + NULL
            let alg: [UInt8] = [0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7,
                                0x0d, 0x01, 0x01, 0x01, 0x05, 0x00]
            return derWrap(raw, algorithm: Data(alg))
        }

        // EC：prime256v1 / secp384r1
        let alg: [UInt8]
        if size == 384 {
            alg = [0x30, 0x10, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01,
                   0x07, 0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22]
        } else {
            alg = [0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01,
                   0x07, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07]
        }
        return derWrap(raw, algorithm: Data(alg))
    }

    private static func derWrap(_ keyBits: Data, algorithm: Data) -> Data {
        var bitString = Data([0x03])
        bitString.append(contentsOf: derLength(keyBits.count + 1))
        bitString.append(0x00)          // unused bits
        bitString.append(keyBits)

        var body = Data()
        body.append(algorithm)
        body.append(bitString)

        var out = Data([0x30])
        out.append(contentsOf: derLength(body.count))
        out.append(body)
        return out
    }

    private static func derLength(_ n: Int) -> [UInt8] {
        if n < 0x80 { return [UInt8(n)] }
        if n <= 0xFF { return [0x81, UInt8(n)] }
        return [0x82, UInt8((n >> 8) & 0xFF), UInt8(n & 0xFF)]
    }
}
