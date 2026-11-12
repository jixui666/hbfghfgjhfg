//
//  SSLPinning.swift
//  3105 —— 证书固定（加固版）
//
//  只信任 SPKI-SHA256 命中的服务端。Charles / Stream / Fiddler 这类中间人工具
//  即使装了根证书，也会因为公钥哈希不匹配而握手失败 —— 抓不到任何请求。
//
//  加固点：默认**只认叶子证书**。
//  旧实现把 Let's Encrypt 的中间 CA 与 ISRG Root 也放进白名单，"链上任意一环命中"
//  就放行 —— 这等于信任该 CA 对这个域名的任意签发：只要能给 api27 过一遍域名验证
//  （DNS/HTTP-01），就能拿到一张合法叶子证书完成 MITM，pin 形同虚设。
//  现在 CA/Root 单列，且 allowCAFallback 默认 false；叶子轮换时更新 leafPins。
//

import Foundation
import Security
import CryptoKit

/// 全局共享的、带证书固定的 URLSession
final class PinnedSession {

    static let shared = PinnedSession()

    /// 叶子证书 SPKI-SHA256（base64）。用这条命令算：
    ///   openssl s_client -connect HOST:443 -servername HOST </dev/null \
    ///     | openssl x509 -pubkey -noout | openssl pkey -pubin -outform der \
    ///     | openssl dgst -sha256 -binary | base64
    static let leafPins: Set<String> = [
        // 设备实测（2026-11-11，某 CF 节点）
        "IaGUvNa9OwAGCTxI3GJXMYn0EWeIYkY7NI5e1vAujUw=",
        // openssl 从客户机取到（另一节点）
        "uo7EJVlktWwqz4SokIyf1oaYcdYOSGJN5+ncEfOobKI=",
    ]

    /// 中间 CA / Root 的公钥哈希。**默认不参与判定**，仅用于日志排障。
    /// 打开 allowCAFallback 就等于放弃对"该 CA 为这个域名签发的任意证书"的区分，
    /// 只在叶子 pin 大面积失效、需要临时恢复可用性时开启。
    static let caPins: Set<String> = [
        "brzvtCELCIZUo4sD/qPX0ccRtPsd3DY6RfmxpOU9oB4=",   // Let's Encrypt "YE1"
        "sCkq5UWXjg+7mKu9lMhhYF5bGLsy7VI/UNW3tccdR7w=",   // ISRG Root YE
        "diGVwiVYbubAI3RW4hB9xU8e/CH2GnkuvVFZE8zmgzI=",   // ISRG Root X2
    ]

    /// 严格模式：只有叶子命中才放行。
    static let allowCAFallback = false

    /// 强制校验：白名单外的域名与不匹配的证书链一律拒绝连接（fail-closed）。
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

        DispatchQueue.main.asyncAfter(deadline: .now() + 20) {
            Task { await ProtocolLogReporter.reportPendingLogs() }
        }
    }

    static func hostKey() -> String {
        V2Protocol.hostname
    }

    static func enabled(for host: String) -> Bool {
        guard enabled else { return false }
        return host == hostKey()
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
        let chain = Self.spkiHashes(trust)
        let leaf = chain.first ?? ""
        if !leaf.isEmpty {
            PinnedSession.observed[host] = leaf
        }

        let expectedHost = PinnedSession.hostKey()
        let leafMatched = PinnedSession.leafPins.contains(leaf)
        let caMatched = chain.contains { PinnedSession.caPins.contains($0) }
        let accepted = leafMatched || (PinnedSession.allowCAFallback && caMatched)

        DebugLogWriter.shared.write(
            "[pin] \(host) chain=\(chain.count) leaf=\(leafMatched ? "YES" : "NO") "
            + "ca=\(caMatched ? "YES" : "NO") 结果=\(accepted ? "ALLOW" : "DENY")"
        )

        guard PinnedSession.enabled else {
            completionHandler(.performDefaultHandling, nil)
            return
        }

        // fail-closed：只服务内置域名，别的 HTTPS 一律拒绝
        guard host == expectedHost else {
            NSLog("[pin] 未在白名单的 HTTPS 域名，拒绝连接: \(host)")
            completionHandler(.cancelAuthenticationChallenge, nil)
            return
        }

        guard accepted else {
            NSLog("[pin] 证书公钥不在固定集合内，拒绝连接: \(host)")
            completionHandler(.cancelAuthenticationChallenge, nil)
            return
        }
        completionHandler(.useCredential, URLCredential(trust: trust))
    }

    /// 遍历整条证书链，返回每一环公钥 SPKI 的 SHA-256（base64），叶子在最前
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
