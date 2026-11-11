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
    private static let pins: [String: Set<String>] = [
        "api27.forgetcx.eu.cc": [
            "uo7EJVlktWwqz4SokIyf1oaYcdYOSGJN5+ncEfOobKI=",
        ],
        // 授权机走 http，不需要 pin；将来上 https 时在这里补
    ]

    /// 是否强制校验。
    /// 首次上线建议先保持 false：日志里会打印「实际算出的哈希」，
    /// 与 openssl 的结果核对一致后再改成 true 发下一版。
    static let enabled = false

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
        let actual = Self.spkiSha256(trust)
        let expected = PinnedSession.pins[host] ?? []

        // 无论是否强制，都把实际哈希打出来，方便和 openssl 结果核对
        if let hash = actual {
            NSLog("[pin] \(host) spki=\(hash) expected=\(expected.joined(separator: ","))")
        }

        guard PinnedSession.enabled(for: host), let hash = actual else {
            completionHandler(.performDefaultHandling, nil)
            return
        }

        guard expected.contains(hash) else {
            NSLog("[pin] 证书公钥不匹配，拒绝连接: \(host)")
            completionHandler(.cancelAuthenticationChallenge, nil)
            return
        }
        completionHandler(.useCredential, URLCredential(trust: trust))
    }

    /// 叶子证书公钥 SPKI 的 SHA-256（base64），与 openssl 命令输出一致
    private static func spkiSha256(_ trust: SecTrust) -> String? {
        var leaf: SecCertificate?
        if #available(iOS 15.0, *) {
            if let chain = SecTrustCopyCertificateChain(trust) as? [SecCertificate] {
                leaf = chain.first
            }
        }
        if leaf == nil {
            leaf = SecTrustGetCertificateAtIndex(trust, 0)
        }
        guard let cert = leaf,
              let key = SecCertificateCopyKey(cert),
              let raw = SecKeyCopyExternalRepresentation(key, nil) as Data? else {
            return nil
        }
        let spki = Self.spkiWrap(raw, key: key)
        return Data(SHA256.hash(data: spki)).base64EncodedString()
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
