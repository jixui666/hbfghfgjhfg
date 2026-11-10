import Foundation
import CommonCrypto

/// Single place for every protocol key the app uses.
///
/// Why this file exists: the three keys used to live inline next to the code that
/// consumed them (`ProtocolCrypto`, `LocalLinkProvider`, `ShellConfigProvider`),
/// which made a rotation a three-file edit and left the old material in git
/// history. Everything now comes from here, so rotating means regenerating this
/// one file (and re-encrypting `links.txt` / `shell.txt`, see
/// `tools/rotate_keys.py`).
///
/// Note on the bundled `apptrace.framework`: its link key is not a string — it is
/// assembled at runtime from obfuscated immediates and consumed by `CCCrypt`
/// (see `_apptrace_fns.txt`), so it cannot follow a rotation without patching the
/// Mach-O. `LegacyTraceGate.useLegacyBinaries` is therefore off: the in-app
/// pipeline, which reads the keys below, is used on every iOS version.
enum KeyMaterial {
    // links.txt: base64( AES-128-CBC( JSON array of URLs, PKCS7 ) )
    static let linksKey: [UInt8] = Array("ZX2dTqYepmVGRZPE".utf8)
    static let linkIV: [UInt8] = Array("DXsZEcu5BurQg1TH".utf8)

    // shell.txt: base64( AES-128-CBC( "url=…\ntitle=…", PKCS7 ) )
    static let shellKey: [UInt8] = Array("WIx1sxGK9vHybdRx".utf8)
    static let shellIV: [UInt8] = Array("8gicinLCfhFSLbZj".utf8)

    // main protocol (`params` field of every /api request)
    static let apiKeyHex = "db4f76d0877feb1371b7a3eef3d15a85"
    static let apiIVHex = "e95f92340225fbd30bb983821e881941"


    // Constants baked into apptrace.framework's Mach-O at 0x13C420 / 0x13C3E0.
    // Keep in sync with tools/patch_apptrace_keys.py: whatever the endpoint at
    // 127.0.0.1:8888 returns must be encrypted with this pair.
    static let apptraceKey: [UInt8] = [
        0xf9, 0xef, 0x63, 0xa4, 0x30, 0xbe, 0x40, 0x30,
        0x6a, 0xc8, 0x56, 0x5e, 0xed, 0x39, 0x28, 0x86,
    ]
    static let apptraceIV: [UInt8] = [
        0xce, 0xf5, 0x70, 0x9a, 0x94, 0x83, 0xf3, 0x4b,
        0x3e, 0xa2, 0xfb, 0x85, 0x8b, 0xf1, 0x78, 0xcc,
    ]

    static func encrypt(_ plaintext: Data, key: [UInt8], iv: [UInt8]) -> Data? {
        crypt(CCOperation(kCCEncrypt), data: plaintext, key: key, iv: iv)
    }

    static func decrypt(_ ciphertext: Data, key: [UInt8], iv: [UInt8]) -> Data? {
        crypt(CCOperation(kCCDecrypt), data: ciphertext, key: key, iv: iv)
    }

    static var apiKey: Data? { Data(hexString: apiKeyHex) }
    static var apiIV: Data? { Data(hexString: apiIVHex) }

    /// AES-128-CBC + PKCS7, no padding tricks, base64 handled by the caller.
    static func crypt(
        _ operation: CCOperation,
        data: Data,
        key: [UInt8],
        iv: [UInt8]
    ) -> Data? {
        guard key.count == kCCKeySizeAES128, iv.count == kCCBlockSizeAES128 else {
            return nil
        }
        let capacity = data.count + kCCBlockSizeAES128
        var buffer = [UInt8](repeating: 0, count: capacity)
        var written = 0
        let status = data.withUnsafeBytes { dataRaw in
            key.withUnsafeBytes { keyRaw in
                iv.withUnsafeBytes { ivRaw in
                    CCCrypt(
                        operation,
                        CCAlgorithm(kCCAlgorithmAES128),
                        CCOptions(kCCOptionPKCS7Padding),
                        keyRaw.baseAddress,
                        key.count,
                        ivRaw.baseAddress,
                        dataRaw.baseAddress,
                        data.count,
                        &buffer,
                        capacity,
                        &written
                    )
                }
            }
        }
        guard status == kCCSuccess else { return nil }
        return Data(buffer[0..<written])
    }
}
