// 在 macOS 上直接验证 SecureBox 能不能把 GeneratedSecrets 里的密文解回明文。
// CI 里跑：swiftc 编译 GeneratedSecrets.swift + SecureBox.swift + 本文件，然后执行。
// 期望从环境变量 SECRETS_JSON 读（与 gen_secrets.py 用的是同一份配置）。
//
// 这一步的意义：iOS 上跑不了单元测试，但解密逻辑是纯 Foundation/CryptoKit，
// 在 macOS 上行为一致 —— 能在构建阶段就把"生成器与 SecureBox 对不上"抓出来。

import Foundation

let raw = ProcessInfo.processInfo.environment["SECRETS_JSON"] ?? ""
var expected: [String] = []
if let data = raw.data(using: .utf8),
   let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
   let entries = object["entries"] as? [String] {
    expected = entries
}

print("expected entries:", expected.isEmpty ? "(none — 只检查非空)" : "\(expected.count)")

var failed = 0
for id in GeneratedSecrets.ID.allCases {
    let index = id.rawValue
    let got = SecureBox.string(id)
    if got.isEmpty {
        print("  [\(index)] \(id)  EMPTY")
        failed += 1
        continue
    }
    if index < expected.count {
        if got == expected[index] {
            print("  [\(index)] \(id)  ok  (\(got.count) chars)")
        } else {
            let head = String(got.prefix(6))
            let expHead = String(expected[index].prefix(6))
            print("  [\(index)] \(id)  MISMATCH got=\(head)…(\(got.count)) exp=\(expHead)…(\(expected[index].count))")
            failed += 1
        }
    } else {
        print("  [\(index)] \(id)  ok  (\(got.count) chars)")
    }
}

print(failed == 0 ? "SWIFT SECRETS OK" : "SWIFT SECRETS FAILED: \(failed)")
exit(failed == 0 ? 0 : 1)
