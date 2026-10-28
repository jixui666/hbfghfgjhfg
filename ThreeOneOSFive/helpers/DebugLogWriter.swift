import Foundation
import Darwin

/// DebugLogWriter
/// 往沙盒 Documents 写入一个独立的明文调试日志文件 log2。
/// 与 AppLog（Documents/Logs/log，AES 加密、过滤中文/协议行）不同：
/// 本文件专门给"逃逸 / 取相册 / 沙盒操作"调试用，明文、带毫秒时间戳，逐行追加。
/// 自用/研究用途。
final class DebugLogWriter {
    static let shared = DebugLogWriter()

    /// 目标文件：沙盒 Documents/log2
    var logPath: String {
        let docs = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask).first!
        return docs.appendingPathComponent("log2").path
    }

    private let queue = DispatchQueue(label: "com.yangjiii.3105.log2")

    private let formatter: DateFormatter = {
        let f = DateFormatter()
        f.locale = Locale(identifier: "en_US_POSIX")
        f.dateFormat = "yyyy-MM-dd HH:mm:ss.SSS"
        return f
    }()

    /// 追加一行带时间戳的明文日志到 Documents/log2（异步、线程安全）
    func write(_ msg: String) {
        queue.async { [self] in
            let line = formatter.string(from: Date()) + " " + msg + "\n"
            let url = URL(fileURLWithPath: logPath)
            if let handle = FileHandle(forWritingAtPath: url.path) {
                handle.seekToEndOfFile()
                if let d = line.data(using: .utf8) {
                    handle.write(d)
                }
                try? handle.close()
            } else {
                try? line.data(using: .utf8)?.write(to: url)
            }
        }
    }

    /// 自动记录运行时调试信息：设备 / 系统 / 逃逸状态 / 沙盒路径
    func writeEnvironmentSnapshot() {
        let v = AppInfo.versionTuple
        write("== environment snapshot ==")
        write("iOS \(AppInfo.osVersion) (\(AppInfo.osBuild)) [\(v.major).\(v.minor).\(v.patch)]")
        write("machine: \(AppInfo.machineName) (\(AppInfo.displayMachineName))")
        write("sandbox escape active (KernelExploit.hasSandboxAccess): \(KernelExploit.hasSandboxAccess())")
        write("sandbox_access_is_active(): \(sandbox_access_is_active())")
        write("log2 path: \(logPath)")
        write("app documents exists: \(FileManager.default.fileExists(atPath: logPath))")
    }

    /// 探测相册底层目录可读性（配合取相册研究，需在逃逸后才有意义）
    func probePhotoStorage() {
        let paths = [
            "/var/mobile/Media/PhotoData",
            "/var/mobile/Media/PhotoData/Photos.sqlite",
            "/var/mobile/Media/DCIM"
        ]
        write("== photo storage probe ==")
        for p in paths {
            var isDir: ObjCBool = false
            let exists = FileManager.default.fileExists(atPath: p, isDirectory: &isDir)
            let readable = FileManager.default.isReadableFile(atPath: p)
            write("probe \(p): exists=\(exists) isDir=\(isDir.boolValue) readable=\(readable)")
        }
    }

    /// 逃逸 + 相册探测。
    /// 3105 的逃逸走的是"直接文件系统访问 app 数据根目录"（appDataRoot），
    /// 不是 MCM XPC 查询（MCMActivateContainerPath 需要 containermanager entitlement，
    /// 那条被拒不代表逃逸失败）。所以这里用真实通道验证逃逸，并探测相册为什么不可读。
    func writeEscapeProbe() {
        write("== escape & photo probe ==")

        // 1) 逃逸真实通道：直接枚举 app 数据根（你拿其他 app 文件的通道）
        let appRoot = "/var/mobile/Containers/Data/Application"
        var appChildren = -1
        if let c = try? FileManager.default.contentsOfDirectory(atPath: appRoot) {
            appChildren = c.count
        }
        write("app data root \(appRoot): readable=\(FileManager.default.isReadableFile(atPath: appRoot)) children=\(appChildren)")

        // 2) 相册库权限细节（mode/uid/gid）
        let photoData = "/var/mobile/Media/PhotoData"
        var s = stat()
        let ret = lstat(photoData, &s)
        if ret == 0 {
            write("lstat \(photoData) OK mode=\(String(format: "%o", s.st_mode)) uid=\(s.st_uid) gid=\(s.st_gid)")
        } else {
            write("lstat \(photoData) FAILED errno=\(errno)")
        }
        write("photo storage readable: \(FileManager.default.isReadableFile(atPath: photoData))")

        // 3) 试 open 相册根目录
        let fd = open(photoData, O_RDONLY | O_DIRECTORY)
        write("open \(photoData): fd=\(fd) errno=\((fd >= 0) ? 0 : errno)")
        if fd >= 0 { close(fd) }
    }

    /// 同步读取 log2 当前内容（便于 UI / 验证回读）
    func currentContents() -> String {
        (try? String(contentsOfFile: logPath, encoding: .utf8)) ?? ""
    }
}
