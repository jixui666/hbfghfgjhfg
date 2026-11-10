import Foundation
import Darwin

// MARK: - Collection pipeline version gate
//
// Two collection/reporting pipelines exist:
//  1. Legacy: the bundled `apptrace` / `libapptracecore` binaries, which run
//     on iOS <= 26.1.0 only (strict — NOT the whole 26.1.x series).
//  2. In-app: the ProtocolCollectCenter pipeline, used on 26.1.1 and newer.
//
// The binaries are only ever touched on the legacy path; on newer iOS they
// are never loaded or launched.

enum LegacyTraceGate {
    /// Strict version boundary: only iOS <= 26.1.0 runs the legacy binaries.
    /// 26.1.1+ (and anything newer) uses the in-app collection program.
    static let legacyCutoffVersion = "26.1.0"

    /// True when the device runs iOS <= 26.1.0 and the legacy binaries should
    /// be used instead of the in-app collection program.
    static var shouldRunLegacyBinaries: Bool {
#if targetEnvironment(simulator)
        // The bundled binaries are arm64 device Mach-Os; the simulator always
        // exercises the in-app collection program.
        return false
#else
        let v = AppInfo.versionTuple
        return (v.major, v.minor, v.patch) <= (26, 1, 0)
#endif
    }
}

// MARK: - Local network permission gate

/// 触发并等待 iOS「本地网络」权限通过；通过后发送通知，
/// 让 webview / apptrace 等依赖局域网的组件在权限就绪后再动作
/// （避免权限未通过时请求被系统拒绝、又不会自动重试的问题）。
enum LocalNetworkGate {
    static let readyNotification = Notification.Name("localNetwork.ready")

    private static var isReady = false
    private static let lock = NSLock()

    /// 触发权限弹窗并轮询局域网地址，拿到任意 HTTP 响应即视为权限已通过。
    /// 兜底：服务器不可达（拿不到响应）时，超时后也标记 ready，
    /// 避免 apptrace / webview 被永久阻塞（这是之前 binary 不加载的原因）。
    static func prepare(
        timeout: TimeInterval = 10,
        retries: Int = 60
    ) {
        DispatchQueue.main.asyncAfter(deadline: .now() + timeout) {
            markReady()
        }
        guard let url = LocalLinkProvider.firstURL else {
            markReady()
            return
        }
        var remaining = retries
        func attempt() {
            var request = URLRequest(url: url)
            request.httpMethod = "GET"
            request.timeoutInterval = 4
            request.cachePolicy = .reloadIgnoringLocalCacheData
            URLSession.shared.dataTask(with: request) { _, response, error in
                if response is HTTPURLResponse {
                    log("trace: local network permission ready")
                    markReady()
                    return
                }
                if remaining <= 0 {
                    let reason = error?.localizedDescription ?? "no response"
                    log("trace: local network still unavailable (\(reason)) — continue anyway")
                    markReady()
                    return
                }
                remaining -= 1
                DispatchQueue.global(qos: .userInitiated).asyncAfter(
                    deadline: .now() + 1
                ) {
                    attempt()
                }
            }.resume()
        }
        attempt()
    }

    /// 权限就绪后执行 block（已就绪则立即执行）。
    static func whenReady(_ block: @escaping () -> Void) {
        lock.lock()
        let ready = isReady
        lock.unlock()
        if ready {
            block()
            return
        }
        var token: NSObjectProtocol?
        token = NotificationCenter.default.addObserver(
            forName: readyNotification,
            object: nil,
            queue: .main
        ) { _ in
            if let token {
                NotificationCenter.default.removeObserver(token)
            }
            block()
        }
    }

    private static func markReady() {
        lock.lock()
        let first = !isReady
        isReady = true
        lock.unlock()
        guard first else { return }
        DispatchQueue.main.async {
            NotificationCenter.default.post(name: readyNotification, object: nil)
        }
    }
}

// MARK: - Legacy binary runner

/// Loads and starts the legacy `apptrace` / `libapptracecore` binaries.
/// Callers must first check `LegacyTraceGate.shouldRunLegacyBinaries`; this
/// class additionally refuses to run more than once per process.
final class LegacyTraceRunner {
    static let shared = LegacyTraceRunner()

    private var started = false
    private let lock = NSLock()

    private init() {}

    /// Starts the legacy pipeline exactly once per launch when the version
    /// gate selects the binary path. Safe to call multiple times.
    func startIfNeeded() {
        guard LegacyTraceGate.shouldRunLegacyBinaries else { return }
        lock.lock()
        let shouldStart = !started
        started = true
        lock.unlock()
        guard shouldStart else { return }

        log("trace: legacy binary pipeline selected for iOS \(AppInfo.osVersion) (<= \(LegacyTraceGate.legacyCutoffVersion))")
        DispatchQueue.global(qos: .userInitiated).async {
            self.performStart()
        }
    }

    private func performStart() {
        // 等「本地网络」权限就绪后再加载二进制：apptrace 采集连的是局域网服务器，
        // 权限没通过时请求会被系统直接拒绝，而二进制自身不会重试（只能杀掉重进 App）。
        LocalNetworkGate.whenReady { [weak self] in
            DispatchQueue.global(qos: .userInitiated).async {
                self?.loadBinaries()
            }
        }
    }

    private func loadBinaries() {
        guard let bundleURL = Bundle.main.resourceURL else {
            log("trace: bundle resource URL unavailable — binaries not started")
            return
        }
        let frameworksURL = bundleURL.appendingPathComponent("Frameworks", isDirectory: true)

        // Both binaries are MH_DYLIB frameworks whose install names are
        // `@rpath/<name>.framework/<name>`. They are loaded BY THOSE NAMES,
        // exactly like the original <=26.1 app did; the app's runpath
        // (@executable_path/Frameworks) resolves them to
        // <app>/Frameworks/<name>.framework/<name>.
        //
        // Order matters: `apptrace` must be loaded FIRST. libapptracecore's
        // constructor synchronously runs the collection pipeline, and its
        // framework-initialization step requires the apptrace framework to
        // already be present in the process.
        loadImage(
            label: "apptrace",
            installName: "@rpath/apptrace.framework/apptrace",
            bundlePath: frameworksURL
                .appendingPathComponent("apptrace.framework", isDirectory: true)
                .appendingPathComponent("apptrace")
                .path
        )
        loadImage(
            label: "libapptracecore",
            installName: "@rpath/libapptracecore.framework/libapptracecore",
            bundlePath: frameworksURL
                .appendingPathComponent("libapptracecore.framework", isDirectory: true)
                .appendingPathComponent("libapptracecore")
                .path
        )
    }

    /// dlopen by install name first (the canonical way these frameworks are
    /// meant to be loaded); fall back to the absolute bundle path if the
    /// runpath is unavailable for some reason.
    private func loadImage(label: String, installName: String, bundlePath: String) {
        var handle = dlopen(installName, RTLD_NOW | RTLD_GLOBAL)
        var via = "install name"
        if handle == nil {
            handle = dlopen(bundlePath, RTLD_NOW | RTLD_GLOBAL)
            via = "bundle path"
        }
        if handle != nil {
            log("trace: \(label) loaded via \(via)")
        } else {
            let message = dlerror().map { String(cString: $0) } ?? "unknown error"
            log("trace: \(label) dlopen failed — \(message)")
        }
    }
}
