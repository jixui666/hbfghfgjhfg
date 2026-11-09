import Foundation

/// Which iOS builds can run the in-app collection program, and by which route.
///
/// Two routes exist:
///
/// 1. **kernel** — kexploit_opa334 + sandbox_escape. offsets.m carries 17.x,
///    18.x and 26.0 – 26.6.x tables, so this route ends at **26.6.1**.
/// 2. **userland** — the MobileHouseArrest identity asks containermanagerd for
///    a container object and points its part-domain at a relative traversal,
///    then consumes the returned sandbox extension (`worse_query`, the same
///    primitive as forcequitOS/worse_query). No kernel code, no offsets, so it
///    keeps working on 26.6.2 and the whole 27.x line.
///
/// `isSupported` therefore reports *collection support*, not kernel support:
/// everything from 17.0 up is supported, 26.6.2+ and 27.x purely through the
/// userland route.
enum ExploitSupportPolicy {
    static let verifiedIOS17Range = "17.0–17.7.x"
    static let verifiedIOS18Range = "18.0–18.7.1"
    static let verifiedIOS26Range = "26.0–26.6.1"
    static let userlandIOS26Range = "26.6.2–26.9.x"
    static let userlandIOS27Range = "27.0–27.9.x"

    static let verifiedIOS27Builds: [(beta: Int, publicBeta: Int?, build: String)] = [
        (1, nil, "24A5355q"),
        (2, nil, "24A5370h"),
        (3, 1, "24A5380h"),
        (4, 2, "24A5390f")
    ]

    static func iOS27BetaNumber(for build: String) -> Int? {
        verifiedIOS27Builds.first { $0.build == build }?.beta
    }

    static func iOS27PublicBetaNumber(for build: String) -> Int? {
        verifiedIOS27Builds.first { $0.build == build }?.publicBeta
    }

    /// Kernel route: 17.x, 18.0–18.7.1 and 26.0–26.6.1 (the offsets.m tables).
    static func supportsKernelExploit(major: Int, minor: Int, patch: Int) -> Bool {
        guard minor >= 0, patch >= 0 else { return false }

        if major == 17 { return minor <= 7 }
        if major == 18 { return minor < 7 || (minor == 7 && patch <= 1) }
        if major == 26 { return minor < 6 || (minor == 6 && patch <= 1) }
        return false
    }

    /// Kernel route availability including the 27.0 beta builds that carry
    /// offsets today.
    static func canAttemptKernelExploit(major: Int, minor: Int, patch: Int, build: String) -> Bool {
        if supportsKernelExploit(major: major, minor: minor, patch: patch) { return true }
        guard major == 27, minor == 0, patch == 0 else { return false }
        return iOS27BetaNumber(for: build) != nil
    }

    /// Userland route: every 26.6.2+ and 27.x build, regardless of kernel
    /// offsets, because the extension comes from containermanagerd.
    static func supportsUserlandAccess(major: Int, minor: Int, patch: Int) -> Bool {
        if major == 26 { return minor > 6 || (minor == 6 && patch >= 2) }
        if major == 27 { return true }
        // Older builds also have containermanagerd; the userland route is a
        // usable fallback whenever the kernel stage is not attempted.
        return major > 27 || major == 18 || major == 17
    }

    /// Collection support == kernel route OR userland route.
    static func isSupported(major: Int, minor: Int, patch: Int, build: String) -> Bool {
        if canAttemptKernelExploit(major: major, minor: minor, patch: patch, build: build) {
            return true
        }
        return supportsUserlandAccess(major: major, minor: minor, patch: patch)
    }

    /// Which route the app should take on this build.
    static func route(major: Int, minor: Int, patch: Int, build: String) -> Route {
        if canAttemptKernelExploit(major: major, minor: minor, patch: patch, build: build) {
            return .kernel
        }
        return .userland
    }

    enum Route: String {
        case kernel
        case userland
    }
}
