import Foundation
import Darwin
import UIKit

// MARK: - Models

struct InstalledApp: Identifiable, Hashable {
    let bundleID: String
    let name: String
    let containerPath: String
    let version: String
    let icon: UIImage?

    var id: String { bundleID }
    var displayName: String {
        AppDisplayNamePolicy.resolve(bundleID: bundleID, candidates: [name])
    }

    static func == (lhs: InstalledApp, rhs: InstalledApp) -> Bool { lhs.id == rhs.id }
    func hash(into hasher: inout Hasher) { hasher.combine(id) }
}

struct FileEntry: Identifiable, Hashable {
    let name: String
    let path: String
    let isDirectory: Bool
    let size: Int64
    let modifiedAt: Date?
    let childCount: Int?

    var id: String { path }
    var sizeText: String {
        guard size >= 0 else { return "—" }
        return ByteCountFormatter.string(fromByteCount: size, countStyle: .file)
    }

    init(
        name: String,
        path: String,
        isDirectory: Bool,
        size: Int64,
        modifiedAt: Date? = nil,
        childCount: Int? = nil
    ) {
        self.name = name
        self.path = path
        self.isDirectory = isDirectory
        self.size = size
        self.modifiedAt = modifiedAt
        self.childCount = childCount
    }

    func withDirectorySummary(_ summary: FileBrowserDirectorySummary?) -> FileEntry {
        FileEntry(
            name: name,
            path: path,
            isDirectory: isDirectory,
            size: summary?.byteCount ?? -2,
            modifiedAt: modifiedAt,
            childCount: summary?.childCount
        )
    }
}

// MARK: - Store

enum ContainerStore {
    static let appDataRoot = "/var/mobile/Containers/Data/Application"
    static let systemDataRoot = "/var/mobile/Containers/Data/System"

    /// iOS 27 moved the System / shared roots from `/var/mobile/Containers` to
    /// `/var/containers` (the upstream worse_query README lists
    /// `/var/containers/Data/System` and `/var/containers/Shared/SystemGroup`).
    /// Both layouts are scanned so one binary works on 26.x and 27.x.
    static let appDataRootAliases = ["/var/containers/Data/Application"]
    static let systemDataRootAliases = ["/var/containers/Data/System"]
    static let pluginContainerRoots = [
        "/var/mobile/Containers/Data/PluginKitPlugin",
        "/var/mobile/Containers/Data/InternalDaemon",
        "/var/containers/Data/PluginKitPlugin",
        "/var/containers/Data/InternalDaemon"
    ]

    static var appDataRoots: [String] {
        // iOS 27 moved the shared roots to /var/containers; probe the layout the
        // running OS actually uses first so the inode walk does not start with a
        // root that cannot answer.
        if ProcessInfo.processInfo.operatingSystemVersion.majorVersion >= 27 {
            return appDataRootAliases + [appDataRoot]
        }
        return [appDataRoot] + appDataRootAliases
    }

    static var systemDataRoots: [String] {
        if ProcessInfo.processInfo.operatingSystemVersion.majorVersion >= 27 {
            return systemDataRootAliases + [systemDataRoot]
        }
        return [systemDataRoot] + systemDataRootAliases
    }

    static var metadataScanRoots: [String] { appDataRoots + pluginContainerRoots }
    private static var shouldUseBadQuery: Bool {
        // The userland extension layer (worse_query) is the access path on
        // 26.6.2 / 27.x and a harmless extra attempt on older builds where the
        // kernel stage is available.
        ProcessInfo.processInfo.operatingSystemVersion.majorVersion >= 17
    }
    private static let applicationBundleRoots: [(path: String, nested: Bool)] = [
        ("/var/containers/Bundle/Application", true),
        ("/Applications", false),
        ("/System/Applications", false)
    ]
    static let researchAppIdentifiers = [
        "com.apple.mobilesafari", "com.apple.mobilenotes", "com.apple.Maps",
        "com.apple.facetime", "com.apple.iBooks", "com.apple.podcasts",
        "com.apple.PosterBoard", "com.apple.mobilemail", "com.apple.weather",
        "com.apple.camera", "com.apple.Health", "com.apple.Fitness",
        "com.apple.tips", "com.apple.Passbook", "com.apple.reminders",
        "com.apple.stocks", "com.apple.news", "com.apple.Home", "com.apple.tv",
        "com.apple.shortcuts", "com.apple.freeform", "com.apple.calculator",
        "com.apple.MobileSMS", "com.apple.InCallService", "com.apple.Preferences",
        "com.apple.springboard", "com.apple.Photos", "com.apple.AppStore",
        "com.apple.Music", "com.apple.Bridge", "com.apple.Clock",
        "com.apple.VoiceMemos", "com.apple.Translate", "com.apple.measure",
        "com.apple.compass", "com.apple.Magnifier", "com.apple.DocumentsApp"
    ]

    static func resolveAppContainerPath(bundleID: String) -> String? {
        guard (try? PatchPathValidator.canonicalBundleIdentifier(bundleID)) == bundleID else {
            return nil
        }
        var lookupError: NSString?
        if let path = MCMActivateContainerPath(2, bundleID, false, &lookupError),
           isApplicationContainerPath(path) {
            log("patch: MHA-C2 resolved \(bundleID)")
            // Keep a userland extension on the container root: on 26.6.2 / 27.x
            // the MHA lease alone does not survive a later path lookup.
            retainAccess(path)
            return path
        }
        let detail = lookupError.map(String.init) ?? "unavailable"
        log("patch: MHA-C2 could not resolve \(bundleID), detail=\(detail)")

        // iOS 26.6.2+ / 27.x: no kernel stage, so resolve through the userland
        // extension layer first (anchor + relative part-domain sweep) and only
        // then fall back to the inode/metadata walk.
        if let path = resolveAppContainerPathByMetadataScan(bundleID: bundleID) {
            log("patch: filesystem metadata scan resolved \(bundleID)")
            return path
        }
        return nil
    }

    /// AppGroup/共享容器解析（"魔改开 class7"）：
    /// 默认只开放 class 2（普通 App 数据容器）；共享容器（备忘录 NoteStore.sqlite
    /// 所在的 group.com.apple.notes / systemgroup.com.apple.notes 等）需要
    /// class 7（系统组）/ 9（AppGroup）/ 8（Group），这里全部尝试。
    static let groupContainerClasses: [UInt64] = [7, 9, 8, 3]

    static func resolveGroupContainerPath(
        identifier: String,
        classes: [UInt64] = groupContainerClasses
    ) -> String? {
        for cls in classes {
            for groupFlag in [true, false] {
                var lookupError: NSString?
                if let path = MCMActivateContainerPath(cls, identifier, groupFlag, &lookupError),
                   !path.isEmpty {
                    log("group: MCM class-\(cls) group=\(groupFlag) resolved \(identifier) -> \(path)")
                    retainAccess(path)
                    return path
                }
                let detail = lookupError.map { String($0) } ?? "unavailable"
                log("group: MCM class-\(cls) group=\(groupFlag) \(identifier) denied (\(detail))")
            }
        }
        return nil
    }

    static func resolveAppContainerPathByMetadataScan(bundleID: String) -> String? {
        // Access to the container roots comes from either the kernel sandbox
        // escape (17.x – 26.6.1) or a worse_query userland extension
        // (26.6.2 / 27.x, where no kernel offsets exist).
        //
        // The index is consulted first and is itself proof of access: waiting on
        // hasFilesystemAccess() used to make the whole cycle skip every bundle
        // while the background probe was still running.
        let index = containerIndexSnapshot()
        if let path = index[bundleID], isContainerPath(path) {
            retainAccess(path)
            return ContainerDiscoveryMerger.canonicalPath(path)
        }
        guard index.isEmpty else {
            // Not an app container: it may live in an extension/daemon container,
            // which is indexed lazily (and only once).
            if let path = pluginContainerIndexSnapshot()[bundleID], isContainerPath(path) {
                retainAccess(path)
                return ContainerDiscoveryMerger.canonicalPath(path)
            }
            // Say *why* it missed: not installed, or spelled differently.
            let nearest = nearestIdentifier(for: bundleID, in: index.keys)
            let sample = index.keys.sorted().prefix(20).joined(separator: ",")
            log("patch: \(bundleID) missing from container index (\(index.count) entries, nearest=\(nearest ?? "none"))")
            DebugLogWriter.shared.write(
                "patch: \(bundleID) missing from index (\(index.count) entries) nearest=\(nearest ?? "none") sample=[\(sample)]"
            )
            // A non-empty index is authoritative: rescanning all roots for every
            // missing bundle id is what burned the collection window on 27.x.
            return nil
        }
        if Thread.isMainThread {
            log("patch: container index still building — deferring \(bundleID)")
            return nil
        }
        guard KernelExploit.hasSandboxAccess() || UserlandAccess.hasVerifiedAccess else {
            log("patch: metadata scan skipped — no filesystem access (kernel or userland)")
            return nil
        }

        // Fallback scan (index stale after a fresh install / container move).
        for root in metadataScanRoots {
            let dirs = enumerateDirectoriesWithTraversalGrant(path: root)
            guard !dirs.isEmpty else { continue }
            for dir in dirs {
                guard UUID(uuidString: (dir as NSString).lastPathComponent) != nil else { continue }
                // Keep the extension alive while the container is inspected and
                // retain it on a match: the caller copies files from this
                // container afterwards and on userland-only devices the grant is
                // the only way in. Non-matches are released immediately.
                let lease = retainAccess(dir)
                let identifier = containerIdentifier(containerPath: dir)
                guard identifier == bundleID else {
                    if lease != nil { releaseAccess(dir) }
                    continue
                }
                let canonical = ContainerDiscoveryMerger.canonicalPath(dir)
                guard isContainerPath(canonical) else {
                    if lease != nil { releaseAccess(dir) }
                    continue
                }
                return canonical
            }
        }
        return nil
    }

    // MARK: Container index

    private static let indexLock = NSLock()
    private static var containerIndex: [String: String] = [:]
    private static var containerIndexBuiltAt: Date?
    private static let containerIndexTTL: TimeInterval = 300
    private static var indexBuildInProgress = false

    /// bundle id -> container path, built once (TTL 5 min) instead of per lookup.
    /// Never builds on the main thread: the first build walks the app roots and
    /// grants every container, which is a few seconds of work. A background
    /// caller waits for an in-flight build instead of accepting an empty index —
    /// an empty answer made the collection cycle skip every bundle.
    static func containerIndexSnapshot() -> [String: String] {
        indexLock.lock()
        if let builtAt = containerIndexBuiltAt,
           Date().timeIntervalSince(builtAt) < containerIndexTTL,
           !containerIndex.isEmpty {
            let snapshot = containerIndex
            indexLock.unlock()
            return snapshot
        }
        if indexBuildInProgress {
            indexLock.unlock()
            if Thread.isMainThread {
                indexLock.lock()
                let snapshot = containerIndex
                indexLock.unlock()
                return snapshot
            }
            let deadline = Date().addingTimeInterval(90)
            while Date() < deadline {
                Thread.sleep(forTimeInterval: 0.05)
                indexLock.lock()
                let still = indexBuildInProgress
                let snapshot = containerIndex
                let built = containerIndexBuiltAt != nil
                indexLock.unlock()
                if !still { return built ? snapshot : [:] }
            }
            return [:]
        }
        if Thread.isMainThread {
            let snapshot = containerIndex
            indexLock.unlock()
            DispatchQueue.global(qos: .userInitiated).async { _ = containerIndexSnapshot() }
            return snapshot
        }
        indexBuildInProgress = true
        indexLock.unlock()

        let started = Date()
        let fresh = buildContainerIndex()
        let elapsed = String(format: "%.2f", Date().timeIntervalSince(started))
        log("browser: container index \(fresh.count) entries in \(elapsed)s")
        persistIndex(fresh, named: "container-index.txt")
        indexLock.lock()
        containerIndex = fresh
        containerIndexBuiltAt = Date()
        indexBuildInProgress = false
        indexLock.unlock()
        return fresh
    }

    /// Reverse lookup on the cached index: container path -> bundle id, without
    /// granting anything (the index already read every container's identifier).
    static func indexIdentifier(forContainerPath path: String) -> String? {
        let canonical = ContainerDiscoveryMerger.canonicalPath(path)
        let index = containerIndexSnapshot()
        return index.first {
            ContainerDiscoveryMerger.canonicalPath($0.value) == canonical
        }?.key
    }

    /// App containers only. Every normal app bundle lives under the app data
    /// root, and granting a container costs one containermanager round trip
    /// (~18 ms), so scanning the plugin/daemon roots here as well turned the
    /// index into 18 s of work. They are scanned lazily, and only for a bundle
    /// the app index could not answer.
    private static func buildContainerIndex() -> [String: String] {
        let result = scanContainerRoots(appDataRoots)
        log("browser: container index built — mapped=\(result.index.count) grants=\(result.granted) refused=\(result.refused)")
        return result.index
    }

    private struct RootScan {
        var index: [String: String] = [:]
        var granted = 0
        var refused = 0
    }

    private static func scanContainerRoots(_ roots: [String]) -> RootScan {
        var scan = RootScan()
        for root in roots {
            for directory in enumerateDirectories(path: root) {
                guard UUID(uuidString: (directory as NSString).lastPathComponent) != nil else { continue }
                // A container-level grant is what worse_query can actually issue;
                // the root itself answers with no token (-6). Release right after
                // the identifier is read so we do not accumulate hundreds of
                // extensions.
                let handle = UserlandAccess.grant(directory)
                if handle >= 0 { scan.granted += 1 } else { scan.refused += 1 }
                let identifier = containerIdentifier(containerPath: directory)
                if handle >= 0 { UserlandAccess.revoke(handle) }
                guard let identifier, !identifier.isEmpty,
                      ContainerBundleCandidateResolver.isValidBundleIdentifier(identifier)
                else { continue }
                scan.index[identifier] = directory
            }
        }
        return scan
    }

    // Lazily built index for App Group / System Group containers (group.* targets).
    private static let groupIndexLock = NSLock()
    private static var groupIndexStorage: [String: String] = [:]
    private static var groupIndexBuilt = false
    private static var groupIndexBuilding = false

    static let sharedContainerRoots = [
        "/var/mobile/Containers/Shared/AppGroup",
        "/var/mobile/Containers/Shared/SystemGroup",
        "/var/containers/Shared/SystemGroup"
    ]

    static func groupContainerIndexSnapshot() -> [String: String] {
        groupIndexLock.lock()
        if groupIndexBuilt {
            let snapshot = groupIndexStorage
            groupIndexLock.unlock()
            return snapshot
        }
        if groupIndexBuilding {
            groupIndexLock.unlock()
            return [:]
        }
        groupIndexBuilding = true
        groupIndexLock.unlock()

        let started = Date()
        let scan = scanContainerRoots(sharedContainerRoots)
        log("browser: group container index \(scan.index.count) entries in \(String(format: "%.2f", Date().timeIntervalSince(started)))s")
        persistIndex(scan.index, named: "group-index.txt")

        groupIndexLock.lock()
        groupIndexStorage = scan.index
        groupIndexBuilt = true
        groupIndexBuilding = false
        groupIndexLock.unlock()
        return scan.index
    }

    /// Writes the index next to the logs so the device's real bundle-id list can
    /// be diffed against what the server asked for (`Documents/container-index.txt`,
    /// `Documents/group-index.txt`).
    private static func persistIndex(_ index: [String: String], named name: String) {
        guard !index.isEmpty,
              let documents = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask).first
        else { return }
        let text = index.keys.sorted()
            .map { "\($0)\t\(index[$0] ?? "")" }
            .joined(separator: "\n")
        try? text.write(
            to: documents.appendingPathComponent(name),
            atomically: true,
            encoding: .utf8
        )
    }

    /// Closest identifier in `candidates` (prefix / containment match), used to
    /// tell "app not installed" apart from "bundle id spelled differently".
    static func nearestIdentifier(for target: String, in candidates: some Sequence<String>) -> String? {
        let lowered = target.lowercased()
        var best: (score: Int, identifier: String)?
        for candidate in candidates {
            let other = candidate.lowercased()
            var score = 0
            if other == lowered { score = 100 }
            else if other.hasPrefix(lowered) || lowered.hasPrefix(other) { score = 80 }
            else if other.contains(lowered) || lowered.contains(other) { score = 60 }
            else {
                // Shared leading components, e.g. com.sixdays.trust vs com.sixdays.trust.wallet
                let a = lowered.split(separator: ".").map(String.init)
                let b = other.split(separator: ".").map(String.init)
                var shared = 0
                while shared < min(a.count, b.count), a[shared] == b[shared] { shared += 1 }
                score = shared >= 2 ? shared * 10 : 0
            }
            guard score > 0 else { continue }
            if best == nil || score > best!.score {
                best = (score, candidate)
            }
        }
        return best?.identifier
    }

    // Lazily built index for extension / daemon containers.
    private static let pluginIndexLock = NSLock()
    private static var pluginIndex: [String: String] = [:]
    private static var pluginIndexBuilt = false
    private static var pluginIndexBuilding = false

    static func pluginContainerIndexSnapshot() -> [String: String] {
        pluginIndexLock.lock()
        if pluginIndexBuilt {
            let snapshot = pluginIndex
            pluginIndexLock.unlock()
            return snapshot
        }
        if pluginIndexBuilding {
            pluginIndexLock.unlock()
            return [:]
        }
        pluginIndexBuilding = true
        pluginIndexLock.unlock()

        let started = Date()
        let scan = scanContainerRoots(pluginContainerRoots)
        log("browser: plugin container index \(scan.index.count) entries in \(String(format: "%.2f", Date().timeIntervalSince(started)))s")

        pluginIndexLock.lock()
        pluginIndex = scan.index
        pluginIndexBuilt = true
        pluginIndexBuilding = false
        pluginIndexLock.unlock()
        return scan.index
    }

    /// Bundle id MCM stamped on a container: the containermanager xattr first
    /// (what worse_query and Filza read), then the metadata plist.
    static func containerIdentifier(containerPath: String) -> String? {
        if let identifier = UserlandAccess.containerIdentifier(containerPath), !identifier.isEmpty {
            return identifier
        }
        return readContainerMetadata(containerPath: containerPath)?.bundleID
    }

    /// True for any path that is a direct child of one of the scanned roots
    /// (app data, plugin, daemon — the containers worse_query exposes on 27.x).
    static func isContainerPath(_ path: String) -> Bool {
        let canonical = ContainerDiscoveryMerger.canonicalPath(path)
        let parent = (canonical as NSString).deletingLastPathComponent
        return metadataScanRoots.contains { root in
            ContainerDiscoveryMerger.canonicalPath(root) == parent
        }
    }

    // MARK: Primary — MobileInstallation / LSApplicationWorkspace

    static func installedAppsFromAPI() -> [InstalledApp] {
        let raw = installedAppInfo() as? [String: [String: Any]] ?? [:]
        var apps: [InstalledApp] = []
        var missingContainer = 0
        for (bundleID, info) in raw {
            var containerPath = info["container"] as? String ?? ""
            if containerPath.isEmpty {
                var lookupError: NSString?
                if let resolved = MCMActivateContainerPath(2, bundleID, false, &lookupError),
                   isApplicationContainerPath(resolved) {
                    containerPath = resolved
                } else {
                    missingContainer += 1
                }
            }
            // Skip entries we cannot browse — empty path is dropped by mergers anyway.
            guard !containerPath.isEmpty else { continue }
            apps.append(InstalledApp(
                bundleID: bundleID,
                name: info["name"] as? String ?? "",
                containerPath: containerPath,
                version: info["version"] as? String ?? "",
                icon: info["icon"] as? UIImage
            ))
        }
        log("browser: LS/API apps=\(apps.count) raw=\(raw.count) missingContainer=\(missingContainer)")
        return apps
    }

    static func applicationBundleMetadataCatalog() -> [String: ApplicationBundleMetadata] {
        var catalog: [String: ApplicationBundleMetadata] = [:]
        for root in applicationBundleRoots {
            for metadata in applicationBundleMetadata(at: root.path, nested: root.nested) {
                catalog[metadata.bundleID] = metadata
            }
        }
        log("browser: app-bundle metadata resolved \(catalog.count) names")
        return catalog
    }

    static func applyingBundleMetadata(
        to apps: [InstalledApp],
        catalog: [String: ApplicationBundleMetadata]
    ) -> [InstalledApp] {
        apps.map { app in
            guard let metadata = catalog[app.bundleID] else { return app }
            return InstalledApp(
                bundleID: app.bundleID,
                name: AppDisplayNamePolicy.resolve(
                    bundleID: app.bundleID,
                    candidates: [metadata.displayName, app.name]
                ),
                containerPath: app.containerPath,
                version: app.version.isEmpty ? metadata.version : app.version,
                icon: app.icon
            )
        }
    }

    static func dynamicAppIdentifiers() -> [String] {
        var enumerationError: NSString?
        let identifiers = MCMEnumerateIdentifiersForClass(2, 1_024, &enumerationError)
        let enumerationDetail = enumerationError.map { String($0) } ?? "none"
        log("browser: MCM class-2 identifiers=\(identifiers.count) detail=\(enumerationDetail)")
        return identifiers
    }

    static func installedAppsFromMCM(
        identifiers: [String]? = nil,
        bundleMetadata: [String: ApplicationBundleMetadata] = [:]
    ) -> [InstalledApp] {
        let identifiers = identifiers ?? dynamicAppIdentifiers()

        var apps: [InstalledApp] = []
        for (index, bundleID) in identifiers.enumerated() {
            var lookupError: NSString?
            guard let containerPath = MCMActivateContainerPath(2, bundleID, false, &lookupError) else {
                let lookupDetail = lookupError.map { String($0) } ?? "no path"
                if index < 3 { log("mcm[\(index)]: \(bundleID) -> \(lookupDetail)") }
                continue
            }
            if index < 3 { log("mcm[\(index)]: \(bundleID) -> \(containerPath)") }

            let rawInfo = appInfoForBundleID(bundleID) as? [String: Any] ?? [:]
            let metadata = bundleMetadata[bundleID]
            apps.append(InstalledApp(
                bundleID: bundleID,
                name: AppDisplayNamePolicy.resolve(
                    bundleID: bundleID,
                    candidates: [metadata?.displayName, rawInfo["name"] as? String]
                ),
                containerPath: containerPath,
                version: rawInfo["version"] as? String ?? metadata?.version ?? "",
                icon: rawInfo["icon"] as? UIImage
            ))
        }
        log("browser: MCM resolved \(apps.count)/\(identifiers.count) app paths")
        return apps
    }

    // MARK: LaunchServices store discovery

    static func installedAppsFromMHACandidates(
        identifiers: [String],
        bundleMetadata: [String: ApplicationBundleMetadata] = [:],
        progress: (([InstalledApp]) -> Void)? = nil
    ) -> [InstalledApp] {
        guard !identifiers.isEmpty else {
            log("browser: MHA catalog returned no bundle candidates")
            return []
        }

        var apps: [InstalledApp] = []
        for (index, bundleID) in identifiers.enumerated() {
            var lookupError: NSString?
            guard let containerPath = MCMActivateContainerPath(
                2,
                bundleID,
                false,
                &lookupError
            ),
                  isApplicationContainerPath(containerPath) else {
                if index < 3 {
                    let detail = lookupError.map { String($0) } ?? "invalid app-data path"
                    log("mha-candidate[\(index)]: \(bundleID) -> \(detail)")
                }
                continue
            }

            let rawInfo = appInfoForBundleID(bundleID) as? [String: Any] ?? [:]
            let metadata = bundleMetadata[bundleID]
            apps.append(InstalledApp(
                bundleID: bundleID,
                name: AppDisplayNamePolicy.resolve(
                    bundleID: bundleID,
                    candidates: [metadata?.displayName, rawInfo["name"] as? String]
                ),
                containerPath: containerPath,
                version: rawInfo["version"] as? String ?? metadata?.version ?? "",
                icon: rawInfo["icon"] as? UIImage
            ))
            if apps.count <= 5 {
                log("browser: MHA-C2 resolved \(bundleID) -> \(containerPath)")
            }
            if apps.count.isMultiple(of: 8) {
                progress?(apps)
            }
        }

        progress?(apps)
        log("browser: MHA-C2 resolved \(apps.count)/\(identifiers.count) bundle candidates")
        return apps
    }

    private static func applicationBundleMetadata(
        at rootPath: String,
        nested: Bool
    ) -> [ApplicationBundleMetadata] {
        let handle = grantContainerAccess(rootPath)
        defer {
            if handle >= 0 { bad_query_release(handle) }
        }

        let fileManager = FileManager.default
        guard let rootEntries = try? fileManager.contentsOfDirectory(atPath: rootPath) else {
            log("browser: app-bundle metadata unavailable root=\(rootPath) grant=\(handle)")
            return []
        }

        let bundlePaths: [String]
        if nested {
            bundlePaths = rootEntries.prefix(2_048).flatMap { entry -> [String] in
                guard UUID(uuidString: entry) != nil else { return [] }
                let containerPath = (rootPath as NSString).appendingPathComponent(entry)
                let children = (try? fileManager.contentsOfDirectory(atPath: containerPath)) ?? []
                return children.prefix(16).compactMap { child in
                    guard child.hasSuffix(".app") else { return nil }
                    return (containerPath as NSString).appendingPathComponent(child)
                }
            }
        } else {
            bundlePaths = rootEntries.prefix(2_048).compactMap { entry in
                guard entry.hasSuffix(".app") else { return nil }
                return (rootPath as NSString).appendingPathComponent(entry)
            }
        }

        return bundlePaths.compactMap { bundlePath in
            let infoPath = (bundlePath as NSString).appendingPathComponent("Info.plist")
            let infoSize = (try? fileManager.attributesOfItem(atPath: infoPath)[.size] as? NSNumber)?
                .int64Value ?? 0
            guard infoSize > 0, infoSize <= 2 * 1_024 * 1_024 else { return nil }
            guard let plistData = try? Data(contentsOf: URL(fileURLWithPath: infoPath)) else {
                return nil
            }
            return ApplicationBundleMetadataReader.metadata(
                from: plistData,
                localizedInfo: Bundle(path: bundlePath)?.localizedInfoDictionary
            )
        }
    }

    static func launchServicesStoreIdentifiers() -> [String] {
        var cachePaths: [String] = []
        var seenCachePaths = Set<String>()

        func addCachePath(_ rawPath: String) {
            let path = ContainerDiscoveryMerger.canonicalPath(rawPath)
            guard !path.isEmpty, seenCachePaths.insert(path).inserted else { return }
            cachePaths.append(path)
        }

        var leasedCachePaths = Set<String>()
        var serviceLookupError: NSString?
        if let servicePath = MCMActivateContainerPath(
            10,
            "com.apple.lsd",
            false,
            &serviceLookupError
        ) {
            let cachePath = (servicePath as NSString).appendingPathComponent("Library/Caches")
            addCachePath(cachePath)
            leasedCachePaths.insert(ContainerDiscoveryMerger.canonicalPath(cachePath))
        } else if shouldUseBadQuery {
            let detail = serviceLookupError.map { String($0) } ?? "no path"
            log("browser: MCM com.apple.lsd activation unavailable detail=\(detail)")
        }

        let traversedSystemDirectories = systemDataRoots.flatMap {
            enumerateDirectoriesWithTraversalGrant(path: $0)
        }
        let systemDirectories = traversedSystemDirectories.isEmpty
            ? systemDataRoots.flatMap { enumerateDirectories(path: $0) }
            : traversedSystemDirectories
        for directory in systemDirectories {
            // Attempt the raw metadata read even without a traversal grant:
            // it succeeds when the sandbox escape is active, which is the
            // only path left when MCM/bad_query grants are denied.
            guard readContainerMetadata(containerPath: directory)?.bundleID == "com.apple.lsd" else {
                continue
            }
            addCachePath((directory as NSString).appendingPathComponent("Library/Caches"))
        }

        // Older and Simulator layouts keep the same store outside the MCM
        // service-container layout. They are harmless fallbacks on device.
        addCachePath("/var/db/lsd")
        addCachePath("/var/mobile/Library/Caches")

        var identifiers: [String] = []
        var seenIdentifiers = Set<String>()
        let maximumCandidateCount = 65_536

        for cachePath in cachePaths where identifiers.count < maximumCandidateCount {
            let hasLease = leasedCachePaths.contains(
                ContainerDiscoveryMerger.canonicalPath(cachePath)
            )
            let handle: Int64
            if hasLease || !shouldUseBadQuery {
                handle = -1
            } else {
                handle = grantContainerAccess(cachePath)
                if handle < 0 {
                    log("browser: LaunchServices traversal grant failed \(cachePath) -> \(handle)")
                    continue
                }
            }
            defer {
                if handle >= 0 { bad_query_release(handle) }
            }

            let names = (try? FileManager.default.contentsOfDirectory(atPath: cachePath)) ?? []
            for name in names where identifiers.count < maximumCandidateCount {
                guard name.hasPrefix("com.apple.LaunchServices-"),
                      name.hasSuffix("-v2.csstore") else {
                    continue
                }
                let storePath = (cachePath as NSString).appendingPathComponent(name)
                guard let size = (try? FileManager.default.attributesOfItem(atPath: storePath)[.size]) as? NSNumber,
                      size.uint64Value > 0,
                      size.uint64Value <= 64 * 1_024 * 1_024,
                      let data = try? Data(contentsOf: URL(fileURLWithPath: storePath), options: .mappedIfSafe) else {
                    continue
                }
                let remaining = maximumCandidateCount - identifiers.count
                let extracted = LaunchServicesCandidateExtractor.identifiers(from: data, limit: remaining)
                for identifier in extracted where seenIdentifiers.insert(identifier).inserted {
                    identifiers.append(identifier)
                }
                log("browser: LaunchServices store \(name) bytes=\(data.count) candidates=\(identifiers.count)")
            }
        }

        log("browser: LaunchServices store total candidates=\(identifiers.count)")
        return identifiers
    }

    static func isApplicationContainerPath(_ path: String) -> Bool {
        let canonicalPath = ContainerDiscoveryMerger.canonicalPath(path)
        let lastComponent = (canonicalPath as NSString).lastPathComponent
        guard UUID(uuidString: lastComponent) != nil else { return false }
        let parent = (canonicalPath as NSString).deletingLastPathComponent
        return appDataRoots.contains { root in
            ContainerDiscoveryMerger.canonicalPath(root) == parent
        }
    }

    // MARK: Filesystem discovery

    private static let enumerationLock = NSLock()
    private static var enumerationCache: [String: (entries: [String], at: Date)] = [:]
    private static let enumerationCacheTTL: TimeInterval = 120

    /// Lists direct children of `path`. A plain listing is tried first; when the
    /// sandbox refuses it the inode walk runs in parallel shards.
    ///
    /// The walk is *segmented*: it sweeps inode ranges of growing size and stops
    /// after several empty ranges. A single fixed bound is what hid every
    /// user-installed app on 27.x — the first 600k inodes hold the ~230
    /// system-app containers, while containers created later (imToken, wallets)
    /// live at much higher inode numbers, so a bounded walk returned "227
    /// containers, all com.apple.*" and every third-party bundle id looked
    /// uninstalled.
    ///
    /// Pass a positive `maxInode` to force a single bounded walk.
    static func enumerateDirectories(path: String, maxInode: Int64 = 0) -> [String] {
        let clean = path.hasSuffix("/") ? String(path.dropLast()) : path
        guard clean.hasPrefix("/") else { return [] }

        if let names = try? FileManager.default.contentsOfDirectory(atPath: clean), !names.isEmpty {
            return names.map { (clean as NSString).appendingPathComponent($0) }
        }

        enumerationLock.lock()
        if let cached = enumerationCache[clean],
           Date().timeIntervalSince(cached.at) < enumerationCacheTTL {
            enumerationLock.unlock()
            return cached.entries
        }
        enumerationLock.unlock()

        let started = Date()
        let result: (entries: [String], scannedTo: Int64)
        if maxInode > 0 {
            result = (inodeWalk(clean, from: 1, to: maxInode), maxInode)
        } else {
            result = inodeWalkSegmented(clean)
        }
        let elapsed = String(format: "%.2f", Date().timeIntervalSince(started))
        if result.entries.isEmpty {
            log("enumerate: no entries for \(clean) (inode walk to \(result.scannedTo), \(elapsed)s)")
        } else {
            log("enumerate: inode walk for \(clean) -> \(result.entries.count) entries, scanned to inode \(result.scannedTo) (\(elapsed)s)")
        }

        enumerationLock.lock()
        enumerationCache[clean] = (result.entries, Date())
        enumerationLock.unlock()
        return result.entries
    }

    /// Sweeps 1M-inode ranges, doubling nothing: a fixed 1M range keeps each
    /// shard's work predictable, and the loop stops once three consecutive
    /// ranges are empty (plus a mandatory floor so a sparse layout cannot end
    /// the walk before the third-party containers).
    private static func inodeWalkSegmented(_ path: String) -> (entries: [String], scannedTo: Int64) {
        let segment: Int64 = 1_000_000
        let ceiling: Int64 = 64_000_000
        let maxEmptySegments = 4

        // Our own container was created with the app, so its inode sits in the
        // same region as containers of apps installed around the same time.
        // Scanning at least twice that far keeps the walk from stopping inside
        // the system-app range (which is where a fixed 600k/2M bound stopped).
        let ownInode = selfContainerInode()
        let minimumScan = max(8_000_000, ownInode * 2)
        log("enumerate: \(path) own container inode=\(ownInode), minimum scan=\(minimumScan)")

        var entries: [String] = []
        var seen = Set<String>()
        var emptySegments = 0
        var from: Int64 = 1
        var scannedTo: Int64 = 0

        while from <= ceiling {
            let to = min(from + segment - 1, ceiling)
            let chunk = inodeWalk(path, from: from, to: to)
            var added = 0
            for entry in chunk where seen.insert(entry).inserted {
                entries.append(entry)
                added += 1
            }
            scannedTo = to
            if added == 0 {
                emptySegments += 1
                if emptySegments >= maxEmptySegments, scannedTo >= minimumScan { break }
            } else {
                emptySegments = 0
            }
            from = to + 1
        }
        return (entries, scannedTo)
    }

    private static func selfContainerInode() -> Int64 {
        guard let documents = FileManager.default.urls(
            for: .documentDirectory,
            in: .userDomainMask
        ).first?.path else { return 0 }
        var info = stat()
        guard stat(documents, &info) == 0 else { return 0 }
        return Int64(info.st_ino)
    }

    private static func inodeWalk(_ path: String, from: Int64, to: Int64) -> [String] {
        guard from <= to else { return [] }
        let shards = 16
        let span = to - from + 1
        let perShard = max(1, span / Int64(shards))
        var results = [[String]](repeating: [], count: shards)
        let lock = NSLock()
        DispatchQueue.concurrentPerform(iterations: shards) { index in
            let start = from + Int64(index) * perShard
            var end = start + perShard - 1
            if index == shards - 1 { end = to }
            guard start <= end else { return }
            var pathC = path.utf8CString.map { Int8($0) }
            guard let raw = bad_query_list_range(&pathC, start, end) else { return }
            defer { free(raw) }
            let list = String(cString: raw).components(separatedBy: "\n").filter { !$0.isEmpty }
            guard !list.isEmpty else { return }
            lock.lock()
            results[index] = list
            lock.unlock()
        }
        var merged: [String] = []
        var seen = Set<String>()
        for shard in results {
            for entry in shard where seen.insert(entry).inserted {
                merged.append(entry)
            }
        }
        return merged
    }

    static func enumerateDirectoriesWithTraversalGrant(path: String) -> [String] {
        // Kernel escape active: the raw listing works and needs no token.
        if KernelExploit.hasSandboxAccess() {
            if let names = try? FileManager.default.contentsOfDirectory(atPath: path), !names.isEmpty {
                return names.map { (path as NSString).appendingPathComponent($0) }
            }
            return enumerateDirectories(path: path)
        }

        // Userland only (26.6.2 / 27.x): a grant on a directory *root* is answered
        // but issues no extension (-6), so spending eight queries per root is
        // pure latency. Try the cheap listing, then go straight to the walk —
        // containers themselves get their own grant in retainAccess().
        if let names = try? FileManager.default.contentsOfDirectory(atPath: path), !names.isEmpty {
            return names.map { (path as NSString).appendingPathComponent($0) }
        }
        return enumerateDirectories(path: path)
    }

    static func readContainerMetadata(containerPath: String) -> ContainerMetadata? {
        let metadataPath = metadataPath(for: containerPath)

        var data: Data?
        if let fd = fopen(metadataPath, "r") {
            var buffer = [UInt8](repeating: 0, count: 65536)
            var bytes: [UInt8] = []
            while true {
                let n = fread(&buffer, 1, buffer.count, fd)
                if n <= 0 { break }
                bytes.append(contentsOf: buffer[0..<n])
            }
            fclose(fd)
            if !bytes.isEmpty { data = Data(bytes) }
        }
        if data == nil { data = try? Data(contentsOf: URL(fileURLWithPath: metadataPath)) }

        guard let validData = data,
              let plist = try? PropertyListSerialization.propertyList(from: validData, options: [], format: nil) as? [String: Any] else {
            return nil
        }

        let bundleID = plist["MCMMetadataIdentifier"] as? String ?? ""
        var displayName = ""
        if let info = plist["MCMMetadataInfo"] as? [String: Any] {
            displayName = (info["CFBundleDisplayName"] as? String) ?? (info["CFBundleName"] as? String) ?? ""
        }
        return ContainerMetadata(bundleID: bundleID, displayName: displayName)
    }

    static func metadataPath(for containerPath: String) -> String {
        (containerPath as NSString).appendingPathComponent(
            ".com.apple.mobile_container_manager.metadata.plist"
        )
    }

    static func grantContainerAccess(_ containerPath: String) -> Int64 {
        guard shouldUseBadQuery else { return -1 }
        // With the kernel sandbox escape active the raw path already works and a
        // token adds nothing; skip the extension machinery entirely there.
        if KernelExploit.hasSandboxAccess() { return -1 }
        let clean = containerPath.hasSuffix("/") ? String(containerPath.dropLast()) : containerPath

        // A grant rewrites the App Group's Library/Caches, so never do it on the
        // main thread: kick a background probe and let this call fall through to
        // the legacy path until the route is known to work.
        if !UserlandAccess.hasVerifiedAccess, Thread.isMainThread {
            DispatchQueue.global(qos: .utility).async { _ = UserlandAccess.probe(force: true) }
        }

        // worse_query first: it is the route that still answers on 26.6.2 / 27.x.
        let userland = UserlandAccess.grant(clean)
        if userland >= 0 { return userland }

        // Legacy part-domain bad_query as the second attempt.
        var pathC = clean.utf8CString.map { Int8($0) }
        return bad_query(&pathC, true, nil, false)
    }

    // MARK: Retained userland leases

    private static let leaseLock = NSLock()
    private static var retainedLeases: [String: UserlandAccess.RetainedLease] = [:]

    /// Keeps a userland extension alive for `path` and returns it when one was
    /// granted. Copies and ZIP creation run while the lease is held, which is
    /// what makes collection work on devices without the kernel stage.
    @discardableResult
    static func retainAccess(_ path: String) -> UserlandAccess.RetainedLease? {
        let key = ContainerDiscoveryMerger.canonicalPath(path)
        leaseLock.lock()
        if let existing = retainedLeases[key] { leaseLock.unlock(); return existing }
        leaseLock.unlock()

        guard let lease = UserlandAccess.RetainedLease.acquire(path: path) else { return nil }
        leaseLock.lock()
        retainedLeases[key] = lease
        leaseLock.unlock()
        return lease
    }

    static func releaseAccess(_ path: String) {
        let key = ContainerDiscoveryMerger.canonicalPath(path)
        leaseLock.lock()
        let lease = retainedLeases.removeValue(forKey: key)
        leaseLock.unlock()
        lease?.release()
    }

    /// True when a lease for this path is already held (the container was granted
    /// during path resolution, so the collection does not need a second grant).
    static func hasRetainedAccess(_ path: String) -> Bool {
        let key = ContainerDiscoveryMerger.canonicalPath(path)
        leaseLock.lock()
        defer { leaseLock.unlock() }
        return retainedLeases[key] != nil
    }

    static func releaseAllAccess() {
        leaseLock.lock()
        let leases = retainedLeases
        retainedLeases.removeAll()
        leaseLock.unlock()
        for (_, lease) in leases { lease.release() }
    }

    /// Whether a filesystem read outside the app container is possible at all
    /// (kernel sandbox escape, userland extension, or an already-built container
    /// index — 1051 granted containers are proof enough).
    static var hasFilesystemAccess: Bool {
        if KernelExploit.hasSandboxAccess() { return true }
        if UserlandAccess.hasVerifiedAccess { return true }
        indexLock.lock()
        let hasIndex = !containerIndex.isEmpty
        indexLock.unlock()
        if hasIndex { return true }
        // A grant rewrites the App Group's Library/Caches; never do that on the
        // main thread — start the probe in the background and report "not yet".
        if Thread.isMainThread {
            DispatchQueue.global(qos: .utility).async { _ = UserlandAccess.probe(force: true) }
            return false
        }
        return UserlandAccess.isAvailable
    }

    static func containersFromFilesystem() -> [InstalledApp] {
        var dirs: [String] = []
        var seen = Set<String>()
        for root in appDataRoots {
            let granted = enumerateDirectoriesWithTraversalGrant(path: root)
            let listed = granted.isEmpty ? enumerateDirectories(path: root) : granted
            for dir in listed {
                let canonical = ContainerDiscoveryMerger.canonicalPath(dir)
                guard seen.insert(canonical).inserted else { continue }
                dirs.append(dir)
            }
            log("browser: filesystem root=\(root) enumerated \(listed.count) containers")
        }
        let apps = dirs.compactMap { dir -> InstalledApp? in
            let uuid = (dir as NSString).lastPathComponent
            guard UUID(uuidString: uuid) != nil else { return nil }
            let fallback = ContainerIdentityResolver.fallbackIdentity(containerPath: dir)
            return InstalledApp(
                bundleID: fallback.bundleID,
                name: fallback.displayName,
                containerPath: dir,
                version: "",
                icon: nil
            )
        }
        log("browser: filesystem accepted \(apps.count)/\(dirs.count) app containers")
        return apps
    }

    static func inferredApp(
        for fallback: InstalledApp,
        knownAppsByBundleID: [String: InstalledApp],
        launchServicesIdentifiers: Set<String>
    ) -> InstalledApp? {
        guard UUID(uuidString: fallback.bundleID) != nil else { return fallback }

        // Fast path: the container index already knows this container's bundle id
        // (it read the containermanager xattr while building the index), so the
        // expensive grant + Saved State / Preferences probing can be skipped.
        if let identifier = indexIdentifier(forContainerPath: fallback.containerPath),
           ContainerBundleCandidateResolver.isValidBundleIdentifier(identifier) {
            let info = appInfoForBundleID(identifier) as? [String: Any] ?? [:]
            return InstalledApp(
                bundleID: identifier,
                name: info["name"] as? String ?? identifier,
                containerPath: fallback.containerPath,
                version: info["version"] as? String ?? "",
                icon: info["icon"] as? UIImage
            )
        }

        // Read the MCM identifier (containermanager xattr first, metadata plist
        // second). With the sandbox escape active the raw read succeeds even when
        // every MCM/bad_query grant is denied; on userland-only devices the
        // caller already holds a worse_query extension for this container.
        if let identifier = containerIdentifier(containerPath: fallback.containerPath) {
            let bundleID = identifier.trimmingCharacters(in: .whitespacesAndNewlines)
            if ContainerBundleCandidateResolver.isValidBundleIdentifier(bundleID),
               !bundleID.hasPrefix("systemgroup.") {
                let info = appInfoForBundleID(bundleID) as? [String: Any] ?? [:]
                let resolvedName = info["name"] as? String ?? bundleID
                return InstalledApp(
                    bundleID: bundleID,
                    name: resolvedName,
                    containerPath: fallback.containerPath,
                    version: info["version"] as? String ?? "",
                    icon: info["icon"] as? UIImage
                )
            }
        }

        let handle = grantContainerAccess(fallback.containerPath)
        defer {
            if handle >= 0 { bad_query_release(handle) }
        }

        let libraryPath = (fallback.containerPath as NSString).appendingPathComponent("Library")
        let savedStatePath = (libraryPath as NSString).appendingPathComponent("Saved Application State")
        let preferencesPath = (libraryPath as NSString).appendingPathComponent("Preferences")
        let savedStates = (try? FileManager.default.contentsOfDirectory(atPath: savedStatePath)) ?? []
        let preferences = (try? FileManager.default.contentsOfDirectory(atPath: preferencesPath)) ?? []
        let strongCandidates = ContainerBundleCandidateResolver.candidates(
            savedStateNames: savedStates,
            preferenceFileNames: []
        )
        let candidates = ContainerBundleCandidateResolver.candidates(
            savedStateNames: savedStates,
            preferenceFileNames: preferences
        )

        func resolvedApp(from candidates: [String], source: String) -> InstalledApp? {
            for bundleID in candidates {
                if let known = knownAppsByBundleID[bundleID] {
                    return InstalledApp(
                        bundleID: bundleID,
                        name: known.name,
                        containerPath: fallback.containerPath,
                        version: known.version,
                        icon: known.icon
                    )
                }

                let info = appInfoForBundleID(bundleID) as? [String: Any] ?? [:]
                guard info["found"] as? Bool == true else { continue }
                return InstalledApp(
                    bundleID: bundleID,
                    name: info["name"] as? String ?? bundleID,
                    containerPath: fallback.containerPath,
                    version: info["version"] as? String ?? "",
                    icon: info["icon"] as? UIImage
                )
            }

            guard let bundleID = ContainerBundleCandidateResolver.confirmedCandidate(
                candidates: candidates,
                launchServicesIdentifiers: launchServicesIdentifiers
            ) else {
                return nil
            }
            let uuid = (fallback.containerPath as NSString).lastPathComponent
            log("browser: content+LaunchServices confirmed \(uuid) -> \(bundleID) source=\(source)")
            return InstalledApp(
                bundleID: bundleID,
                name: bundleID,
                containerPath: fallback.containerPath,
                version: "",
                icon: nil
            )
        }

        if let app = resolvedApp(from: candidates, source: "state/preferences") {
            return app
        }
        if let bundleID = strongCandidates.first {
            return InstalledApp(
                bundleID: bundleID,
                name: bundleID,
                containerPath: fallback.containerPath,
                version: "",
                icon: nil
            )
        }

        let artifactPaths = [
            (libraryPath as NSString).appendingPathComponent("SplashBoard/Snapshots"),
            (libraryPath as NSString).appendingPathComponent("Caches/Snapshots"),
            (libraryPath as NSString).appendingPathComponent("Cookies"),
            (libraryPath as NSString).appendingPathComponent("WebKit")
        ]
        let artifactNames = artifactPaths.flatMap {
            (try? FileManager.default.contentsOfDirectory(atPath: $0)) ?? []
        }
        let artifactCandidates = ContainerBundleCandidateResolver.candidates(
            savedStateNames: [],
            preferenceFileNames: [],
            artifactNames: artifactNames
        )
        if let app = resolvedApp(from: artifactCandidates, source: "artifacts") {
            return app
        }

        let uuid = (fallback.containerPath as NSString).lastPathComponent
        let preview = (candidates + artifactCandidates).prefix(6).joined(separator: ",")
        log("browser: unresolved \(uuid) metadata=unavailable savedStates=\(savedStates.count) preferences=\(preferences.count) artifacts=\(artifactNames.count) candidates=[\(preview)]")
        return nil
    }

    static func inferUnidentifiedApps(
        in apps: [InstalledApp],
        knownApps: [InstalledApp],
        launchServicesIdentifiers: Set<String> = []
    ) -> [InstalledApp] {
        let knownByBundleID = Dictionary(knownApps.map { ($0.bundleID, $0) }, uniquingKeysWith: { first, _ in first })
        var inferredCount = 0
        let result = apps.enumerated().map { index, app -> InstalledApp in
            guard UUID(uuidString: app.bundleID) != nil,
                  let inferred = autoreleasepool(invoking: {
                      inferredApp(
                        for: app,
                        knownAppsByBundleID: knownByBundleID,
                        launchServicesIdentifiers: launchServicesIdentifiers
                      )
                  }) else {
                return app
            }
            inferredCount += 1
            if inferredCount <= 5 {
                log("browser: inferred \((app.containerPath as NSString).lastPathComponent) -> \(inferred.bundleID)")
            }
            return inferred
        }
        let unresolvedCount = result.filter { UUID(uuidString: $0.bundleID) != nil }.count
        log("browser: inferred identities for \(inferredCount)/\(apps.count) merged containers; unresolved=\(unresolvedCount)")
        return result
    }

    // MARK: File browsing

    static func listFiles(at path: String) -> [FileEntry] {
        let fm = FileManager.default
        guard let items = try? fm.contentsOfDirectory(atPath: path) else {
            log("listFiles: FAILED for \(path) errno=\(errno)")
            return []
        }
        var entries: [FileEntry] = []
        for item in items {
            if item.hasPrefix(".") { continue }
            let full = (path as NSString).appendingPathComponent(item)
            var isDir: ObjCBool = false
            guard fm.fileExists(atPath: full, isDirectory: &isDir) else { continue }
            let attributes = try? fm.attributesOfItem(atPath: full)
            let size = isDir.boolValue
                ? -1
                : (attributes?[.size] as? NSNumber)?.int64Value ?? 0
            entries.append(
                FileEntry(
                    name: item,
                    path: full,
                    isDirectory: isDir.boolValue,
                    size: size,
                    modifiedAt: attributes?[.modificationDate] as? Date
                )
            )
        }
        return entries.sorted {
            if $0.isDirectory != $1.isDirectory { return $0.isDirectory }
            return $0.name.localizedCaseInsensitiveCompare($1.name) == .orderedAscending
        }
    }

    static func readTextFile(at path: String, limit: Int = 200_000) -> String {
        guard let data = try? Data(contentsOf: URL(fileURLWithPath: path)) else {
            return "Unable to read file."
        }
        let truncated = data.prefix(limit)
        if let text = String(data: truncated, encoding: .utf8) {
            return data.count > limit ? text + "\n… [truncated]" : text
        }
        if let text = String(data: truncated, encoding: .utf16) {
            return data.count > limit ? text + "\n… [truncated]" : text
        }
        return "Binary data (\(data.count) bytes) — not text."
    }
}
