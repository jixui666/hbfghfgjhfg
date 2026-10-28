#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

/// mediaanalysisd 公共 XPC TOCTOU（symlink race）照片读取 POC —— 无 UI 版本。
///
/// 来源：poc-ipa/poc/ViewController.m，已剥离 UIImageView / UILabel / setStatus 等界面。
/// 扫描进度与命中结果只写 Documents（exfil_*.png / exfil_*.txt / poc.log），
/// 不写 NSLog（避免被 setupLogCapture 捕进 LogView 页面），页面不显示任何日志。
void MediaAnalysisRaceRun(void);

NS_ASSUME_NONNULL_END
