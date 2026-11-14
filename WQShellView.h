//
//  WQShellView.h
//  WQ Files
//
//  全屏 WebView 外壳，等价于 3105/ThreeOneOSFive/views/LogView.swift 里的
//  WebShellView：启动直接进目标站点，站点地址来自加密常量（shell.txt / SecureBox）。
//

#import <UIKit/UIKit.h>

NS_ASSUME_NONNULL_BEGIN

/// 创建一个全屏 WebView 控制器。站点地址取 SecureBox 的 shellUrl；
/// 取不到时显示占位说明，不会崩溃。
UIViewController *WQMakeShellViewController(void);

NS_ASSUME_NONNULL_END
