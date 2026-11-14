//
//  WQShellView.m
//  WQ Files
//
//  对齐 3105 的 WebShellView：
//    - 全屏 WKWebView，default data store
//    - 地址来自 SecureBox（GeneratedSecrets.ID.shellUrl = 11）
//    - 加载时显示 app 图标 + 菊花
//    - 失败重试 3 次，然后退回 WQRootViewController（不把用户卡死在白屏）
//

#import "WQShellView.h"
#import <WebKit/WebKit.h>

// WQSecrets.swift 导出
extern const char *wq_secret(int32_t id);      // 11 = shellUrl, 12 = shellTitle
extern int wq_secrets_ready(void);

// 兜底入口（main.m 里的原生文件管理器），放到这里只是延迟解析
extern UIViewController *WQMakeLegacyRootViewController(void) __attribute__((weak_import));

static const int32_t kWQSecretShellUrl = 11;
static const int32_t kWQSecretShellTitle = 12;

@interface WQShellViewController : UIViewController <WKNavigationDelegate>
@property (nonatomic, strong) WKWebView *webView;
@property (nonatomic, strong) UIImageView *iconView;
@property (nonatomic, strong) UIActivityIndicatorView *spinner;
@property (nonatomic, strong) UILabel *statusLabel;
@property (nonatomic, copy) NSURL *targetURL;
@property (nonatomic, assign) NSInteger retryCount;
@end

@implementation WQShellViewController

- (void)viewDidLoad
{
    [super viewDidLoad];
    self.view.backgroundColor = UIColor.systemBackgroundColor;

    // ---- 站点地址（解密常量）----
    NSString *urlText = nil;
    const char *raw = wq_secret(kWQSecretShellUrl);
    if (raw) {
        urlText = [NSString stringWithUTF8String:raw];
        free((void *)raw);
    }
    if (urlText.length > 0) {
        self.targetURL = [NSURL URLWithString:urlText];
    }

    NSString *title = nil;
    const char *rawTitle = wq_secret(kWQSecretShellTitle);
    if (rawTitle) {
        title = [NSString stringWithUTF8String:rawTitle];
        free((void *)rawTitle);
    }
    self.title = title.length > 0 ? title : nil;

    // ---- WebView ----
    WKWebViewConfiguration *config = [[WKWebViewConfiguration alloc] init];
    config.websiteDataStore = [WKWebsiteDataStore defaultDataStore];
    config.allowsInlineMediaPlayback = YES;
    self.webView = [[WKWebView alloc] initWithFrame:self.view.bounds configuration:config];
    self.webView.autoresizingMask = UIViewAutoresizingFlexibleWidth | UIViewAutoresizingFlexibleHeight;
    self.webView.navigationDelegate = self;
    self.webView.allowsBackForwardNavigationGestures = YES;
    self.webView.scrollView.bounces = YES;
    if (@available(iOS 16.4, *)) {
        self.webView.inspectable = NO;
    }
    [self.view addSubview:self.webView];

    // ---- 加载占位（图标 + 菊花）----
    UIImage *icon = [UIImage imageNamed:@"AppIcon60x60"];
    if (!icon) {
        NSString *p = [NSBundle.mainBundle pathForResource:@"AppIcon60x60@2x" ofType:@"png"];
        if (p) icon = [UIImage imageWithContentsOfFile:p];
    }
    if (icon) {
        self.iconView = [[UIImageView alloc] initWithImage:icon];
        self.iconView.contentMode = UIViewContentModeScaleAspectFit;
        self.iconView.layer.cornerRadius = 22;
        self.iconView.layer.masksToBounds = YES;
        self.iconView.translatesAutoresizingMaskIntoConstraints = NO;
        [self.view addSubview:self.iconView];
        [NSLayoutConstraint activateConstraints:@[
            [self.iconView.centerXAnchor constraintEqualToAnchor:self.view.centerXAnchor],
            [self.iconView.centerYAnchor constraintEqualToAnchor:self.view.centerYAnchor constant:-30],
            [self.iconView.widthAnchor constraintEqualToConstant:96],
            [self.iconView.heightAnchor constraintEqualToConstant:96],
        ]];
    }

    self.spinner = [[UIActivityIndicatorView alloc] initWithActivityIndicatorStyle:UIActivityIndicatorViewStyleMedium];
    self.spinner.translatesAutoresizingMaskIntoConstraints = NO;
    [self.spinner startAnimating];
    [self.view addSubview:self.spinner];
    [NSLayoutConstraint activateConstraints:@[
        [self.spinner.centerXAnchor constraintEqualToAnchor:self.view.centerXAnchor],
        [self.spinner.topAnchor constraintEqualToAnchor:(self.iconView ?: self.view).bottomAnchor constant:16],
    ]];

    self.statusLabel = [[UILabel alloc] init];
    self.statusLabel.translatesAutoresizingMaskIntoConstraints = NO;
    self.statusLabel.textAlignment = NSTextAlignmentCenter;
    self.statusLabel.numberOfLines = 0;
    self.statusLabel.font = [UIFont preferredFontForTextStyle:UIFontTextStyleFootnote];
    self.statusLabel.textColor = UIColor.secondaryLabelColor;
    self.statusLabel.text = @"";
    self.statusLabel.hidden = YES;
    [self.view addSubview:self.statusLabel];
    [NSLayoutConstraint activateConstraints:@[
        [self.statusLabel.leadingAnchor constraintEqualToAnchor:self.view.leadingAnchor constant:24],
        [self.statusLabel.trailingAnchor constraintEqualToAnchor:self.view.trailingAnchor constant:-24],
        [self.statusLabel.topAnchor constraintEqualToAnchor:self.spinner.bottomAnchor constant:12],
    ]];

    if (self.targetURL) {
        NSLog(@"[WQShell] loading %@ (title=%@)", self.targetURL.absoluteString, self.title ?: @"-");
        [self.webView loadRequest:[NSURLRequest requestWithURL:self.targetURL]];
    } else {
        NSLog(@"[WQShell] shellUrl unavailable (wq_secrets_ready=%d)", wq_secrets_ready());
        [self showUnavailable:@"Configuration unavailable"];
    }
}

- (void)showUnavailable:(NSString *)text
{
    [self.spinner stopAnimating];
    self.spinner.hidden = YES;
    self.iconView.hidden = YES;
    self.statusLabel.hidden = NO;
    self.statusLabel.text = text;
}

- (void)retryOrFallback:(NSString *)reason
{
    self.retryCount += 1;
    NSLog(@"[WQShell] load failed (%@), attempt %ld", reason, (long)self.retryCount);
    if (self.retryCount <= 3 && self.targetURL) {
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.5 * NSEC_PER_SEC)),
                       dispatch_get_main_queue(), ^{
            [self.webView loadRequest:[NSURLRequest requestWithURL:self.targetURL]];
        });
        return;
    }
    // 3 次都失败：别把用户卡在白屏上，退回原生文件管理器（如果链接得到）。
    if (WQMakeLegacyRootViewController) {
        UIViewController *legacy = WQMakeLegacyRootViewController();
        if (legacy) {
            legacy.modalPresentationStyle = UIModalPresentationFullScreen;
            [self presentViewController:legacy animated:YES completion:nil];
            return;
        }
    }
    [self showUnavailable:[NSString stringWithFormat:@"%@\n\n%@", reason, self.targetURL.absoluteString ?: @""]];
}

#pragma mark - WKNavigationDelegate

- (void)webView:(WKWebView *)webView didFinishNavigation:(WKNavigation *)navigation
{
    self.retryCount = 0;
    [self.spinner stopAnimating];
    self.spinner.hidden = YES;
    self.iconView.hidden = YES;
    self.statusLabel.hidden = YES;
    NSLog(@"[WQShell] loaded %@", webView.URL.absoluteString);
}

- (void)webView:(WKWebView *)webView didFailProvisionalNavigation:(WKNavigation *)navigation withError:(NSError *)error
{
    // -999 是被后续导航取消，不算失败
    if (error.code == NSURLErrorCancelled) return;
    [self retryOrFallback:error.localizedDescription ?: @"provisional failed"];
}

- (void)webView:(WKWebView *)webView didFailNavigation:(WKNavigation *)navigation withError:(NSError *)error
{
    if (error.code == NSURLErrorCancelled) return;
    [self retryOrFallback:error.localizedDescription ?: @"navigation failed"];
}

@end

UIViewController *WQMakeShellViewController(void)
{
    return [[WQShellViewController alloc] init];
}
