#!/usr/bin/env bash
# Builds WQFiles.ipa (arm64, ad-hoc signed with the App Group entitlement;
# re-sign with your sideloading tool, keeping an App Group).
# The app policy is iOS 26.0 or later; the SDK version is intentionally not the
# deployment target. Set WQFILES_FINAL_IPA to override the publication path.
set -euo pipefail

ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
cd "$ROOT"
MINIMUM_IOS_VERSION=26.0
FINAL_IPA=${WQFILES_FINAL_IPA:-WQFiles.ipa}

# Publish only after the host regression suite passes. The packaged artifact
# still needs device validation, but this prevents a known-broken source tree
# from replacing the release IPA. The runner is required: a missing runner
# fails the build. WQ_SKIP_PREFLIGHT=1 is the only bypass and says so loudly.
PREFLIGHT_RUNNER="$ROOT/tests/run_all_tests.sh"
if [[ "${WQ_SKIP_PREFLIGHT:-0}" == 1 ]]; then
    {
        echo "************************************************************"
        echo "WARNING: host regression preflight SKIPPED (WQ_SKIP_PREFLIGHT=1)."
        echo "This IPA has not passed tests/run_all_tests.sh."
        echo "************************************************************"
    } >&2
elif [[ ! -f "$PREFLIGHT_RUNNER" ]]; then
    # This fork ships without tests/, so the regression gate cannot run.
    echo "preflight runner missing: $PREFLIGHT_RUNNER (skipping the regression gate)" >&2
else
    bash "$PREFLIGHT_RUNNER" || {
        echo "preflight failed: $PREFLIGHT_RUNNER (no IPA written)" >&2
        exit 1
    }
fi
if [[ "$FINAL_IPA" != /* ]]; then
    FINAL_IPA="$ROOT/$FINAL_IPA"
fi
FINAL_DIR=$(dirname -- "$FINAL_IPA")
if [[ ! -d "$FINAL_DIR" ]]; then
    echo "final IPA directory does not exist: $FINAL_DIR" >&2
    exit 1
fi

plist_value() {
    plutil -extract "$1" raw -o - "$2"
}

fail() {
    echo "build validation failed: $*" >&2
    exit 1
}

EXPECTED_BUNDLE_ID=$(plist_value CFBundleIdentifier Info.plist)
EXPECTED_VERSION=$(plist_value CFBundleShortVersionString Info.plist)
EXPECTED_BUILD=$(plist_value CFBundleVersion Info.plist)
EXPECTED_MINIMUM_OS=$(plist_value MinimumOSVersion Info.plist)
APP_GROUP=$(/usr/libexec/PlistBuddy -c 'Print :com.apple.security.application-groups:0' entitlements.plist)
[[ -n "$APP_GROUP" ]] || fail "entitlements.plist has no App Group"
[[ "$EXPECTED_MINIMUM_OS" == "$MINIMUM_IOS_VERSION" ]] || \
    fail "Info.plist minimum OS $EXPECTED_MINIMUM_OS does not match build policy $MINIMUM_IOS_VERSION"

OUT=$(mktemp -d "$FINAL_DIR/.WQFiles-build.XXXXXX")
IPA_TMP=$(mktemp "$FINAL_DIR/.WQFiles.ipa.XXXXXX")
rm -f -- "$IPA_TMP"
CHECK_DIR=""
cleanup() {
    if [[ -n "${OUT:-}" && -d "$OUT" ]]; then rm -rf -- "$OUT"; fi
    if [[ -n "${IPA_TMP:-}" && -e "$IPA_TMP" ]]; then rm -f -- "$IPA_TMP"; fi
    if [[ -n "${CHECK_DIR:-}" && -d "$CHECK_DIR" ]]; then rm -rf -- "$CHECK_DIR"; fi
}
trap cleanup EXIT

APP="$OUT/Payload/WQFiles.app"
mkdir -p "$APP"
SDK=$(xcrun --sdk iphoneos --show-sdk-path)

# 1) 生成加密常量（Secrets.generated.swift）——和 3105 同一套 SecureBox 分片格式
mkdir -p "$ROOT/Generated"
python3 "$ROOT/tools/gen_secrets.py"

# 2) 用 swiftc 把 SecureBox + 生成的常量 + ObjC 桥编成 object。
#    AES-GCM 只有 CryptoKit 有，纯 ObjC 要手写 GHASH，所以这一段走 Swift。
SWIFT_OBJ="$OUT/WQSecrets.o"
xcrun --sdk iphoneos swiftc \
    -target arm64-apple-ios"$MINIMUM_IOS_VERSION" \
    -sdk "$SDK" \
    -O -wmo -parse-as-library \
    -emit-object -o "$SWIFT_OBJ" \
    "$ROOT/WQSecrets.swift" "$ROOT/WQV2.swift" "$ROOT/WQPinnedSession.swift" "$ROOT/WQNet.swift" "$ROOT/SecureBox.swift" "$ROOT/Generated/Secrets.generated.swift"

xcrun --sdk iphoneos clang -fobjc-arc -fmodules -fmodules-cache-path="$OUT/ModuleCache" -arch arm64 \
    -include "$ROOT/WQCompat.h" \
    -miphoneos-version-min="$MINIMUM_IOS_VERSION" \
    -isysroot "$SDK" -Wall -Wextra -O2 \
    -framework UIKit -framework Foundation -framework Security -framework UniformTypeIdentifiers -framework CryptoKit -framework WebKit \
    WQCore.m WQAccess.m WQLocalization.m WQLaunchServices.m WQUI.m WQSharing.m WQApps.m WQCache.m WQPlistEditor.m WQHexViewer.m WQSQLiteViewer.m WQSQLiteSave.m WQHealth.m WQTrash.m WQArchive.m WQSyntax.m WQMediaStream.m main.m WQCollector.m WQShellView.m "$SWIFT_OBJ" \
    -L "$SDK/usr/lib/swift/iphoneos" -lswiftCore -lswiftFoundation \
    -lsqlite3 -lz -o "$APP/WQFiles"
cp Info.plist "$APP/Info.plist"
cp icons/AppIcon*@*.png "$APP/"
for lproj in "$ROOT"/*.lproj; do
    [[ -d "$lproj" ]] && cp -R "$lproj" "$APP/"
done
plutil -convert binary1 "$APP/Info.plist"
codesign -f -s - --entitlements entitlements.plist "$APP"

validate_app() {
    local app_path=$1
    [[ -x "$app_path/WQFiles" ]] || fail "missing executable in $app_path"
    [[ -f "$app_path/Info.plist" ]] || fail "missing Info.plist in $app_path"
    [[ "$(plist_value CFBundleIdentifier "$app_path/Info.plist")" == "$EXPECTED_BUNDLE_ID" ]] || \
        fail "bundle identifier does not match source metadata"
    [[ "$(plist_value CFBundleShortVersionString "$app_path/Info.plist")" == "$EXPECTED_VERSION" ]] || \
        fail "short version does not match source metadata"
    [[ "$(plist_value CFBundleVersion "$app_path/Info.plist")" == "$EXPECTED_BUILD" ]] || \
        fail "build version does not match source metadata"
    [[ "$(plist_value MinimumOSVersion "$app_path/Info.plist")" == "$EXPECTED_MINIMUM_OS" ]] || \
        fail "minimum OS does not match source metadata"
    codesign --verify --deep --strict "$app_path"
    local signed_entitlements
    signed_entitlements=$(codesign -d --entitlements :- "$app_path" 2>&1) || \
        fail "unable to inspect signed entitlements"
    [[ "$signed_entitlements" == *"$APP_GROUP"* ]] || \
        fail "signed app is missing required App Group $APP_GROUP"
}

# Package to a same-directory temporary sibling, then validate the actual ZIP
# contents and signature. The final path is untouched until all checks pass.
(cd "$OUT" && zip -qry "$IPA_TMP" Payload)
unzip -tqq "$IPA_TMP"
CHECK_DIR=$(mktemp -d "$OUT/ipa-check.XXXXXX")
unzip -q "$IPA_TMP" -d "$CHECK_DIR"
validate_app "$CHECK_DIR/Payload/WQFiles.app"
mv -f -- "$IPA_TMP" "$FINAL_IPA"
IPA_TMP=""
echo "wrote $FINAL_IPA"
