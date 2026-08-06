#!/bin/bash
# ============================================================
# FilzaJailedDS → IPA 自动构建脚本 (macOS)
# 目标: iPhone 17 Pro (iPhone18,3) / A19 Pro / iOS 26.3
# ============================================================
set -e

echo "========================================"
echo " FilzaJailedDS 26.3 IPA 构建脚本"
echo "========================================"

# ---------- 1. 环境检查 ----------
echo ""
echo "[1/6] 检查环境..."
if [ ! -d /opt/theos ]; then
    echo "  ✗ Theos 未安装，正在安装..."
    export THEOS=/opt/theos
    sudo git clone --recursive https://github.com/theos/theos.git $THEOS
    # 安装 iOS SDK (需要从 Xcode 复制)
    echo "  ⚠️ 需要从 Xcode 复制 iOS SDK 到 $THEOS/sdks/"
    echo "     Xcode → Preferences → Locations → Command Line Tools"
    echo "     或手动: cp -r /Applications/Xcode.app/Contents/Developer/Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS.sdk $THEOS/sdks/"
    exit 1
else
    echo "  ✓ Theos 已安装"
fi

# 检查 iOS SDK
if [ ! -d /opt/theos/sdks/iPhoneOS.sdk ]; then
    echo "  ✗ 缺少 iOS SDK!"
    echo "    请从 Xcode 复制 SDK 到 /opt/theos/sdks/"
    exit 1
fi
echo "  ✓ iOS SDK 已找到"

# ---------- 2. 进入项目 ----------
echo ""
echo "[2/6] 进入项目..."
PROJECT_DIR="$HOME/FilzaJailedDS"
if [ ! -d "$PROJECT_DIR" ]; then
    echo "  ✗ 未找到项目目录 $PROJECT_DIR"
    echo "    请先 git clone https://github.com/34306/FilzaJailedDS.git"
    exit 1
fi
cd "$PROJECT_DIR"
echo "  ✓ 项目目录: $PROJECT_DIR"

# ---------- 3. 替换文件 ----------
echo ""
echo "[3/6] 替换修改后的文件..."
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
FILES_TO_REPLACE=(
    "kexploit/kexploit_opa334.h"
    "kexploit/kexploit_opa334.m"
    "kexploit/offsets.m"
    "kexploit/kutils.m"
    "sandbox_escape.m"
)
for f in "${FILES_TO_REPLACE[@]}"; do
    SRC="$SCRIPT_DIR/$(basename "$f")"
    DST="$PROJECT_DIR/$f"
    if [ -f "$SRC" ]; then
        cp "$SRC" "$DST"
        echo "  ✓ 已替换: $f"
    else
        echo "  ✗ 未找到: $SRC"
        exit 1
    fi
done

# ---------- 4. 编译 ----------
echo ""
echo "[4/6] 编译..."
make clean 2>/dev/null || true
make 2>&1 | tee /tmp/build.log
if [ $? -ne 0 ]; then
    echo "  ✗ 编译失败! 查看 /tmp/build.log"
    exit 1
fi
echo "  ✓ 编译成功"

# 找到编译产物
DEB=$(ls -t *.deb 2>/dev/null | head -1)
if [ -z "$DEB" ]; then
    echo "  ✗ 未找到 .deb 文件"
    exit 1
fi
echo "  ✓ 编译产物: $DEB"

# ---------- 5. 签名打包 ----------
echo ""
echo "[5/6] 签名打包 IPA..."
# 需要: 你的企业证书 + 原版 Filza.ipa
# 这里假设你有原版 Filza.ipa 和签名工具
FILZA_IPA="Filza.ipa"
if [ ! -f "$FILZA_IPA" ]; then
    echo "  ✗ 未找到原版 Filza.ipa"
    echo "    请将原版 Filza.ipa 放在项目目录"
    exit 1
fi

# 用 zsign 或 ios-app-signer 签名
# 检查是否有 zsign
if which zsign >/dev/null 2>&1; then
    echo "  ✓ 使用 zsign 签名"
    # 解压 Filza.ipa
    unzip -o "$FILZA_IPA" -d /tmp/filza_signed/
    # 替换 dylib
    cp "$PROJECT_DIR/.theos/obj/xxx.dylib" /tmp/filza_signed/Payload/Filza.app/ 2>/dev/null || echo "  ⚠️ 需手动替换 dylib"
    # 签名
    zsign -k "证书.p12" -p "密码" /tmp/filza_signed/
    echo "  ✓ 签名完成"
else
    echo "  ⚠️ 未找到 zsign，请手动用 Xcode/ios-app-signer 签名"
fi

# ---------- 6. 完成 ----------
echo ""
echo "[6/6] 完成!"
echo "========================================"
echo " 构建产物: $PROJECT_DIR/$DEB"
echo " 安装: 用 AltStore/Sideloadly 安装到设备"
echo "========================================"

