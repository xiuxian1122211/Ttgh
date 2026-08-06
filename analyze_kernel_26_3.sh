#!/bin/bash
# ============================================================
# iOS 26.3 Kernelcache Offset Analyzer for iPhone18,3 (A18 Pro)
#
# Purpose: Extract actual struct offsets from iOS 26.3 kernelcache
#          to fix Filza sandbox escape on iOS 26.3
#
# Usage: ./analyze_kernel_26_3.sh
#
# Requirements: macOS with xcode-select installed
# ============================================================

set -e

TARGET_DEVICE="iPhone18,3"
BUILD="23D127"
FIRMWARE="26.3"

WORK_DIR="/tmp/kernel_analysis_26_3"
mkdir -p "$WORK_DIR"
cd "$WORK_DIR"

echo "[1/4] Checking tools..."
for cmd in unzip otool strings; do
    if ! command -v "$cmd" &>/dev/null; then
        echo "  ERROR: $cmd not found. Install Xcode CLI tools."
        exit 1
    fi
done
echo "  All tools found."

echo "[2/4] Downloading iOS 26.3 IPSW for $TARGET_DEVICE..."
# Apple's public CDN for signed firmware
IPSW_URL="https://updates-http.cdn-apple.com/2026/05/15/df9a045d-xxxx-xxxx-xxxx-xxxxxxxxxxxx/01/XXX.ipsw"

# Try ipsw.me API to get the download URL
API_URL="https://api.ipsw.me/v4/ipsw/${TARGET_DEVICE}"
echo "  Fetching firmware info from ipsw.me..."

# Check if we can use Python
if command -v python3 &>/dev/null; then
    echo "  Using python3 to fetch IPSW URL..."
    python3 << 'PYEOF'
import urllib.request
import json

url = "https://api.ipsw.me/v4/ipsw/iPhone18,3"
try:
    req = urllib.request.urlopen(url, timeout=30)
    data = json.loads(req.read().decode())
    
    # Find 26.3 release
    for key in ["build_id", "build_version"]:
        for entry in data.get(key, []):
            if entry.get("version") == "26.3" or "26.3" in str(entry.get("version", "")):
                ipsw_url = entry.get("url", "")
                build = entry.get("build", "")
                print(f"FOUND: build={build}, version=26.3")
                print(f"URL: {ipsw_url}")
                # Write to file for bash to read
                with open("ipsw_url.txt", "w") as f:
                    f.write(ipsw_url)
                break
    else:
        # If not found by version, try build number
        for entry in data.get("build_id", []):
            if "23D127" in str(entry.get("build", "")):
                ipsw_url = entry.get("url", "")
                print(f"FOUND by build: {ipsw_url}")
                with open("ipsw_url.txt", "w") as f:
                    f.write(ipsw_url)
                break
        else:
            print("26.3 not found. Listing all available versions:")
            for entry in data.get("build_id", [])[:10]:
                print(f"  {entry.get('version')} ({entry.get('build')})")
            print("Download manually from: https://ipsw.me/firmware/iPhone18_3")
except Exception as e:
    print(f"Error: {e}")
    print("Manual download: https://ipsw.me/firmware/iPhone18_3")
PYEOF
else
    echo "  python3 not found. Manual download needed."
    echo "  Go to: https://ipsw.me/firmware/iPhone18_3"
    echo "  Download the 26.3 ipsw for iPhone 16 Pro (iPhone18,3)"
    echo "  Place it in this directory as: firmware.ipsw"
fi

# Check if we have the URL
if [ -f "ipsw_url.txt" ]; then
    IPSW_URL=$(cat ipsw_url.txt)
    echo "  Downloading from: $IPSW_URL"
    curl -L --retry 3 --connect-timeout 30 --max-time 600 "$IPSW_URL" -o firmware.ipsw
    echo "  Downloaded: $(ls -lh firmware.ipsw | awk '{print $5}')"
else
    echo "  No automatic download available."
    echo "  Please download manually:"
    echo "  1. Go to https://ipsw.me/firmware/iPhone18_3"
    echo "  2. Download the iOS 26.3 (23D127) firmware"
    echo "  3. Place it in this directory as firmware.ipsw"
    echo "  4. Then re-run this script"
    echo ""
    echo "  Or on your macOS VM, run:"
    echo "  curl -L 'https://api.ipsw.me/v4/ipsw/iPhone18_3' | python3 -m json.tool | grep -A2 26.3"
    echo "  Then download the ipsw manually."
fi

if [ ! -f "firmware.ipsw" ]; then
    echo ""
    echo "  No firmware.ipsw found. Creating a sample analysis from xnu source instead..."
    echo ""
    echo "  ========================================================="
    echo "  ALTERNATIVE: Manual struct offset lookup"
    echo "  ========================================================="
    echo ""
    echo "  The proc_ro struct in xnu is defined in bsd/sys/proc.h or bsd/kern/kern_proc.c"
    echo ""
    echo "  Key fields:"
    echo "    struct proc_ro { ..."
    echo "        task_t    pr_task;        // offset 0x08"
    echo "        struct ucred *p_ucred;   // offset 0x20 (17.x) or 0x28 (18.x+) or ?"
    echo "    };"
    echo ""
    echo "  In iOS 26.0.x, off_proc_ro_p_ucred = 0x28"
    echo "  In iOS 26.3, it MAY be different. Here's how to find it:"
    echo ""
    echo "  Option A: Check xnu source at https://opensource.apple.com/tarballs/xnu/"
    echo "  Option B: Disassemble kernelcache with Hopper/Ghidra"
    echo "  Option C: Use the dump function in sandbox_escape.m (RECOMMENDED)"
    echo ""
    echo "  RECOMMENDED: Just run the modified Filza on your device and read the"
    echo "  [DUMP] output in syslog. It will show ALL values at proc_ro+0x00..0x70."
    echo ""
    echo "  To read syslog on your device:"
    echo "    sudo dmesg | grep -E \"DUMP|SBX\""
    echo "  Or via USB:"
    echo "    idevicesyslog | grep -E \"DUMP|SBX\""
    echo ""
    exit 0
fi

echo "[3/4] Extracting kernelcache from IPSW..."
# Kernelcache is inside the IPSW
if unzip -l firmware.ipsw | grep -qi "kernelcache"; then
    echo "  Found kernelcache in IPSW..."
    unzip -o firmware.ipsw "kernelcache*" -d extracted/ 2>/dev/null
    # Also check for Restore/kernelcache
    unzip -o firmware.ipsw "Restore/kernelcache*" -d extracted/ 2>/dev/null || true
    # Check for kernelcache.release.*
    for kc in extracted/kernelcache*; do
        if [ -f "$kc" ] && [ "$(stat -f%z "$kc" 2>/dev/null || echo 0)" -gt 10000000 ]; then
            KC_FILE="$kc"
            echo "  Extracted: $KC_FILE ($(ls -lh "$KC_FILE" | awk '{print $5}'))"
            break
        fi
    done
fi

if [ -z "$KC_FILE" ]; then
    echo "  Kernelcache not found in standard locations."
    echo "  Checking all files in IPSW..."
    unzip -l firmware.ipsw | grep -i kernel
fi

if [ -z "${KC_FILE:-}" ]; then
    echo "  Could not extract kernelcache. This is unusual."
    echo "  The kernelcache may be encrypted or in a non-standard location."
    echo "  Proceeding with alternative analysis..."
    
    # Try to find kernelcache in Restore/
    mkdir -p extracted
    unzip -o firmware.ipsw -d extracted/ >/dev/null 2>&1
    find extracted -name "*kernelcache*" -type f -size +10M 2>/dev/null | head -5
    for kc in $(find extracted -name "*kernelcache*" -type f -size +10M 2>/dev/null); do
        KC_FILE="$kc"
        echo "  Found: $KC_FILE ($(ls -lh "$KC_FILE" | awk '{print $5}'))"
        break
    done
fi

if [ -z "${KC_FILE:-}" ]; then
    echo ""
    echo "  No kernelcache found. This is a large ipsw (may be missing kernelcache)."
    echo "  Some ipsws have kernelcache embedded differently."
    echo ""
    echo "  Alternative: Download pre-extracted kernelcache from:"
    echo "  https://github.com/34306/kernelcache-offsets"
    echo ""
    echo "  Or just run the modified Filza and read the dump output."
    exit 0
fi

echo "[4/4] Analyzing kernelcache..."

# Try to find symbol table
SYMBOLS=$(nm "$KC_FILE" 2>/dev/null | grep -i "proc_ro\|p_ucred\|struct proc" | head -10 || true)
if [ -n "$SYMBOLS" ]; then
    echo ""
    echo "  === Symbol table (nm) ==="
    echo "$SYMBOLS"
else
    echo "  No symbols in kernelcache (stripped). Using strings analysis..."
fi

# Search for proc_ro related strings
STRINGS=$(strings "$KC_FILE" 2>/dev/null | grep -i "proc_ro\|p_ucred\|cr_label" | head -20 || true)
if [ -n "$STRINGS" ]; then
    echo ""
    echo "  === Relevant strings ==="
    echo "$STRINGS"
fi

# Use otool to look for section info
echo ""
echo "  === Mach-O section info ==="
otool -l "$KC_FILE" 2>/dev/null | grep -A5 "__data\|__text\|__bss\|__const" | head -30 || true

echo ""
echo "  === Analysis complete ==="
echo ""
echo "  The kernelcache analysis gives us limited info on a stripped binary."
echo "  The MOST PRACTICAL approach is to:"
echo ""
echo "  1. Run the modified Filza (with dump function) on your iOS 26.3 device"
echo "  2. Read syslog output: idevicesyslog | grep DUMP"
echo "  3. The dump shows ALL values at proc_ro+0x00..0x70"
echo "  4. Identify which offset points to a valid ucred"
echo "  5. Update offsets.m with the correct values"
echo ""
echo "  Expected ucred characteristics:"
echo "    - Points to a kernel address"
echo "    - Has cr_label (MAC label) at some offset (0x60-0x90)"
echo "    - The label points to a sandbox struct"
echo "    - posix_cred area has valid uid (501 for mobile, 0 for launchd)"
echo ""
echo "  Once you identify the correct offset, update offsets.m:"
echo "    off_proc_ro_p_ucred = 0x??;  // The new offset"
echo ""
