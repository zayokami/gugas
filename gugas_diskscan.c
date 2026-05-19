/* =============================================================================
 * gugas_diskscan.c
 *
 * Copyright (c) 2026 zayoka
 * =============================================================================
 */

#define WIN32_LEAN_AND_MEAN
#include "gugas_diskscan.h"

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

/* =============================================================================
 * 敏感词检测（与 gugas_core.c 保持一致）
 * =============================================================================
 */
static const char* SUSPICIOUS_KW[] = {
    "keylogger", "hack", "spy", "injector", "hook",
    "cheat", "bypass", "dump", "rat", "trojan", "rootkit"
};
#define SUSPICIOUS_KW_COUNT ((int)(sizeof(SUSPICIOUS_KW)/sizeof(SUSPICIOUS_KW[0])))

static void str_to_lower_copy(const char* src, char* dst, size_t dstSize) {
    if (!dst || dstSize == 0) return;
    size_t i = 0;
    if (src) {
        for (; src[i] && i + 1 < dstSize; i++)
            dst[i] = (char)tolower((unsigned char)src[i]);
    }
    dst[i] = '\0';
}

static const char* find_suspicious_kw(const char* haystack) {
    if (!haystack || !haystack[0]) return NULL;
    char lower[2048];
    str_to_lower_copy(haystack, lower, sizeof(lower));
    for (int i = 0; i < SUSPICIOUS_KW_COUNT; i++)
        if (strstr(lower, SUSPICIOUS_KW[i])) return SUSPICIOUS_KW[i];
    return NULL;
}

static int str_icontains(const char* haystack, const char* needleLower) {
    if (!haystack || !needleLower) return 0;
    char lower[2048];
    str_to_lower_copy(haystack, lower, sizeof(lower));
    return strstr(lower, needleLower) != NULL;
}

/* =============================================================================
 * 获取可用盘符
 * =============================================================================
 */
int Gds_GetAvailableDrives(char* outDrives, int maxCount) {
    if (!outDrives || maxCount <= 0) return 0;

    DWORD mask = GetLogicalDrives();
    int count = 0;
    for (int i = 0; i < 26 && count < maxCount; i++) {
        if (mask & (1U << i)) {
            outDrives[count++] = (char)('A' + i);
        }
    }
    return count;
}

/* =============================================================================
 * 单目录递归扫描
 * =============================================================================
 */

/* 可执行/脚本扩展名检测 */
static int is_executable_ext(const char* ext) {
    if (!ext) return 0;
    char el[16];
    str_to_lower_copy(ext, el, sizeof(el));
    return (strcmp(el, ".exe") == 0 || strcmp(el, ".dll") == 0 ||
            strcmp(el, ".sys") == 0 || strcmp(el, ".bat") == 0 ||
            strcmp(el, ".cmd") == 0 || strcmp(el, ".vbs") == 0 ||
            strcmp(el, ".ps1") == 0 || strcmp(el, ".wsf") == 0 ||
            strcmp(el, ".scr") == 0 || strcmp(el, ".com") == 0);
}

/* 原子检查是否被取消 */
static inline int is_cancelled(GdsProgress* prog) {
    if (!prog) return 0;
    /* 使用原子读：LOCK 前缀的 xadd 读-0 不会有副作用，
     * 但更简单的方式是用编译器 barrier + volatile */
    int32_t val;
    __asm__ __volatile__ (
        "movl %1, %0"
        : "=r" (val)
        : "m" (prog->cancelled)
        : "memory"
    );
    return val != 0;
}

static int scan_dir_recurse(const char* root,
                            const char* cur,
                            int maxDepth,
                            int curDepth,
                            GdsFileEntry* outList,
                            int* outCount,
                            int maxCount,
                            GdsProgress* prog)
{
    if (*outCount >= maxCount) return 0;
    if (maxDepth > 0 && curDepth > maxDepth) return 0;
    if (is_cancelled(prog)) return 0;

    char sp[MAX_PATH * 2];
    snprintf(sp, sizeof(sp), "%s\\*.*", cur);

    WIN32_FIND_DATAA fd;
    HANDLE hFind = FindFirstFileA(sp, &fd);
    if (hFind == INVALID_HANDLE_VALUE) return 0;

    do {
        if (*outCount >= maxCount) break;
        if (is_cancelled(prog)) break;
        if (strcmp(fd.cFileName, ".") == 0 || strcmp(fd.cFileName, "..") == 0)
            continue;

        char fp[MAX_PATH * 2];
        snprintf(fp, sizeof(fp), "%s\\%s", cur, fd.cFileName);

        /* 跳过符号链接 / junction */
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)
            continue;

        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            if (prog) gds_atomic_inc(&prog->dirsScanned);
            scan_dir_recurse(root, fp, maxDepth, curDepth + 1,
                             outList, outCount, maxCount, prog);
        } else {
            if (prog) gds_atomic_inc(&prog->filesScanned);

            const char* ext = strrchr(fd.cFileName, '.');
            int isExec = is_executable_ext(ext);

            int suspicious = 0;
            char reason[256] = {0};

            if (isExec) {
                const char* hit = find_suspicious_kw(fd.cFileName);
                if (hit) {
                    suspicious = 1;
                    snprintf(reason, sizeof(reason), "文件名命中敏感词: '%s'", hit);
                } else if (str_icontains(fp, "\\temp\\")) {
                    suspicious = 1;
                    snprintf(reason, sizeof(reason), "可执行文件位于 \\Temp\\");
                } else if (str_icontains(fp, "\\appdata\\")) {
                    suspicious = 1;
                    snprintf(reason, sizeof(reason), "可执行文件位于 \\AppData\\");
                } else if (str_icontains(fp, "\\downloads\\")) {
                    suspicious = 1;
                    snprintf(reason, sizeof(reason), "可执行文件位于 \\Downloads\\");
                }
            }
            if ((fd.dwFileAttributes & FILE_ATTRIBUTE_HIDDEN) && isExec && !suspicious) {
                suspicious = 1;
                snprintf(reason, sizeof(reason), "隐藏的可执行文件");
            }

            if (suspicious) {
                GdsFileEntry* dst = &outList[*outCount];
                memset(dst, 0, sizeof(*dst));
                strncpy(dst->path, fp, sizeof(dst->path) - 1);
                strncpy(dst->name, fd.cFileName, sizeof(dst->name) - 1);
                dst->attributes = fd.dwFileAttributes;
                dst->sizeHigh   = fd.nFileSizeHigh;
                dst->sizeLow    = fd.nFileSizeLow;
                dst->writeTime  = fd.ftLastWriteTime;
                dst->isSuspicious = 1;
                strncpy(dst->reason, reason, sizeof(dst->reason) - 1);
                (*outCount)++;
                if (prog) gds_atomic_inc(&prog->filesSuspicious);
            }
        }
    } while (FindNextFileA(hFind, &fd));

    FindClose(hFind);
    return 0;
}

int Gds_ScanDirectory(const char* rootPath,
                      GdsFileEntry* outList,
                      int maxCount,
                      int maxDepth,
                      GdsProgress* progress)
{
    if (!rootPath || !outList || maxCount <= 0) return -1;

    int count = 0;
    scan_dir_recurse(rootPath, rootPath, maxDepth, 0,
                     outList, &count, maxCount, progress);
    return count;
}

/* =============================================================================
 * 多线程并行扫描
 * =============================================================================
 */

typedef struct {
    char       driveLetter;
    GdsScanMode mode;
    GdsFileEntry* localList;
    int        localMax;
    int        localCount;
    GdsProgress* progress;
} GdsThreadData;

static DWORD WINAPI gds_thread_proc(LPVOID lpParam) {
    GdsThreadData* d = (GdsThreadData*)lpParam;
    d->localCount = 0;

    char rootPath[8];
    snprintf(rootPath, sizeof(rootPath), "%c:\\", d->driveLetter);

    if (d->mode == GDS_MODE_QUICK) {
        /* 快速模式：扫描系统关键目录 */
        const char* quickPaths[] = {
            "C:\\Windows\\System32",
            "C:\\Windows\\SysWOW64",
            "C:\\ProgramData",
        };
        for (int i = 0; i < 3 && d->localCount < d->localMax; i++) {
            /* 只有 C 盘有这些路径；其他盘直接扫根目录（一般只有用户数据） */
            if (d->driveLetter == 'C' || d->driveLetter == 'c') {
                int n = Gds_ScanDirectory(quickPaths[i],
                                          d->localList + d->localCount,
                                          d->localMax - d->localCount,
                                          2, d->progress);
                if (n > 0) d->localCount += n;
            } else {
                /* 非 C 盘快速模式只扫根目录深度 1 */
                char dp[8];
                snprintf(dp, sizeof(dp), "%c:\\", d->driveLetter);
                int n = Gds_ScanDirectory(dp,
                                          d->localList + d->localCount,
                                          d->localMax - d->localCount,
                                          1, d->progress);
                if (n > 0) d->localCount += n;
                break;
            }
        }
    } else {
        /* 深度模式：全盘递归 */
        int n = Gds_ScanDirectory(rootPath,
                                  d->localList,
                                  d->localMax,
                                  4, d->progress);
        if (n > 0) d->localCount = n;
    }
    return 0;
}

int Gds_ScanDrivesMulti(const char* drives,
                        int driveCount,
                        GdsScanMode mode,
                        GdsFileEntry* outList,
                        int maxCount,
                        GdsProgress* progress)
{
    if (!drives || driveCount <= 0 || !outList || maxCount <= 0)
        return -1;

    if (driveCount == 1) {
        char rootPath[8];
        snprintf(rootPath, sizeof(rootPath), "%c:\\", drives[0]);
        int maxDepth = (mode == GDS_MODE_QUICK) ? 2 : 4;
        return Gds_ScanDirectory(rootPath, outList, maxCount, maxDepth, progress);
    }

    if (progress) {
        progress->running = 1;
        gds_atomic_fence();
    }

    HANDLE* threads = (HANDLE*)calloc(driveCount, sizeof(HANDLE));
    GdsThreadData* tdata = (GdsThreadData*)calloc(driveCount, sizeof(GdsThreadData));
    if (!threads || !tdata) {
        free(threads); free(tdata);
        return -1;
    }

    /* 每个线程分配独立的输出缓冲，避免锁竞争 */
    int perThreadMax = maxCount / driveCount;
    if (perThreadMax < 256) perThreadMax = 256;

    for (int i = 0; i < driveCount; i++) {
        tdata[i].driveLetter = drives[i];
        tdata[i].mode        = mode;
        tdata[i].localList   = (GdsFileEntry*)calloc(perThreadMax, sizeof(GdsFileEntry));
        tdata[i].localMax    = perThreadMax;
        tdata[i].localCount  = 0;
        tdata[i].progress    = progress;
        threads[i] = CreateThread(NULL, 0, gds_thread_proc, &tdata[i], 0, NULL);
    }

    WaitForMultipleObjects(driveCount, threads, TRUE, INFINITE);

    int total = 0;
    for (int i = 0; i < driveCount; i++) {
        for (int j = 0; j < tdata[i].localCount && total < maxCount; j++) {
            outList[total++] = tdata[i].localList[j];
        }
        free(tdata[i].localList);
        if (threads[i]) CloseHandle(threads[i]);
    }

    free(threads);
    free(tdata);

    if (progress) {
        progress->running = 0;
        gds_atomic_fence();
    }
    return total;
}
