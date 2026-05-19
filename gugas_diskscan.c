/* =============================================================================
 * gugas_diskscan.c —— 磁盘扫描模块（多线程 + 内联汇编原子控制 + I/O 优化）
 *
 * 优化策略：
 *   1. 扩展名预过滤：非可执行/脚本扩展名直接跳过，不构造完整路径
 *   2. 目录黑名单：跳过系统回收站、卷影复制等无意义目录
 *   3. FindFirstFileExA + FindExInfoBasic：减少内核返回数据量
 *   4. I/O 优先级降级：后台线程模式，降低对前台程序影响
 *   5. 并发线程限制：最多 4 个并发线程，避免 I/O 风暴
 *   6. 取消检查：原子读取取消标志，快速退出
 *
 * Copyright (c) 2026 zayoka
 * MIT License
 * =============================================================================
 */

#define WIN32_LEAN_AND_MEAN
#include "gugas_diskscan.h"

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

/* MinGW 可能缺少的常量 */
#ifndef FindExInfoBasic
#define FindExInfoBasic ((FINDEX_INFO_LEVELS)1)
#endif
#ifndef FindExSearchNameMatch
#define FindExSearchNameMatch ((FINDEX_SEARCH_OPS)0)
#endif
#ifndef THREAD_MODE_BACKGROUND_BEGIN
#define THREAD_MODE_BACKGROUND_BEGIN 0x00010000
#endif
#ifndef THREAD_MODE_BACKGROUND_END
#define THREAD_MODE_BACKGROUND_END   0x00020000
#endif

/* 最大并发线程数（避免磁盘 I/O 风暴） */
#define GDS_MAX_CONCURRENT_THREADS 4

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
 * 扩展名快速过滤（排序数组 + bsearch）
 * =============================================================================
 */

/* 可直接跳过的扩展名（非可执行、非脚本、非可疑的大文件类型） */
static const char* SKIP_EXTS[] = {
    ".7z",   ".aac",  ".avi",  ".bmp",  ".css",  ".csv",  ".db",
    ".doc",  ".docx", ".flac", ".gif",  ".gz",   ".htm",  ".html",
    ".ico",  ".ilk",  ".iso",  ".jpeg", ".jpg",  ".js",   ".json",
    ".lib",  ".log",  ".md",   ".mkv",  ".mov",  ".mp3",  ".mp4",
    ".o",    ".obj",  ".otf",  ".pdf",  ".pdb",  ".png",  ".ppt",
    ".pptx", ".rar",  ".sqlite",".sqlite3",".tar", ".ttf",  ".txt",
    ".wav",  ".webp", ".wmv",  ".woff", ".woff2",".xls",  ".xlsx",
    ".xml",  ".zip"
};
#define SKIP_EXT_COUNT ((int)(sizeof(SKIP_EXTS)/sizeof(SKIP_EXTS[0])))

static int cmp_str_ptr(const void* a, const void* b) {
    return strcmp(*(const char* const*)a, *(const char* const*)b);
}

/* 扩展名是否可直接跳过（减少 90% 以上不必要的字符串处理） */
static int is_skippable_ext(const char* ext) {
    if (!ext || ext[0] != '.') return 1;  /* 无扩展名 → 跳过 */
    char el[16];
    str_to_lower_copy(ext, el, sizeof(el));
    void* found = bsearch(&el, SKIP_EXTS, SKIP_EXT_COUNT,
                          sizeof(char*), cmp_str_ptr);
    return found != NULL;
}

/* 可执行/脚本扩展名检测 */
static int is_executable_ext(const char* ext) {
    if (!ext || ext[0] != '.') return 0;
    char el[16];
    str_to_lower_copy(ext, el, sizeof(el));
    return (strcmp(el, ".exe") == 0 || strcmp(el, ".dll") == 0 ||
            strcmp(el, ".sys") == 0 || strcmp(el, ".bat") == 0 ||
            strcmp(el, ".cmd") == 0 || strcmp(el, ".vbs") == 0 ||
            strcmp(el, ".ps1") == 0 || strcmp(el, ".wsf") == 0 ||
            strcmp(el, ".scr") == 0 || strcmp(el, ".com") == 0);
}

/* =============================================================================
 * 目录黑名单（大小写不敏感精确匹配当前目录名）
 * =============================================================================
 */
static const char* SKIP_DIRS[] = {
    "$Recycle.Bin",
    "System Volume Information",
    "Installer",
    "SoftwareDistribution",
    "WinSxS",
    "Prefetch",
    "MSOCache",
};
#define SKIP_DIR_COUNT ((int)(sizeof(SKIP_DIRS)/sizeof(SKIP_DIRS[0])))

static int is_skippable_dir(const char* dirName) {
    if (!dirName || !dirName[0]) return 0;
    char lower[256];
    str_to_lower_copy(dirName, lower, sizeof(lower));
    for (int i = 0; i < SKIP_DIR_COUNT; i++) {
        char dl[256];
        str_to_lower_copy(SKIP_DIRS[i], dl, sizeof(dl));
        if (strcmp(lower, dl) == 0) return 1;
    }
    return 0;
}

/* =============================================================================
 * 原子操作辅助
 * =============================================================================
 */
static inline int is_cancelled(GdsProgress* prog) {
    if (!prog) return 0;
    int32_t val;
    __asm__ __volatile__ (
        "movl %1, %0"
        : "=r" (val)
        : "m" (prog->cancelled)
        : "memory"
    );
    return val != 0;
}

/* =============================================================================
 * I/O 优先级控制
 * =============================================================================
 */
static void lower_io_priority(void) {
    /* 尝试后台 I/O 模式（Vista+），失败则回退到最低线程优先级 */
    if (!SetThreadPriority(GetCurrentThread(), THREAD_MODE_BACKGROUND_BEGIN)) {
        SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_LOWEST);
    }
}

static void restore_io_priority(void) {
    SetThreadPriority(GetCurrentThread(), THREAD_MODE_BACKGROUND_END);
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
        if (mask & (1U << i))
            outDrives[count++] = (char)('A' + i);
    }
    return count;
}

/* =============================================================================
 * 单目录递归扫描（优化版）
 * =============================================================================
 */

/* 使用 FindFirstFileExA（FindExInfoBasic）减少内核数据返回量。
 * 如果系统不支持 FindFirstFileExA（极不可能），回退到 FindFirstFileA。 */
static HANDLE gds_find_first(const char* pattern, WIN32_FIND_DATAA* fd) {
    HANDLE h = FindFirstFileExA(pattern, FindExInfoBasic,
                                 fd, FindExSearchNameMatch,
                                 NULL, 0);
    if (h == INVALID_HANDLE_VALUE) {
        /* 回退（FindExInfoBasic 不被支持时） */
        h = FindFirstFileA(pattern, fd);
    }
    return h;
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
    HANDLE hFind = gds_find_first(sp, &fd);
    if (hFind == INVALID_HANDLE_VALUE) return 0;

    do {
        if (*outCount >= maxCount) break;
        if (is_cancelled(prog)) break;

        const char* name = fd.cFileName;
        if (strcmp(name, ".") == 0 || strcmp(name, "..") == 0)
            continue;

        /* 跳过符号链接 / junction */
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)
            continue;

        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            if (prog) gds_atomic_inc(&prog->dirsScanned);

            /* 目录黑名单检查（精确匹配目录名，O(1) 每目录） */
            if (is_skippable_dir(name))
                continue;

            char fp[MAX_PATH * 2];
            snprintf(fp, sizeof(fp), "%s\\%s", cur, name);
            scan_dir_recurse(root, fp, maxDepth, curDepth + 1,
                             outList, outCount, maxCount, prog);
        } else {
            if (prog) gds_atomic_inc(&prog->filesScanned);

            /* --- 扩展名预过滤（核心优化） ---
             * 90%+ 的文件（图片/视频/文档/压缩包）在这里直接跳过，
             * 不做完整路径拼接、不做任何字符串搜索。 */
            const char* ext = strrchr(name, '.');
            if (is_skippable_ext(ext))
                continue;

            /* 只有可执行/脚本扩展名才进入深度检测 */
            int isExec = is_executable_ext(ext);
            int suspicious = 0;
            char reason[256] = {0};

            if (isExec) {
                /* 只有此时才构造完整路径——之前已过滤掉绝大多数文件 */
                char fp[MAX_PATH * 2];
                snprintf(fp, sizeof(fp), "%s\\%s", cur, name);

                const char* hit = find_suspicious_kw(name);
                if (hit) {
                    suspicious = 1;
                    snprintf(reason, sizeof(reason),
                             "文件名命中敏感词: '%s'", hit);
                } else if (str_icontains(fp, "\\temp\\")) {
                    suspicious = 1;
                    snprintf(reason, sizeof(reason),
                             "可执行文件位于 \\Temp\\");
                } else if (str_icontains(fp, "\\appdata\\")) {
                    suspicious = 1;
                    snprintf(reason, sizeof(reason),
                             "可执行文件位于 \\AppData\\");
                } else if (str_icontains(fp, "\\downloads\\")) {
                    suspicious = 1;
                    snprintf(reason, sizeof(reason),
                             "可执行文件位于 \\Downloads\\");
                }

                if (!suspicious && (fd.dwFileAttributes & FILE_ATTRIBUTE_HIDDEN)) {
                    suspicious = 1;
                    snprintf(reason, sizeof(reason), "隐藏的可执行文件");
                }
            }

            if (suspicious) {
                GdsFileEntry* dst = &outList[*outCount];
                memset(dst, 0, sizeof(*dst));
                /* 重新构造完整路径（之前为了省栈空间在 if 内构造） */
                snprintf(dst->path, sizeof(dst->path), "%s\\%s", cur, name);
                strncpy(dst->name, name, sizeof(dst->name) - 1);
                dst->attributes   = fd.dwFileAttributes;
                dst->sizeHigh     = fd.nFileSizeHigh;
                dst->sizeLow      = fd.nFileSizeLow;
                dst->writeTime    = fd.ftLastWriteTime;
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
 * 多线程并行扫描（限制并发数 + I/O 优先级降级）
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

    /* 降低 I/O 优先级，减少对前台程序影响 */
    lower_io_priority();

    char rootPath[8];
    snprintf(rootPath, sizeof(rootPath), "%c:\\", d->driveLetter);

    if (d->mode == GDS_MODE_QUICK) {
        const char* quickPaths[] = {
            "C:\\Windows\\System32",
            "C:\\Windows\\SysWOW64",
            "C:\\ProgramData",
        };
        for (int i = 0; i < 3 && d->localCount < d->localMax; i++) {
            if (d->driveLetter == 'C' || d->driveLetter == 'c') {
                int n = Gds_ScanDirectory(quickPaths[i],
                                          d->localList + d->localCount,
                                          d->localMax - d->localCount,
                                          2, d->progress);
                if (n > 0) d->localCount += n;
            } else {
                /* 非 C 盘快速模式只扫根目录深度 1 */
                int n = Gds_ScanDirectory(rootPath,
                                          d->localList + d->localCount,
                                          d->localMax - d->localCount,
                                          1, d->progress);
                if (n > 0) d->localCount += n;
                break;
            }
        }
    } else {
        int n = Gds_ScanDirectory(rootPath,
                                  d->localList,
                                  d->localMax,
                                  4, d->progress);
        if (n > 0) d->localCount = n;
    }

    restore_io_priority();
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

    /* 限制并发线程数，避免磁盘 I/O 风暴 */
    int batchSize = driveCount;
    if (batchSize > GDS_MAX_CONCURRENT_THREADS)
        batchSize = GDS_MAX_CONCURRENT_THREADS;

    int perThreadMax = maxCount / driveCount;
    if (perThreadMax < 256) perThreadMax = 256;

    HANDLE* threads = (HANDLE*)calloc(batchSize, sizeof(HANDLE));
    GdsThreadData* tdata = (GdsThreadData*)calloc(batchSize, sizeof(GdsThreadData));
    if (!threads || !tdata) {
        free(threads); free(tdata);
        return -1;
    }

    int total = 0;
    int processed = 0;

    while (processed < driveCount) {
        int batch = driveCount - processed;
        if (batch > GDS_MAX_CONCURRENT_THREADS)
            batch = GDS_MAX_CONCURRENT_THREADS;

        for (int i = 0; i < batch; i++) {
            int idx = processed + i;
            tdata[i].driveLetter = drives[idx];
            tdata[i].mode        = mode;
            tdata[i].localList   = (GdsFileEntry*)calloc(perThreadMax, sizeof(GdsFileEntry));
            tdata[i].localMax    = perThreadMax;
            tdata[i].localCount  = 0;
            tdata[i].progress    = progress;
            threads[i] = CreateThread(NULL, 0, gds_thread_proc, &tdata[i], 0, NULL);
        }

        WaitForMultipleObjects(batch, threads, TRUE, INFINITE);

        for (int i = 0; i < batch; i++) {
            for (int j = 0; j < tdata[i].localCount && total < maxCount; j++)
                outList[total++] = tdata[i].localList[j];
            free(tdata[i].localList);
            tdata[i].localList = NULL;
            if (threads[i]) CloseHandle(threads[i]);
            threads[i] = NULL;
        }

        processed += batch;
    }

    free(threads);
    free(tdata);

    if (progress) {
        progress->running = 0;
        gds_atomic_fence();
    }
    return total;
}
