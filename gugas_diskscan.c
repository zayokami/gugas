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
#include <math.h>

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
 * PE 文件头解析
 * =============================================================================
 */

/* 简化的 PE 结构（与 Windows SDK 兼容） */
#pragma pack(push, 1)
typedef struct {
    WORD  e_magic; WORD  e_cblp; WORD  e_cp; WORD  e_crlc;
    WORD  e_cparhdr; WORD  e_minalloc; WORD  e_maxalloc;
    WORD  e_ss; WORD  e_sp; WORD  e_csum; WORD  e_ip;
    WORD  e_cs; WORD  e_lfarlc; WORD  e_ovno;
    WORD  e_res[4]; WORD  e_oemid; WORD  e_oeminfo;
    WORD  e_res2[10]; LONG  e_lfanew;
} GDS_IMAGE_DOS_HEADER;

typedef struct {
    WORD  Machine; WORD  NumberOfSections;
    DWORD TimeDateStamp; DWORD PointerToSymbolTable;
    DWORD NumberOfSymbols; WORD  SizeOfOptionalHeader;
    WORD  Characteristics;
} GDS_IMAGE_FILE_HEADER;

typedef struct { DWORD VirtualAddress; DWORD Size; } GDS_IMAGE_DATA_DIRECTORY;

typedef struct {
    WORD  Magic; BYTE  MajorLinkerVersion; BYTE  MinorLinkerVersion;
    DWORD SizeOfCode; DWORD SizeOfInitializedData;
    DWORD SizeOfUninitializedData; DWORD AddressOfEntryPoint;
    DWORD BaseOfCode; DWORD BaseOfData; DWORD ImageBase;
    DWORD SectionAlignment; DWORD FileAlignment;
    WORD  MajorOperatingSystemVersion; WORD  MinorOperatingSystemVersion;
    WORD  MajorImageVersion; WORD  MinorImageVersion;
    WORD  MajorSubsystemVersion; WORD  MinorSubsystemVersion;
    DWORD Win32VersionValue; DWORD SizeOfImage;
    DWORD SizeOfHeaders; DWORD CheckSum;
    WORD  Subsystem; WORD  DllCharacteristics;
    DWORD SizeOfStackReserve; DWORD SizeOfStackCommit;
    DWORD SizeOfHeapReserve; DWORD SizeOfHeapCommit;
    DWORD LoaderFlags; DWORD NumberOfRvaAndSizes;
    GDS_IMAGE_DATA_DIRECTORY DataDirectory[16];
} GDS_IMAGE_OPTIONAL_HEADER32;

typedef struct {
    WORD  Magic; BYTE  MajorLinkerVersion; BYTE  MinorLinkerVersion;
    DWORD SizeOfCode; DWORD SizeOfInitializedData;
    DWORD SizeOfUninitializedData; DWORD AddressOfEntryPoint;
    DWORD BaseOfCode; ULONGLONG ImageBase;
    DWORD SectionAlignment; DWORD FileAlignment;
    WORD  MajorOperatingSystemVersion; WORD  MinorOperatingSystemVersion;
    WORD  MajorImageVersion; WORD  MinorImageVersion;
    WORD  MajorSubsystemVersion; WORD  MinorSubsystemVersion;
    DWORD Win32VersionValue; DWORD SizeOfImage;
    DWORD SizeOfHeaders; DWORD CheckSum;
    WORD  Subsystem; WORD  DllCharacteristics;
    ULONGLONG SizeOfStackReserve; ULONGLONG SizeOfStackCommit;
    ULONGLONG SizeOfHeapReserve; ULONGLONG SizeOfHeapCommit;
    DWORD LoaderFlags; DWORD NumberOfRvaAndSizes;
    GDS_IMAGE_DATA_DIRECTORY DataDirectory[16];
} GDS_IMAGE_OPTIONAL_HEADER64;

typedef struct {
    DWORD Signature;
    GDS_IMAGE_FILE_HEADER FileHeader;
} GDS_IMAGE_NT_HEADERS;
#pragma pack(pop)

#define GDS_IMAGE_DOS_SIGNATURE  0x5A4D
#define GDS_IMAGE_NT_SIGNATURE   0x00004550
#define GDS_IMAGE_NT_OPTIONAL_HDR32_MAGIC 0x10b
#define GDS_IMAGE_NT_OPTIONAL_HDR64_MAGIC 0x20b

/* 读取文件前 8KB 并解析 PE 头 */
static int gds_read_pe_header(const char* path, GdsPEHeader* out) {
    memset(out, 0, sizeof(*out));
    HANDLE hFile = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ,
                                NULL, OPEN_EXISTING,
                                FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN,
                                NULL);
    if (hFile == INVALID_HANDLE_VALUE) return 0;

    BYTE buf[8192];
    DWORD read = 0;
    if (!ReadFile(hFile, buf, sizeof(buf), &read, NULL) || read < 128) {
        CloseHandle(hFile); return 0;
    }
    CloseHandle(hFile);

    GDS_IMAGE_DOS_HEADER* dos = (GDS_IMAGE_DOS_HEADER*)buf;
    if (dos->e_magic != GDS_IMAGE_DOS_SIGNATURE) return 0;

    LONG peOff = dos->e_lfanew;
    if (peOff < 0 || (size_t)(peOff + 4) > read) return 0;

    DWORD* peSig = (DWORD*)(buf + peOff);
    if (*peSig != GDS_IMAGE_NT_SIGNATURE) return 0;

    GDS_IMAGE_NT_HEADERS* nth = (GDS_IMAGE_NT_HEADERS*)(buf + peOff);
    out->isPE  = 1;
    out->machine = nth->FileHeader.Machine;
    out->timestamp = nth->FileHeader.TimeDateStamp;
    out->characteristics = nth->FileHeader.Characteristics;
    out->numSections = nth->FileHeader.NumberOfSections;

    WORD optMagic = *(WORD*)((BYTE*)nth + sizeof(GDS_IMAGE_NT_HEADERS));
    if (optMagic == GDS_IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        out->is64Bit = 1;
        GDS_IMAGE_OPTIONAL_HEADER64* opt =
            (GDS_IMAGE_OPTIONAL_HEADER64*)((BYTE*)nth + sizeof(GDS_IMAGE_NT_HEADERS));
        out->subsystem   = opt->Subsystem;
        out->entryPoint = opt->AddressOfEntryPoint;
        out->imageBase64 = opt->ImageBase;
        out->hasCertDir = (opt->DataDirectory[4].VirtualAddress != 0 &&
                           opt->DataDirectory[4].Size != 0);
    } else if (optMagic == GDS_IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
        GDS_IMAGE_OPTIONAL_HEADER32* opt =
            (GDS_IMAGE_OPTIONAL_HEADER32*)((BYTE*)nth + sizeof(GDS_IMAGE_NT_HEADERS));
        out->subsystem   = opt->Subsystem;
        out->entryPoint = opt->AddressOfEntryPoint;
        out->imageBase32 = opt->ImageBase;
        out->hasCertDir = (opt->DataDirectory[4].VirtualAddress != 0 &&
                           opt->DataDirectory[4].Size != 0);
    }
    return 1;
}

/* 计算文件熵值（0.0 - 8.0），读取前 64KB 采样 */
static float gds_calc_entropy(const char* path) {
    HANDLE hFile = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ,
                                NULL, OPEN_EXISTING,
                                FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN,
                                NULL);
    if (hFile == INVALID_HANDLE_VALUE) return 0.0f;

    DWORD freq[256] = {0};
    BYTE buf[4096];
    DWORD total = 0;
    while (total < 65536) {
        DWORD rd = 0;
        if (!ReadFile(hFile, buf, sizeof(buf), &rd, NULL) || rd == 0) break;
        for (DWORD i = 0; i < rd; i++) freq[buf[i]]++;
        total += rd;
    }
    CloseHandle(hFile);
    if (total == 0) return 0.0f;

    double entropy = 0.0;
    for (int i = 0; i < 256; i++) {
        if (freq[i] == 0) continue;
        double p = (double)freq[i] / (double)total;
        entropy -= p * log2(p);
    }
    return (float)entropy;
}

/* =============================================================================
 * 数字签名验证（WinVerifyTrust）
 * =============================================================================
 */
#include <wintrust.h>
#include <softpub.h>

static GdsSigResult gds_verify_signature(const char* path) {
    wchar_t wpath[MAX_PATH];
    if (MultiByteToWideChar(CP_UTF8, 0, path, -1, wpath, MAX_PATH) == 0)
        return GDS_SIG_ERROR;

    WINTRUST_FILE_INFO fileInfo = {0};
    fileInfo.cbStruct = sizeof(fileInfo);
    fileInfo.pcwszFilePath = wpath;

    GUID action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    WINTRUST_DATA trustData = {0};
    trustData.cbStruct = sizeof(trustData);
    trustData.dwUIChoice = WTD_UI_NONE;
    trustData.fdwRevocationChecks = WTD_REVOKE_NONE;
    trustData.dwUnionChoice = WTD_CHOICE_FILE;
    trustData.pFile = &fileInfo;
    trustData.dwStateAction = WTD_STATEACTION_VERIFY;
    trustData.dwProvFlags = WTD_SAFER_FLAG;

    LONG status = WinVerifyTrust((HWND)INVALID_HANDLE_VALUE, &action, &trustData);

    trustData.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust((HWND)INVALID_HANDLE_VALUE, &action, &trustData);

    if (status == ERROR_SUCCESS)         return GDS_SIG_VALID;
    if (status == TRUST_E_NOSIGNATURE)   return GDS_SIG_UNSIGNED;
    if (status == TRUST_E_EXPLICIT_DISTRUST) return GDS_SIG_UNTRUSTED;
    if (status == CRYPT_E_SECURITY_SETTINGS)   return GDS_SIG_UNTRUSTED;
    return GDS_SIG_INVALID;
}

/* =============================================================================
 * 扩展名快速过滤
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

/* 扩展名是否可直接跳过（线性查找，50+ 项，开销可忽略） */
static int is_skippable_ext(const char* ext) {
    if (!ext || ext[0] != '.') return 1;  /* 无扩展名 → 跳过 */
    char el[16];
    str_to_lower_copy(ext, el, sizeof(el));
    for (int i = 0; i < SKIP_EXT_COUNT; i++)
        if (strcmp(el, SKIP_EXTS[i]) == 0) return 1;
    return 0;
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
                /* 重新构造完整路径 */
                snprintf(dst->path, sizeof(dst->path), "%s\\%s", cur, name);
                strncpy(dst->name, name, sizeof(dst->name) - 1);
                dst->attributes   = fd.dwFileAttributes;
                dst->sizeHigh     = fd.nFileSizeHigh;
                dst->sizeLow      = fd.nFileSizeLow;
                dst->writeTime    = fd.ftLastWriteTime;
                dst->isSuspicious = 1;
                strncpy(dst->reason, reason, sizeof(dst->reason) - 1);

                /* 读取 PE 头、熵值、签名（只对可疑可执行文件） */
                if (isExec) {
                    gds_read_pe_header(dst->path, &dst->pe);
                    dst->entropy = gds_calc_entropy(dst->path);
                    if (dst->pe.hasCertDir)
                        dst->sigResult = gds_verify_signature(dst->path);
                    else
                        dst->sigResult = GDS_SIG_UNSIGNED;

                    /* 熵值过高（>= 7.5）追加可疑原因 */
                    if (dst->entropy >= 7.5f) {
                        char tmp[512];
                        snprintf(tmp, sizeof(tmp), "%s | 高熵值 %.2f（可能加壳/加密）",
                                 dst->reason, dst->entropy);
                        strncpy(dst->reason, tmp, sizeof(dst->reason) - 1);
                        dst->reason[sizeof(dst->reason) - 1] = '\0';
                    }
                    /* 无签名追加提示 */
                    if (dst->sigResult == GDS_SIG_UNSIGNED) {
                        char tmp[512];
                        snprintf(tmp, sizeof(tmp), "%s | 无数字签名", dst->reason);
                        strncpy(dst->reason, tmp, sizeof(dst->reason) - 1);
                        dst->reason[sizeof(dst->reason) - 1] = '\0';
                    }
                    /* 签名无效追加提示 */
                    if (dst->sigResult == GDS_SIG_INVALID ||
                        dst->sigResult == GDS_SIG_UNTRUSTED) {
                        char tmp[512];
                        snprintf(tmp, sizeof(tmp), "%s | 签名无效/不受信任", dst->reason);
                        strncpy(dst->reason, tmp, sizeof(dst->reason) - 1);
                        dst->reason[sizeof(dst->reason) - 1] = '\0';
                    }
                }

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
