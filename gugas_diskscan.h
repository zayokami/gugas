/* =============================================================================
 * gugas_diskscan.h
 *
 * Copyright (c) 2026 zayoka
 * =============================================================================
 */

#ifndef GUGAS_DISKSCAN_H
#define GUGAS_DISKSCAN_H

#include <windows.h>
#include <stdint.h>

/* 复用 gugas_core 的导出宏 */
#ifndef GUGAS_CORE_API
  #ifdef GUGAS_CORE_BUILD
    #define GUGAS_CORE_API __declspec(dllexport)
  #else
    #define GUGAS_CORE_API __declspec(dllimport)
  #endif
#endif

#ifdef __cplusplus
extern "C" {
#endif

/* ---------------------------------------------------------------------------
 * 原子操作（内联汇编实现）
 * ---------------------------------------------------------------------------*/

/* 原子自增，返回增加后的值 */
static inline int32_t gds_atomic_inc(int32_t volatile* ptr) {
    int32_t ret;
    __asm__ __volatile__ (
        "lock xadd %0, %1\n\t"
        "inc %0"
        : "=r" (ret), "+m" (*ptr)
        : "0" (1)
        : "memory", "cc"
    );
    return ret;
}

/* 原子加，返回旧值 */
static inline int32_t gds_atomic_add(int32_t volatile* ptr, int32_t val) {
    int32_t ret;
    __asm__ __volatile__ (
        "lock xadd %0, %1"
        : "=r" (ret), "+m" (*ptr)
        : "0" (val)
        : "memory", "cc"
    );
    return ret;
}

/* 原子比较并交换，成功返回 1 */
static inline int gds_atomic_cas(int32_t volatile* ptr,
                                  int32_t expected,
                                  int32_t newval) {
    int32_t prev;
    __asm__ __volatile__ (
        "lock cmpxchg %2, %1"
        : "=a" (prev), "+m" (*ptr)
        : "r" (newval), "a" (expected)
        : "memory", "cc"
    );
    return prev == expected;
}

/* 内存屏障 */
static inline void gds_atomic_fence(void) {
    __asm__ __volatile__ ("mfence" ::: "memory");
}

/* ---------------------------------------------------------------------------
 * PE 文件头信息（从磁盘读取）
 * ---------------------------------------------------------------------------*/
typedef struct {
    WORD    machine;          /* IMAGE_FILE_MACHINE_* */
    WORD    subsystem;        /* IMAGE_SUBSYSTEM_* */
    DWORD   timestamp;        /* TimeDateStamp */
    WORD    characteristics;  /* IMAGE_FILE_* */
    WORD    numSections;
    DWORD   entryPoint;
    DWORD   imageBase32;
    ULONGLONG imageBase64;
    int     isPE;             /* 1 = 有效的 PE 文件 */
    int     is64Bit;          /* 1 = PE32+ */
    int     hasCertDir;       /* 证书目录存在 */
} GdsPEHeader;

/* 签名验证结果 */
typedef enum {
    GDS_SIG_UNKNOWN = 0,   /* 未检查 */
    GDS_SIG_UNSIGNED,      /* 无签名 */
    GDS_SIG_VALID,         /* 签名有效 */
    GDS_SIG_INVALID,       /* 签名无效/被篡改 */
    GDS_SIG_UNTRUSTED,     /* 签名不受信任 */
    GDS_SIG_ERROR          /* 检查出错 */
} GdsSigResult;

/* ---------------------------------------------------------------------------
 * 扫描结果条目
 * ---------------------------------------------------------------------------*/
typedef struct {
    char      path[1024];
    char      name[256];
    DWORD     attributes;
    DWORD     sizeHigh;
    DWORD     sizeLow;
    FILETIME  writeTime;
    int       isSuspicious;
    char      reason[256];

    /* PE 头信息 */
    GdsPEHeader pe;
    GdsSigResult sigResult;
    char      signerName[256];  /* 签名者名称（如果有） */
    float     entropy;          /* 文件熵值（0.0-8.0），越高越可能加壳 */
} GdsFileEntry;

/* ---------------------------------------------------------------------------
 * 扫描进度（线程共享，所有字段由原子操作访问）
 * ---------------------------------------------------------------------------*/
typedef struct {
    int32_t volatile filesScanned;      /* 已扫描文件总数 */
    int32_t volatile filesSuspicious;   /* 已发现可疑文件数 */
    int32_t volatile dirsScanned;       /* 已扫描目录总数 */
    int32_t volatile running;           /* 是否仍在运行（1=是, 0=完成） */
    int32_t volatile cancelled;         /* 是否被取消（1=是） */
} GdsProgress;

/* ---------------------------------------------------------------------------
 * 扫描模式
 * ---------------------------------------------------------------------------*/
typedef enum {
    GDS_MODE_QUICK,   /* 快速：System32/SysWOW64/ProgramData, 深度 2 */
    GDS_MODE_DEEP     /* 深度：全系统, 深度 4+ */
} GdsScanMode;

/* ---------------------------------------------------------------------------
 * 导出接口
 * ---------------------------------------------------------------------------*/

/* 获取所有可用盘符。
 * outDrives: 输出缓冲，如 "CDEF"（每个字符一个盘符）
 * maxCount:  最大输出数量
 * 返回实际盘符数量 */
GUGAS_CORE_API int Gds_GetAvailableDrives(char* outDrives, int maxCount);

/* 单线程扫描单个目录。
 * rootPath  : 起始路径，如 "C:\\" 或 "C:\\Windows"
 * outList   : 输出数组
 * maxCount  : 输出数组容量
 * maxDepth  : 最大递归深度，<=0 表示无限制
 * progress  : 可选的进度统计（线程共享，NULL 表示不追踪）
 * 返回实际写入 outList 的条目数，失败返回 -1 */
GUGAS_CORE_API int Gds_ScanDirectory(const char* rootPath,
                      GdsFileEntry* outList,
                      int maxCount,
                      int maxDepth,
                      GdsProgress* progress);

/* 多线程并行扫描多个盘符。
 * drives    : 盘符数组，如 {'C','D','E'}
 * driveCount: 盘符数量
 * mode      : 扫描模式（决定默认扫描深度和路径范围）
 * outList   : 输出数组
 * maxCount  : 输出数组容量
 * progress  : 进度统计（由调用方分配，函数内部原子更新）
 * 返回实际写入 outList 的条目数，失败返回 -1 */
GUGAS_CORE_API int Gds_ScanDrivesMulti(const char* drives,
                        int driveCount,
                        GdsScanMode mode,
                        GdsFileEntry* outList,
                        int maxCount,
                        GdsProgress* progress);

/* 取消正在进行的扫描 */
static inline void Gds_CancelScan(GdsProgress* progress) {
    if (progress) {
        __asm__ __volatile__ (
            "movl $1, %0"
            : "=m" (progress->cancelled)
            :
            : "memory"
        );
    }
}

/* 重置进度 */
static inline void Gds_ResetProgress(GdsProgress* progress) {
    if (progress) {
        progress->filesScanned    = 0;
        progress->filesSuspicious = 0;
        progress->dirsScanned     = 0;
        progress->running         = 0;
        progress->cancelled       = 0;
        gds_atomic_fence();
    }
}

#ifdef __cplusplus
}
#endif

#endif /* GUGAS_DISKSCAN_H */
