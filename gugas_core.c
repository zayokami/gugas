/* =============================================================================
 * gugas_core.c
 *
 * Copyright (c) 2026 zayoka
 *
 * Compile (DLL) / 编译命令：
 *   C:/mingw64/bin/gcc -std=c11 -O2 -shared \
 *       -Wno-stringop-truncation \
 *       -o gugas_core.dll gugas_core.c \
 *       -lpsapi -luser32 -lkernel32 -ladvapi32 \
 *       -static-libgcc \
 *       -Wl,--out-implib,libgugas_core.dll.a
 * =============================================================================
 */

#define WIN32_LEAN_AND_MEAN
#define _WIN32_WINNT 0x0A00      /* Windows 10 */
#ifndef GUGAS_CORE_BUILD
#define GUGAS_CORE_BUILD          /* 让 GUGAS_CORE_API 解析为 dllexport */
#endif

#include "gugas_core.h"

#include <windows.h>
#include <tlhelp32.h>             /* CreateToolhelp32Snapshot / Process32First */
#include <psapi.h>                /* EnumDeviceDrivers / GetDeviceDriverBaseNameA / QueryFullProcessImageNameA */
#include <iphlpapi.h>             /* GetExtendedTcpTable / GetExtendedUdpTable */
#include <shlobj.h>               /* SHGetFolderPathA / CSIDL_* */
#include <ws2tcpip.h>             /* ntohs */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stdint.h>

/* SetWindowDisplayAffinity 的常量在某些 MinGW 头里不一定齐全，自行兜底 */
#ifndef WDA_NONE
#define WDA_NONE                0x00000000
#endif
#ifndef WDA_MONITOR
#define WDA_MONITOR             0x00000001
#endif
#ifndef WDA_EXCLUDEFROMCAPTURE
#define WDA_EXCLUDEFROMCAPTURE  0x00000011  /* Win10 2004+ : 真正从截屏中排除 */
#endif

/* =============================================================================
 * 通用工具
 * =============================================================================
 */

/* 敏感词数组（小写形式，比对前会把目标串也转小写） */
static const char* SUSPICIOUS_KW[] = {
    "keylogger", "hack", "spy", "injector", "hook",
    "cheat", "bypass", "dump", "rat", "trojan", "rootkit"
};
#define SUSPICIOUS_KW_COUNT ((int)(sizeof(SUSPICIOUS_KW)/sizeof(SUSPICIOUS_KW[0])))

/* 线程局部错误缓冲：每次导出函数失败时写入，供 Gugas_GetLastErrorString 读取 */
static __thread char g_lastError[256] = {0};

/* 把 Win32 错误码格式化为人类可读文本，存入 g_lastError */
static void SetDllError(const char* ctx, DWORD err) {
    g_lastError[0] = '\0';
    if (!ctx) ctx = "未知错误";

    char sysMsg[512] = {0};
    if (err != 0) {
        FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                       NULL, err, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                       sysMsg, sizeof(sysMsg), NULL);
        /* 去掉尾部的换行/回车 */
        size_t L = strlen(sysMsg);
        while (L > 0 && (sysMsg[L-1] == '\r' || sysMsg[L-1] == '\n'))
            sysMsg[--L] = '\0';
    }

    if (sysMsg[0]) {
        snprintf(g_lastError, sizeof(g_lastError), "%s: %s (错误码 %lu)",
                 ctx, sysMsg, (unsigned long)err);
    } else {
        snprintf(g_lastError, sizeof(g_lastError), "%s", ctx);
    }
}

/* 导出：获取最近一次错误描述 */
GUGAS_CORE_API const char* Gugas_GetLastErrorString(void) {
    return g_lastError;
}

/* 把字符串拷贝并转小写到目标缓冲，最多 dstSize-1 字节 */
static void str_to_lower_copy(const char* src, char* dst, size_t dstSize) {
    if (!dst || dstSize == 0) return;
    size_t i = 0;
    if (src) {
        for (; src[i] && i + 1 < dstSize; i++) {
            dst[i] = (char)tolower((unsigned char)src[i]);
        }
    }
    dst[i] = '\0';
}

/* 大小写不敏感地检查 haystack 是否含任一敏感词
 * 返回命中的关键字指针；未命中返回 NULL */
static const char* find_suspicious_kw(const char* haystack) {
    if (!haystack || !haystack[0]) return NULL;
    char lower[2048];
    str_to_lower_copy(haystack, lower, sizeof(lower));
    for (int i = 0; i < SUSPICIOUS_KW_COUNT; i++) {
        if (strstr(lower, SUSPICIOUS_KW[i])) return SUSPICIOUS_KW[i];
    }
    return NULL;
}

/* 大小写不敏感的子串匹配（用于 \Temp\ \AppData\ 这类路径片段） */
static int str_icontains(const char* haystack, const char* needleLower) {
    if (!haystack || !needleLower) return 0;
    char lower[2048];
    str_to_lower_copy(haystack, lower, sizeof(lower));
    return strstr(lower, needleLower) != NULL;
}

/* 取 path 中最后一个 '\' 之后的部分（basename） */
static const char* path_basename(const char* path) {
    if (!path) return "";
    const char* p = strrchr(path, '\\');
    if (p) return p + 1;
    p = strrchr(path, '/');
    if (p) return p + 1;
    return path;
}

/* =============================================================================
 * Gugas_ScanProcesses —— 枚举所有进程并标记可疑项
 * =============================================================================
 */
GUGAS_CORE_API void Gugas_ScanProcesses(ProcessInfo* outList, int* outCount, int maxCount) {
    g_lastError[0] = '\0';
    if (!outList || !outCount || maxCount <= 0) {
        if (outCount) *outCount = -1;
        SetDllError("参数非法: outList/outCount 为空或 maxCount<=0", 0);
        return;
    }
    *outCount = 0;

    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) {
        SetDllError("CreateToolhelp32Snapshot 失败", GetLastError());
        *outCount = -1;
        return;
    }

    PROCESSENTRY32 pe = {0};
    pe.dwSize = sizeof(pe);

    if (!Process32First(hSnap, &pe)) {
        SetDllError("Process32First 失败", GetLastError());
        *outCount = -1;
        CloseHandle(hSnap);
        return;
    }

    do {
        if (*outCount >= maxCount) break;

        ProcessInfo* dst = &outList[*outCount];
        memset(dst, 0, sizeof(*dst));
        dst->pid = pe.th32ProcessID;
        strncpy(dst->name, pe.szExeFile, sizeof(dst->name) - 1);

        HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION,
                                   FALSE, pe.th32ProcessID);
        if (hProc) {
            DWORD pathSize = (DWORD)sizeof(dst->fullPath);
            if (!QueryFullProcessImageNameA(hProc, 0, dst->fullPath, &pathSize)) {
                dst->fullPath[0] = '\0';
            }
            CloseHandle(hProc);
        }

        const char* hit = find_suspicious_kw(dst->name);
        if (hit) {
            dst->isSuspicious = 1;
            snprintf(dst->reason, sizeof(dst->reason),
                     "进程名命中敏感词: '%s'", hit);
        } else if (dst->fullPath[0]) {
            if (str_icontains(dst->fullPath, "\\temp\\")) {
                dst->isSuspicious = 1;
                snprintf(dst->reason, sizeof(dst->reason),
                         "路径位于 \\Temp\\ 子目录（用户可写区域）");
            } else if (str_icontains(dst->fullPath, "\\appdata\\")) {
                dst->isSuspicious = 1;
                snprintf(dst->reason, sizeof(dst->reason),
                         "路径位于 \\AppData\\ 子目录（用户可写区域）");
            } else {
                const char* phit = find_suspicious_kw(dst->fullPath);
                if (phit) {
                    dst->isSuspicious = 1;
                    snprintf(dst->reason, sizeof(dst->reason),
                             "完整路径命中敏感词: '%s'", phit);
                }
            }
        }

        if (!dst->isSuspicious) {
            strncpy(dst->reason, "正常", sizeof(dst->reason) - 1);
        }

        (*outCount)++;
    } while (Process32Next(hSnap, &pe));

    CloseHandle(hSnap);
}

/* =============================================================================
 * Gugas_ScanDrivers —— 枚举所有已加载内核驱动
 * =============================================================================
 */
GUGAS_CORE_API void Gugas_ScanDrivers(DriverInfo* outList, int* outCount, int maxCount) {
    g_lastError[0] = '\0';
    if (!outList || !outCount || maxCount <= 0) {
        if (outCount) *outCount = -1;
        SetDllError("参数非法: outList/outCount 为空或 maxCount<=0", 0);
        return;
    }
    *outCount = 0;

    LPVOID drivers[1024];
    DWORD cbNeeded = 0;

    if (!EnumDeviceDrivers(drivers, sizeof(drivers), &cbNeeded)) {
        SetDllError("EnumDeviceDrivers 失败", GetLastError());
        *outCount = -1;
        return;
    }

    int totalCount = (int)(cbNeeded / sizeof(LPVOID));
    if (totalCount > 1024) totalCount = 1024;

    for (int i = 0; i < totalCount && *outCount < maxCount; i++) {
        DriverInfo* dst = &outList[*outCount];
        memset(dst, 0, sizeof(*dst));

        if (GetDeviceDriverBaseNameA(drivers[i], dst->name, sizeof(dst->name)) == 0) {
            continue;
        }

        const char* hit = find_suspicious_kw(dst->name);
        if (hit) {
            dst->isSuspicious = 1;
            snprintf(dst->reason, sizeof(dst->reason),
                     "驱动名命中敏感词: '%s'", hit);
        } else {
            strncpy(dst->reason, "正常", sizeof(dst->reason) - 1);
        }

        (*outCount)++;
    }
}

/* =============================================================================
 * Gugas_ScanOverlayWindows —— 枚举所有顶层可见窗口，标记可疑覆盖层
 * =============================================================================
 */

typedef struct {
    WindowInfo* list;
    int*        count;
    int         maxCount;
    int         screenW;
    int         screenH;
} OverlayCtx;

static void get_process_name_by_pid(DWORD pid, char* out, size_t outSize) {
    if (!out || outSize == 0) return;
    out[0] = '\0';

    HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!hProc) return;

    char fullPath[1024] = {0};
    DWORD sz = (DWORD)sizeof(fullPath);
    if (QueryFullProcessImageNameA(hProc, 0, fullPath, &sz)) {
        const char* base = path_basename(fullPath);
        strncpy(out, base, outSize - 1);
        out[outSize - 1] = '\0';
    }
    CloseHandle(hProc);
}

static BOOL CALLBACK overlay_enum_proc(HWND hwnd, LPARAM lParam) {
    OverlayCtx* ctx = (OverlayCtx*)lParam;
    if (ctx->maxCount <= 0 || *ctx->count >= ctx->maxCount) return FALSE;

    if (!IsWindowVisible(hwnd)) return TRUE;

    RECT rc = {0};
    if (!GetWindowRect(hwnd, &rc)) return TRUE;

    int w = rc.right - rc.left;
    int h = rc.bottom - rc.top;
    if (w <= 0 || h <= 0) return TRUE;

    LONG style   = GetWindowLongA(hwnd, GWL_STYLE);
    LONG exStyle = GetWindowLongA(hwnd, GWL_EXSTYLE);

    int suspicious = 0;
    char reason[256] = {0};

    int isBorderless = !(style & WS_BORDER) && !(style & WS_CAPTION);
    int isLayered    = (exStyle & (WS_EX_LAYERED | WS_EX_TRANSPARENT)) ? 1 : 0;
    int isFullscreen = (w >= (int)(ctx->screenW * 0.9)) &&
                       (h >= (int)(ctx->screenH * 0.9));

    if (isBorderless) {
        suspicious = 1;
        strncat(reason, "无边框窗口; ", sizeof(reason) - strlen(reason) - 1);
    }
    if (isLayered) {
        suspicious = 1;
        strncat(reason, "分层/透明窗口; ", sizeof(reason) - strlen(reason) - 1);
    }
    if (isFullscreen) {
        suspicious = 1;
        strncat(reason, "尺寸>=屏幕90%(疑似全屏覆盖); ",
                sizeof(reason) - strlen(reason) - 1);
    }

    if (!suspicious) return TRUE;

    WindowInfo* dst = &ctx->list[*ctx->count];
    memset(dst, 0, sizeof(*dst));
    dst->hwnd    = hwnd;
    dst->width   = w;
    dst->height  = h;
    dst->style   = (DWORD)style;
    dst->exStyle = (DWORD)exStyle;
    strncpy(dst->reason, reason, sizeof(dst->reason) - 1);

    GetWindowTextA(hwnd, dst->title, (int)sizeof(dst->title));
    GetClassNameA(hwnd, dst->className, (int)sizeof(dst->className));

    DWORD pid = 0;
    GetWindowThreadProcessId(hwnd, &pid);
    get_process_name_by_pid(pid, dst->ownerProcess, sizeof(dst->ownerProcess));

    (*ctx->count)++;
    return TRUE;
}

GUGAS_CORE_API void Gugas_ScanOverlayWindows(WindowInfo* outList, int* outCount, int maxCount) {
    g_lastError[0] = '\0';
    if (!outList || !outCount || maxCount <= 0) {
        if (outCount) *outCount = -1;
        SetDllError("参数非法: outList/outCount 为空或 maxCount<=0", 0);
        return;
    }
    *outCount = 0;

    OverlayCtx ctx;
    ctx.list     = outList;
    ctx.count    = outCount;
    ctx.maxCount = maxCount;
    ctx.screenW  = GetSystemMetrics(SM_CXSCREEN);
    ctx.screenH  = GetSystemMetrics(SM_CYSCREEN);

    EnumWindows(overlay_enum_proc, (LPARAM)&ctx);
}

/* =============================================================================
 * Gugas_ScanHosts —— 解析 hosts 文件并标记非本地重定向
 * =============================================================================
 */

static int is_local_ip(const char* ip) {
    if (!ip) return 0;
    if (strcmp(ip, "127.0.0.1") == 0) return 1;
    if (strcmp(ip, "0.0.0.0")   == 0) return 1;
    if (strcmp(ip, "::1")        == 0) return 1;
    if (strcmp(ip, "::")         == 0) return 1;
    return 0;
}

GUGAS_CORE_API void Gugas_ScanHosts(HostsEntry* outList, int* outCount, int maxCount) {
    g_lastError[0] = '\0';
    if (!outList || !outCount || maxCount <= 0) {
        if (outCount) *outCount = -1;
        SetDllError("参数非法: outList/outCount 为空或 maxCount<=0", 0);
        return;
    }
    *outCount = 0;

    FILE* fp = fopen("C:\\Windows\\System32\\drivers\\etc\\hosts", "r");
    if (!fp) {
        SetDllError("无法打开 hosts 文件", GetLastError());
        *outCount = -1;
        return;
    }

    char line[1024];
    while (fgets(line, sizeof(line), fp) && *outCount < maxCount) {
        size_t L = strlen(line);
        while (L > 0 && (line[L-1] == '\r' || line[L-1] == '\n')) line[--L] = '\0';
        if (L == 0) continue;

        const char* p = line;
        while (*p == ' ' || *p == '\t') p++;
        if (*p == '#' || *p == '\0') continue;

        char ip[64] = {0};
        char domain[256] = {0};
        if (sscanf(p, "%63s %255s", ip, domain) < 2) continue;

        HostsEntry* dst = &outList[*outCount];
        memset(dst, 0, sizeof(*dst));
        strncpy(dst->ip,      ip,     sizeof(dst->ip) - 1);
        strncpy(dst->domain,  domain, sizeof(dst->domain) - 1);
        strncpy(dst->rawLine, line,   sizeof(dst->rawLine) - 1);
        dst->isSuspicious = is_local_ip(ip) ? 0 : 1;

        (*outCount)++;
    }
    fclose(fp);

    int total = *outCount;
    for (int i = 0; i < total; i++) {
        char d1[256];
        str_to_lower_copy(outList[i].domain, d1, sizeof(d1));
        int cnt = 0;
        for (int j = 0; j < total; j++) {
            char d2[256];
            str_to_lower_copy(outList[j].domain, d2, sizeof(d2));
            if (strcmp(d1, d2) == 0) cnt++;
        }
        if (cnt > 1) outList[i].isSuspicious = 1;
    }
}

/* =============================================================================
 * Gugas_EnableAntiCapture —— 对窗口启用截屏排除
 * =============================================================================
 */
GUGAS_CORE_API BOOL Gugas_EnableAntiCapture(HWND hwnd) {
    g_lastError[0] = '\0';
    if (!hwnd || !IsWindow(hwnd)) {
        SetDllError("目标句柄无效或窗口已关闭", 0);
        return FALSE;
    }

    typedef BOOL (WINAPI *SWDA_fn)(HWND, DWORD);
    HMODULE user32 = GetModuleHandleA("user32.dll");
    if (!user32) {
        SetDllError("无法获取 user32.dll 模块句柄", GetLastError());
        return FALSE;
    }

    SWDA_fn pSWDA = (SWDA_fn)(void*)GetProcAddress(user32, "SetWindowDisplayAffinity");
    if (!pSWDA) {
        SetDllError("当前系统不支持 SetWindowDisplayAffinity（Windows 版本过低）", 0);
        return FALSE;
    }

    if (pSWDA(hwnd, WDA_EXCLUDEFROMCAPTURE)) return TRUE;
    DWORD err1 = GetLastError();

    if (pSWDA(hwnd, WDA_MONITOR)) return TRUE;
    DWORD err2 = GetLastError();

    SetDllError("SetWindowDisplayAffinity 全部模式均失败",
                err2 ? err2 : err1);
    return FALSE;
}

/* =============================================================================
 * Gugas_ObfuscatePassword —— 生成密码的视觉混淆预览
 * =============================================================================
 */
GUGAS_CORE_API void Gugas_ObfuscatePassword(const char* input,
                                            char* outObfuscated,
                                            uint8_t* outRealMask,
                                            int* outLen) {
    g_lastError[0] = '\0';
    if (!outLen) return;
    *outLen = 0;
    if (!input || !outObfuscated || !outRealMask) {
        SetDllError("参数非法: input/outObfuscated/outRealMask 为空", 0);
        return;
    }
    if (input[0] == '\0') {
        outObfuscated[0] = '\0';
        return;
    }

    srand((unsigned)GetTickCount());

    char real[256] = {0};
    int realLen = 0;
    for (int i = 0; input[i] && realLen < 255; i++) {
        real[realLen++] = input[i];
    }

    for (int i = realLen - 1; i > 0; i--) {
        int j = rand() % (i + 1);
        char t = real[i]; real[i] = real[j]; real[j] = t;
    }

    /* OUT_CAP=1023 的容量推导：realLen<=255，最多插入 254*3=762 个噪声，
     * 总计 255+762=1017 < 1023，加上末尾 '\0' 刚好在 1024 范围内。 */
    const int OUT_CAP = 1023;
    int outIdx = 0;

    for (int i = 0; i < realLen; i++) {
        if (outIdx >= OUT_CAP) break;
        outObfuscated[outIdx] = real[i];
        outRealMask[outIdx]   = 1;
        outIdx++;

        if (i < realLen - 1) {
            int noiseCount = 1 + (rand() % 3);
            for (int n = 0; n < noiseCount && outIdx < OUT_CAP; n++) {
                int c = 33 + (rand() % (126 - 33 + 1));
                outObfuscated[outIdx] = (char)c;
                outRealMask[outIdx]   = 0;
                outIdx++;
            }
        }
    }

    outObfuscated[outIdx] = '\0';
    *outLen = outIdx;
}

/* =============================================================================
 * Gugas_InjectPassword —— 通过 SendInput 将真实密码注入目标窗口
 * =============================================================================
 */
GUGAS_CORE_API BOOL Gugas_InjectPassword(HWND targetHwnd, const char* realPassword) {
    g_lastError[0] = '\0';
    if (!realPassword || !realPassword[0]) {
        SetDllError("密码为空", 0);
        return FALSE;
    }
    if (!targetHwnd || !IsWindow(targetHwnd)) {
        SetDllError("目标窗口句柄无效或窗口已关闭", 0);
        return FALSE;
    }

    if (!SetForegroundWindow(targetHwnd)) {
        SetDllError("SetForegroundWindow 失败（目标窗口可能无响应或被其他窗口阻挡）",
                    GetLastError());
        return FALSE;
    }
    Sleep(50);

    srand((unsigned)GetTickCount());

    for (int i = 0; realPassword[i]; i++) {
        WORD ch = (WORD)(unsigned char)realPassword[i];

        INPUT in;
        memset(&in, 0, sizeof(in));
        in.type       = INPUT_KEYBOARD;
        in.ki.wScan   = ch;
        in.ki.dwFlags = KEYEVENTF_UNICODE;

        if (SendInput(1, &in, sizeof(INPUT)) == 0) {
            SetDllError("SendInput 失败（可能因 UIPI 完整性隔离被目标窗口拒绝）",
                        GetLastError());
            return FALSE;
        }

        in.ki.dwFlags = KEYEVENTF_UNICODE | KEYEVENTF_KEYUP;
        SendInput(1, &in, sizeof(INPUT));

        Sleep(80 + (rand() % 121));
    }
    return TRUE;
}

/* =============================================================================
 * Gugas_ScanServices —— 枚举系统服务
 * =============================================================================
 */
GUGAS_CORE_API void Gugas_ScanServices(ServiceInfo* outList, int* outCount, int maxCount) {
    g_lastError[0] = '\0';
    if (!outList || !outCount || maxCount <= 0) {
        if (outCount) *outCount = -1;
        SetDllError("参数非法: outList/outCount 为空或 maxCount<=0", 0);
        return;
    }
    *outCount = 0;

    SC_HANDLE hSCM = OpenSCManagerA(NULL, NULL, SC_MANAGER_ENUMERATE_SERVICE);
    if (!hSCM) {
        SetDllError("OpenSCManager 失败", GetLastError());
        *outCount = -1;
        return;
    }

    DWORD bytesNeeded = 0, servicesReturned = 0, resumeHandle = 0;
    EnumServicesStatusExA(hSCM, SC_ENUM_PROCESS_INFO,
                          SERVICE_WIN32 | SERVICE_DRIVER,
                          SERVICE_STATE_ALL,
                          NULL, 0, &bytesNeeded,
                          &servicesReturned, &resumeHandle, NULL);
    if (GetLastError() != ERROR_MORE_DATA) {
        SetDllError("EnumServicesStatusEx 查询缓冲区大小失败", GetLastError());
        CloseServiceHandle(hSCM);
        *outCount = -1;
        return;
    }

    LPENUM_SERVICE_STATUS_PROCESSA services =
        (LPENUM_SERVICE_STATUS_PROCESSA)malloc(bytesNeeded);
    if (!services) {
        SetDllError("内存分配失败", 0);
        CloseServiceHandle(hSCM);
        *outCount = -1;
        return;
    }

    if (!EnumServicesStatusExA(hSCM, SC_ENUM_PROCESS_INFO,
                               SERVICE_WIN32 | SERVICE_DRIVER,
                               SERVICE_STATE_ALL,
                               (LPBYTE)services, bytesNeeded, &bytesNeeded,
                               &servicesReturned, &resumeHandle, NULL)) {
        SetDllError("EnumServicesStatusEx 枚举失败", GetLastError());
        free(services);
        CloseServiceHandle(hSCM);
        *outCount = -1;
        return;
    }

    for (DWORD i = 0; i < servicesReturned && *outCount < maxCount; i++) {
        ServiceInfo* dst = &outList[*outCount];
        memset(dst, 0, sizeof(*dst));
        strncpy(dst->serviceName, services[i].lpServiceName,
                sizeof(dst->serviceName) - 1);
        if (services[i].lpDisplayName)
            strncpy(dst->displayName, services[i].lpDisplayName,
                    sizeof(dst->displayName) - 1);
        dst->processId    = services[i].ServiceStatusProcess.dwProcessId;
        dst->serviceStatus= services[i].ServiceStatusProcess.dwCurrentState;

        const char* hit = find_suspicious_kw(dst->serviceName);
        if (hit) {
            dst->isSuspicious = 1;
            snprintf(dst->reason, sizeof(dst->reason),
                     "服务名命中敏感词: '%s'", hit);
        } else {
            SC_HANDLE hSvc = OpenServiceA(hSCM, dst->serviceName, SERVICE_QUERY_CONFIG);
            if (hSvc) {
                DWORD cbNeed = 0;
                QueryServiceConfigA(hSvc, NULL, 0, &cbNeed);
                if (GetLastError() == ERROR_INSUFFICIENT_BUFFER && cbNeed > 0) {
                    LPQUERY_SERVICE_CONFIGA cfg =
                        (LPQUERY_SERVICE_CONFIGA)malloc(cbNeed);
                    if (cfg && QueryServiceConfigA(hSvc, cfg, cbNeed, &cbNeed)) {
                        if (cfg->lpBinaryPathName) {
                            const char* phit = find_suspicious_kw(cfg->lpBinaryPathName);
                            if (phit) {
                                dst->isSuspicious = 1;
                                snprintf(dst->reason, sizeof(dst->reason),
                                         "服务路径命中敏感词: '%s'", phit);
                            } else if (str_icontains(cfg->lpBinaryPathName, "\\temp\\")) {
                                dst->isSuspicious = 1;
                                snprintf(dst->reason, sizeof(dst->reason),
                                         "服务路径位于 \\Temp\\ 子目录");
                            } else if (str_icontains(cfg->lpBinaryPathName, "\\appdata\\")) {
                                dst->isSuspicious = 1;
                                snprintf(dst->reason, sizeof(dst->reason),
                                         "服务路径位于 \\AppData\\ 子目录");
                            }
                        }
                    }
                    free(cfg);
                }
                CloseServiceHandle(hSvc);
            }
        }
        if (!dst->isSuspicious)
            strncpy(dst->reason, "正常", sizeof(dst->reason) - 1);
        (*outCount)++;
    }

    free(services);
    CloseServiceHandle(hSCM);
}

/* =============================================================================
 * Gugas_ScanStartupEntries —— 注册表 Run/RunOnce + 启动文件夹
 * =============================================================================
 */
static void scan_registry_run(HKEY hRoot, const char* sub, const char* label,
                              StartupEntry* outList, int* outCount, int maxCount) {
    HKEY hKey;
    if (RegOpenKeyExA(hRoot, sub, 0, KEY_READ, &hKey) != ERROR_SUCCESS)
        return;

    DWORD idx = 0;
    char name[256], data[1024];
    DWORD nameSz, dataSz, type;
    while (*outCount < maxCount) {
        nameSz = sizeof(name); dataSz = sizeof(data);
        LONG ret = RegEnumValueA(hKey, idx++, name, &nameSz, NULL,
                                 &type, (LPBYTE)data, &dataSz);
        if (ret == ERROR_NO_MORE_ITEMS) break;
        if (ret != ERROR_SUCCESS) continue;
        if (type != REG_SZ && type != REG_EXPAND_SZ) continue;

        StartupEntry* dst = &outList[*outCount];
        memset(dst, 0, sizeof(*dst));
        strncpy(dst->name, name, sizeof(dst->name) - 1);
        strncpy(dst->path, data, sizeof(dst->path) - 1);
        snprintf(dst->location, sizeof(dst->location), "Registry %s", label);

        const char* hit = find_suspicious_kw(dst->name);
        if (hit) {
            dst->isSuspicious = 1;
            snprintf(dst->reason, sizeof(dst->reason),
                     "名称命中敏感词: '%s'", hit);
        } else {
            const char* phit = find_suspicious_kw(dst->path);
            if (phit) {
                dst->isSuspicious = 1;
                snprintf(dst->reason, sizeof(dst->reason),
                         "路径命中敏感词: '%s'", phit);
            } else if (str_icontains(dst->path, "\\temp\\")) {
                dst->isSuspicious = 1;
                snprintf(dst->reason, sizeof(dst->reason),
                         "路径位于 \\Temp\\ 子目录");
            }
        }
        if (!dst->isSuspicious)
            strncpy(dst->reason, "正常", sizeof(dst->reason) - 1);
        (*outCount)++;
    }
    RegCloseKey(hKey);
}

static void scan_startup_folder(int csidl, const char* label,
                                StartupEntry* outList, int* outCount, int maxCount) {
    char path[MAX_PATH];
    if (SHGetFolderPathA(NULL, csidl, NULL, 0, path) != S_OK)
        return;

    char searchPath[MAX_PATH + 4];
    snprintf(searchPath, sizeof(searchPath), "%s\\*.*", path);

    WIN32_FIND_DATAA fd;
    HANDLE hFind = FindFirstFileA(searchPath, &fd);
    if (hFind == INVALID_HANDLE_VALUE) return;

    do {
        if (strcmp(fd.cFileName, ".") == 0 || strcmp(fd.cFileName, "..") == 0)
            continue;
        if (*outCount >= maxCount) break;

        StartupEntry* dst = &outList[*outCount];
        memset(dst, 0, sizeof(*dst));
        strncpy(dst->name, fd.cFileName, sizeof(dst->name) - 1);
        snprintf(dst->path, sizeof(dst->path), "%s\\%s", path, fd.cFileName);
        snprintf(dst->location, sizeof(dst->location), "StartupFolder %s", label);

        const char* hit = find_suspicious_kw(dst->name);
        if (hit) {
            dst->isSuspicious = 1;
            snprintf(dst->reason, sizeof(dst->reason),
                     "名称命中敏感词: '%s'", hit);
        } else {
            strncpy(dst->reason, "正常", sizeof(dst->reason) - 1);
        }
        (*outCount)++;
    } while (FindNextFileA(hFind, &fd));
    FindClose(hFind);
}

GUGAS_CORE_API void Gugas_ScanStartupEntries(StartupEntry* outList,
                                              int* outCount, int maxCount) {
    g_lastError[0] = '\0';
    if (!outList || !outCount || maxCount <= 0) {
        if (outCount) *outCount = -1;
        SetDllError("参数非法: outList/outCount 为空或 maxCount<=0", 0);
        return;
    }
    *outCount = 0;

    scan_registry_run(HKEY_LOCAL_MACHINE,
        "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        "HKLM\\Run", outList, outCount, maxCount);
    scan_registry_run(HKEY_CURRENT_USER,
        "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        "HKCU\\Run", outList, outCount, maxCount);
    scan_registry_run(HKEY_LOCAL_MACHINE,
        "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
        "HKLM\\RunOnce", outList, outCount, maxCount);

    scan_startup_folder(CSIDL_COMMON_STARTUP, "Common", outList, outCount, maxCount);
    scan_startup_folder(CSIDL_STARTUP,       "User",   outList, outCount, maxCount);
}

/* =============================================================================
 * Gugas_ScanNetworkConnections —— 枚举 TCP + UDP 连接
 * =============================================================================
 */
GUGAS_CORE_API void Gugas_ScanNetworkConnections(ConnectionInfo* outList,
                                                  int* outCount, int maxCount) {
    g_lastError[0] = '\0';
    if (!outList || !outCount || maxCount <= 0) {
        if (outCount) *outCount = -1;
        SetDllError("参数非法: outList/outCount 为空或 maxCount<=0", 0);
        return;
    }
    *outCount = 0;

    /* --- TCP --- */
    DWORD tcpSz = 0;
    GetExtendedTcpTable(NULL, &tcpSz, TRUE, AF_INET,
                        TCP_TABLE_OWNER_PID_ALL, 0);
    if (tcpSz > 0) {
        PMIB_TCPTABLE_OWNER_PID tcpTbl =
            (PMIB_TCPTABLE_OWNER_PID)malloc(tcpSz);
        if (tcpTbl && GetExtendedTcpTable(tcpTbl, &tcpSz, TRUE, AF_INET,
                TCP_TABLE_OWNER_PID_ALL, 0) == NO_ERROR) {
            for (DWORD i = 0; i < tcpTbl->dwNumEntries && *outCount < maxCount; i++) {
                ConnectionInfo* dst = &outList[*outCount];
                memset(dst, 0, sizeof(*dst));
                MIB_TCPROW_OWNER_PID* r = &tcpTbl->table[i];

                DWORD la = r->dwLocalAddr, ra = r->dwRemoteAddr;
                snprintf(dst->localAddr,  sizeof(dst->localAddr),
                         "%lu.%lu.%lu.%lu",
                         (la>>0)&0xFF,(la>>8)&0xFF,(la>>16)&0xFF,(la>>24)&0xFF);
                snprintf(dst->remoteAddr, sizeof(dst->remoteAddr),
                         "%lu.%lu.%lu.%lu",
                         (ra>>0)&0xFF,(ra>>8)&0xFF,(ra>>16)&0xFF,(ra>>24)&0xFF);
                dst->localPort  = ntohs((u_short)r->dwLocalPort);
                dst->remotePort = ntohs((u_short)r->dwRemotePort);
                dst->state      = r->dwState;
                dst->pid        = r->dwOwningPid;
                get_process_name_by_pid(dst->pid, dst->processName,
                                        sizeof(dst->processName));

                if (dst->state == MIB_TCP_STATE_ESTAB && dst->remotePort != 0) {
                    DWORD common[] = {80,443,53,123,22,993,995,587,465,0};
                    int isCommon = 0;
                    for (int k = 0; common[k]; k++)
                        if (dst->remotePort == (DWORD)common[k]) { isCommon=1; break; }
                    if (!isCommon) {
                        dst->isSuspicious = 1;
                        snprintf(dst->reason, sizeof(dst->reason),
                                 "已建立连接至非常见端口 %lu",
                                 (unsigned long)dst->remotePort);
                    }
                }
                if (!dst->isSuspicious) {
                    const char* hit = find_suspicious_kw(dst->processName);
                    if (hit) {
                        dst->isSuspicious = 1;
                        snprintf(dst->reason, sizeof(dst->reason),
                                 "进程名命中敏感词: '%s'", hit);
                    }
                }
                if (!dst->isSuspicious)
                    strncpy(dst->reason, "正常", sizeof(dst->reason) - 1);
                (*outCount)++;
            }
        }
        free(tcpTbl);
    }

    /* --- UDP --- */
    DWORD udpSz = 0;
    GetExtendedUdpTable(NULL, &udpSz, TRUE, AF_INET,
                        UDP_TABLE_OWNER_PID, 0);
    if (udpSz > 0 && *outCount < maxCount) {
        PMIB_UDPTABLE_OWNER_PID udpTbl =
            (PMIB_UDPTABLE_OWNER_PID)malloc(udpSz);
        if (udpTbl && GetExtendedUdpTable(udpTbl, &udpSz, TRUE, AF_INET,
                UDP_TABLE_OWNER_PID, 0) == NO_ERROR) {
            for (DWORD i = 0; i < udpTbl->dwNumEntries && *outCount < maxCount; i++) {
                ConnectionInfo* dst = &outList[*outCount];
                memset(dst, 0, sizeof(*dst));
                MIB_UDPROW_OWNER_PID* r = &udpTbl->table[i];

                DWORD la = r->dwLocalAddr;
                snprintf(dst->localAddr, sizeof(dst->localAddr),
                         "%lu.%lu.%lu.%lu",
                         (la>>0)&0xFF,(la>>8)&0xFF,(la>>16)&0xFF,(la>>24)&0xFF);
                dst->localPort = ntohs((u_short)r->dwLocalPort);
                dst->pid       = r->dwOwningPid;
                dst->state     = 0; /* UDP 无状态 */
                get_process_name_by_pid(dst->pid, dst->processName,
                                        sizeof(dst->processName));

                const char* hit = find_suspicious_kw(dst->processName);
                if (hit) {
                    dst->isSuspicious = 1;
                    snprintf(dst->reason, sizeof(dst->reason),
                             "进程名命中敏感词: '%s'", hit);
                } else {
                    strncpy(dst->reason, "正常", sizeof(dst->reason) - 1);
                }
                (*outCount)++;
            }
        }
        free(udpTbl);
    }
}

/* =============================================================================
 * Gugas_ScanFileSystem —— 递归扫描单个目录下的可疑文件
 * =============================================================================
 */
static void scan_dir_recurse(const char* root, const char* cur,
                             int maxDepth, int curDepth,
                             FileEntry* outList, int* outCount, int maxCount) {
    if (*outCount >= maxCount) return;
    if (maxDepth > 0 && curDepth > maxDepth) return;

    char sp[MAX_PATH * 2];
    snprintf(sp, sizeof(sp), "%s\\*.*", cur);

    WIN32_FIND_DATAA fd;
    HANDLE hFind = FindFirstFileA(sp, &fd);
    if (hFind == INVALID_HANDLE_VALUE) return;

    do {
        if (*outCount >= maxCount) break;
        if (strcmp(fd.cFileName, ".") == 0 || strcmp(fd.cFileName, "..") == 0)
            continue;

        char fp[MAX_PATH * 2];
        snprintf(fp, sizeof(fp), "%s\\%s", cur, fd.cFileName);

        if (fd.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)
            continue; /* 跳过符号链接/ junction */

        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            scan_dir_recurse(root, fp, maxDepth, curDepth + 1,
                             outList, outCount, maxCount);
        } else {
            const char* ext = strrchr(fd.cFileName, '.');
            int isExec = 0;
            if (ext) {
                char el[16];
                str_to_lower_copy(ext, el, sizeof(el));
                if (strcmp(el, ".exe") == 0 || strcmp(el, ".dll") == 0 ||
                    strcmp(el, ".sys") == 0 || strcmp(el, ".bat") == 0 ||
                    strcmp(el, ".cmd") == 0 || strcmp(el, ".vbs") == 0 ||
                    strcmp(el, ".ps1") == 0 || strcmp(el, ".wsf") == 0 ||
                    strcmp(el, ".scr") == 0) {
                    isExec = 1;
                }
            }

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
                FileEntry* dst = &outList[*outCount];
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
            }
        }
    } while (FindNextFileA(hFind, &fd));
    FindClose(hFind);
}

GUGAS_CORE_API void Gugas_ScanFileSystem(const char* rootPath,
                                         FileEntry* outList,
                                         int* outCount,
                                         int maxCount,
                                         int maxDepth) {
    g_lastError[0] = '\0';
    if (!rootPath || !outList || !outCount || maxCount <= 0) {
        if (outCount) *outCount = -1;
        SetDllError("参数非法", 0);
        return;
    }
    *outCount = 0;
    scan_dir_recurse(rootPath, rootPath, maxDepth, 0,
                     outList, outCount, maxCount);
}

/* =============================================================================
 * Gugas_ScanFileSystemMulti —— 多线程并行扫描多个根目录
 * =============================================================================
 */
typedef struct {
    const char* rootPath;
    int         maxDepth;
    FileEntry*  localList;
    int         localCount;
    int         localMax;
} FSThreadData;

static DWORD WINAPI fs_thread_proc(LPVOID lpParam) {
    FSThreadData* d = (FSThreadData*)lpParam;
    d->localCount = 0;
    Gugas_ScanFileSystem(d->rootPath, d->localList, &d->localCount,
                         d->localMax, d->maxDepth);
    return 0;
}

GUGAS_CORE_API void Gugas_ScanFileSystemMulti(const char** rootPaths,
                                              int rootCount,
                                              FileEntry* outList,
                                              int* outCount,
                                              int maxCount,
                                              int maxDepth) {
    g_lastError[0] = '\0';
    if (!rootPaths || rootCount <= 0 || !outList || !outCount || maxCount <= 0) {
        if (outCount) *outCount = -1;
        SetDllError("参数非法", 0);
        return;
    }
    *outCount = 0;

    if (rootCount == 1) {
        Gugas_ScanFileSystem(rootPaths[0], outList, outCount, maxCount, maxDepth);
        return;
    }

    HANDLE* threads = (HANDLE*)calloc(rootCount, sizeof(HANDLE));
    FSThreadData* tdata = (FSThreadData*)calloc(rootCount, sizeof(FSThreadData));
    if (!threads || !tdata) {
        SetDllError("内存分配失败", 0);
        *outCount = -1;
        free(threads); free(tdata);
        return;
    }

    for (int i = 0; i < rootCount; i++) {
        tdata[i].rootPath = rootPaths[i];
        tdata[i].maxDepth = maxDepth;
        tdata[i].localList = (FileEntry*)calloc(4096, sizeof(FileEntry));
        tdata[i].localMax  = 4096;
        tdata[i].localCount = 0;
        threads[i] = CreateThread(NULL, 0, fs_thread_proc, &tdata[i], 0, NULL);
    }

    WaitForMultipleObjects(rootCount, threads, TRUE, INFINITE);

    for (int i = 0; i < rootCount; i++) {
        for (int j = 0; j < tdata[i].localCount && *outCount < maxCount; j++) {
            outList[*outCount] = tdata[i].localList[j];
            (*outCount)++;
        }
        free(tdata[i].localList);
        if (threads[i]) CloseHandle(threads[i]);
    }
    free(threads);
    free(tdata);
}

/* =============================================================================
 * Gugas_ScanLoadedModules —— 扫描指定进程已加载的模块
 * =============================================================================
 */
GUGAS_CORE_API void Gugas_ScanLoadedModules(DWORD pid,
                                            ModuleInfo* outList,
                                            int* outCount,
                                            int maxCount) {
    g_lastError[0] = '\0';
    if (!outList || !outCount || maxCount <= 0) {
        if (outCount) *outCount = -1;
        SetDllError("参数非法", 0);
        return;
    }
    *outCount = 0;

    HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
                               FALSE, pid);
    if (!hProc) {
        SetDllError("OpenProcess 失败", GetLastError());
        *outCount = -1;
        return;
    }

    HMODULE hMods[1024];
    DWORD cbNeeded;
    if (!EnumProcessModules(hProc, hMods, sizeof(hMods), &cbNeeded)) {
        SetDllError("EnumProcessModules 失败", GetLastError());
        CloseHandle(hProc);
        *outCount = -1;
        return;
    }

    int n = (int)(cbNeeded / sizeof(HMODULE));
    if (n > 1024) n = 1024;
    for (int i = 0; i < n && *outCount < maxCount; i++) {
        ModuleInfo* dst = &outList[*outCount];
        memset(dst, 0, sizeof(*dst));

        char modName[MAX_PATH], modPath[MAX_PATH];
        if (GetModuleBaseNameA(hProc, hMods[i], modName, sizeof(modName)))
            strncpy(dst->moduleName, modName, sizeof(dst->moduleName) - 1);

        MODULEINFO mi;
        if (GetModuleInformation(hProc, hMods[i], &mi, sizeof(mi))) {
            dst->baseAddr   = (ULONG_PTR)mi.lpBaseOfDll;
            dst->moduleSize = mi.SizeOfImage;
        }
        if (GetModuleFileNameExA(hProc, hMods[i], modPath, sizeof(modPath)))
            strncpy(dst->modulePath, modPath, sizeof(dst->modulePath) - 1);

        const char* hit = find_suspicious_kw(dst->moduleName);
        if (hit) {
            dst->isSuspicious = 1;
            snprintf(dst->reason, sizeof(dst->reason),
                     "模块名命中敏感词: '%s'", hit);
        } else if (dst->modulePath[0]) {
            const char* phit = find_suspicious_kw(dst->modulePath);
            if (phit) {
                dst->isSuspicious = 1;
                snprintf(dst->reason, sizeof(dst->reason),
                         "模块路径命中敏感词: '%s'", phit);
            } else if (str_icontains(dst->modulePath, "\\temp\\")) {
                dst->isSuspicious = 1;
                snprintf(dst->reason, sizeof(dst->reason),
                         "模块位于 \\Temp\\");
            } else if (str_icontains(dst->modulePath, "\\appdata\\")) {
                dst->isSuspicious = 1;
                snprintf(dst->reason, sizeof(dst->reason),
                         "模块位于 \\AppData\\");
            }
        }
        if (!dst->isSuspicious)
            strncpy(dst->reason, "正常", sizeof(dst->reason) - 1);
        (*outCount)++;
    }
    CloseHandle(hProc);
}

/* DLL 入口点 */
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved) {
    (void)hinstDLL; (void)lpReserved;
    switch (fdwReason) {
        case DLL_PROCESS_ATTACH: break;
        case DLL_PROCESS_DETACH: break;
    }
    return TRUE;
}
