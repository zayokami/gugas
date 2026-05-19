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
#include "gugas_diskscan.h"

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

/* 宽字符 → UTF-8（ImGui/前端统一用 UTF-8） */
static void wchar_to_utf8(const wchar_t* wsrc, char* out, size_t outSize) {
    if (!out || outSize == 0) return;
    out[0] = '\0';
    if (!wsrc || !wsrc[0]) return;
    int need = WideCharToMultiByte(CP_UTF8, 0, wsrc, -1, NULL, 0, NULL, NULL);
    if (need <= 0 || (size_t)need > outSize) {
        WideCharToMultiByte(CP_UTF8, 0, wsrc, (int)(outSize - 1),
                            out, (int)outSize, NULL, NULL);
        out[outSize - 1] = '\0';
    } else {
        WideCharToMultiByte(CP_UTF8, 0, wsrc, -1, out, need, NULL, NULL);
    }
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

    PROCESSENTRY32W pe = {0};
    pe.dwSize = sizeof(pe);

    if (!Process32FirstW(hSnap, &pe)) {
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
        wchar_to_utf8(pe.szExeFile, dst->name, sizeof(dst->name));

        HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION,
                                   FALSE, pe.th32ProcessID);
        if (hProc) {
            wchar_t wpath[1024] = {0};
            DWORD pathSize = (DWORD)(sizeof(wpath)/sizeof(wpath[0]));
            if (QueryFullProcessImageNameW(hProc, 0, wpath, &pathSize)) {
                wchar_to_utf8(wpath, dst->fullPath, sizeof(dst->fullPath));
            } else {
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
    } while (Process32NextW(hSnap, &pe));

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

        wchar_t wname[256] = {0};
        if (GetDeviceDriverBaseNameW(drivers[i], wname, ARRAYSIZE(wname)) == 0) {
            continue;
        }
        wchar_to_utf8(wname, dst->name, sizeof(dst->name));

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

    wchar_t wpath[1024] = {0};
    DWORD sz = (DWORD)ARRAYSIZE(wpath);
    if (QueryFullProcessImageNameW(hProc, 0, wpath, &sz)) {
        wchar_t* p = wcsrchr(wpath, L'\\');
        if (!p) p = wcsrchr(wpath, L'/');
        const wchar_t* base = p ? (p + 1) : wpath;
        wchar_to_utf8(base, out, outSize);
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

    wchar_t wbuf[256];
    GetWindowTextW(hwnd, wbuf, ARRAYSIZE(wbuf));
    wchar_to_utf8(wbuf, dst->title, sizeof(dst->title));
    GetClassNameW(hwnd, wbuf, ARRAYSIZE(wbuf));
    wchar_to_utf8(wbuf, dst->className, sizeof(dst->className));

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
    int n = Gds_ScanDirectory(rootPath, (GdsFileEntry*)outList,
                               maxCount, maxDepth, NULL);
    if (n < 0) {
        SetDllError("Gds_ScanDirectory 失败", 0);
        *outCount = -1;
    } else {
        *outCount = n;
    }
}

/* =============================================================================
 * Gugas_ScanFileSystemMulti —— 多线程并行扫描多个根目录
 *   使用 gugas_diskscan 模块的 Gds_ScanDrivesMulti，内联汇编原子控制进度
 * =============================================================================
 */
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

    /* 提取盘符 */
    char drives[26];
    int dcount = 0;
    for (int i = 0; i < rootCount && dcount < 26; i++) {
        if (rootPaths[i] && rootPaths[i][0] && rootPaths[i][1] == ':')
            drives[dcount++] = rootPaths[i][0];
    }
    if (dcount == 0) {
        SetDllError("无法从 rootPaths 提取有效盘符", 0);
        *outCount = -1;
        return;
    }

    GdsScanMode mode = (maxDepth <= 2) ? GDS_MODE_QUICK : GDS_MODE_DEEP;
    int n = Gds_ScanDrivesMulti(drives, dcount, mode,
                                 (GdsFileEntry*)outList, maxCount, NULL);
    if (n < 0) {
        SetDllError("Gds_ScanDrivesMulti 失败", 0);
        *outCount = -1;
    } else {
        *outCount = n;
    }
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

/* =============================================================================
 * 键盘安全 & 隐匿线程检测
 * =============================================================================
 */

/* --- NtQueryInformationThread（未文档化 API）函数指针 --- */
typedef LONG (NTAPI *NtQueryInformationThread_t)(HANDLE ThreadHandle,
    ULONG ThreadInformationClass, PVOID ThreadInformation,
    ULONG ThreadInformationLength, PULONG ReturnLength);

static NtQueryInformationThread_t get_ntqit(void) {
    static NtQueryInformationThread_t p = NULL;
    if (!p) {
        HMODULE ntdll = GetModuleHandleA("ntdll.dll");
        if (ntdll) p = (NtQueryInformationThread_t)GetProcAddress(ntdll, "NtQueryInformationThread");
    }
    return p;
}

/* --- 动态提取 syscall number（从 ntdll stub）--- */
static DWORD get_syscall_number(const char* apiName) {
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) return 0;
    BYTE* addr = (BYTE*)GetProcAddress(ntdll, apiName);
    if (!addr) return 0;
    /* 期望: mov r10,rcx ; mov eax, imm32 ; syscall ; ret
     * 字节码: 4C 8B D1 B8 NN NN NN 00 0F 05 C3 */
    if (addr[0] == 0x4C && addr[1] == 0x8B && addr[2] == 0xD1 &&
        addr[3] == 0xB8) {
        return *(DWORD*)(addr + 4);
    }
    return 0;
}

/* --- MinGW x64 内联汇编 direct syscall（备用路径）--- */
__attribute__((noinline))
static LONG gugas_direct_syscall(DWORD syscallNum, HANDLE hThread, ULONG infoClass,
                                  PVOID info, ULONG infoLen, PULONG retLen) {
    LONG status;
    (void)syscallNum; (void)hThread; (void)infoClass;
    (void)info; (void)infoLen; (void)retLen;
    /* Windows x64 syscall 约定：
     *   R10=arg1(原RCX), RDX=arg2, R8=arg3, R9=arg4, stack=arg5+
     *   EAX=syscall number
     * 函数参数按 Windows x64 CC 到达：
     *   RCX=syscallNum, RDX=hThread, R8=infoClass, R9=info,
     *   [RSP+0x28]=infoLen, [RSP+0x30]=retLen
     * 需要重排为：
     *   R10=hThread, RDX=infoClass, R8=info, R9=infoLen, EAX=syscallNum
     */
    __asm__ __volatile__ (
        "movq %%rdx, %%r10\n\t"        /* R10 = hThread */
        "movq %%r8, %%rdx\n\t"         /* RDX = infoClass */
        "movq %%r9, %%r8\n\t"          /* R8 = info */
        "movq 0x28(%%rsp), %%r9\n\t"   /* R9 = infoLen */
        "movl %%ecx, %%eax\n\t"        /* EAX = syscallNum */
        "syscall"
        : "=a"(status)
        : /* operands already in correct registers per calling convention */
        : "rcx", "rdx", "r8", "r9", "r10", "r11", "memory"
    );
    return status;
}

/* --- 批量检查进程导入表中是否含可疑键盘 API --- */
static void check_keylogger_apis_batch(HANDLE hProc, int* hasHook,
                                        int* hasRawInput, int* hasKeyPoll) {
    *hasHook = 0; *hasRawInput = 0; *hasKeyPoll = 0;

    HMODULE hMods[1024];
    DWORD cbNeeded;
    if (!EnumProcessModules(hProc, hMods, sizeof(hMods), &cbNeeded))
        return;

    int n = (int)(cbNeeded / sizeof(HMODULE));
    if (n > 1024) n = 1024;

    for (int i = 0; i < n; i++) {
        IMAGE_DOS_HEADER dosHdr;
        SIZE_T read = 0;
        if (!ReadProcessMemory(hProc, hMods[i], &dosHdr, sizeof(dosHdr), &read))
            continue;
        if (dosHdr.e_magic != IMAGE_DOS_SIGNATURE)
            continue;

        IMAGE_NT_HEADERS ntHdr;
        if (!ReadProcessMemory(hProc, (BYTE*)hMods[i] + dosHdr.e_lfanew,
                               &ntHdr, sizeof(ntHdr), &read))
            continue;
        if (ntHdr.Signature != IMAGE_NT_SIGNATURE)
            continue;

        DWORD importRVA = ntHdr.OptionalHeader.DataDirectory[
            IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
        DWORD importSize = ntHdr.OptionalHeader.DataDirectory[
            IMAGE_DIRECTORY_ENTRY_IMPORT].Size;
        if (importRVA == 0 || importSize == 0)
            continue;

        DWORD rva = importRVA;
        while (rva < importRVA + importSize) {
            IMAGE_IMPORT_DESCRIPTOR iid;
            if (!ReadProcessMemory(hProc, (BYTE*)hMods[i] + rva,
                                   &iid, sizeof(iid), &read))
                break;
            if (iid.Name == 0) break;

            DWORD iltRVA = iid.OriginalFirstThunk
                         ? iid.OriginalFirstThunk : iid.FirstThunk;
            if (iltRVA == 0) {
                rva += sizeof(IMAGE_IMPORT_DESCRIPTOR);
                continue;
            }

            DWORD entryRva = iltRVA;
            while (1) {
                ULONG_PTR iltEntry = 0;
                if (!ReadProcessMemory(hProc, (BYTE*)hMods[i] + entryRva,
                                       &iltEntry, sizeof(iltEntry), &read))
                    break;
                if (iltEntry == 0) break;

                /* 按名称导入（最高位为0） */
                ULONG_PTR highBit = ((ULONG_PTR)1 << (sizeof(ULONG_PTR)*8 - 1));
                if ((iltEntry & highBit) == 0) {
                    char nameBuf[64];
                    /* IMAGE_IMPORT_BY_NAME: WORD Hint + CHAR Name[] */
                    if (ReadProcessMemory(hProc,
                            (BYTE*)hMods[i] + (DWORD)iltEntry + 2,
                            nameBuf, sizeof(nameBuf), &read)) {
                        nameBuf[sizeof(nameBuf)-1] = '\0';
                        if (!*hasHook && (_stricmp(nameBuf, "SetWindowsHookExW") == 0 ||
                                          _stricmp(nameBuf, "SetWindowsHookExA") == 0))
                            *hasHook = 1;
                        if (!*hasRawInput && _stricmp(nameBuf, "RegisterRawInputDevices") == 0)
                            *hasRawInput = 1;
                        if (!*hasKeyPoll && (_stricmp(nameBuf, "GetAsyncKeyState") == 0 ||
                                             _stricmp(nameBuf, "GetKeyState") == 0 ||
                                             _stricmp(nameBuf, "GetKeyboardState") == 0))
                            *hasKeyPoll = 1;
                        if (*hasHook && *hasRawInput && *hasKeyPoll)
                            return; /* 全部找到，提前退出 */
                    }
                }
                entryRva += sizeof(ULONG_PTR);
            }
            rva += sizeof(IMAGE_IMPORT_DESCRIPTOR);
        }
    }
}

/* =============================================================================
 * Gugas_ScanKeyloggers —— 键盘安全启发式扫描
 * =============================================================================
 */
GUGAS_CORE_API void Gugas_ScanKeyloggers(KeyloggerInfo* outList, int* outCount,
                                          int maxCount) {
    g_lastError[0] = '\0';
    if (!outList || !outCount || maxCount <= 0) {
        if (outCount) *outCount = -1;
        SetDllError("参数非法", 0);
        return;
    }
    *outCount = 0;

    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) {
        SetDllError("CreateToolhelp32Snapshot 失败", GetLastError());
        *outCount = -1;
        return;
    }

    PROCESSENTRY32W pe = {0};
    pe.dwSize = sizeof(pe);

    if (!Process32FirstW(hSnap, &pe)) {
        SetDllError("Process32FirstW 失败", GetLastError());
        *outCount = -1;
        CloseHandle(hSnap);
        return;
    }

    do {
        if (*outCount >= maxCount) break;
        if (pe.th32ProcessID == 0 || pe.th32ProcessID == 4) continue;

        KeyloggerInfo* dst = &outList[*outCount];
        memset(dst, 0, sizeof(*dst));
        dst->pid = pe.th32ProcessID;
        wchar_to_utf8(pe.szExeFile, dst->processName, sizeof(dst->processName));

        /* 尝试打开进程进行导入表扫描 */
        HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
                                   FALSE, pe.th32ProcessID);
        if (hProc) {
            wchar_t wpath[1024] = {0};
            DWORD pathSize = (DWORD)(sizeof(wpath)/sizeof(wpath[0]));
            if (QueryFullProcessImageNameW(hProc, 0, wpath, &pathSize))
                wchar_to_utf8(wpath, dst->processPath, sizeof(dst->processPath));

            check_keylogger_apis_batch(hProc, &dst->hasHookApi,
                                       &dst->hasRawInputApi, &dst->hasKeyPollApi);
            CloseHandle(hProc);
        }

        /* 风险评分 */
        int score = 0;
        if (dst->hasHookApi) score += 3;
        if (dst->hasRawInputApi) score += 2;
        if (dst->hasKeyPollApi) score += 1;
        if (str_icontains(dst->processPath, "\\temp\\")) score += 2;
        if (str_icontains(dst->processPath, "\\appdata\\")) score += 2;
        if (str_icontains(dst->processPath, "\\downloads\\")) score += 2;
        if (find_suspicious_kw(dst->processName)) score += 2;
        if (find_suspicious_kw(dst->processPath)) score += 2;

        /* 系统白名单：降低常见系统进程的误报 */
        if (_stricmp(dst->processName, "explorer.exe") == 0 ||
            _stricmp(dst->processName, "SearchIndexer.exe") == 0 ||
            _stricmp(dst->processName, "ShellExperienceHost.exe") == 0 ||
            _stricmp(dst->processName, "StartMenuExperienceHost.exe") == 0) {
            if (dst->hasKeyPollApi) score -= 1;
        }

        if (score < 0) score = 0;
        if (score > 10) score = 10;
        dst->riskScore = score;
        dst->isSuspicious = (score >= 3);

        if (dst->isSuspicious) {
            char reasons[256] = {0};
            if (dst->hasHookApi)
                strncat(reasons, "导入SetWindowsHookEx ", sizeof(reasons)-1);
            if (dst->hasRawInputApi)
                strncat(reasons, "导入RegisterRawInputDevices ", sizeof(reasons)-1);
            if (dst->hasKeyPollApi)
                strncat(reasons, "导入键盘轮询API ", sizeof(reasons)-1);
            if (score >= 5 && (str_icontains(dst->processPath, "\\temp\\") ||
                str_icontains(dst->processPath, "\\appdata\\"))) {
                strncat(reasons, "路径在用户可写区域 ", sizeof(reasons)-1);
            }
            if (find_suspicious_kw(dst->processName)) {
                strncat(reasons, "进程名含敏感词 ", sizeof(reasons)-1);
            }
            size_t L = strlen(reasons);
            while (L > 0 && reasons[L-1] == ' ') reasons[--L] = '\0';
            if (L == 0) strncpy(reasons, "综合风险评分触发", sizeof(reasons)-1);
            strncpy(dst->reason, reasons, sizeof(dst->reason)-1);
        } else {
            strncpy(dst->reason, "正常", sizeof(dst->reason)-1);
        }

        (*outCount)++;
    } while (Process32NextW(hSnap, &pe));

    CloseHandle(hSnap);
}

/* =============================================================================
 * Gugas_ScanGhostThreads —— 隐匿线程检测
 * =============================================================================
 */
GUGAS_CORE_API void Gugas_ScanGhostThreads(GhostThreadInfo* outList,
                                            int* outCount, int maxCount) {
    g_lastError[0] = '\0';
    if (!outList || !outCount || maxCount <= 0) {
        if (outCount) *outCount = -1;
        SetDllError("参数非法", 0);
        return;
    }
    *outCount = 0;

    NtQueryInformationThread_t ntqit = get_ntqit();
    if (!ntqit) {
        SetDllError("无法从 ntdll 获取 NtQueryInformationThread", 0);
        *outCount = -1;
        return;
    }

    DWORD syscallNum = get_syscall_number("NtQueryInformationThread");

    HANDLE hProcSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hProcSnap == INVALID_HANDLE_VALUE) {
        SetDllError("CreateToolhelp32Snapshot(PROCESS) 失败", GetLastError());
        *outCount = -1;
        return;
    }

    PROCESSENTRY32W pe = {0};
    pe.dwSize = sizeof(pe);

    if (!Process32FirstW(hProcSnap, &pe)) {
        SetDllError("Process32FirstW 失败", GetLastError());
        *outCount = -1;
        CloseHandle(hProcSnap);
        return;
    }

    do {
        DWORD pid = pe.th32ProcessID;
        if (pid == 0) continue;

        char procName[256] = {0};
        wchar_to_utf8(pe.szExeFile, procName, sizeof(procName));

        HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
                                   FALSE, pid);
        if (!hProc) continue;

        /* 缓存模块列表用于验证线程启动地址 */
        HMODULE hMods[1024];
        DWORD cbNeeded = 0;
        int modCount = 0;
        struct ModRange { ULONG_PTR base; DWORD size; } mods[1024];
        if (EnumProcessModules(hProc, hMods, sizeof(hMods), &cbNeeded)) {
            modCount = (int)(cbNeeded / sizeof(HMODULE));
            if (modCount > 1024) modCount = 1024;
            for (int i = 0; i < modCount; i++) {
                MODULEINFO mi;
                if (GetModuleInformation(hProc, hMods[i], &mi, sizeof(mi))) {
                    mods[i].base = (ULONG_PTR)mi.lpBaseOfDll;
                    mods[i].size = mi.SizeOfImage;
                } else {
                    mods[i].base = 0;
                    mods[i].size = 0;
                }
            }
        }

        /* 枚举该进程的所有线程 */
        HANDLE hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if (hThreadSnap != INVALID_HANDLE_VALUE) {
            THREADENTRY32 te = {0};
            te.dwSize = sizeof(te);
            if (Thread32First(hThreadSnap, &te)) {
                do {
                    if (te.th32OwnerProcessID != pid) continue;
                    if (*outCount >= maxCount) break;

                    GhostThreadInfo* dst = &outList[*outCount];
                    memset(dst, 0, sizeof(*dst));
                    dst->pid = pid;
                    strncpy(dst->processName, procName, sizeof(dst->processName)-1);
                    dst->tid = te.th32ThreadID;

                    HANDLE hThread = OpenThread(THREAD_QUERY_INFORMATION,
                                                FALSE, te.th32ThreadID);
                    if (hThread) {
                        ULONG_PTR startAddr = 0;
                        ULONG retLen = 0;
                        LONG status = ntqit(hThread,
                            9 /*ThreadQuerySetWin32StartAddress*/,
                            &startAddr, sizeof(startAddr), &retLen);

                        if (status != 0 && syscallNum != 0) {
                            status = gugas_direct_syscall(syscallNum, hThread,
                                9, &startAddr, sizeof(startAddr), &retLen);
                        }

                        if (status == 0 && retLen == sizeof(startAddr)) {
                            dst->startAddress = startAddr;
                            int inModule = 0;
                            for (int i = 0; i < modCount; i++) {
                                if (mods[i].base == 0 || mods[i].size == 0) continue;
                                if (startAddr >= mods[i].base &&
                                    startAddr < mods[i].base + mods[i].size) {
                                    inModule = 1;
                                    break;
                                }
                            }
                            dst->isGhost = !inModule;
                        }

                        ULONG hideFlag = 0;
                        retLen = 0;
                        status = ntqit(hThread, 17 /*ThreadHideFromDebugger*/,
                                       &hideFlag, sizeof(hideFlag), &retLen);
                        if (status == 0 && retLen == sizeof(hideFlag)) {
                            dst->isHiddenFromDebugger = (hideFlag != 0);
                        }

                        CloseHandle(hThread);
                    }

                    dst->isSuspicious = (dst->isGhost || dst->isHiddenFromDebugger);
                    if (dst->isGhost && dst->isHiddenFromDebugger) {
                        snprintf(dst->reason, sizeof(dst->reason),
                            "隐匿线程 + 对调试器隐藏");
                    } else if (dst->isGhost) {
                        snprintf(dst->reason, sizeof(dst->reason),
                            "启动地址不在任何模块范围内");
                    } else if (dst->isHiddenFromDebugger) {
                        snprintf(dst->reason, sizeof(dst->reason),
                            "线程被标记为对调试器隐藏");
                    } else {
                        strncpy(dst->reason, "正常", sizeof(dst->reason)-1);
                    }

                    (*outCount)++;
                } while (Thread32Next(hThreadSnap, &te));
            }
            CloseHandle(hThreadSnap);
        }

        CloseHandle(hProc);
    } while (Process32NextW(hProcSnap, &pe));

    CloseHandle(hProcSnap);
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
