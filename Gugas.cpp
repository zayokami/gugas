/* =============================================================================
 * Gugas.cpp —— 主程序：ImGUI + DirectX 11 前端 + 4-Tab 安全自检
 *                + 错误处理 + Toast 通知 + Modal 确认 + Tooltip + 状态栏
 *                + 白名单/黑名单系统
 *
 * Compile (EXE) / 编译命令：
 *   C:/mingw64/bin/g++ -std=c++17 -O2 -DIMGUI_USE_WCHAR32 -o Gugas.exe \
 *       Gugas.cpp \
 *       imgui-1.92.8/imgui.cpp imgui-1.92.8/imgui_draw.cpp \
 *       imgui-1.92.8/imgui_tables.cpp imgui-1.92.8/imgui_widgets.cpp \
 *       imgui-1.92.8/backends/imgui_impl_win32.cpp \
 *       imgui-1.92.8/backends/imgui_impl_dx11.cpp \
 *       -Iimgui-1.92.8 -Iimgui-1.92.8/backends -L. -lgugas_core \
 *       -ld3d11 -ld3dcompiler -ldxgi -lgdi32 -luser32 -lkernel32 -ldwmapi \
 *       -static-libgcc -static-libstdc++ -mwindows
 * =============================================================================
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <d3d11.h>
#include <tchar.h>

#include "imgui.h"
#include "imgui_impl_win32.h"
#include "imgui_impl_dx11.h"

#include "gugas_core.h"
#include "gugas_diskscan.h"

#include <vector>
#include <string>
#include <set>
#include <algorithm>
#include <cstring>
#include <cstdio>
#include <cstdint>
#include <ctime>

/* -----------------------------------------------------------------------------
 * 全局 DX11 资源
 * ---------------------------------------------------------------------------*/
namespace {
    ID3D11Device*           g_pd3dDevice        = nullptr;
    ID3D11DeviceContext*    g_pd3dDeviceContext = nullptr;
    IDXGISwapChain*         g_pSwapChain        = nullptr;
    ID3D11RenderTargetView* g_mainRTV           = nullptr;
    UINT                    g_resizeWidth       = 0;
    UINT                    g_resizeHeight      = 0;
}

extern IMGUI_IMPL_API LRESULT ImGui_ImplWin32_WndProcHandler(HWND, UINT, WPARAM, LPARAM);

/* -----------------------------------------------------------------------------
 * 颜色常量
 * ---------------------------------------------------------------------------*/
namespace col {
    constexpr ImU32 DANGER     = IM_COL32(0xff, 0x44, 0x44, 0xff);
    constexpr ImU32 DANGER_BG  = IM_COL32(0xff, 0x44, 0x44, 0x28);
    constexpr ImU32 OK_GREEN   = IM_COL32(0x00, 0xff, 0x9f, 0xff);
    constexpr ImU32 WARN_AMBER = IM_COL32(0xff, 0xaa, 0x00, 0xff);
    constexpr ImU32 DIM_TEXT   = IM_COL32(0x6a, 0x70, 0x80, 0xff);
    constexpr ImU32 INFO_BLUE  = IM_COL32(0x00, 0x95, 0xff, 0xff);
    constexpr ImU32 WHITE      = IM_COL32(0xff, 0xff, 0xff, 0xff);

    inline ImVec4 v4(int r, int g, int b, int a = 255) {
        return ImVec4(r/255.f, g/255.f, b/255.f, a/255.f);
    }
}

/* -----------------------------------------------------------------------------
 * Toast 通知系统
 * ---------------------------------------------------------------------------*/
enum class NotifyType { Info, Warning, Error };

struct Notification {
    NotifyType  type;
    std::string msg;
    float       remainingSec;
};

static std::vector<Notification> g_notifications;

static void Notify(NotifyType t, const char* fmt, ...) {
    char buf[512];
    va_list args;
    va_start(args, fmt);
    vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);
    g_notifications.push_back({ t, buf, 6.0f });
}

/* -----------------------------------------------------------------------------
 * 白名单 / 黑名单系统
 *
 * 设计原则：
 *   - 白名单：进程名 / 完整路径 精确匹配（大小写不敏感）。
 *     命中白名单的进程在扫描时 isSuspicious 被强制置 0，reason 改为"白名单忽略"。
 *   - 黑名单：用户自定义关键词（可含进程名、路径片段、驱动名、窗口类名等）。
 *     命中黑名单的项 isSuspicious 被强制置 1，reason 追加"命中用户黑名单: xxx"。
 *   - 持久化：程序退出时自动保存到 %LOCALAPPDATA%\Gugas\gugas_rules.ini
 *     启动时自动加载。不写入注册表，不污染系统目录。
 *   - 内存表示：std::set<std::string> 小写归一化存储，比对时统一转小写。
 * ---------------------------------------------------------------------------*/

struct RuleSystem {
    std::set<std::string> processWhitelist;   /* 进程白名单（进程名或完整路径） */
    std::set<std::string> driverWhitelist;    /* 驱动白名单 */
    std::set<std::string> windowWhitelist;    /* 窗口白名单（窗口类名或标题关键词） */
    std::set<std::string> hostsWhitelist;     /* hosts 白名单（域名） */

    std::set<std::string> processBlacklist;   /* 进程黑名单关键词 */
    std::set<std::string> driverBlacklist;    /* 驱动黑名单关键词 */
    std::set<std::string> windowBlacklist;    /* 窗口黑名单关键词 */
    std::set<std::string> hostsBlacklist;     /* hosts 黑名单关键词 */

    /* 临时编辑缓冲 */
    char wlBuf[256] = {0};
    char blBuf[256] = {0};
    int  editTab = 0;   /* 0=进程 1=驱动 2=窗口 3=hosts */

    std::string GetConfigPath() const {
        char path[MAX_PATH];
        if (GetEnvironmentVariableA("LOCALAPPDATA", path, MAX_PATH) == 0)
            return std::string("gugas_rules.ini");
        return std::string(path) + "\\Gugas\\gugas_rules.ini";
    }

    void EnsureDir() const {
        std::string p = GetConfigPath();
        size_t pos = p.find_last_of("\\/");
        if (pos != std::string::npos) {
            std::string dir = p.substr(0, pos);
            CreateDirectoryA(dir.c_str(), nullptr);  /* 忽略已存在 */
        }
    }

    /* 小写归一 */
    static std::string lower(const char* s) {
        if (!s) return "";
        std::string r = s;
        for (auto& c : r) c = (char)tolower((unsigned char)c);
        return r;
    }

    bool InWhitelist(const std::set<std::string>& list, const char* item) const {
        return list.find(lower(item)) != list.end();
    }

    /* 检查 item 是否命中 list 中任一关键词（子串匹配） */
    bool HitBlacklist(const std::set<std::string>& list, const char* item) const {
        if (!item) return false;
        std::string it = lower(item);
        for (auto& kw : list) {
            if (it.find(kw) != std::string::npos) return true;
        }
        return false;
    }

    void Save() {
        EnsureDir();
        FILE* fp = fopen(GetConfigPath().c_str(), "w");
        if (!fp) return;
        fprintf(fp, "# Gugas 规则配置文件\n");
        fprintf(fp, "# 每行一个条目，空行和 # 开头被忽略\n\n");

        fprintf(fp, "[ProcessWhitelist]\n");
        for (auto& s : processWhitelist) fprintf(fp, "%s\n", s.c_str());
        fprintf(fp, "\n[ProcessBlacklist]\n");
        for (auto& s : processBlacklist) fprintf(fp, "%s\n", s.c_str());
        fprintf(fp, "\n[DriverWhitelist]\n");
        for (auto& s : driverWhitelist)   fprintf(fp, "%s\n", s.c_str());
        fprintf(fp, "\n[DriverBlacklist]\n");
        for (auto& s : driverBlacklist)   fprintf(fp, "%s\n", s.c_str());
        fprintf(fp, "\n[WindowWhitelist]\n");
        for (auto& s : windowWhitelist)   fprintf(fp, "%s\n", s.c_str());
        fprintf(fp, "\n[WindowBlacklist]\n");
        for (auto& s : windowBlacklist)   fprintf(fp, "%s\n", s.c_str());
        fprintf(fp, "\n[HostsWhitelist]\n");
        for (auto& s : hostsWhitelist)    fprintf(fp, "%s\n", s.c_str());
        fprintf(fp, "\n[HostsBlacklist]\n");
        for (auto& s : hostsBlacklist)    fprintf(fp, "%s\n", s.c_str());
        fclose(fp);
    }

    void Load() {
        FILE* fp = fopen(GetConfigPath().c_str(), "r");
        if (!fp) return;

        std::set<std::string>* target = nullptr;
        char line[512];
        while (fgets(line, sizeof(line), fp)) {
            size_t L = strlen(line);
            while (L > 0 && (line[L-1] == '\r' || line[L-1] == '\n')) line[--L] = '\0';
            if (L == 0 || line[0] == '#') continue;

            if      (strcmp(line, "[ProcessWhitelist]") == 0) target = &processWhitelist;
            else if (strcmp(line, "[ProcessBlacklist]") == 0) target = &processBlacklist;
            else if (strcmp(line, "[DriverWhitelist]")  == 0) target = &driverWhitelist;
            else if (strcmp(line, "[DriverBlacklist]")  == 0) target = &driverBlacklist;
            else if (strcmp(line, "[WindowWhitelist]")  == 0) target = &windowWhitelist;
            else if (strcmp(line, "[WindowBlacklist]")  == 0) target = &windowBlacklist;
            else if (strcmp(line, "[HostsWhitelist]")   == 0) target = &hostsWhitelist;
            else if (strcmp(line, "[HostsBlacklist]")   == 0) target = &hostsBlacklist;
            else if (target) {
                std::string lo = lower(line);
                if (!lo.empty()) target->insert(lo);
            }
        }
        fclose(fp);
    }
};

static RuleSystem g_rules;

/* -----------------------------------------------------------------------------
 * 应用状态
 * ---------------------------------------------------------------------------*/
struct AppState {
    std::vector<ProcessInfo>   procs;
    std::vector<DriverInfo>    drivers;
    std::vector<WindowInfo>    windows;
    std::vector<HostsEntry>    hosts;
    std::vector<ServiceInfo>   services;
    std::vector<StartupEntry>  startups;
    std::vector<ConnectionInfo> connections;
    std::vector<GdsFileEntry>  fileEntries;

    char passwordInput[256] = {0};
    char obfuscated[1024]   = {0};
    uint8_t realMask[1024]  = {0};
    int  obfLen             = 0;
    int  comboSel           = -1;

    bool injectDonePending  = false;
    bool injectConfirmOpen  = false;
    bool injectFailedOpen   = false;
    char injectFailMsg[256] = {0};

    bool isAdmin            = false;
    bool antiCaptureOk      = false;
    float lastScanElapsed   = 0.0f;
    bool didInitialScan     = false;

    /* 深度扫描 Tab */
    bool deepScanRunning    = false;
    bool fileScanRunning    = false;
    int  fileScanProgress   = 0;
    int  fileScanTotal      = 0;

    /* 文件系统扫描 —— 盘符选择 */
    bool selectedDrives[26] = {false};
    int  selectedDriveCount = 0;
    GdsProgress fileProgress = {0};

    /* 筛选关键词 */
    char procFilter[128]    = {0};
    char driverFilter[128]  = {0};
    char windowFilter[128]  = {0};
    char hostsFilter[128]   = {0};
    char svcFilter[128]     = {0};
    char startupFilter[128] = {0};
    char connFilter[128]    = {0};
    char fileFilter[128]    = {0};
};

static AppState g_state;

static const char* tcp_state_str(DWORD state) {
    switch (state) {
        case 1:  return "CLOSED";
        case 2:  return "LISTEN";
        case 3:  return "SYN_SENT";
        case 4:  return "SYN_RCVD";
        case 5:  return "ESTAB";
        case 6:  return "FIN_WAIT1";
        case 7:  return "FIN_WAIT2";
        case 8:  return "CLOSE_WAIT";
        case 9:  return "CLOSING";
        case 10: return "LAST_ACK";
        case 11: return "TIME_WAIT";
        case 12: return "DELETE";
        default: return "UNKNOWN";
    }
}

/* 不区分大小写子串匹配；needle 为空时恒为 true */
static bool str_icontains(const char* haystack, const char* needle) {
    if (!needle || !needle[0]) return true;
    if (!haystack) return false;
    size_t nlen = strlen(needle);
    for (const char* p = haystack; *p; ++p) {
        if (_strnicmp(p, needle, nlen) == 0) return true;
    }
    return false;
}

/* -----------------------------------------------------------------------------
 * 管理员权限检测
 * ---------------------------------------------------------------------------*/
static BOOL IsUserAdmin() {
    BOOL isAdmin = FALSE;
    PSID adminsGroup = NULL;
    SID_IDENTIFIER_AUTHORITY ntAuth = SECURITY_NT_AUTHORITY;
    if (AllocateAndInitializeSid(
        &ntAuth, 2,
        SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS,
        0, 0, 0, 0, 0, 0, &adminsGroup)) {
        CheckTokenMembership(NULL, adminsGroup, &isAdmin);
        FreeSid(adminsGroup);
    }
    return isAdmin;
}

/* -----------------------------------------------------------------------------
 * 应用白名单/黑名单到扫描结果
 * ---------------------------------------------------------------------------*/
static void ApplyProcessRules(std::vector<ProcessInfo>& list) {
    for (auto& p : list) {
        /* 白名单优先 */
        if (g_rules.InWhitelist(g_rules.processWhitelist, p.name) ||
            g_rules.InWhitelist(g_rules.processWhitelist, p.fullPath)) {
            p.isSuspicious = 0;
            snprintf(p.reason, sizeof(p.reason), "%s", "白名单忽略");
            continue;
        }
        /* 黑名单追加 */
        if (g_rules.HitBlacklist(g_rules.processBlacklist, p.name) ||
            g_rules.HitBlacklist(g_rules.processBlacklist, p.fullPath)) {
            p.isSuspicious = 1;
            char old[256];
            strncpy(old, p.reason, sizeof(old)-1);
            snprintf(p.reason, sizeof(p.reason), "%s | 命中用户黑名单", old);
        }
    }
}

static void ApplyDriverRules(std::vector<DriverInfo>& list) {
    for (auto& d : list) {
        if (g_rules.InWhitelist(g_rules.driverWhitelist, d.name)) {
            d.isSuspicious = 0;
            snprintf(d.reason, sizeof(d.reason), "%s", "白名单忽略");
            continue;
        }
        if (g_rules.HitBlacklist(g_rules.driverBlacklist, d.name)) {
            d.isSuspicious = 1;
            char old[256];
            strncpy(old, d.reason, sizeof(old)-1);
            snprintf(d.reason, sizeof(d.reason), "%s | 命中用户黑名单", old);
        }
    }
}

static void ApplyWindowRules(std::vector<WindowInfo>& list) {
    for (auto& w : list) {
        if (g_rules.InWhitelist(g_rules.windowWhitelist, w.className) ||
            g_rules.InWhitelist(g_rules.windowWhitelist, w.title) ||
            g_rules.InWhitelist(g_rules.windowWhitelist, w.ownerProcess)) {
            continue;  /* 白名单项稍后统一剔除 */
        }
        if (g_rules.HitBlacklist(g_rules.windowBlacklist, w.className) ||
            g_rules.HitBlacklist(g_rules.windowBlacklist, w.title) ||
            g_rules.HitBlacklist(g_rules.windowBlacklist, w.ownerProcess)) {
            /* 已经是可疑项才追加 reason；若本来不可疑则直接标记 */
            char old[256];
            strncpy(old, w.reason, sizeof(old)-1);
            snprintf(w.reason, sizeof(w.reason), "%s | 命中用户黑名单", old);
        }
    }
    /* 白名单命中的项从展示列表中剔除（它们不应出现在"可疑覆盖层"列表里） */
    list.erase(
        std::remove_if(list.begin(), list.end(),
            [](const WindowInfo& w) {
                return g_rules.InWhitelist(g_rules.windowWhitelist, w.className) ||
                       g_rules.InWhitelist(g_rules.windowWhitelist, w.title) ||
                       g_rules.InWhitelist(g_rules.windowWhitelist, w.ownerProcess);
            }),
        list.end());
}

static void ApplyHostsRules(std::vector<HostsEntry>& list) {
    for (auto& h : list) {
        if (g_rules.InWhitelist(g_rules.hostsWhitelist, h.domain)) {
            h.isSuspicious = 0;
            continue;
        }
        if (g_rules.HitBlacklist(g_rules.hostsBlacklist, h.domain) ||
            g_rules.HitBlacklist(g_rules.hostsBlacklist, h.ip)) {
            h.isSuspicious = 1;
        }
    }
}

/* -----------------------------------------------------------------------------
 * 扫描包装（含规则应用）
 * ---------------------------------------------------------------------------*/
static void RefreshProcesses() {
    static ProcessInfo buf[4096];
    int n = 0;
    Gugas_ScanProcesses(buf, &n, 4096);
    if (n < 0) {
        g_state.procs.clear();
        Notify(NotifyType::Error, u8"进程扫描失败：%s", Gugas_GetLastErrorString());
    } else {
        g_state.procs.assign(buf, buf + n);
        ApplyProcessRules(g_state.procs);
    }
}

static void RefreshDrivers() {
    static DriverInfo buf[1024];
    int n = 0;
    Gugas_ScanDrivers(buf, &n, 1024);
    if (n < 0) {
        g_state.drivers.clear();
        Notify(NotifyType::Error, u8"驱动扫描失败：%s", Gugas_GetLastErrorString());
    } else {
        g_state.drivers.assign(buf, buf + n);
        ApplyDriverRules(g_state.drivers);
        if (n > 0 && n < 30 && !g_state.isAdmin) {
            Notify(NotifyType::Warning,
                u8"仅检测到 %d 个内核驱动，列表极不完整——请以管理员身份运行", n);
        }
    }
}

static void RefreshOverlayWindows() {
    static WindowInfo buf[1024];
    int n = 0;
    Gugas_ScanOverlayWindows(buf, &n, 1024);
    if (n < 0) {
        g_state.windows.clear();
        Notify(NotifyType::Error, u8"窗口扫描失败：%s", Gugas_GetLastErrorString());
    } else {
        g_state.windows.assign(buf, buf + n);
        ApplyWindowRules(g_state.windows);
        if (g_state.comboSel >= (int)g_state.windows.size()) g_state.comboSel = -1;
    }
}

static void RefreshHosts() {
    static HostsEntry buf[1024];
    int n = 0;
    Gugas_ScanHosts(buf, &n, 1024);
    if (n < 0) {
        g_state.hosts.clear();
        Notify(NotifyType::Error, u8"Hosts 文件读取失败：%s", Gugas_GetLastErrorString());
    } else {
        g_state.hosts.assign(buf, buf + n);
        ApplyHostsRules(g_state.hosts);
    }
}

static void RefreshAll() {
    RefreshProcesses();
    RefreshDrivers();
    RefreshOverlayWindows();
    RefreshHosts();
    g_state.didInitialScan = true;
    g_state.lastScanElapsed = 0.0f;
}

static void RefreshServices() {
    static ServiceInfo buf[1024];
    int n = 0;
    Gugas_ScanServices(buf, &n, 1024);
    if (n < 0) {
        g_state.services.clear();
        Notify(NotifyType::Error, u8"服务扫描失败：%s", Gugas_GetLastErrorString());
    } else {
        g_state.services.assign(buf, buf + n);
    }
}

static void RefreshStartup() {
    static StartupEntry buf[1024];
    int n = 0;
    Gugas_ScanStartupEntries(buf, &n, 1024);
    if (n < 0) {
        g_state.startups.clear();
        Notify(NotifyType::Error, u8"启动项扫描失败：%s", Gugas_GetLastErrorString());
    } else {
        g_state.startups.assign(buf, buf + n);
    }
}

static void RefreshNetwork() {
    static ConnectionInfo buf[4096];
    int n = 0;
    Gugas_ScanNetworkConnections(buf, &n, 4096);
    if (n < 0) {
        g_state.connections.clear();
        Notify(NotifyType::Error, u8"网络连接扫描失败：%s", Gugas_GetLastErrorString());
    } else {
        g_state.connections.assign(buf, buf + n);
    }
}

static void RefreshFileSystemScan(GdsScanMode mode) {
    static GdsFileEntry buf[8192];

    /* 收集选中的盘符 */
    char drives[26];
    int dcount = 0;
    for (int i = 0; i < 26; i++) {
        if (g_state.selectedDrives[i])
            drives[dcount++] = (char)('A' + i);
    }
    if (dcount == 0) {
        Notify(NotifyType::Warning, u8"请至少选择一个盘符");
        return;
    }

    Gds_ResetProgress(&g_state.fileProgress);
    g_state.fileScanRunning = true;

    int n = Gds_ScanDrivesMulti(drives, dcount, mode,
                                 (GdsFileEntry*)buf, 8192,
                                 &g_state.fileProgress);
    g_state.fileScanRunning = false;

    if (n < 0) {
        g_state.fileEntries.clear();
        Notify(NotifyType::Error, u8"文件扫描失败");
    } else {
        g_state.fileEntries.assign(buf, buf + n);
        Notify(NotifyType::Info, u8"%s扫描完成，发现 %d 个可疑文件",
               mode == GDS_MODE_QUICK ? u8"快速" : u8"深度", n);
    }
}

/* -----------------------------------------------------------------------------
 * DX11 设备
 * ---------------------------------------------------------------------------*/
static void CreateRenderTarget() {
    ID3D11Texture2D* backBuffer = nullptr;
    g_pSwapChain->GetBuffer(0, IID_PPV_ARGS(&backBuffer));
    if (backBuffer) {
        g_pd3dDevice->CreateRenderTargetView(backBuffer, nullptr, &g_mainRTV);
        backBuffer->Release();
    }
}
static void CleanupRenderTarget() {
    if (g_mainRTV) { g_mainRTV->Release(); g_mainRTV = nullptr; }
}
static bool CreateDeviceD3D(HWND hWnd) {
    DXGI_SWAP_CHAIN_DESC sd = {};
    sd.BufferCount        = 2;
    sd.BufferDesc.Width   = 0;
    sd.BufferDesc.Height  = 0;
    sd.BufferDesc.Format  = DXGI_FORMAT_R8G8B8A8_UNORM;
    sd.BufferDesc.RefreshRate.Numerator   = 60;
    sd.BufferDesc.RefreshRate.Denominator = 1;
    sd.Flags              = DXGI_SWAP_CHAIN_FLAG_ALLOW_MODE_SWITCH;
    sd.BufferUsage        = DXGI_USAGE_RENDER_TARGET_OUTPUT;
    sd.OutputWindow       = hWnd;
    sd.SampleDesc.Count   = 1;
    sd.SampleDesc.Quality = 0;
    sd.Windowed           = TRUE;
    sd.SwapEffect         = DXGI_SWAP_EFFECT_DISCARD;

    UINT createDeviceFlags = 0;
    D3D_FEATURE_LEVEL featureLevel;
    const D3D_FEATURE_LEVEL featureLevelArray[2] = { D3D_FEATURE_LEVEL_11_0, D3D_FEATURE_LEVEL_10_0, };
    HRESULT hr = D3D11CreateDeviceAndSwapChain(
        nullptr, D3D_DRIVER_TYPE_HARDWARE, nullptr, createDeviceFlags,
        featureLevelArray, 2, D3D11_SDK_VERSION,
        &sd, &g_pSwapChain, &g_pd3dDevice, &featureLevel, &g_pd3dDeviceContext);
    if (hr == DXGI_ERROR_UNSUPPORTED) {
        hr = D3D11CreateDeviceAndSwapChain(
            nullptr, D3D_DRIVER_TYPE_WARP, nullptr, createDeviceFlags,
            featureLevelArray, 2, D3D11_SDK_VERSION,
            &sd, &g_pSwapChain, &g_pd3dDevice, &featureLevel, &g_pd3dDeviceContext);
    }
    if (FAILED(hr)) return false;
    CreateRenderTarget();
    return true;
}
static void CleanupDeviceD3D() {
    CleanupRenderTarget();
    if (g_pSwapChain)        { g_pSwapChain->Release();        g_pSwapChain        = nullptr; }
    if (g_pd3dDeviceContext) { g_pd3dDeviceContext->Release(); g_pd3dDeviceContext = nullptr; }
    if (g_pd3dDevice)        { g_pd3dDevice->Release();        g_pd3dDevice        = nullptr; }
}

/* -----------------------------------------------------------------------------
 * 窗口过程
 * ---------------------------------------------------------------------------*/
static LRESULT WINAPI WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    if (ImGui_ImplWin32_WndProcHandler(hWnd, msg, wParam, lParam)) return true;
    switch (msg) {
        case WM_SIZE:
            if (wParam == SIZE_MINIMIZED) return 0;
            g_resizeWidth  = (UINT)LOWORD(lParam);
            g_resizeHeight = (UINT)HIWORD(lParam);
            return 0;
        case WM_SYSCOMMAND:
            if ((wParam & 0xfff0) == SC_KEYMENU) return 0;
            break;
        case WM_DESTROY:
            PostQuitMessage(0);
            return 0;
    }
    return ::DefWindowProcW(hWnd, msg, wParam, lParam);
}

/* -----------------------------------------------------------------------------
 * 样式
 * ---------------------------------------------------------------------------*/
static void ApplyDarkStyle(float dpiScale) {
    ImGui::StyleColorsDark();
    ImGuiStyle& s = ImGui::GetStyle();
    s.WindowRounding   = 6.0f;
    s.FrameRounding    = 4.0f;
    s.GrabRounding     = 4.0f;
    s.TabRounding      = 4.0f;
    s.PopupRounding    = 4.0f;
    s.ScrollbarRounding= 8.0f;
    s.WindowPadding    = ImVec2(12, 12);
    s.FramePadding     = ImVec2(8, 5);
    s.ItemSpacing      = ImVec2(8, 6);
    s.ItemInnerSpacing = ImVec2(6, 4);
    s.ScrollbarSize    = 14.0f;
    s.GrabMinSize      = 12.0f;

    using col::v4;
    s.Colors[ImGuiCol_WindowBg]        = v4(0x0d,0x0f,0x14);
    s.Colors[ImGuiCol_ChildBg]         = v4(0x15,0x18,0x20);
    s.Colors[ImGuiCol_PopupBg]         = v4(0x15,0x18,0x20, 240);
    s.Colors[ImGuiCol_Border]          = v4(0x2a,0x30,0x3c);
    s.Colors[ImGuiCol_FrameBg]         = v4(0x15,0x18,0x20);
    s.Colors[ImGuiCol_FrameBgHovered]  = v4(0x1a,0x1f,0x2a);
    s.Colors[ImGuiCol_FrameBgActive]   = v4(0x22,0x2a,0x38);
    s.Colors[ImGuiCol_TitleBg]         = v4(0x0d,0x0f,0x14);
    s.Colors[ImGuiCol_TitleBgActive]   = v4(0x0d,0x0f,0x14);
    s.Colors[ImGuiCol_MenuBarBg]       = v4(0x0d,0x0f,0x14);
    s.Colors[ImGuiCol_ScrollbarBg]     = v4(0x0d,0x0f,0x14);
    s.Colors[ImGuiCol_ScrollbarGrab]   = v4(0x2a,0x30,0x3c);
    s.Colors[ImGuiCol_CheckMark]       = v4(0x00,0x95,0xff);
    s.Colors[ImGuiCol_SliderGrab]      = v4(0x00,0x95,0xff);
    s.Colors[ImGuiCol_SliderGrabActive]= v4(0x33,0xaa,0xff);
    s.Colors[ImGuiCol_Button]          = v4(0x00,0x95,0xff, 200);
    s.Colors[ImGuiCol_ButtonHovered]   = v4(0x33,0xaa,0xff);
    s.Colors[ImGuiCol_ButtonActive]    = v4(0x00,0x70,0xc0);
    s.Colors[ImGuiCol_Header]          = v4(0x00,0x95,0xff, 80);
    s.Colors[ImGuiCol_HeaderHovered]   = v4(0x00,0x95,0xff, 140);
    s.Colors[ImGuiCol_HeaderActive]    = v4(0x00,0x95,0xff);
    s.Colors[ImGuiCol_Separator]       = v4(0x2a,0x30,0x3c);
    s.Colors[ImGuiCol_SeparatorHovered]= v4(0x00,0x95,0xff);
    s.Colors[ImGuiCol_SeparatorActive] = v4(0x33,0xaa,0xff);
    s.Colors[ImGuiCol_Tab]             = v4(0x15,0x18,0x20);
    s.Colors[ImGuiCol_TabHovered]      = v4(0x00,0x95,0xff, 180);
    s.Colors[ImGuiCol_TabActive]       = v4(0x00,0x95,0xff);
    s.Colors[ImGuiCol_TabUnfocused]    = v4(0x15,0x18,0x20);
    s.Colors[ImGuiCol_TabUnfocusedActive] = v4(0x1a,0x1f,0x2a);
    s.Colors[ImGuiCol_Text]            = v4(0xc8,0xd0,0xe0);
    s.Colors[ImGuiCol_TextDisabled]    = v4(0x6a,0x70,0x80);
    s.Colors[ImGuiCol_TableHeaderBg]   = v4(0x1a,0x1f,0x2a);
    s.Colors[ImGuiCol_TableBorderStrong] = v4(0x2a,0x30,0x3c);
    s.Colors[ImGuiCol_TableBorderLight]  = v4(0x22,0x28,0x32);
    s.Colors[ImGuiCol_TableRowBg]      = v4(0x12,0x15,0x1c);
    s.Colors[ImGuiCol_TableRowBgAlt]   = v4(0x15,0x18,0x20);
    s.ScaleAllSizes(dpiScale);
}

/* -----------------------------------------------------------------------------
 * 字体
 * ---------------------------------------------------------------------------*/
static bool LoadFonts(float dpiScale) {
    ImGuiIO& io = ImGui::GetIO();
    const float FSIZE = 16.0f * dpiScale;

    const char* monoPaths[] = {
        "C:\\Windows\\Fonts\\JetBrainsMono-Regular.ttf",
        "C:\\Users\\Public\\Fonts\\JetBrainsMono-Regular.ttf",
        "C:\\Windows\\Fonts\\consola.ttf",
    };
    ImFont* base = nullptr;
    for (auto p : monoPaths) {
        if (GetFileAttributesA(p) != INVALID_FILE_ATTRIBUTES) {
            base = io.Fonts->AddFontFromFileTTF(p, FSIZE);
            if (base) break;
        }
    }
    if (!base) io.Fonts->AddFontDefault();

    ImFontConfig cfgCJK; cfgCJK.MergeMode = true; cfgCJK.PixelSnapH = true;
    if (GetFileAttributesA("C:\\Windows\\Fonts\\msyh.ttc") != INVALID_FILE_ATTRIBUTES) {
        io.Fonts->AddFontFromFileTTF("C:\\Windows\\Fonts\\msyh.ttc", FSIZE,
            &cfgCJK, io.Fonts->GetGlyphRangesChineseSimplifiedCommon());
    }

    static const ImWchar symRanges[] = {
        0x2300, 0x23FF, 0x2600, 0x26FF, 0x2700, 0x27BF, 0x1F300, 0x1F6FF, 0
    };
    ImFontConfig cfgSym; cfgSym.MergeMode = true; cfgSym.PixelSnapH = true;
    if (GetFileAttributesA("C:\\Windows\\Fonts\\seguisym.ttf") != INVALID_FILE_ATTRIBUTES) {
        io.Fonts->AddFontFromFileTTF("C:\\Windows\\Fonts\\seguisym.ttf", FSIZE,
            &cfgSym, symRanges);
    }
    return true;
}

/* -----------------------------------------------------------------------------
 * Tab 1 —— 进程审计（含一键加入白名单）
 * ---------------------------------------------------------------------------*/
static void DrawTab1_Processes() {
    if (ImGui::Button(u8"🔄 刷新扫描", ImVec2(140, 0))) RefreshProcesses();
    if (ImGui::IsItemHovered(0)) ImGui::SetTooltip(u8"重新执行进程扫描，更新当前列表");
    ImGui::SameLine();

    if (g_state.procs.empty() && g_state.didInitialScan) {
        ImGui::TextColored(col::v4(0xff,0x44,0x44), u8"⚠ 扫描失败");
    } else {
        size_t sus = 0;
        for (auto& p : g_state.procs) if (p.isSuspicious) sus++;
        ImGui::TextDisabled(u8"共 %zu 个进程，%zu 项可疑", g_state.procs.size(), sus);
    }
    ImGui::SameLine();
    ImGui::SetNextItemWidth(180);
    ImGui::InputTextWithHint("##procf", u8"🔍 筛选进程", g_state.procFilter, sizeof(g_state.procFilter));
    ImGui::Spacing();

    if (g_state.procs.empty() && g_state.didInitialScan) {
        ImGui::Dummy(ImVec2(0, 40));
        ImGui::SetCursorPosX(ImGui::GetWindowWidth() * 0.35f);
        ImGui::TextColored(col::v4(0xff,0x44,0x44), u8"⚠ 进程扫描失败，请尝试以管理员身份运行");
        return;
    }

    if (ImGui::BeginTable("##split", 2,
            ImGuiTableFlags_BordersInnerV | ImGuiTableFlags_Resizable |
            ImGuiTableFlags_ScrollY | ImGuiTableFlags_ScrollX,
            ImVec2(-1, ImGui::GetContentRegionAvail().y))) {
        ImGui::TableSetupColumn("LeftAll");
        ImGui::TableSetupColumn("RightSuspicious");
        ImGui::TableNextRow();

        ImGui::TableNextColumn();
        ImGui::TextColored(col::v4(0xc8,0xd0,0xe0), u8"全部进程");
        ImGui::Separator();
        if (ImGui::BeginTable("##all", 5,
                ImGuiTableFlags_RowBg | ImGuiTableFlags_Borders |
                ImGuiTableFlags_ScrollY | ImGuiTableFlags_ScrollX | ImGuiTableFlags_Resizable |
                ImGuiTableFlags_Sortable | ImGuiTableFlags_SortMulti,
                ImVec2(-1, -1))) {
            ImGui::TableSetupScrollFreeze(0, 1);
            ImGui::TableSetupColumn("PID",  ImGuiTableColumnFlags_WidthFixed, 60.0f, 0);
            ImGui::TableSetupColumn(u8"进程名", ImGuiTableColumnFlags_WidthFixed, 180.0f, 1);
            ImGui::TableSetupColumn(u8"路径", ImGuiTableColumnFlags_WidthStretch, 0.0f, 2);
            ImGui::TableSetupColumn(u8"状态", ImGuiTableColumnFlags_WidthFixed, 80.0f, 3);
            ImGui::TableSetupColumn(u8"操作",  ImGuiTableColumnFlags_WidthFixed | ImGuiTableColumnFlags_NoSort, 80.0f, 4);
            ImGui::TableHeadersRow();

            if (ImGuiTableSortSpecs* sort_specs = ImGui::TableGetSortSpecs())
                if (sort_specs->SpecsDirty) {
                    std::sort(g_state.procs.begin(), g_state.procs.end(),
                        [&](const ProcessInfo& a, const ProcessInfo& b) {
                            for (int n = 0; n < sort_specs->SpecsCount; n++) {
                                const auto& spec = sort_specs->Specs[n];
                                int delta = 0;
                                switch (spec.ColumnUserID) {
                                    case 0: delta = (int)a.pid - (int)b.pid; break;
                                    case 1: delta = _stricmp(a.name, b.name); break;
                                    case 2: delta = _stricmp(a.fullPath, b.fullPath); break;
                                    case 3: delta = (int)b.isSuspicious - (int)a.isSuspicious; break;
                                }
                                if (delta != 0)
                                    return (spec.SortDirection == ImGuiSortDirection_Ascending) ? (delta < 0) : (delta > 0);
                            }
                            return false;
                        });
                    sort_specs->SpecsDirty = false;
                }

            for (auto& p : g_state.procs) {
                if (g_state.procFilter[0]) {
                    char pidStr[32]; snprintf(pidStr, sizeof(pidStr), "%lu", (unsigned long)p.pid);
                    if (!str_icontains(pidStr, g_state.procFilter) &&
                        !str_icontains(p.name, g_state.procFilter) &&
                        !str_icontains(p.fullPath, g_state.procFilter))
                        continue;
                }
                ImGui::TableNextRow();
                if (p.isSuspicious) ImGui::TableSetBgColor(ImGuiTableBgTarget_RowBg0, col::DANGER_BG);
                ImGui::TableNextColumn(); ImGui::Text("%lu", (unsigned long)p.pid);
                ImGui::TableNextColumn(); ImGui::TextUnformatted(p.name);
                ImGui::TableNextColumn(); ImGui::TextUnformatted(p.fullPath[0] ? p.fullPath : "—");
                ImGui::TableNextColumn();
                if (p.isSuspicious) ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(col::DANGER), u8"⚠ 可疑");
                else                ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(col::OK_GREEN), u8"✓ 正常");
                ImGui::TableNextColumn();
                /* 一键加入白名单 */
                char btnId[64]; snprintf(btnId, sizeof(btnId), u8"+白##%lu", (unsigned long)p.pid);
                if (ImGui::SmallButton(btnId)) {
                    g_rules.processWhitelist.insert(g_rules.lower(p.name));
                    g_rules.Save();
                    ApplyProcessRules(g_state.procs);
                    Notify(NotifyType::Info, u8"已将 '%s' 加入进程白名单", p.name);
                }
                if (ImGui::IsItemHovered(0)) ImGui::SetTooltip(u8"加入白名单：以后该进程不再被标记为可疑");
            }
            ImGui::EndTable();
        }

        ImGui::TableNextColumn();
        ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(col::DANGER), u8"⚠ 可疑进程");
        ImGui::Separator();
        if (ImGui::BeginTable("##sus", 4,
                ImGuiTableFlags_RowBg | ImGuiTableFlags_Borders |
                ImGuiTableFlags_ScrollY | ImGuiTableFlags_ScrollX | ImGuiTableFlags_Resizable |
                ImGuiTableFlags_Sortable | ImGuiTableFlags_SortMulti,
                ImVec2(-1, -1))) {
            ImGui::TableSetupScrollFreeze(0, 1);
            ImGui::TableSetupColumn("PID",      ImGuiTableColumnFlags_WidthFixed, 60.0f, 0);
            ImGui::TableSetupColumn(u8"进程名", ImGuiTableColumnFlags_WidthFixed, 180.0f, 1);
            ImGui::TableSetupColumn(u8"触发原因", ImGuiTableColumnFlags_WidthStretch, 0.0f, 2);
            ImGui::TableSetupColumn(u8"操作",    ImGuiTableColumnFlags_WidthFixed | ImGuiTableColumnFlags_NoSort, 80.0f, 3);
            ImGui::TableHeadersRow();

            if (ImGuiTableSortSpecs* sort_specs = ImGui::TableGetSortSpecs())
                if (sort_specs->SpecsDirty) {
                    std::sort(g_state.procs.begin(), g_state.procs.end(),
                        [&](const ProcessInfo& a, const ProcessInfo& b) {
                            for (int n = 0; n < sort_specs->SpecsCount; n++) {
                                const auto& spec = sort_specs->Specs[n];
                                int delta = 0;
                                switch (spec.ColumnUserID) {
                                    case 0: delta = (int)a.pid - (int)b.pid; break;
                                    case 1: delta = _stricmp(a.name, b.name); break;
                                    case 2: delta = _stricmp(a.reason, b.reason); break;
                                }
                                if (delta != 0)
                                    return (spec.SortDirection == ImGuiSortDirection_Ascending) ? (delta < 0) : (delta > 0);
                            }
                            return false;
                        });
                    sort_specs->SpecsDirty = false;
                }

            bool anySus = false;
            for (auto& p : g_state.procs) {
                if (!p.isSuspicious) continue;
                if (g_state.procFilter[0]) {
                    char pidStr[32]; snprintf(pidStr, sizeof(pidStr), "%lu", (unsigned long)p.pid);
                    if (!str_icontains(pidStr, g_state.procFilter) &&
                        !str_icontains(p.name, g_state.procFilter) &&
                        !str_icontains(p.reason, g_state.procFilter))
                        continue;
                }
                anySus = true;
                ImGui::TableNextRow();
                ImGui::TableSetBgColor(ImGuiTableBgTarget_RowBg0, col::DANGER_BG);
                ImGui::TableNextColumn(); ImGui::Text("%lu", (unsigned long)p.pid);
                ImGui::TableNextColumn(); ImGui::TextUnformatted(p.name);
                ImGui::TableNextColumn(); ImGui::TextUnformatted(p.reason);
                ImGui::TableNextColumn();
                char btnId[64]; snprintf(btnId, sizeof(btnId), u8"+白##s%lu", (unsigned long)p.pid);
                if (ImGui::SmallButton(btnId)) {
                    g_rules.processWhitelist.insert(g_rules.lower(p.name));
                    g_rules.Save();
                    ApplyProcessRules(g_state.procs);
                    Notify(NotifyType::Info, u8"已将 '%s' 加入进程白名单", p.name);
                }
                if (ImGui::IsItemHovered(0)) ImGui::SetTooltip(u8"加入白名单");
            }
            if (!anySus) {
                ImGui::TableNextRow();
                ImGui::TableNextColumn();
                ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(col::OK_GREEN), u8"✓ 未检测到可疑进程");
            }
            ImGui::EndTable();
        }
        ImGui::EndTable();
    }
}

/* -----------------------------------------------------------------------------
 * Tab 2 —— 驱动 & 窗口
 * ---------------------------------------------------------------------------*/
static void DrawTab2_DriversWindows() {
    if (ImGui::Button(u8"🔄 重新扫描", ImVec2(140, 0))) {
        RefreshDrivers();
        RefreshOverlayWindows();
    }
    if (ImGui::IsItemHovered(0)) ImGui::SetTooltip(u8"重新扫描内核驱动和可疑覆盖层窗口");
    ImGui::Spacing();

    /* 可疑驱动 */
    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(col::DANGER), u8"⚠ 可疑驱动");
    if (ImGui::IsItemHovered(0)) ImGui::SetTooltip(u8"需要管理员权限才能列出完整的内核驱动列表");
    ImGui::SameLine();
    ImGui::SetNextItemWidth(180);
    ImGui::InputTextWithHint("##drvfilter", u8"🔍 筛选驱动", g_state.driverFilter, sizeof(g_state.driverFilter));
    ImGui::Separator();
    if (g_state.drivers.empty() && g_state.didInitialScan) {
        ImGui::TextColored(col::v4(0xff,0x44,0x44), u8"⚠ 驱动扫描失败或权限不足");
    } else {
        bool any = false;
        for (auto& d : g_state.drivers) if (d.isSuspicious) { any = true; break; }
        if (!any) {
            ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(col::OK_GREEN),
                u8"✓ 未检测到可疑驱动（已扫描 %zu 个已加载内核驱动）",
                g_state.drivers.size());
        } else {
            ImVec2 sz(-1, ImGui::GetTextLineHeightWithSpacing() * 10);
            if (ImGui::BeginTable("##drv", 3,
                    ImGuiTableFlags_RowBg | ImGuiTableFlags_Borders |
                    ImGuiTableFlags_ScrollY | ImGuiTableFlags_ScrollX |
                    ImGuiTableFlags_Sortable | ImGuiTableFlags_SortMulti, sz)) {
                ImGui::TableSetupScrollFreeze(0, 1);
                ImGui::TableSetupColumn(u8"驱动名", ImGuiTableColumnFlags_WidthFixed, 220.0f, 0);
                ImGui::TableSetupColumn(u8"触发原因", ImGuiTableColumnFlags_WidthStretch, 0.0f, 1);
                ImGui::TableSetupColumn(u8"操作",    ImGuiTableColumnFlags_WidthFixed | ImGuiTableColumnFlags_NoSort, 80.0f, 2);
                ImGui::TableHeadersRow();

                if (ImGuiTableSortSpecs* sort_specs = ImGui::TableGetSortSpecs())
                    if (sort_specs->SpecsDirty) {
                        std::sort(g_state.drivers.begin(), g_state.drivers.end(),
                            [&](const DriverInfo& a, const DriverInfo& b) {
                                for (int n = 0; n < sort_specs->SpecsCount; n++) {
                                    const auto& spec = sort_specs->Specs[n];
                                    int delta = 0;
                                    switch (spec.ColumnUserID) {
                                        case 0: delta = _stricmp(a.name, b.name); break;
                                        case 1: delta = _stricmp(a.reason, b.reason); break;
                                    }
                                    if (delta != 0)
                                        return (spec.SortDirection == ImGuiSortDirection_Ascending) ? (delta < 0) : (delta > 0);
                                }
                                return false;
                            });
                        sort_specs->SpecsDirty = false;
                    }

                for (auto& d : g_state.drivers) {
                    if (!d.isSuspicious) continue;
                    if (g_state.driverFilter[0] &&
                        !str_icontains(d.name, g_state.driverFilter) &&
                        !str_icontains(d.reason, g_state.driverFilter))
                        continue;
                    ImGui::TableNextRow();
                    ImGui::TableSetBgColor(ImGuiTableBgTarget_RowBg0, col::DANGER_BG);
                    ImGui::TableNextColumn(); ImGui::TextUnformatted(d.name);
                    ImGui::TableNextColumn(); ImGui::TextUnformatted(d.reason);
                    ImGui::TableNextColumn();
                    char btnId[64]; snprintf(btnId, sizeof(btnId), u8"+白##d%s", d.name);
                    if (ImGui::SmallButton(btnId)) {
                        g_rules.driverWhitelist.insert(g_rules.lower(d.name));
                        g_rules.Save();
                        ApplyDriverRules(g_state.drivers);
                        Notify(NotifyType::Info, u8"已将 '%s' 加入驱动白名单", d.name);
                    }
                    if (ImGui::IsItemHovered(0)) ImGui::SetTooltip(u8"加入白名单");
                }
                ImGui::EndTable();
            }
        }
    }

    ImGui::Spacing(); ImGui::Separator(); ImGui::Spacing();

    /* 可疑覆盖层窗口 */
    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(col::DANGER), u8"⚠ 疑似覆盖层窗口");
    ImGui::SameLine();
    ImGui::SetNextItemWidth(180);
    ImGui::InputTextWithHint("##wndfilter", u8"🔍 筛选窗口", g_state.windowFilter, sizeof(g_state.windowFilter));
    ImGui::Separator();
    if (g_state.windows.empty() && g_state.didInitialScan) {
        ImGui::TextColored(col::v4(0xff,0x44,0x44), u8"⚠ 窗口扫描失败");
    } else if (g_state.windows.empty()) {
        ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(col::OK_GREEN),
            u8"✓ 未检测到可疑覆盖窗口");
    } else {
        if (ImGui::BeginTable("##wnd", 6,
                ImGuiTableFlags_RowBg | ImGuiTableFlags_Borders |
                ImGuiTableFlags_ScrollY | ImGuiTableFlags_ScrollX | ImGuiTableFlags_Resizable |
                ImGuiTableFlags_Sortable | ImGuiTableFlags_SortMulti, ImVec2(-1, -1))) {
            ImGui::TableSetupScrollFreeze(0, 1);
            ImGui::TableSetupColumn(u8"窗口标题",   ImGuiTableColumnFlags_WidthStretch, 0.0f, 0);
            ImGui::TableSetupColumn(u8"所属进程",   ImGuiTableColumnFlags_WidthFixed, 160.0f, 1);
            ImGui::TableSetupColumn(u8"尺寸",       ImGuiTableColumnFlags_WidthFixed, 100.0f, 2);
            ImGui::TableSetupColumn(u8"窗口类名",   ImGuiTableColumnFlags_WidthFixed, 160.0f, 3);
            ImGui::TableSetupColumn(u8"触发原因",   ImGuiTableColumnFlags_WidthStretch, 0.0f, 4);
            ImGui::TableSetupColumn(u8"操作",       ImGuiTableColumnFlags_WidthFixed | ImGuiTableColumnFlags_NoSort, 80.0f, 5);
            ImGui::TableHeadersRow();

            if (ImGuiTableSortSpecs* sort_specs = ImGui::TableGetSortSpecs())
                if (sort_specs->SpecsDirty) {
                    std::sort(g_state.windows.begin(), g_state.windows.end(),
                        [&](const WindowInfo& a, const WindowInfo& b) {
                            for (int n = 0; n < sort_specs->SpecsCount; n++) {
                                const auto& spec = sort_specs->Specs[n];
                                int delta = 0;
                                switch (spec.ColumnUserID) {
                                    case 0: delta = _stricmp(a.title, b.title); break;
                                    case 1: delta = _stricmp(a.ownerProcess, b.ownerProcess); break;
                                    case 2: delta = (a.width * a.height) - (b.width * b.height); break;
                                    case 3: delta = _stricmp(a.className, b.className); break;
                                    case 4: delta = _stricmp(a.reason, b.reason); break;
                                }
                                if (delta != 0)
                                    return (spec.SortDirection == ImGuiSortDirection_Ascending) ? (delta < 0) : (delta > 0);
                            }
                            return false;
                        });
                    sort_specs->SpecsDirty = false;
                }

            for (auto& w : g_state.windows) {
                if (g_state.windowFilter[0] &&
                    !str_icontains(w.title, g_state.windowFilter) &&
                    !str_icontains(w.ownerProcess, g_state.windowFilter) &&
                    !str_icontains(w.className, g_state.windowFilter) &&
                    !str_icontains(w.reason, g_state.windowFilter))
                    continue;
                ImGui::TableNextRow();
                ImGui::TableSetBgColor(ImGuiTableBgTarget_RowBg0, col::DANGER_BG);
                ImGui::TableNextColumn(); ImGui::TextUnformatted(w.title[0] ? w.title : "(无标题)");
                ImGui::TableNextColumn(); ImGui::TextUnformatted(w.ownerProcess[0] ? w.ownerProcess : "—");
                ImGui::TableNextColumn(); ImGui::Text("%dx%d", w.width, w.height);
                ImGui::TableNextColumn(); ImGui::TextUnformatted(w.className);
                ImGui::TableNextColumn(); ImGui::TextUnformatted(w.reason);
                ImGui::TableNextColumn();
                char btnId[64]; snprintf(btnId, sizeof(btnId), u8"+白##w%p", (void*)w.hwnd);
                if (ImGui::SmallButton(btnId)) {
                    g_rules.windowWhitelist.insert(g_rules.lower(w.className));
                    g_rules.Save();
                    ApplyWindowRules(g_state.windows);
                    Notify(NotifyType::Info, u8"已将 '%s' 加入窗口白名单", w.className);
                }
                if (ImGui::IsItemHovered(0)) ImGui::SetTooltip(u8"加入白名单");
            }
            ImGui::EndTable();
        }
    }
}

/* -----------------------------------------------------------------------------
 * Tab 3 —— 🔑 密码保镖
 * ---------------------------------------------------------------------------*/
static void DrawTab3_Password() {
    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(col::DIM_TEXT),
        u8"在下方输入你的密码，选择目标窗口后点击注入。");
    ImGui::Spacing();

    ImGui::Text(u8"明文密码");
    ImGui::SetNextItemWidth(-1);
    ImGui::InputText("##pwd", g_state.passwordInput, sizeof(g_state.passwordInput),
        ImGuiInputTextFlags_Password);
    if (ImGui::IsItemHovered(0)) ImGui::SetTooltip(u8"输入需要注入的真实密码，不会写入磁盘或注册表");
    ImGui::Spacing();

    ImGui::Text(u8"目标窗口");
    ImGui::SetNextItemWidth(-160);
    {
        const char* preview = (g_state.comboSel >= 0 && g_state.comboSel < (int)g_state.windows.size())
            ? g_state.windows[g_state.comboSel].title : u8"(请选择 —— 点右侧刷新可刷新列表)";
        if (ImGui::BeginCombo("##target", preview)) {
            for (int i = 0; i < (int)g_state.windows.size(); i++) {
                auto& w = g_state.windows[i];
                char label[512];
                snprintf(label, sizeof(label), "%s — %s##w%d",
                    w.title[0] ? w.title : "(无标题)",
                    w.ownerProcess[0] ? w.ownerProcess : "?", i);
                if (ImGui::Selectable(label, g_state.comboSel == i)) g_state.comboSel = i;
            }
            ImGui::EndCombo();
        }
    }
    ImGui::SameLine();
    if (ImGui::Button(u8"🔄 刷新窗口", ImVec2(140, 0))) RefreshOverlayWindows();
    if (ImGui::IsItemHovered(0)) ImGui::SetTooltip(u8"重新扫描可疑覆盖层窗口");
    ImGui::Spacing(); ImGui::Spacing();

    if (ImGui::Button(u8"🔀 生成混淆预览", ImVec2(180, 0))) {
        Gugas_ObfuscatePassword(g_state.passwordInput,
            g_state.obfuscated, g_state.realMask, &g_state.obfLen);
    }
    if (ImGui::IsItemHovered(0)) ImGui::SetTooltip(u8"模拟键盘记录器看到的乱序字符流（仅用于展示）");
    ImGui::SameLine();

    bool canInject = (g_state.passwordInput[0] != '\0') &&
                     (g_state.comboSel >= 0 && g_state.comboSel < (int)g_state.windows.size());
    ImGui::BeginDisabled(!canInject);
    if (ImGui::Button(u8"⌨ 注入密码到目标窗口", ImVec2(220, 0))) {
        g_state.injectConfirmOpen = true;
    }
    if (ImGui::IsItemHovered(0)) ImGui::SetTooltip(u8"通过 SendInput 向目标窗口逐字符发送真实密码");
    ImGui::EndDisabled();

    if (g_state.injectConfirmOpen) {
        ImGui::OpenPopup(u8"确认注入");
        g_state.injectConfirmOpen = false;
    }
    if (ImGui::BeginPopupModal(u8"确认注入", nullptr,
            ImGuiWindowFlags_AlwaysAutoResize | ImGuiWindowFlags_NoSavedSettings)) {
        auto& w = g_state.windows[g_state.comboSel];
        ImGui::Text(u8"即将向以下窗口注入密码：");
        ImGui::TextColored(col::v4(0x00,0x95,0xff), "  %s", w.title[0] ? w.title : "(无标题)");
        ImGui::Text(u8"目标进程：%s", w.ownerProcess[0] ? w.ownerProcess : "?");
        ImGui::Spacing();
        ImGui::TextColored(col::v4(0xff,0xaa,0x00), u8"⚠ 注入后密码将直接出现在目标窗口的输入焦点处，请确认目标正确。");
        ImGui::Spacing();
        if (ImGui::Button(u8"确认注入", ImVec2(120, 0))) {
            HWND h = g_state.windows[g_state.comboSel].hwnd;
            if (Gugas_InjectPassword(h, g_state.passwordInput)) {
                g_state.injectDonePending = true;
            } else {
                strncpy(g_state.injectFailMsg, Gugas_GetLastErrorString(), sizeof(g_state.injectFailMsg)-1);
                g_state.injectFailedOpen = true;
            }
            ImGui::CloseCurrentPopup();
        }
        ImGui::SameLine();
        if (ImGui::Button(u8"取消", ImVec2(120, 0))) ImGui::CloseCurrentPopup();
        ImGui::EndPopup();
    }

    if (g_state.injectDonePending) {
        Notify(NotifyType::Info, u8"✓ 密码已成功注入到目标窗口");
        g_state.injectDonePending = false;
    }
    if (g_state.injectFailedOpen) {
        ImGui::OpenPopup(u8"注入失败");
        g_state.injectFailedOpen = false;
    }
    if (ImGui::BeginPopupModal(u8"注入失败", nullptr,
            ImGuiWindowFlags_AlwaysAutoResize | ImGuiWindowFlags_NoSavedSettings)) {
        ImGui::TextColored(col::v4(0xff,0x44,0x44), u8"⚠ 注入失败");
        ImGui::TextWrapped("%s", g_state.injectFailMsg);
        ImGui::Spacing();
        if (ImGui::Button(u8"确定", ImVec2(120, 0))) ImGui::CloseCurrentPopup();
        ImGui::EndPopup();
    }

    ImGui::Spacing(); ImGui::Spacing();

    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(col::DIM_TEXT), u8"混淆预览（绿色=真实字符，灰色=干扰字符）");
    ImGui::Separator();
    if (ImGui::BeginChild("##obfBox", ImVec2(-1, 110), true)) {
        if (g_state.obfLen == 0) {
            ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(col::DIM_TEXT),
                u8"（点击上方 [生成混淆预览] 按钮以可视化反键盘记录效果）");
        } else {
            float wrap = ImGui::GetContentRegionAvail().x;
            float curW = 0;
            for (int i = 0; i < g_state.obfLen; i++) {
                char ch[2] = { g_state.obfuscated[i], 0 };
                ImVec2 sz = ImGui::CalcTextSize(ch);
                if (curW + sz.x + 2 > wrap) { curW = 0; }
                else if (i > 0) { ImGui::SameLine(0, 0); }
                ImU32 color = g_state.realMask[i] ? col::OK_GREEN : col::DIM_TEXT;
                ImGui::PushStyleColor(ImGuiCol_Text, color);
                ImGui::TextUnformatted(ch);
                ImGui::PopStyleColor();
                curW += sz.x;
            }
        }
    }
    ImGui::EndChild();

    ImGui::Spacing();
    ImGui::PushStyleColor(ImGuiCol_Text, ImGui::ColorConvertU32ToFloat4(col::WARN_AMBER));
    ImGui::TextWrapped(
        u8"⚠ 本功能仅对抗顺序记录型 Keylogger，无法防御截屏类监控软件，"
        u8"也无法防御内核级低层钩子（WH_KEYBOARD_LL）。请按真实风险等级综合判断。");
    ImGui::PopStyleColor();
}

/* -----------------------------------------------------------------------------
 * Tab 4 —— 📋 Hosts 审计
 * ---------------------------------------------------------------------------*/
static void DrawTab4_Hosts() {
    if (ImGui::Button(u8"🔄 刷新", ImVec2(140, 0))) RefreshHosts();
    if (ImGui::IsItemHovered(0)) ImGui::SetTooltip(u8"重新读取并解析 hosts 文件");
    ImGui::SameLine();

    if (g_state.hosts.empty() && g_state.didInitialScan) {
        ImGui::TextColored(col::v4(0xff,0x44,0x44), u8"⚠ Hosts 读取失败");
    } else {
        size_t susCount = 0;
        for (auto& h : g_state.hosts) if (h.isSuspicious) susCount++;
        ImGui::TextDisabled(u8"共 %zu 条 hosts 记录，%zu 项可疑", g_state.hosts.size(), susCount);
    }
    ImGui::SameLine();
    ImGui::SetNextItemWidth(180);
    ImGui::InputTextWithHint("##hostsf", u8"🔍 筛选 hosts", g_state.hostsFilter, sizeof(g_state.hostsFilter));
    ImGui::Spacing();

    if (g_state.hosts.empty() && g_state.didInitialScan) {
        ImGui::Dummy(ImVec2(0, 40));
        ImGui::SetCursorPosX(ImGui::GetWindowWidth() * 0.35f);
        ImGui::TextColored(col::v4(0xff,0x44,0x44), u8"⚠ 无法读取 hosts 文件，请检查文件权限");
        return;
    }

    if (ImGui::BeginTable("##hosts", 5,
            ImGuiTableFlags_RowBg | ImGuiTableFlags_Borders |
            ImGuiTableFlags_ScrollY | ImGuiTableFlags_ScrollX | ImGuiTableFlags_Resizable |
            ImGuiTableFlags_Sortable | ImGuiTableFlags_SortMulti,
            ImVec2(-1, ImGui::GetTextLineHeightWithSpacing() * 10))) {
        ImGui::TableSetupScrollFreeze(0, 1);
        ImGui::TableSetupColumn(u8"IP 地址",   ImGuiTableColumnFlags_WidthFixed, 140.0f, 0);
        ImGui::TableSetupColumn(u8"域名",      ImGuiTableColumnFlags_WidthFixed, 220.0f, 1);
        ImGui::TableSetupColumn(u8"原始行内容",ImGuiTableColumnFlags_WidthStretch, 0.0f, 2);
        ImGui::TableSetupColumn(u8"风险说明",  ImGuiTableColumnFlags_WidthFixed, 220.0f, 3);
        ImGui::TableSetupColumn(u8"操作",      ImGuiTableColumnFlags_WidthFixed | ImGuiTableColumnFlags_NoSort, 80.0f, 4);
        ImGui::TableHeadersRow();

        if (ImGuiTableSortSpecs* sort_specs = ImGui::TableGetSortSpecs())
            if (sort_specs->SpecsDirty) {
                std::sort(g_state.hosts.begin(), g_state.hosts.end(),
                    [&](const HostsEntry& a, const HostsEntry& b) {
                        for (int n = 0; n < sort_specs->SpecsCount; n++) {
                            const auto& spec = sort_specs->Specs[n];
                            int delta = 0;
                            switch (spec.ColumnUserID) {
                                case 0: delta = _stricmp(a.ip, b.ip); break;
                                case 1: delta = _stricmp(a.domain, b.domain); break;
                                case 2: delta = _stricmp(a.rawLine, b.rawLine); break;
                                case 3: delta = (int)b.isSuspicious - (int)a.isSuspicious; break;
                            }
                            if (delta != 0)
                                return (spec.SortDirection == ImGuiSortDirection_Ascending) ? (delta < 0) : (delta > 0);
                        }
                        return false;
                    });
                sort_specs->SpecsDirty = false;
            }

        for (auto& h : g_state.hosts) {
            if (g_state.hostsFilter[0] &&
                !str_icontains(h.ip, g_state.hostsFilter) &&
                !str_icontains(h.domain, g_state.hostsFilter) &&
                !str_icontains(h.rawLine, g_state.hostsFilter))
                continue;
            ImGui::TableNextRow();
            if (h.isSuspicious) ImGui::TableSetBgColor(ImGuiTableBgTarget_RowBg0, col::DANGER_BG);
            ImGui::TableNextColumn();
            if (h.isSuspicious) ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(col::DANGER), "%s", h.ip);
            else                ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(col::DIM_TEXT), "%s", h.ip);
            ImGui::TableNextColumn(); ImGui::TextUnformatted(h.domain);
            ImGui::TableNextColumn(); ImGui::TextUnformatted(h.rawLine);
            ImGui::TableNextColumn();
            if (h.isSuspicious)
                ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(col::DANGER), u8"⚠ 非本地重定向，疑似劫持");
            else
                ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(col::DIM_TEXT), u8"✓ 本地回环，正常");
            ImGui::TableNextColumn();
            char btnId[64]; snprintf(btnId, sizeof(btnId), u8"+白##h%s", h.domain);
            if (ImGui::SmallButton(btnId)) {
                g_rules.hostsWhitelist.insert(g_rules.lower(h.domain));
                g_rules.Save();
                ApplyHostsRules(g_state.hosts);
                Notify(NotifyType::Info, u8"已将 '%s' 加入 hosts 白名单", h.domain);
            }
            if (ImGui::IsItemHovered(0)) ImGui::SetTooltip(u8"加入白名单");
        }
        ImGui::EndTable();
    }

    ImGui::Spacing();
    ImGui::PushStyleColor(ImGuiCol_Text, ImGui::ColorConvertU32ToFloat4(col::DIM_TEXT));
    ImGui::TextWrapped(
        u8"提示：Hosts 文件位于 C:\\Windows\\System32\\drivers\\etc\\hosts，"
        u8"它在 DNS 解析之前生效。攻击者可借此把游戏/支付/邮箱域名劫持到钓鱼服务器。"
        u8"本工具仅检测，**不**修改该文件。");
    ImGui::PopStyleColor();
}

/* -----------------------------------------------------------------------------
 * Tab 5 —— ⚙ 白名单/黑名单管理
 * ---------------------------------------------------------------------------*/
static void DrawTab5_Rules() {
    ImGui::TextColored(col::v4(0xc8,0xd0,0xe0), u8"白名单 / 黑名单管理");
    ImGui::SameLine();
    ImGui::TextDisabled(u8"  规则文件：%s", g_rules.GetConfigPath().c_str());
    ImGui::Separator();

    const char* cats[] = { u8"进程", u8"驱动", u8"窗口", u8"Hosts" };
    ImGui::Combo(u8"类别##cat", &g_rules.editTab, cats, IM_ARRAYSIZE(cats));
    ImGui::Spacing();

    auto DrawList = [](const char* title, const std::set<std::string>& list,
                       std::set<std::string>& mutableList,
                       const char* /*addHint*/, const char* delHint) {
        ImGui::TextColored(col::v4(0x00,0x95,0xff), "%s", title);
        ImGui::Separator();
        if (list.empty()) {
            ImGui::TextDisabled(u8"（暂无规则）");
        } else {
            if (ImGui::BeginTable("##rl", 2, ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg)) {
                ImGui::TableSetupColumn(u8"规则内容", ImGuiTableColumnFlags_WidthStretch);
                ImGui::TableSetupColumn(u8"操作",     ImGuiTableColumnFlags_WidthFixed, 60.0f);
                for (auto it = list.begin(); it != list.end(); ) {
                    ImGui::TableNextRow();
                    ImGui::TableNextColumn(); ImGui::TextUnformatted(it->c_str());
                    ImGui::TableNextColumn();
                    char delId[64]; snprintf(delId, sizeof(delId), u8"删除##%s%u", it->c_str(), (unsigned)(it->size()));
                    if (ImGui::SmallButton(delId)) {
                        it = mutableList.erase(it);
                        g_rules.Save();
                        continue;
                    }
                    if (ImGui::IsItemHovered(0)) ImGui::SetTooltip(delHint);
                    ++it;
                }
                ImGui::EndTable();
            }
        }
    };

    switch (g_rules.editTab) {
        case 0: {
            ImGui::Columns(2, nullptr, true);
            DrawList(u8"进程白名单", g_rules.processWhitelist, g_rules.processWhitelist,
                     u8"", u8"删除该白名单规则");
            ImGui::NextColumn();
            DrawList(u8"进程黑名单", g_rules.processBlacklist, g_rules.processBlacklist,
                     u8"", u8"删除该黑名单规则");
            ImGui::Columns(1);
            ImGui::Spacing();
            ImGui::InputText(u8"添加白名单##wl", g_rules.wlBuf, sizeof(g_rules.wlBuf));
            ImGui::SameLine();
            if (ImGui::Button(u8"添加")) {
                if (g_rules.wlBuf[0]) {
                    g_rules.processWhitelist.insert(g_rules.lower(g_rules.wlBuf));
                    g_rules.wlBuf[0] = '\0';
                    g_rules.Save();
                    ApplyProcessRules(g_state.procs);
                    Notify(NotifyType::Info, u8"进程白名单已更新并生效");
                }
            }
            ImGui::InputText(u8"添加黑名单##bl", g_rules.blBuf, sizeof(g_rules.blBuf));
            ImGui::SameLine();
            if (ImGui::Button(u8"添加##blbtn")) {
                if (g_rules.blBuf[0]) {
                    g_rules.processBlacklist.insert(g_rules.lower(g_rules.blBuf));
                    g_rules.blBuf[0] = '\0';
                    g_rules.Save();
                    ApplyProcessRules(g_state.procs);
                    Notify(NotifyType::Info, u8"进程黑名单已更新并生效");
                }
            }
            break;
        }
        case 1: {
            ImGui::Columns(2, nullptr, true);
            DrawList(u8"驱动白名单", g_rules.driverWhitelist, g_rules.driverWhitelist, u8"", u8"删除");
            ImGui::NextColumn();
            DrawList(u8"驱动黑名单", g_rules.driverBlacklist, g_rules.driverBlacklist, u8"", u8"删除");
            ImGui::Columns(1);
            ImGui::Spacing();
            ImGui::InputText(u8"添加白名单##wl", g_rules.wlBuf, sizeof(g_rules.wlBuf));
            ImGui::SameLine();
            if (ImGui::Button(u8"添加")) {
                if (g_rules.wlBuf[0]) {
                    g_rules.driverWhitelist.insert(g_rules.lower(g_rules.wlBuf));
                    g_rules.wlBuf[0] = '\0'; g_rules.Save();
                    ApplyDriverRules(g_state.drivers);
                    Notify(NotifyType::Info, u8"驱动白名单已更新并生效");
                }
            }
            ImGui::InputText(u8"添加黑名单##bl", g_rules.blBuf, sizeof(g_rules.blBuf));
            ImGui::SameLine();
            if (ImGui::Button(u8"添加##blbtn")) {
                if (g_rules.blBuf[0]) {
                    g_rules.driverBlacklist.insert(g_rules.lower(g_rules.blBuf));
                    g_rules.blBuf[0] = '\0'; g_rules.Save();
                    ApplyDriverRules(g_state.drivers);
                    Notify(NotifyType::Info, u8"驱动黑名单已更新并生效");
                }
            }
            break;
        }
        case 2: {
            ImGui::Columns(2, nullptr, true);
            DrawList(u8"窗口白名单", g_rules.windowWhitelist, g_rules.windowWhitelist, u8"", u8"删除");
            ImGui::NextColumn();
            DrawList(u8"窗口黑名单", g_rules.windowBlacklist, g_rules.windowBlacklist, u8"", u8"删除");
            ImGui::Columns(1);
            ImGui::Spacing();
            ImGui::InputText(u8"添加白名单##wl", g_rules.wlBuf, sizeof(g_rules.wlBuf));
            ImGui::SameLine();
            if (ImGui::Button(u8"添加")) {
                if (g_rules.wlBuf[0]) {
                    g_rules.windowWhitelist.insert(g_rules.lower(g_rules.wlBuf));
                    g_rules.wlBuf[0] = '\0'; g_rules.Save();
                    ApplyWindowRules(g_state.windows);
                    Notify(NotifyType::Info, u8"窗口白名单已更新并生效");
                }
            }
            ImGui::InputText(u8"添加黑名单##bl", g_rules.blBuf, sizeof(g_rules.blBuf));
            ImGui::SameLine();
            if (ImGui::Button(u8"添加##blbtn")) {
                if (g_rules.blBuf[0]) {
                    g_rules.windowBlacklist.insert(g_rules.lower(g_rules.blBuf));
                    g_rules.blBuf[0] = '\0'; g_rules.Save();
                    ApplyWindowRules(g_state.windows);
                    Notify(NotifyType::Info, u8"窗口黑名单已更新并生效");
                }
            }
            break;
        }
        case 3: {
            ImGui::Columns(2, nullptr, true);
            DrawList(u8"Hosts 白名单", g_rules.hostsWhitelist, g_rules.hostsWhitelist, u8"", u8"删除");
            ImGui::NextColumn();
            DrawList(u8"Hosts 黑名单", g_rules.hostsBlacklist, g_rules.hostsBlacklist, u8"", u8"删除");
            ImGui::Columns(1);
            ImGui::Spacing();
            ImGui::InputText(u8"添加白名单##wl", g_rules.wlBuf, sizeof(g_rules.wlBuf));
            ImGui::SameLine();
            if (ImGui::Button(u8"添加")) {
                if (g_rules.wlBuf[0]) {
                    g_rules.hostsWhitelist.insert(g_rules.lower(g_rules.wlBuf));
                    g_rules.wlBuf[0] = '\0'; g_rules.Save();
                    ApplyHostsRules(g_state.hosts);
                    Notify(NotifyType::Info, u8"Hosts 白名单已更新并生效");
                }
            }
            ImGui::InputText(u8"添加黑名单##bl", g_rules.blBuf, sizeof(g_rules.blBuf));
            ImGui::SameLine();
            if (ImGui::Button(u8"添加##blbtn")) {
                if (g_rules.blBuf[0]) {
                    g_rules.hostsBlacklist.insert(g_rules.lower(g_rules.blBuf));
                    g_rules.blBuf[0] = '\0'; g_rules.Save();
                    ApplyHostsRules(g_state.hosts);
                    Notify(NotifyType::Info, u8"Hosts 黑名单已更新并生效");
                }
            }
            break;
        }
    }

    ImGui::Spacing(); ImGui::Separator(); ImGui::Spacing();
    ImGui::TextColored(col::v4(0xff,0xaa,0x00), u8"⚠ 规则说明");
    ImGui::BulletText(u8"白名单：精确匹配（大小写不敏感）。命中后该项不再被标记为可疑。");
    ImGui::BulletText(u8"黑名单：子串匹配（大小写不敏感）。命中后强制标记为可疑，并追加提示。");
    ImGui::BulletText(u8"白名单优先级高于黑名单——同一项同时命中两者时按白名单处理。");
    ImGui::BulletText(u8"规则保存于 %%LOCALAPPDATA%%\\Gugas\\gugas_rules.ini，可手动编辑或备份。");
}

/* -----------------------------------------------------------------------------
 * Tab 6 —— 🔍 深度扫描（服务 + 启动项 + 网络连接）
 * ---------------------------------------------------------------------------*/
static void DrawTab6_DeepScan() {
    if (ImGui::Button(u8"🔄 扫描服务", ImVec2(120, 0))) {
        RefreshServices();
    }
    if (ImGui::IsItemHovered(0)) ImGui::SetTooltip(u8"枚举所有系统服务（需要管理员权限才能获取完整信息）");
    ImGui::SameLine();
    if (ImGui::Button(u8"🔄 扫描启动项", ImVec2(120, 0))) {
        RefreshStartup();
    }
    if (ImGui::IsItemHovered(0)) ImGui::SetTooltip(u8"扫描注册表 Run/RunOnce 和启动文件夹");
    ImGui::SameLine();
    if (ImGui::Button(u8"🔄 扫描网络", ImVec2(120, 0))) {
        RefreshNetwork();
    }
    if (ImGui::IsItemHovered(0)) ImGui::SetTooltip(u8"枚举所有 TCP/UDP 连接及对应进程");
    ImGui::Spacing();

    /* --- 服务 --- */
    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(col::DANGER), u8"⚠ 可疑服务");
    if (ImGui::IsItemHovered(0)) ImGui::SetTooltip(u8"服务路径位于 Temp/AppData 或名称含敏感词");
    ImGui::SameLine();
    ImGui::SetNextItemWidth(180);
    ImGui::InputTextWithHint("##svcf", u8"🔍 筛选服务", g_state.svcFilter, sizeof(g_state.svcFilter));
    ImGui::Separator();
    if (g_state.services.empty()) {
        ImGui::TextDisabled(u8"点击上方按钮开始扫描服务");
    } else {
        bool any = false;
        for (auto& s : g_state.services) if (s.isSuspicious) { any = true; break; }
        if (!any) {
            ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(col::OK_GREEN),
                u8"✓ 未检测到可疑服务（已扫描 %zu 个）", g_state.services.size());
        } else {
            ImVec2 sz(-1, ImGui::GetTextLineHeightWithSpacing() * 8);
            if (ImGui::BeginTable("##svc", 4,
                    ImGuiTableFlags_RowBg | ImGuiTableFlags_Borders |
                    ImGuiTableFlags_ScrollY | ImGuiTableFlags_ScrollX |
                    ImGuiTableFlags_Sortable | ImGuiTableFlags_SortMulti, sz)) {
                ImGui::TableSetupScrollFreeze(0, 1);
                ImGui::TableSetupColumn(u8"服务名",     ImGuiTableColumnFlags_WidthFixed, 220.0f, 0);
                ImGui::TableSetupColumn(u8"显示名称",   ImGuiTableColumnFlags_WidthFixed, 280.0f, 1);
                ImGui::TableSetupColumn(u8"触发原因",   ImGuiTableColumnFlags_WidthStretch, 0.0f, 2);
                ImGui::TableSetupColumn(u8"PID",        ImGuiTableColumnFlags_WidthFixed, 60.0f, 3);
                ImGui::TableHeadersRow();

                if (ImGuiTableSortSpecs* sort_specs = ImGui::TableGetSortSpecs())
                    if (sort_specs->SpecsDirty) {
                        std::sort(g_state.services.begin(), g_state.services.end(),
                            [&](const ServiceInfo& a, const ServiceInfo& b) {
                                for (int n = 0; n < sort_specs->SpecsCount; n++) {
                                    const auto& spec = sort_specs->Specs[n];
                                    int delta = 0;
                                    switch (spec.ColumnUserID) {
                                        case 0: delta = _stricmp(a.serviceName, b.serviceName); break;
                                        case 1: delta = _stricmp(a.displayName, b.displayName); break;
                                        case 2: delta = _stricmp(a.reason, b.reason); break;
                                        case 3: delta = (int)a.processId - (int)b.processId; break;
                                    }
                                    if (delta != 0)
                                        return (spec.SortDirection == ImGuiSortDirection_Ascending) ? (delta < 0) : (delta > 0);
                                }
                                return false;
                            });
                        sort_specs->SpecsDirty = false;
                    }

                for (auto& s : g_state.services) {
                    if (!s.isSuspicious) continue;
                    if (g_state.svcFilter[0] &&
                        !str_icontains(s.serviceName, g_state.svcFilter) &&
                        !str_icontains(s.displayName, g_state.svcFilter) &&
                        !str_icontains(s.reason, g_state.svcFilter))
                        continue;
                    ImGui::TableNextRow();
                    ImGui::TableSetBgColor(ImGuiTableBgTarget_RowBg0, col::DANGER_BG);
                    ImGui::TableNextColumn(); ImGui::TextUnformatted(s.serviceName);
                    ImGui::TableNextColumn(); ImGui::TextUnformatted(s.displayName);
                    ImGui::TableNextColumn(); ImGui::TextUnformatted(s.reason);
                    ImGui::TableNextColumn(); ImGui::Text("%lu", (unsigned long)s.processId);
                }
                ImGui::EndTable();
            }
        }
    }

    ImGui::Spacing();

    /* --- 启动项 --- */
    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(col::DANGER), u8"⚠ 可疑启动项");
    if (ImGui::IsItemHovered(0)) ImGui::SetTooltip(u8"注册表或启动文件夹中的可疑自启动条目");
    ImGui::SameLine();
    ImGui::SetNextItemWidth(180);
    ImGui::InputTextWithHint("##startupf", u8"🔍 筛选启动项", g_state.startupFilter, sizeof(g_state.startupFilter));
    ImGui::Separator();
    if (g_state.startups.empty()) {
        ImGui::TextDisabled(u8"点击上方按钮开始扫描启动项");
    } else {
        bool any = false;
        for (auto& s : g_state.startups) if (s.isSuspicious) { any = true; break; }
        if (!any) {
            ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(col::OK_GREEN),
                u8"✓ 未检测到可疑启动项（已扫描 %zu 个）", g_state.startups.size());
        } else {
            ImVec2 sz(-1, ImGui::GetTextLineHeightWithSpacing() * 8);
            if (ImGui::BeginTable("##startup", 4,
                    ImGuiTableFlags_RowBg | ImGuiTableFlags_Borders |
                    ImGuiTableFlags_ScrollY | ImGuiTableFlags_ScrollX |
                    ImGuiTableFlags_Sortable | ImGuiTableFlags_SortMulti, sz)) {
                ImGui::TableSetupScrollFreeze(0, 1);
                ImGui::TableSetupColumn(u8"名称",     ImGuiTableColumnFlags_WidthFixed, 200.0f, 0);
                ImGui::TableSetupColumn(u8"路径",     ImGuiTableColumnFlags_WidthStretch, 0.0f, 1);
                ImGui::TableSetupColumn(u8"位置",     ImGuiTableColumnFlags_WidthFixed, 180.0f, 2);
                ImGui::TableSetupColumn(u8"原因",     ImGuiTableColumnFlags_WidthFixed, 200.0f, 3);
                ImGui::TableHeadersRow();

                if (ImGuiTableSortSpecs* sort_specs = ImGui::TableGetSortSpecs())
                    if (sort_specs->SpecsDirty) {
                        std::sort(g_state.startups.begin(), g_state.startups.end(),
                            [&](const StartupEntry& a, const StartupEntry& b) {
                                for (int n = 0; n < sort_specs->SpecsCount; n++) {
                                    const auto& spec = sort_specs->Specs[n];
                                    int delta = 0;
                                    switch (spec.ColumnUserID) {
                                        case 0: delta = _stricmp(a.name, b.name); break;
                                        case 1: delta = _stricmp(a.path, b.path); break;
                                        case 2: delta = _stricmp(a.location, b.location); break;
                                        case 3: delta = _stricmp(a.reason, b.reason); break;
                                    }
                                    if (delta != 0)
                                        return (spec.SortDirection == ImGuiSortDirection_Ascending) ? (delta < 0) : (delta > 0);
                                }
                                return false;
                            });
                        sort_specs->SpecsDirty = false;
                    }

                for (auto& s : g_state.startups) {
                    if (!s.isSuspicious) continue;
                    if (g_state.startupFilter[0] &&
                        !str_icontains(s.name, g_state.startupFilter) &&
                        !str_icontains(s.path, g_state.startupFilter) &&
                        !str_icontains(s.location, g_state.startupFilter) &&
                        !str_icontains(s.reason, g_state.startupFilter))
                        continue;
                    ImGui::TableNextRow();
                    ImGui::TableSetBgColor(ImGuiTableBgTarget_RowBg0, col::DANGER_BG);
                    ImGui::TableNextColumn(); ImGui::TextUnformatted(s.name);
                    ImGui::TableNextColumn(); ImGui::TextWrapped("%s", s.path);
                    ImGui::TableNextColumn(); ImGui::TextUnformatted(s.location);
                    ImGui::TableNextColumn(); ImGui::TextUnformatted(s.reason);
                }
                ImGui::EndTable();
            }
        }
    }

    ImGui::Spacing();

    /* --- 网络连接 --- */
    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(col::DANGER), u8"⚠ 可疑网络连接");
    if (ImGui::IsItemHovered(0)) ImGui::SetTooltip(u8"已建立至非常见端口的连接或进程名含敏感词");
    ImGui::SameLine();
    ImGui::SetNextItemWidth(180);
    ImGui::InputTextWithHint("##connf", u8"🔍 筛选连接", g_state.connFilter, sizeof(g_state.connFilter));
    ImGui::Separator();
    if (g_state.connections.empty()) {
        ImGui::TextDisabled(u8"点击上方按钮开始扫描网络连接");
    } else {
        bool any = false;
        for (auto& c : g_state.connections) if (c.isSuspicious) { any = true; break; }
        if (!any) {
            ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(col::OK_GREEN),
                u8"✓ 未检测到可疑网络连接（已扫描 %zu 个）", g_state.connections.size());
        } else {
            ImVec2 sz(-1, ImGui::GetTextLineHeightWithSpacing() * 8);
            if (ImGui::BeginTable("##conn", 6,
                    ImGuiTableFlags_RowBg | ImGuiTableFlags_Borders |
                    ImGuiTableFlags_ScrollY | ImGuiTableFlags_ScrollX |
                    ImGuiTableFlags_Sortable | ImGuiTableFlags_SortMulti, sz)) {
                ImGui::TableSetupScrollFreeze(0, 1);
                ImGui::TableSetupColumn(u8"协议",       ImGuiTableColumnFlags_WidthFixed, 50.0f, 0);
                ImGui::TableSetupColumn(u8"本地地址",   ImGuiTableColumnFlags_WidthFixed, 150.0f, 1);
                ImGui::TableSetupColumn(u8"远程地址",   ImGuiTableColumnFlags_WidthFixed, 150.0f, 2);
                ImGui::TableSetupColumn(u8"状态",       ImGuiTableColumnFlags_WidthFixed, 80.0f, 3);
                ImGui::TableSetupColumn(u8"进程",       ImGuiTableColumnFlags_WidthFixed, 140.0f, 4);
                ImGui::TableSetupColumn(u8"原因",       ImGuiTableColumnFlags_WidthStretch, 0.0f, 5);
                ImGui::TableHeadersRow();

                if (ImGuiTableSortSpecs* sort_specs = ImGui::TableGetSortSpecs())
                    if (sort_specs->SpecsDirty) {
                        std::sort(g_state.connections.begin(), g_state.connections.end(),
                            [&](const ConnectionInfo& a, const ConnectionInfo& b) {
                                for (int n = 0; n < sort_specs->SpecsCount; n++) {
                                    const auto& spec = sort_specs->Specs[n];
                                    int delta = 0;
                                    switch (spec.ColumnUserID) {
                                        case 0: delta = (int)a.state - (int)b.state; break;
                                        case 1: delta = _stricmp(a.localAddr, b.localAddr); break;
                                        case 2: delta = _stricmp(a.remoteAddr, b.remoteAddr); break;
                                        case 3: delta = _stricmp(tcp_state_str(a.state), tcp_state_str(b.state)); break;
                                        case 4: delta = _stricmp(a.processName, b.processName); break;
                                        case 5: delta = _stricmp(a.reason, b.reason); break;
                                    }
                                    if (delta != 0)
                                        return (spec.SortDirection == ImGuiSortDirection_Ascending) ? (delta < 0) : (delta > 0);
                                }
                                return false;
                            });
                        sort_specs->SpecsDirty = false;
                    }

                for (auto& c : g_state.connections) {
                    if (!c.isSuspicious) continue;
                    if (g_state.connFilter[0]) {
                        char localStr[64], remoteStr[64];
                        snprintf(localStr, sizeof(localStr), "%s:%lu", c.localAddr, (unsigned long)c.localPort);
                        if (c.remotePort == 0) snprintf(remoteStr, sizeof(remoteStr), "-");
                        else snprintf(remoteStr, sizeof(remoteStr), "%s:%lu", c.remoteAddr, (unsigned long)c.remotePort);
                        const char* proto = (c.state == 0) ? "UDP" : "TCP";
                        const char* stateStr = (c.state == 0) ? "UDP" : tcp_state_str(c.state);
                        if (!str_icontains(proto, g_state.connFilter) &&
                            !str_icontains(localStr, g_state.connFilter) &&
                            !str_icontains(remoteStr, g_state.connFilter) &&
                            !str_icontains(stateStr, g_state.connFilter) &&
                            !str_icontains(c.processName, g_state.connFilter) &&
                            !str_icontains(c.reason, g_state.connFilter))
                            continue;
                    }
                    ImGui::TableNextRow();
                    ImGui::TableSetBgColor(ImGuiTableBgTarget_RowBg0, col::DANGER_BG);
                    const char* proto = (c.state == 0) ? "UDP" : "TCP";
                    ImGui::TableNextColumn(); ImGui::TextUnformatted(proto);
                    ImGui::TableNextColumn();
                    ImGui::Text("%s:%lu", c.localAddr, (unsigned long)c.localPort);
                    ImGui::TableNextColumn();
                    if (c.remotePort == 0) {
                        ImGui::TextUnformatted("-");
                    } else {
                        ImGui::Text("%s:%lu", c.remoteAddr, (unsigned long)c.remotePort);
                    }
                    ImGui::TableNextColumn();
                    ImGui::TextUnformatted((c.state == 0) ? "UDP" : tcp_state_str(c.state));
                    ImGui::TableNextColumn(); ImGui::TextUnformatted(c.processName);
                    ImGui::TableNextColumn(); ImGui::TextUnformatted(c.reason);
                }
                ImGui::EndTable();
            }
        }
    }
}

/* -----------------------------------------------------------------------------
 * Tab 7 —— 📁 文件系统扫描（多线程硬盘目录扫描 + 盘符选择）
 * ---------------------------------------------------------------------------*/
static void DrawTab7_FileSystem() {
    /* --- 盘符选择 --- */
    char avail[26];
    int availCount = Gds_GetAvailableDrives(avail, 26);

    ImGui::Text(u8"选择扫描盘符：");
    if (ImGui::IsItemHovered(0)) ImGui::SetTooltip(u8"可多选，每个盘符由独立线程并行扫描");
    for (int i = 0; i < availCount; i++) {
        if (i > 0) ImGui::SameLine();
        char label[8];
        snprintf(label, sizeof(label), "%c:##drv", avail[i]);
        bool checked = g_state.selectedDrives[avail[i] - 'A'];
        if (ImGui::Checkbox(label, &checked)) {
            g_state.selectedDrives[avail[i] - 'A'] = checked;
        }
    }
    ImGui::SameLine();
    if (ImGui::SmallButton(u8"全选")) {
        for (int i = 0; i < availCount; i++)
            g_state.selectedDrives[avail[i] - 'A'] = true;
    }
    ImGui::SameLine();
    if (ImGui::SmallButton(u8"取消全选")) {
        for (int i = 0; i < 26; i++)
            g_state.selectedDrives[i] = false;
    }
    ImGui::Spacing();

    /* --- 扫描按钮 --- */
    bool hasSelection = false;
    for (int i = 0; i < 26; i++) if (g_state.selectedDrives[i]) { hasSelection = true; break; }

    ImGui::BeginDisabled(!hasSelection || g_state.fileScanRunning);
    if (ImGui::Button(u8"🚀 快速扫描", ImVec2(160, 0))) {
        RefreshFileSystemScan(GDS_MODE_QUICK);
    }
    if (ImGui::IsItemHovered(0)) ImGui::SetTooltip(u8"多线程扫描选中盘符的关键目录，最大深度 2 层");
    ImGui::SameLine();
    if (ImGui::Button(u8"🔥 深度扫描", ImVec2(160, 0))) {
        RefreshFileSystemScan(GDS_MODE_DEEP);
    }
    if (ImGui::IsItemHovered(0)) ImGui::SetTooltip(u8"多线程深度扫描选中盘符，最大深度 4 层，耗时较长");
    ImGui::EndDisabled();

    /* --- 进度显示 --- */
    if (g_state.fileScanRunning) {
        ImGui::SameLine();
        ImGui::TextDisabled(u8"扫描中… 文件 %d / 可疑 %d / 目录 %d",
            (int)g_state.fileProgress.filesScanned,
            (int)g_state.fileProgress.filesSuspicious,
            (int)g_state.fileProgress.dirsScanned);
    } else if (!g_state.fileEntries.empty()) {
        ImGui::SameLine();
        ImGui::TextDisabled(u8"上次扫描发现 %zu 个可疑文件", g_state.fileEntries.size());
    }
    ImGui::Spacing();

    /* --- 结果表格 --- */
    if (!g_state.fileEntries.empty()) {
        ImGui::SetNextItemWidth(220);
        ImGui::InputTextWithHint("##filef", u8"🔍 筛选文件", g_state.fileFilter, sizeof(g_state.fileFilter));
        ImGui::Spacing();
    }
    if (g_state.fileEntries.empty()) {
        ImGui::TextDisabled(u8"选择盘符后点击扫描按钮开始文件系统扫描");
    } else {
        ImVec2 sz(-1, ImGui::GetTextLineHeightWithSpacing() * 16);
        if (ImGui::BeginTable("##files", 5,
                ImGuiTableFlags_RowBg | ImGuiTableFlags_Borders |
                ImGuiTableFlags_ScrollY | ImGuiTableFlags_ScrollX |
                ImGuiTableFlags_Sortable | ImGuiTableFlags_SortMulti, sz)) {
            ImGui::TableSetupScrollFreeze(0, 1);
            ImGui::TableSetupColumn(u8"文件名",       ImGuiTableColumnFlags_WidthFixed, 200.0f, 0);
            ImGui::TableSetupColumn(u8"完整路径",     ImGuiTableColumnFlags_WidthStretch, 0.0f, 1);
            ImGui::TableSetupColumn(u8"大小",         ImGuiTableColumnFlags_WidthFixed, 90.0f, 2);
            ImGui::TableSetupColumn(u8"PE 信息",      ImGuiTableColumnFlags_WidthFixed, 160.0f, 3);
            ImGui::TableSetupColumn(u8"触发原因",     ImGuiTableColumnFlags_WidthFixed, 280.0f, 4);
            ImGui::TableHeadersRow();

            if (ImGuiTableSortSpecs* sort_specs = ImGui::TableGetSortSpecs())
                if (sort_specs->SpecsDirty) {
                    std::sort(g_state.fileEntries.begin(), g_state.fileEntries.end(),
                        [&](const GdsFileEntry& a, const GdsFileEntry& b) {
                            for (int n = 0; n < sort_specs->SpecsCount; n++) {
                                const auto& spec = sort_specs->Specs[n];
                                int delta = 0;
                                switch (spec.ColumnUserID) {
                                    case 0: delta = _stricmp(a.name, b.name); break;
                                    case 1: delta = _stricmp(a.path, b.path); break;
                                    case 2: {
                                        unsigned long long sa = ((unsigned long long)a.sizeHigh << 32) | a.sizeLow;
                                        unsigned long long sb = ((unsigned long long)b.sizeHigh << 32) | b.sizeLow;
                                        delta = (sa > sb) - (sa < sb);
                                        break;
                                    }
                                    case 3: {
                                        delta = (int)b.pe.isPE - (int)a.pe.isPE;
                                        if (delta == 0) delta = (int)(b.entropy * 10) - (int)(a.entropy * 10);
                                        break;
                                    }
                                    case 4: delta = _stricmp(a.reason, b.reason); break;
                                }
                                if (delta != 0)
                                    return (spec.SortDirection == ImGuiSortDirection_Ascending) ? (delta < 0) : (delta > 0);
                            }
                            return false;
                        });
                    sort_specs->SpecsDirty = false;
                }

            for (auto& f : g_state.fileEntries) {
                if (!f.isSuspicious) continue;
                if (g_state.fileFilter[0] &&
                    !str_icontains(f.name, g_state.fileFilter) &&
                    !str_icontains(f.path, g_state.fileFilter) &&
                    !str_icontains(f.reason, g_state.fileFilter))
                    continue;
                ImGui::TableNextRow();
                ImGui::TableSetBgColor(ImGuiTableBgTarget_RowBg0, col::DANGER_BG);
                ImGui::TableNextColumn(); ImGui::TextUnformatted(f.name);
                ImGui::TableNextColumn(); ImGui::TextWrapped("%s", f.path);
                ImGui::TableNextColumn();
                if (f.sizeHigh == 0) {
                    ImGui::Text("%lu B", (unsigned long)f.sizeLow);
                } else {
                    ImGui::Text("%llu B",
                        ((unsigned long long)f.sizeHigh << 32) | f.sizeLow);
                }
                /* PE 信息列：架构 + 签名 + 熵值 */
                ImGui::TableNextColumn();
                if (f.pe.isPE) {
                    /* 架构 */
                    const char* arch = "?";
                    if (f.pe.machine == 0x014c) arch = "x86";
                    else if (f.pe.machine == 0x8664) arch = "x64";
                    else if (f.pe.machine == 0xaa64) arch = "ARM64";
                    else if (f.pe.machine == 0x01c0) arch = "ARM";
                    ImGui::Text("%s%s", arch, f.pe.is64Bit ? "+" : "");
                    /* 签名 */
                    ImGui::SameLine();
                    switch (f.sigResult) {
                        case GDS_SIG_VALID:
                            ImGui::TextColored(col::v4(0x00,0xff,0x9f), u8" 已签");
                            break;
                        case GDS_SIG_UNSIGNED:
                            ImGui::TextColored(col::v4(0xff,0xaa,0x00), u8" 无签");
                            break;
                        case GDS_SIG_INVALID:
                        case GDS_SIG_UNTRUSTED:
                            ImGui::TextColored(col::v4(0xff,0x44,0x44), u8" 无效");
                            break;
                        default:
                            ImGui::TextDisabled(u8" -");
                    }
                    /* 熵值 */
                    if (f.entropy > 0.0f) {
                        ImGui::SameLine();
                        ImU32 ec = (f.entropy >= 7.0f) ? col::DANGER :
                                   (f.entropy >= 6.0f) ? col::WARN_AMBER :
                                   col::DIM_TEXT;
                        ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(ec),
                            " H%.1f", f.entropy);
                    }
                } else {
                    ImGui::TextDisabled(u8"非 PE");
                }
                ImGui::TableNextColumn(); ImGui::TextUnformatted(f.reason);
            }
            ImGui::EndTable();
        }
    }
}

/* -----------------------------------------------------------------------------
 * 底部状态栏
 * ---------------------------------------------------------------------------*/
static void DrawStatusBar() {
    float barH = 28.0f;
    ImGui::SetCursorPosY(ImGui::GetWindowHeight() - barH);
    ImGui::PushStyleColor(ImGuiCol_ChildBg, col::v4(0x0a,0x0c,0x12));
    if (ImGui::BeginChild("##status", ImVec2(-1, barH), false,
            ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse)) {

        if (g_state.isAdmin) {
            ImGui::TextColored(col::v4(0x00,0x95,0xff), u8"● Administrator");
        } else {
            ImGui::TextColored(col::v4(0xff,0xaa,0x00), u8"● Standard User");
        }
        if (ImGui::IsItemHovered(0))
            ImGui::SetTooltip(u8"当前进程的运行权限级别。管理员模式可列出全部内核驱动。");

        ImGui::SameLine(ImGui::GetWindowWidth() * 0.38f);
        if (g_state.antiCaptureOk) {
            ImGui::TextColored(col::v4(0x00,0xff,0x9f), u8"AntiCapture: ON");
        } else {
            ImGui::TextColored(col::v4(0xff,0x44,0x44), u8"AntiCapture: OFF");
        }
        if (ImGui::IsItemHovered(0))
            ImGui::SetTooltip(u8"防截屏状态：ON=窗口内容对标准截屏 API 不可见；OFF=可能被截屏工具捕获");

        ImGui::SameLine(ImGui::GetWindowWidth() * 0.72f);
        int min = (int)(g_state.lastScanElapsed / 60.0f);
        int sec = (int)(g_state.lastScanElapsed) % 60;
        if (min == 0 && sec < 5)
            ImGui::TextDisabled(u8"上次扫描：刚刚");
        else
            ImGui::TextDisabled(u8"上次扫描：%02d:%02d", min, sec);
    }
    ImGui::EndChild();
    ImGui::PopStyleColor();
}

/* -----------------------------------------------------------------------------
 * Toast 通知条渲染
 * ---------------------------------------------------------------------------*/
static void DrawNotifications(float dt) {
    if (g_notifications.empty()) return;

    float notifH = 34.0f;
    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(10, 6));
    ImGui::PushStyleVar(ImGuiStyleVar_ItemSpacing,   ImVec2(6, 0));

    for (size_t i = 0; i < g_notifications.size(); ) {
        auto& n = g_notifications[i];
        n.remainingSec -= dt;
        if (n.remainingSec <= 0.0f) {
            g_notifications.erase(g_notifications.begin() + i);
            continue;
        }

        ImU32 bg = 0;
        switch (n.type) {
            case NotifyType::Info:    bg = IM_COL32(0x00,0x60,0xc0, 200); break;
            case NotifyType::Warning: bg = IM_COL32(0xc0,0x80,0x00, 200); break;
            case NotifyType::Error:   bg = IM_COL32(0xc0,0x20,0x20, 200); break;
        }

        ImVec2 region = ImGui::GetContentRegionAvail();
        ImGui::PushStyleColor(ImGuiCol_ChildBg, bg);
        ImGui::PushStyleColor(ImGuiCol_Border,  IM_COL32(255,255,255,40));
        ImGui::PushStyleVar(ImGuiStyleVar_ChildRounding, 4.0f);
        char id[32]; snprintf(id, sizeof(id), "##n%zu", i);

        ImGui::BeginChild(id, ImVec2(region.x, notifH), true,
            ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse);

        const char* icon = "";
        switch (n.type) {
            case NotifyType::Info:    icon = u8"ℹ "; break;
            case NotifyType::Warning: icon = u8"⚠ "; break;
            case NotifyType::Error:   icon = u8"✖ "; break;
        }
        ImGui::TextColored(col::v4(0xff,0xff,0xff), "%s%s", icon, n.msg.c_str());

        ImGui::SameLine(region.x - 40);
        if (ImGui::SmallButton(u8"×")) { n.remainingSec = 0.0f; }
        ImGui::EndChild();
        ImGui::PopStyleVar();
        ImGui::PopStyleColor(2);
        i++;
    }

    ImGui::PopStyleVar(2);
}

/* -----------------------------------------------------------------------------
 * 主窗口
 * ---------------------------------------------------------------------------*/
static void DrawMainWindow() {
    ImGuiViewport* vp = ImGui::GetMainViewport();
    ImGui::SetNextWindowPos(vp->WorkPos);
    ImGui::SetNextWindowSize(vp->WorkSize);

    ImGuiWindowFlags flags =
        ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoResize |
        ImGuiWindowFlags_NoMove     | ImGuiWindowFlags_NoCollapse |
        ImGuiWindowFlags_NoBringToFrontOnFocus | ImGuiWindowFlags_NoSavedSettings |
        ImGuiWindowFlags_NoNavFocus;

    ImGui::PushStyleVar(ImGuiStyleVar_WindowRounding, 0.0f);
    ImGui::PushStyleVar(ImGuiStyleVar_WindowBorderSize, 0.0f);
    ImGui::Begin(u8"Gugas", nullptr, flags);
    ImGui::PopStyleVar(2);

    ImGui::PushStyleColor(ImGuiCol_Text, ImGui::ColorConvertU32ToFloat4(col::INFO_BLUE));
    ImGui::Text(u8"Gugas v0.1.5");
    ImGui::PopStyleColor();
    ImGui::SameLine();
    ImGui::TextDisabled(u8"  a zayoka presents");
    ImGui::Separator();

    DrawNotifications(ImGui::GetIO().DeltaTime);

    if (ImGui::BeginTabBar("##tabs", ImGuiTabBarFlags_None)) {
        if (ImGui::BeginTabItem(u8"🔍 进程审计"))     { DrawTab1_Processes();    ImGui::EndTabItem(); }
        if (ImGui::BeginTabItem(u8"🛡 驱动 & 窗口"))   { DrawTab2_DriversWindows(); ImGui::EndTabItem(); }
        if (ImGui::BeginTabItem(u8"🔑 密码保镖"))     { DrawTab3_Password();     ImGui::EndTabItem(); }
        if (ImGui::BeginTabItem(u8"📋 Hosts 审计"))   { DrawTab4_Hosts();        ImGui::EndTabItem(); }
        if (ImGui::BeginTabItem(u8"⚙ 白名单/黑名单")) { DrawTab5_Rules();        ImGui::EndTabItem(); }
        if (ImGui::BeginTabItem(u8"🔍 深度扫描"))    { DrawTab6_DeepScan();     ImGui::EndTabItem(); }
        if (ImGui::BeginTabItem(u8"📁 文件系统"))    { DrawTab7_FileSystem();   ImGui::EndTabItem(); }
        ImGui::EndTabBar();
    }

    DrawStatusBar();
    ImGui::End();
}

/* -----------------------------------------------------------------------------
 * WinMain
 * ---------------------------------------------------------------------------*/
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE, LPSTR, int) {
    ImGui_ImplWin32_EnableDpiAwareness();

    WNDCLASSEXW wc = { sizeof(wc), CS_CLASSDC, WndProc, 0L, 0L,
                       hInstance, nullptr, nullptr, nullptr, nullptr,
                       L"GugasWnd", nullptr };
    ::RegisterClassExW(&wc);
    HWND hwnd = ::CreateWindowW(wc.lpszClassName, L"Gugas",
        WS_OVERLAPPEDWINDOW, 100, 100, 1000, 650,
        nullptr, nullptr, wc.hInstance, nullptr);
    if (!hwnd) return 1;

    float dpiScale = ImGui_ImplWin32_GetDpiScaleForHwnd(hwnd);
    ::SetWindowPos(hwnd, nullptr, 0, 0,
        (int)(1000 * dpiScale), (int)(650 * dpiScale),
        SWP_NOMOVE | SWP_NOZORDER | SWP_NOACTIVATE);

    if (!CreateDeviceD3D(hwnd)) {
        CleanupDeviceD3D();
        ::UnregisterClassW(wc.lpszClassName, wc.hInstance);
        MessageBoxW(nullptr,
            L"DirectX 11 设备创建失败。\n请确保显卡驱动正常且系统支持 DX11。",
            L"Gugas 启动错误", MB_OK | MB_ICONERROR);
        return 1;
    }

    g_state.antiCaptureOk = Gugas_EnableAntiCapture(hwnd);

    ::ShowWindow(hwnd, SW_SHOWDEFAULT);
    ::UpdateWindow(hwnd);

    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGuiIO& io = ImGui::GetIO();
    io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard;
    io.IniFilename = nullptr;

    ApplyDarkStyle(dpiScale);
    LoadFonts(dpiScale);

    ImGui_ImplWin32_Init(hwnd);
    ImGui_ImplDX11_Init(g_pd3dDevice, g_pd3dDeviceContext);

    /* 加载规则 */
    g_rules.Load();

    /* 默认选中 C 盘 */
    g_state.selectedDrives['C' - 'A'] = true;

    g_state.isAdmin = IsUserAdmin();
    if (!g_state.isAdmin) {
        Notify(NotifyType::Warning,
            u8"当前以标准用户运行，部分内核驱动不可见，建议右键→以管理员身份运行");
    }
    if (!g_state.antiCaptureOk) {
        Notify(NotifyType::Warning,
            u8"防截屏初始化失败（系统版本过低），窗口仍可能被截屏工具捕获");
    }

    RefreshAll();

    bool done = false;
    while (!done) {
        MSG msg;
        while (::PeekMessage(&msg, nullptr, 0U, 0U, PM_REMOVE)) {
            ::TranslateMessage(&msg);
            ::DispatchMessage(&msg);
            if (msg.message == WM_QUIT) done = true;
        }
        if (done) break;

        if (g_resizeWidth != 0 && g_resizeHeight != 0) {
            CleanupRenderTarget();
            g_pSwapChain->ResizeBuffers(0, g_resizeWidth, g_resizeHeight, DXGI_FORMAT_UNKNOWN, 0);
            g_resizeWidth = g_resizeHeight = 0;
            CreateRenderTarget();
        }

        g_state.lastScanElapsed += io.DeltaTime;

        ImGui_ImplDX11_NewFrame();
        ImGui_ImplWin32_NewFrame();
        ImGui::NewFrame();

        DrawMainWindow();

        ImGui::Render();
        const float clearColor[4] = { 13/255.f, 15/255.f, 20/255.f, 1.0f };
        g_pd3dDeviceContext->OMSetRenderTargets(1, &g_mainRTV, nullptr);
        g_pd3dDeviceContext->ClearRenderTargetView(g_mainRTV, clearColor);
        ImGui_ImplDX11_RenderDrawData(ImGui::GetDrawData());

        g_pSwapChain->Present(1, 0);
    }

    ImGui_ImplDX11_Shutdown();
    ImGui_ImplWin32_Shutdown();
    ImGui::DestroyContext();
    CleanupDeviceD3D();
    ::DestroyWindow(hwnd);
    ::UnregisterClassW(wc.lpszClassName, wc.hInstance);
    return 0;
}
