/* =============================================================================
 * gugas_core.h —— Gugas 安全自检工具 / 核心检测库公共接口
 *
 * MIT License (中英双语 / Bilingual)
 * ---------------------------------------------------------------------------
 * Copyright (c) 2026 zayoka
 *
 * EN: Permission is hereby granted, free of charge, to any person obtaining a
 *     copy of this software and associated documentation files (the "Software"),
 *     to deal in the Software without restriction, including without limitation
 *     the rights to use, copy, modify, merge, publish, distribute, sublicense,
 *     and/or sell copies of the Software, and to permit persons to whom the
 *     Software is furnished to do so, subject to the following conditions:
 *     The above copyright notice and this permission notice shall be included
 *     in all copies or substantial portions of the Software.
 *     THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND.
 *
 * CN: 兹免费授予任何获得本软件及相关文档文件（"软件"）副本的人不受限制地
 *     处置本软件的权利，包括但不限于使用、复制、修改、合并、出版、分发、
 *     再授权及/或销售本软件副本的权利，并允许向其提供本软件之人遵照以下
 *     条件行使该等权利：上述版权声明和本许可声明应包含在本软件的所有副本
 *     或主要部分中。本软件按"原样"提供，不附带任何形式的保证。
 *
 * Disclaimer / 免责声明
 * ---------------------------------------------------------------------------
 * EN: This tool performs READ-ONLY security audits on the local machine. It
 *     does NOT modify any system configuration, registry, or files. Use it
 *     only on machines you are authorised to inspect (e.g. your own PC, or
 *     under explicit consent from the machine owner). The authors disclaim
 *     liability for any misuse.
 *
 * CN: 本工具对本地机器执行**只读**安全审计，不修改任何系统配置、注册表或
 *     文件。仅可在你有权检测的机器上使用（如自有 PC、或经机主明确同意）。
 *     作者对任何滥用行为不承担责任。
 * =============================================================================
 */

#ifndef GUGAS_CORE_H
#define GUGAS_CORE_H

#include <windows.h>
#include <stdint.h>

/* -----------------------------------------------------------------------------
 * 导入/导出宏 —— 编译 DLL 时定义 GUGAS_CORE_BUILD，消费方默认 dllimport
 * ---------------------------------------------------------------------------*/
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

/* -----------------------------------------------------------------------------
 * 数据结构
 * ---------------------------------------------------------------------------*/

/* 进程信息 —— ScanProcesses 返回 */
typedef struct {
    DWORD pid;
    char  name[256];        /* 可执行文件名（无路径） */
    char  fullPath[1024];   /* 完整路径，若 OpenProcess 失败则为空 */
    int   isSuspicious;     /* 1=可疑 / 0=正常 */
    char  reason[256];      /* 可疑原因（中文描述） */
} ProcessInfo;

/* 驱动信息 —— ScanDrivers 返回 */
typedef struct {
    char name[256];         /* 驱动基础名（如 ntoskrnl.exe） */
    int  isSuspicious;
    char reason[256];
} DriverInfo;

/* 窗口信息 —— ScanOverlayWindows 返回，同时供 Password 注入选择目标使用 */
typedef struct {
    HWND  hwnd;
    char  title[256];
    char  className[256];
    char  ownerProcess[256]; /* 所属进程名 */
    int   width;
    int   height;
    DWORD style;             /* GWL_STYLE 原值 */
    DWORD exStyle;           /* GWL_EXSTYLE 原值 */
    char  reason[256];       /* 触发可疑判定的原因 */
} WindowInfo;

/* hosts 文件条目 —— ScanHosts 返回 */
typedef struct {
    char ip[64];
    char domain[256];
    char rawLine[512];
    int  isSuspicious;
} HostsEntry;

/* 服务信息 —— ScanServices 返回 */
typedef struct {
    char  serviceName[256];
    char  displayName[512];
    DWORD processId;
    DWORD serviceStatus;   /* SERVICE_RUNNING / SERVICE_STOPPED 等 */
    int   isSuspicious;
    char  reason[256];
} ServiceInfo;

/* 启动项信息 —— ScanStartupEntries 返回 */
typedef struct {
    char name[256];
    char path[1024];
    char location[256];    /* 如 "Registry HKLM\\Run" 或 "StartupFolder" */
    int  isSuspicious;
    char reason[256];
} StartupEntry;

/* 网络连接信息 —— ScanNetworkConnections 返回 */
typedef struct {
    char  localAddr[64];
    DWORD localPort;
    char  remoteAddr[64];
    DWORD remotePort;
    DWORD state;           /* MIB_TCP_STATE_* */
    DWORD pid;
    char  processName[256];
    int   isSuspicious;
    char  reason[256];
} ConnectionInfo;

/* 文件系统条目 —— ScanFileSystem / ScanFileSystemMulti 返回 */
typedef struct {
    char      path[1024];
    char      name[256];
    DWORD     attributes;
    DWORD     sizeHigh;
    DWORD     sizeLow;
    FILETIME  writeTime;
    int       isSuspicious;
    char      reason[256];
} FileEntry;

/* 已加载模块信息 —— ScanLoadedModules 返回 */
typedef struct {
    char      moduleName[256];
    char      modulePath[1024];
    ULONG_PTR baseAddr;
    DWORD     moduleSize;
    int       isSuspicious;
    char      reason[256];
} ModuleInfo;

/* -----------------------------------------------------------------------------
 * 导出接口
 * ---------------------------------------------------------------------------*/

/* 扫描所有进程；outList 容量 = maxCount，实际写入 *outCount */
GUGAS_CORE_API void Gugas_ScanProcesses(ProcessInfo* outList, int* outCount, int maxCount);

/* 扫描所有已加载内核驱动 */
GUGAS_CORE_API void Gugas_ScanDrivers(DriverInfo* outList, int* outCount, int maxCount);

/* 扫描所有顶层可见窗口；返回的是**触发可疑判定**的窗口子集 */
GUGAS_CORE_API void Gugas_ScanOverlayWindows(WindowInfo* outList, int* outCount, int maxCount);

/* 解析 C:\Windows\System32\drivers\etc\hosts */
GUGAS_CORE_API void Gugas_ScanHosts(HostsEntry* outList, int* outCount, int maxCount);

/* 对目标窗口启用截屏排除（Win10 2004+ 完全隐藏，旧版仅排除外部显示器） */
GUGAS_CORE_API BOOL Gugas_EnableAntiCapture(HWND hwnd);

/* 生成密码混淆预览（仅用于 UI 显示，不参与真实注入）
 * input         : 原始密码
 * outObfuscated : 输出缓冲（建议 1024 字节）
 * outRealMask   : 与 outObfuscated 等长的掩码数组（1=真实字符 0=干扰）
 * outLen        : 实际写入的字节数
 */
GUGAS_CORE_API void Gugas_ObfuscatePassword(const char* input,
                                            char* outObfuscated,
                                            uint8_t* outRealMask,
                                            int* outLen);

/* 通过 SendInput 向目标窗口注入**未打乱的原始密码**
 * 注意：只会发送 realPassword 中的真实字符，不发送任何干扰字符
 */
GUGAS_CORE_API BOOL Gugas_InjectPassword(HWND targetHwnd, const char* realPassword);

/* 获取最近一次 DLL 调用失败的错误描述（线程局部，随最近一次导出函数调用更新）
 * 返回 UTF-8 字符串指针；若上次调用成功，返回空字符串""
 */
GUGAS_CORE_API const char* Gugas_GetLastErrorString(void);

/* 扫描所有系统服务 */
GUGAS_CORE_API void Gugas_ScanServices(ServiceInfo* outList, int* outCount, int maxCount);

/* 扫描注册表及启动文件夹中的自启动项 */
GUGAS_CORE_API void Gugas_ScanStartupEntries(StartupEntry* outList, int* outCount, int maxCount);

/* 扫描所有活跃网络连接（TCP + UDP） */
GUGAS_CORE_API void Gugas_ScanNetworkConnections(ConnectionInfo* outList, int* outCount, int maxCount);

/* 递归扫描单个目录下的可疑文件
 * rootPath : 起始目录（如 "C:\\Windows\\System32"）
 * maxDepth : 最大递归深度，<=0 表示无限制
 */
GUGAS_CORE_API void Gugas_ScanFileSystem(const char* rootPath,
                                         FileEntry* outList,
                                         int* outCount,
                                         int maxCount,
                                         int maxDepth);

/* 多线程并行扫描多个根目录
 * rootPaths : 根目录路径数组
 * rootCount : 根目录数量
 * maxDepth  : 最大递归深度，<=0 表示无限制
 */
GUGAS_CORE_API void Gugas_ScanFileSystemMulti(const char** rootPaths,
                                              int rootCount,
                                              FileEntry* outList,
                                              int* outCount,
                                              int maxCount,
                                              int maxDepth);

/* 扫描指定进程已加载的模块（DLL/SYS 等） */
GUGAS_CORE_API void Gugas_ScanLoadedModules(DWORD pid,
                                            ModuleInfo* outList,
                                            int* outCount,
                                            int maxCount);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* GUGAS_CORE_H */
