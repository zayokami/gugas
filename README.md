# Gugas

Gugas 是一款 Windows 平台安全自检工具，采用**纯只读审计**设计——不修改任何系统配置、注册表或文件。适用于网吧上机前、借用他人电脑后等场景，帮助用户快速发现系统中潜在的可疑进程、驱动、网络连接、启动项及异常文件。

> **警告**：本工具仅可用于你有权检测的机器（如自有 PC、或经机主明确同意）。作者对任何滥用行为不承担责任。

---

## 功能概览

| Tab | 名称 | 功能 |
|-----|------|------|
| 1 | 进程审计 | 枚举所有进程，标记位于 Temp/AppData 或名称含敏感词的进程 |
| 2 | 驱动 & 窗口 | 枚举已加载内核驱动 + 检测无边框/分层/全屏覆盖层窗口 |
| 3 | 密码保镖 | 生成密码混淆预览，通过 SendInput 向目标窗口注入原始密码 |
| 4 | Hosts 审计 | 解析 hosts 文件，检测非本地 DNS 重定向与重复域名 |
| 5 | 白名单/黑名单 | 管理 4 个维度的黑白名单规则，持久化到 `%LOCALAPPDATA%\Gugas\gugas_rules.ini` |
| 6 | 深度扫描 | 枚举系统服务、注册表启动项（Run/RunOnce）、TCP/UDP 网络连接 |
| 7 | 文件系统 | 多线程并行扫描硬盘目录，检测可疑可执行文件与隐藏文件 |

附加功能：
- **防截屏**：`SetWindowDisplayAffinity(WDA_EXCLUDEFROMCAPTURE)` 隐藏窗口不被截屏
- **Toast 通知**：扫描成功/失败、规则更新等事件的顶部通知条
- **Modal 确认**：密码注入前弹出二次确认，失败时显示详细错误信息
- **Tooltip 帮助**：所有按钮/输入框均带悬停提示
- **状态栏**：管理员权限徽章、防截屏状态、距上次扫描经过时间

---

## 系统要求

- Windows 10 64-bit 或 Windows 11
- 支持 DirectX 11 的显卡驱动
- 管理员权限（推荐，否则部分内核驱动/服务不可见）

---

## 构建

### 依赖

- [MinGW-w64 GCC](https://www.mingw-w64.org/)（本项目使用 GCC 15.2.0）
- [CMake](https://cmake.org/) >= 3.16
- [ImGui](https://github.com/ocornut/imgui) v1.92.8（已作为 Git Submodule 包含）

### 克隆

```bash
git clone <repo-url>
cd gugas
git submodule update --init --recursive
```

### 编译

```bash
# 配置（确保 mingw32-make 在 PATH 中）
cmake -B build -G "MinGW Makefiles" \
    -DCMAKE_MAKE_PROGRAM=C:/mingw64/bin/mingw32-make.exe

# 编译
cmake --build build --parallel
```

生成物：
- `build/gugas_core.dll` —— 核心检测库
- `build/Gugas.exe` —— 前端可执行程序

### 运行

```bash
cd build
./Gugas.exe
```

---

## 开源组件声明

本项目使用了以下开源组件，对其作者表示感谢：

| 组件 | 版本 | 许可证 | 来源 |
|------|------|--------|------|
| Dear ImGui | v1.92.8 | MIT License | https://github.com/ocornut/imgui |

ImGui 以 [Git Submodule](https://git-scm.com/book/en/v2/Git-Tools-Submodules) 方式集成，路径为 `imgui-1.92.8/`。其完整许可证文本请参见 `imgui-1.92.8/LICENSE.txt`。

本项目通过 Windows API（如 `CreateToolhelp32Snapshot`、`EnumServicesStatusEx`、`GetExtendedTcpTable` 等）与操作系统交互，相关 API 属于操作系统本身，不受本项目许可证约束。

---

## 许可证

本项目采用 [MIT License](LICENSE) 开源。

```
Copyright (c) 2026 zayoka
```

在保留版权声明的前提下，你可以自由使用、修改、分发本软件。
