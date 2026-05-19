# =============================================================================
# Gugas —— CMake 构建配置
#
# 用法（MinGW Makefiles）：
#   cmake -B build -G "MinGW Makefiles" \
#         -DCMAKE_C_COMPILER=C:/mingw64/bin/gcc \
#         -DCMAKE_CXX_COMPILER=C:/mingw64/bin/g++
#   cmake --build build --parallel
#
# 用法（Ninja，若已安装）：
#   cmake -B build -G Ninja \
#         -DCMAKE_C_COMPILER=C:/mingw64/bin/gcc \
#         -DCMAKE_CXX_COMPILER=C:/mingw64/bin/g++
#   cmake --build build --parallel
# =============================================================================
cmake_minimum_required(VERSION 3.16)
project(Gugas LANGUAGES C CXX)

set(CMAKE_C_STANDARD   11)
set(CMAKE_C_STANDARD_REQUIRED   ON)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# ---------------------------------------------------------------------------
# 编译器检测：强制要求 MinGW-w64（Windows 目标）
# ---------------------------------------------------------------------------
if(NOT CMAKE_C_COMPILER_ID STREQUAL "GNU" OR NOT WIN32)
    message(FATAL_ERROR "本工程仅支持 Windows + MinGW-w64 GCC 编译器")
endif()

# ---------------------------------------------------------------------------
# 全局编译选项
# ---------------------------------------------------------------------------
add_compile_options(
    -O2
    -Wall
    -Wno-stringop-truncation
)

# MinGW 静态链接运行时库（避免依赖 libgcc_s_seh-1.dll / libstdc++-6.dll）
add_link_options(
    -static-libgcc
    -static-libstdc++
)

# ---------------------------------------------------------------------------
# ImGui 源文件
# ---------------------------------------------------------------------------
set(IMGUI_DIR ${CMAKE_CURRENT_SOURCE_DIR}/imgui-1.92.8)
set(IMGUI_SOURCES
    ${IMGUI_DIR}/imgui.cpp
    ${IMGUI_DIR}/imgui_draw.cpp
    ${IMGUI_DIR}/imgui_tables.cpp
    ${IMGUI_DIR}/imgui_widgets.cpp
    ${IMGUI_DIR}/backends/imgui_impl_win32.cpp
    ${IMGUI_DIR}/backends/imgui_impl_dx11.cpp
)

# ---------------------------------------------------------------------------
# 目标 1：gugas_core.dll（纯 C 检测核心）
# ---------------------------------------------------------------------------
add_library(gugas_core SHARED gugas_core.c gugas_diskscan.c)

target_compile_definitions(gugas_core PRIVATE GUGAS_CORE_BUILD)

target_include_directories(gugas_core PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
    $<INSTALL_INTERFACE:include>
)

target_link_libraries(gugas_core PRIVATE
    psapi
    user32
    kernel32
    advapi32
    iphlpapi
    shell32
    ws2_32
)

set_target_properties(gugas_core PROPERTIES
    C_VISIBILITY_PRESET hidden
    OUTPUT_NAME "gugas_core"
    PREFIX ""          # Windows DLL 无前缀
    SUFFIX ".dll"
)

# ---------------------------------------------------------------------------
# 目标 2：Gugas.exe（ImGui + DX11 前端）
# ---------------------------------------------------------------------------
add_executable(Gugas WIN32
    Gugas.cpp
    ${IMGUI_SOURCES}
)

target_compile_definitions(Gugas PRIVATE IMGUI_USE_WCHAR32)

target_include_directories(Gugas PRIVATE
    ${IMGUI_DIR}
    ${IMGUI_DIR}/backends
    ${CMAKE_CURRENT_SOURCE_DIR}
)

target_link_libraries(Gugas PRIVATE
    gugas_core
    d3d11
    d3dcompiler
    dxgi
    gdi32
    user32
    kernel32
    dwmapi
)

set_target_properties(Gugas PROPERTIES
    OUTPUT_NAME "Gugas"
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}
)

# ---------------------------------------------------------------------------
# 安装规则（可选）
# ---------------------------------------------------------------------------
install(TARGETS gugas_core Gugas
    RUNTIME DESTINATION bin
    LIBRARY DESTINATION lib
)
install(FILES gugas_core.h DESTINATION include)
