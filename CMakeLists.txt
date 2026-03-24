cmake_minimum_required(VERSION 3.25)

# vcpkg 工具链配置
set(CMAKE_TOOLCHAIN_FILE "$ENV{VCPKG_ROOT}/scripts/buildsystems/vcpkg.cmake"
    CACHE STRING "Vcpkg toolchain file")

# 编译命令数据库（用于IDE和clangd支持）
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# 项目配置
project(Simple-File-Transfer-Desktop
    VERSION 2.0
    DESCRIPTION "Simple File Transfer Desktop Application"
    LANGUAGES CXX
)

# ============================================================================
# C++ 标准设置
# ============================================================================
set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# ============================================================================
# 构建类型配置
# ============================================================================
if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    message(STATUS "Setting build type to 'Release' as none was specified.")
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Choose the type of build." FORCE)
    set_property(CACHE CMAKE_BUILD_TYPE PROPERTY STRINGS "Debug" "Release" "RelWithDebInfo" "MinSizeRel" "Profile")
endif()

# ============================================================================
# Profiling 配置
# ============================================================================
# 启用 Profiling：使用 -DENABLE_PROFILING=ON 或 -DCMAKE_BUILD_TYPE=Profile
option(ENABLE_PROFILING "Enable profiling support (perf/VS2022)" OFF)

# 如果选择 Profile 构建类型，自动启用 profiling
if(CMAKE_BUILD_TYPE STREQUAL "Profile")
    set(ENABLE_PROFILING ON)
endif()

if(ENABLE_PROFILING)
    message(STATUS "Profiling mode enabled")
endif()

# ============================================================================
# 平台检测
# ============================================================================
if(WIN32)
    set(PLATFORM "Windows")
elseif(APPLE)
    set(PLATFORM "macOS")
elseif(UNIX)
    set(PLATFORM "Linux")
else()
    set(PLATFORM "Unknown")
endif()

message(STATUS "Building for platform: ${PLATFORM}")
message(STATUS "Compiler: ${CMAKE_CXX_COMPILER_ID} ${CMAKE_CXX_COMPILER_VERSION}")
message(STATUS "Build type: ${CMAKE_BUILD_TYPE}")

# ============================================================================
# 编译器标志定义
# ============================================================================

# GCC 和 Clang 通用警告标志
set(GNULIKE_COMMON_WARNINGS
    -Wall
    -Wextra
    -Wpedantic
    -Wpointer-arith
    -Wnon-virtual-dtor
    -Wcast-align
    -Wunused
    -Woverloaded-virtual
    -Wconversion
    -Wsign-conversion
    -Wmisleading-indentation
    -Wnull-dereference
    -Wdouble-promotion
    -Wformat=2
)

# GCC 特有警告
set(GCC_EXTRA_WARNINGS
    -Wduplicated-cond
    -Wduplicated-branches
    -Wlogical-op
    -Wuseless-cast
)

# Clang 特有警告
set(CLANG_EXTRA_WARNINGS
    -Wshadow
    -Wunreachable-code
)

# GCC/Clang 通用调试和发布标志
set(GNULIKE_DEBUG_FLAGS
    -g
    -fno-omit-frame-pointer
)

set(GNULIKE_RELEASE_FLAGS
    -O2
    -march=native
    -flto
)

# GCC/Clang Profiling 标志 (用于 perf, Valgrind, etc.)
# 保持优化的同时启用调试符号和帧指针，便于性能分析
set(GNULIKE_PROFILE_FLAGS
    -O2                      # 保持优化以获得真实性能数据
    -g                       # 调试符号，用于解析函数名
    -fno-omit-frame-pointer  # 保留帧指针，perf 需要用于栈回溯
    -march=native            # 本机优化
    # -fno-inline            # 可选：禁用内联以获得更清晰的调用图（会影响性能）
)

# MSVC 警告标志
set(MSVC_WARNING_FLAGS
    /W4
    /permissive-
    /w14242 /w14254 /w14263 /w14265 /w14287
    /we4289 /w14296 /w14311 /w14545 /w14546
    /w14547 /w14549 /w14555 /w14619 /w14640
    /w14826 /w14905 /w14906 /w14928
    /wd4251 /wd4275  # 禁用 DLL 相关警告
)

set(MSVC_DEBUG_FLAGS /Zi /Od /RTC1 /MP)
set(MSVC_RELEASE_FLAGS /O2 /Ob2 /GL /MP /MT)

# MSVC Profiling 标志 (用于 VS2022 Performance Profiler)
set(MSVC_PROFILE_FLAGS
    /O2           # 保持优化
    /Ob2          # 内联扩展
    /Zi           # 完整调试信息 (PDB)
    /MP           # 多进程编译
    /MT           # 静态链接运行时
    /Oy-          # 禁用帧指针省略，便于调用栈分析
    # /d2cgsummary # 可选：显示代码生成统计（诊断用）
)

# ============================================================================
# 依赖查找
# ============================================================================
find_package(unofficial-sodium CONFIG REQUIRED)

# ============================================================================
# 源文件配置
# ============================================================================
set(SOURCES
    src/main.cpp
    src/main_functions.cpp
)

# 平台特定的源文件
if(WIN32)
    list(APPEND SOURCES src/win32actions.cpp)
    message(STATUS "Added Windows-specific source files")
elseif(APPLE)
    message(STATUS "Building for macOS - no platform-specific sources added")
elseif(UNIX)
    message(STATUS "Building for Linux - no platform-specific sources added")
endif()

message(STATUS "Source files: ${SOURCES}")

# ============================================================================
# 创建可执行文件
# ============================================================================
add_executable(${PROJECT_NAME} ${SOURCES})

find_path(BSHOSHANY_THREAD_POOL_INCLUDE_DIRS "BS_thread_pool.hpp")

# 使用现代 CMake 的 target_* 命令
target_include_directories(${PROJECT_NAME} PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${BSHOSHANY_THREAD_POOL_INCLUDE_DIRS}
)

target_compile_definitions(${PROJECT_NAME} PRIVATE
    VERSION=${PROJECT_VERSION}
    $<$<CONFIG:Debug>:DEBUG>
    $<$<NOT:$<CONFIG:Debug>>:NDEBUG>
)

# ============================================================================
# 编译器特定设置
# ============================================================================
if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
    target_compile_options(${PROJECT_NAME} PRIVATE
        ${GNULIKE_COMMON_WARNINGS}
        ${GCC_EXTRA_WARNINGS}
        $<$<CONFIG:Debug>:${GNULIKE_DEBUG_FLAGS}>
        $<$<AND:$<NOT:$<CONFIG:Debug>>,$<NOT:$<BOOL:${ENABLE_PROFILING}>>>:${GNULIKE_RELEASE_FLAGS}>
        $<$<BOOL:${ENABLE_PROFILING}>:${GNULIKE_PROFILE_FLAGS}>
    )
    target_link_options(${PROJECT_NAME} PRIVATE
        $<$<AND:$<NOT:$<CONFIG:Debug>>,$<NOT:$<BOOL:${ENABLE_PROFILING}>>>:
        -flto
        -static
        >
    )

elseif(CMAKE_CXX_COMPILER_ID MATCHES "Clang")
    # 同时匹配 Clang 和 AppleClang
    target_compile_options(${PROJECT_NAME} PRIVATE
        ${GNULIKE_COMMON_WARNINGS}
        ${CLANG_EXTRA_WARNINGS}
        $<$<CONFIG:Debug>:${GNULIKE_DEBUG_FLAGS}>
        $<$<AND:$<NOT:$<CONFIG:Debug>>,$<NOT:$<BOOL:${ENABLE_PROFILING}>>>:${GNULIKE_RELEASE_FLAGS}>
        $<$<BOOL:${ENABLE_PROFILING}>:${GNULIKE_PROFILE_FLAGS}>
    )
    target_link_options(${PROJECT_NAME} PRIVATE
        $<$<AND:$<NOT:$<CONFIG:Debug>>,$<NOT:$<BOOL:${ENABLE_PROFILING}>>>:
        -flto
        -static
        >
    )

elseif(CMAKE_CXX_COMPILER_ID STREQUAL "MSVC")
    target_compile_options(${PROJECT_NAME} PRIVATE
        ${MSVC_WARNING_FLAGS}
        $<$<CONFIG:Debug>:${MSVC_DEBUG_FLAGS}>
        $<$<AND:$<NOT:$<CONFIG:Debug>>,$<NOT:$<BOOL:${ENABLE_PROFILING}>>>:${MSVC_RELEASE_FLAGS}>
        $<$<BOOL:${ENABLE_PROFILING}>:${MSVC_PROFILE_FLAGS}>
    )
    target_compile_definitions(${PROJECT_NAME} PRIVATE
        _CRT_SECURE_NO_WARNINGS
        NOMINMAX
        WIN32_LEAN_AND_MEAN
        $<$<NOT:$<CONFIG:Debug>>:SODIUM_STATIC=1>
        $<$<NOT:$<CONFIG:Debug>>:SODIUM_EXPORT=>
    )
    target_link_options(${PROJECT_NAME} PRIVATE
        $<$<CONFIG:Debug>:/DEBUG>
        $<$<AND:$<NOT:$<CONFIG:Debug>>,$<NOT:$<BOOL:${ENABLE_PROFILING}>>>:/LTCG>
        # Profiling: 启用调试信息但保持优化
        $<$<BOOL:${ENABLE_PROFILING}>:/DEBUG>
        $<$<BOOL:${ENABLE_PROFILING}>:/OPT:REF>
        $<$<BOOL:${ENABLE_PROFILING}>:/OPT:ICF>
    )
    
    # MSVC 项目设置
    set(CMAKE_VS_PLATFORM_TOOLSET_HOST_ARCHITECTURE x64)
    set_property(GLOBAL PROPERTY USE_FOLDERS ON)

else()
    message(WARNING "未知的编译器: ${CMAKE_CXX_COMPILER_ID}，使用基本警告标志")
    target_compile_options(${PROJECT_NAME} PRIVATE
        -Wall -Wextra
        $<$<CONFIG:Debug>:-g>
        $<$<AND:$<NOT:$<CONFIG:Debug>>,$<NOT:$<BOOL:${ENABLE_PROFILING}>>>:-O2>
        $<$<BOOL:${ENABLE_PROFILING}>:-O2 -g -fno-omit-frame-pointer>
    )
endif()

# ============================================================================
# 平台特定配置
# ============================================================================
if(WIN32)
    # Windows 字符集配置
    option(USE_UNICODE "Use Unicode (UTF-16) instead of ANSI" ON)
    
    if(USE_UNICODE)
        message(STATUS "Using Unicode (UTF-16) character set")
        target_compile_definitions(${PROJECT_NAME} PRIVATE UNICODE _UNICODE)
    else()
        message(STATUS "Using ANSI character set")
        target_compile_definitions(${PROJECT_NAME} PRIVATE _MBCS)
    endif()
    
    # Windows 平台库
    target_link_libraries(${PROJECT_NAME} PRIVATE ws2_32 winmm)
    
    # Visual Studio 特定属性
    set_target_properties(${PROJECT_NAME} PROPERTIES
        VS_GLOBAL_CharacterSet "Unicode"
        VS_GLOBAL_WindowsTargetPlatformVersion "10.0"
    )
    
    if(CMAKE_GENERATOR MATCHES "Visual Studio")
        set_property(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
            PROPERTY VS_STARTUP_PROJECT ${PROJECT_NAME})
    endif()

elseif(APPLE)
    # macOS 配置（如需要可扩展）
    # find_library(COCOA_LIBRARY Cocoa)
    # find_library(IOKIT_LIBRARY IOKit)
    # target_link_libraries(${PROJECT_NAME} PRIVATE ${COCOA_LIBRARY} ${IOKIT_LIBRARY})

elseif(UNIX)
    # Linux 配置（如需要可扩展）
    # target_link_libraries(${PROJECT_NAME} PRIVATE ssl crypto dl pthread)
endif()

# ============================================================================
# 链接库
# ============================================================================
target_link_libraries(${PROJECT_NAME} PRIVATE
    unofficial-sodium::sodium
)

# ============================================================================
# 目标属性设置
# ============================================================================
set_target_properties(${PROJECT_NAME} PROPERTIES
    OUTPUT_NAME "simple-file-transfer"
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
    # 多配置生成器（VS, Xcode）的输出目录
    RUNTIME_OUTPUT_DIRECTORY_DEBUG "${CMAKE_BINARY_DIR}/bin"
    RUNTIME_OUTPUT_DIRECTORY_RELEASE "${CMAKE_BINARY_DIR}/bin"
)

# ============================================================================
# Release 构建后处理（符号剥离）
# ============================================================================
# 注意：Profiling 模式下跳过 strip，以保留符号供性能分析工具使用
if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    if(ENABLE_PROFILING)
        message(STATUS "Symbol stripping disabled (profiling mode)")
    else()
        find_program(STRIP_PROGRAM strip)
        if(STRIP_PROGRAM)
            add_custom_command(TARGET ${PROJECT_NAME} POST_BUILD
                # 仅在 Release 模式下生成 strip 命令
                COMMAND $<$<CONFIG:Release>:${STRIP_PROGRAM}> $<$<CONFIG:Release>:$<TARGET_FILE:${PROJECT_NAME}>>
                COMMENT "$<$<CONFIG:Release>:Stripping executable for release build>"
                VERBATIM
            )
        endif()
    endif()
endif()

# ============================================================================
# 安装配置
# ============================================================================
include(GNUInstallDirs)

install(TARGETS ${PROJECT_NAME}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
)

# ============================================================================
# 可选功能
# ============================================================================
option(BUILD_TESTS "Build tests" OFF)
if(BUILD_TESTS)
    enable_testing()
    # 在这里添加测试相关配置
endif()

option(BUILD_DOCUMENTATION "Build documentation" OFF)
if(BUILD_DOCUMENTATION)
    find_package(Doxygen QUIET)
    if(DOXYGEN_FOUND)
        # 在这里添加文档生成配置
        message(STATUS "Doxygen found, documentation target available")
    else()
        message(WARNING "Doxygen not found, documentation will not be built")
    endif()
endif()

# 仅在非 CI 环境且 Unix/Windows 系统下创建软链接
if(EXISTS "${CMAKE_BINARY_DIR}/compile_commands.json")
    if(NOT EXISTS "${CMAKE_SOURCE_DIR}/compile_commands.json")
        message(STATUS "Linking compile_commands.json to source directory")
        # Windows 需要开启开发者模式或管理员权限才能创建真正的 symlink，
        # 否则 CMake 会回退到拷贝文件。
        execute_process(COMMAND ${CMAKE_COMMAND} -E create_symlink 
            "${CMAKE_BINARY_DIR}/compile_commands.json" 
            "${CMAKE_SOURCE_DIR}/compile_commands.json")
    endif()
endif()

# ============================================================================
# 构建信息摘要
# ============================================================================
message(STATUS "")
message(STATUS "=== Build Configuration ===")
message(STATUS "  Project:      ${PROJECT_NAME}")
message(STATUS "  Version:      ${PROJECT_VERSION}")
message(STATUS "  Platform:     ${PLATFORM}")
message(STATUS "  Compiler:     ${CMAKE_CXX_COMPILER_ID} ${CMAKE_CXX_COMPILER_VERSION}")
message(STATUS "  C++ Standard: C++${CMAKE_CXX_STANDARD}")
message(STATUS "  Build Type:   ${CMAKE_BUILD_TYPE}")
message(STATUS "  Install:      ${CMAKE_INSTALL_PREFIX}")
message(STATUS "==============================")
message(STATUS "")