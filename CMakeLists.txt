cmake_minimum_required(VERSION 3.25)

# 项目配置
project(Simple-File-Transfer-Desktop
    VERSION 1.4.0
    DESCRIPTION "Simple File Transfer Desktop Application"
    LANGUAGES CXX
)

# C++标准设置
set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# 设置默认构建类型
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

# 平台检测
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
message(STATUS "Compiler: ${CMAKE_CXX_COMPILER_ID}")
message(STATUS "Build type: ${CMAKE_BUILD_TYPE}")

# 编译器特定设置
if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
    # GCC编译器设置
    set(COMMON_WARNING_FLAGS 
        -Wall -Wextra -Wpedantic -Wpointer-arith -Wnon-virtual-dtor
        -Wcast-align -Wunused -Woverloaded-virtual -Wpedantic
        -Wconversion -Wsign-conversion -Wmisleading-indentation
        -Wduplicated-cond -Wduplicated-branches -Wlogical-op
        -Wnull-dereference -Wuseless-cast -Wdouble-promotion
        -Wformat=2
    )
    set(DEBUG_FLAGS -g -DDEBUG -fno-omit-frame-pointer)
    set(RELEASE_FLAGS -O3 -march=native -DNDEBUG -flto -static)
    
elseif(CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
    # Clang编译器设置
    set(COMMON_WARNING_FLAGS 
        -Wall -Wextra -Wpedantic -Wpointer-arith -Wnon-virtual-dtor
        -Wcast-align -Wunused -Woverloaded-virtual -Wpedantic
        -Wconversion -Wsign-conversion -Wmisleading-indentation
        -Wnull-dereference -Wdouble-promotion -Wformat=2
        -Wshadow -Wunreachable-code
    )
    set(DEBUG_FLAGS -g -DDEBUG -fno-omit-frame-pointer -fsanitize-address-use-after-scope)
    set(RELEASE_FLAGS -O3 -march=native -DNDEBUG -flto -static)
    
elseif(CMAKE_CXX_COMPILER_ID STREQUAL "MSVC")
    # MSVC编译器设置
    set(COMMON_WARNING_FLAGS 
        /W4 /permissive- /w14242 /w14254 /w14263 /w14265 /w14287
        /we4289 /w14296 /w14311 /w14545 /w14546 /w14547 /w14549
        /w14555 /w14619 /w14640 /w14826 /w14905 /w14906 /w14928
        /wd4251 /wd4275  # 禁用一些DLL相关警告
    )
    set(DEBUG_FLAGS /Zi /Od /DDEBUG /RTC1 /MP)
    set(RELEASE_FLAGS /O2 /Ob2 /DNDEBUG /GL /MT /MP)
    
    # MSVC特定设置
    add_definitions(-D_CRT_SECURE_NO_WARNINGS)
    add_definitions(-DNOMINMAX)
    add_definitions(-DWIN32_LEAN_AND_MEAN)
    
    # Unicode支持 - 强制使用宽字符API
    add_definitions(-DUNICODE)
    add_definitions(-D_UNICODE)
    
    # 设置字符集为Unicode
    set(CMAKE_VS_PLATFORM_TOOLSET_HOST_ARCHITECTURE x64)
    set_property(GLOBAL PROPERTY USE_FOLDERS ON)
    
else()
    # 其他编译器的通用设置
    message(WARNING "未知的编译器: ${CMAKE_CXX_COMPILER_ID}")
    set(COMMON_WARNING_FLAGS -Wall -Wextra)
    set(DEBUG_FLAGS -g -DDEBUG)
    set(RELEASE_FLAGS -O2 -DNDEBUG)
endif()

# 应用编译器标志
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    add_compile_options(${COMMON_WARNING_FLAGS} ${DEBUG_FLAGS})
    if(CMAKE_CXX_COMPILER_ID STREQUAL "MSVC")
        add_link_options(/DEBUG)
    endif()
else()
    add_compile_options(${COMMON_WARNING_FLAGS} ${RELEASE_FLAGS})
    if(CMAKE_CXX_COMPILER_ID STREQUAL "MSVC")
        add_link_options(/LTCG)  # 链接时代码生成
    endif()
endif()

# 平台特定的链接库设置
if(WIN32)
    set(PLATFORM_LIBS ws2_32 winmm)
    
    # Windows字符集配置
    option(USE_UNICODE "Use Unicode (UTF-16) instead of ANSI" ON)
    
    if(USE_UNICODE)
        message(STATUS "Using Unicode (UTF-16) character set")
        add_definitions(-DUNICODE -D_UNICODE)
    else()
        message(STATUS "Using ANSI character set")
        add_definitions(-D_MBCS)
    endif()
    
elseif(APPLE)
    find_library(COCOA_LIBRARY Cocoa)
    find_library(IOKIT_LIBRARY IOKit)
    set(PLATFORM_LIBS ${COCOA_LIBRARY} ${IOKIT_LIBRARY})
elseif(UNIX)
    set(PLATFORM_LIBS pthread dl)
endif()

# 查找线程库（跨平台）
find_package(Threads REQUIRED)

# 源文件配置
set(SOURCES
    main.cpp
    main_functions.cpp
    # 在这里添加其他通用源文件
)

# 平台特定的源文件
if(WIN32)
    list(APPEND SOURCES
        win32actions.cpp
        # 在这里添加其他Windows特定的源文件
    )
    message(STATUS "Added Windows-specific source files")
elseif(APPLE)
    # macOS特定的源文件
    # list(APPEND SOURCES
    #     macos_specific.cpp
    # )
    message(STATUS "Building for macOS - no platform-specific sources added")
elseif(UNIX)
    # Linux特定的源文件
    # list(APPEND SOURCES
    #     linux_specific.cpp
    # )
    message(STATUS "Building for Linux - no platform-specific sources added")
endif()

# 打印所有源文件
message(STATUS "Source files: ${SOURCES}")

# 头文件包含目录
include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

# 创建可执行文件
add_executable(${PROJECT_NAME} ${SOURCES})

# 链接库
target_link_libraries(${PROJECT_NAME} 
    PRIVATE 
    Threads::Threads
    ${PLATFORM_LIBS}
)

# 设置可执行文件属性
set_target_properties(${PROJECT_NAME} PROPERTIES
    OUTPUT_NAME "simple-file-transfer"
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin
)

# Windows特定的目标属性
if(WIN32)
    set_target_properties(${PROJECT_NAME} PROPERTIES
        VS_GLOBAL_CharacterSet "Unicode"
        VS_GLOBAL_WindowsTargetPlatformVersion "10.0"
    )
    
    # 如果使用Visual Studio生成器，设置启动项目
    if(CMAKE_GENERATOR MATCHES "Visual Studio")
        set_property(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR} PROPERTY VS_STARTUP_PROJECT ${PROJECT_NAME})
    endif()
endif()

# 安装配置
install(TARGETS ${PROJECT_NAME}
    RUNTIME DESTINATION bin
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib
)

# 平台特定的安装后处理
if(WIN32 AND CMAKE_BUILD_TYPE STREQUAL "Release")
    # Windows下的Release版本可以进行strip处理
    if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU" OR CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
        add_custom_command(TARGET ${PROJECT_NAME} POST_BUILD
            COMMAND ${CMAKE_STRIP} $<TARGET_FILE:${PROJECT_NAME}>
            COMMENT "Stripping executable"
        )
    endif()
elseif(UNIX AND CMAKE_BUILD_TYPE STREQUAL "Release")
    # Unix系统下的strip处理
    add_custom_command(TARGET ${PROJECT_NAME} POST_BUILD
        COMMAND ${CMAKE_STRIP} $<TARGET_FILE:${PROJECT_NAME}>
        COMMENT "Stripping executable"
    )
endif()

# 生成编译命令数据库（用于IDE支持）
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# 打印构建信息
message(STATUS "=== Build Configuration ===")
message(STATUS "Project: ${PROJECT_NAME}")
message(STATUS "Version: ${PROJECT_VERSION}")
message(STATUS "Platform: ${PLATFORM}")
message(STATUS "Compiler: ${CMAKE_CXX_COMPILER_ID} ${CMAKE_CXX_COMPILER_VERSION}")
message(STATUS "C++ Standard: C++${CMAKE_CXX_STANDARD}")
message(STATUS "Build Type: ${CMAKE_BUILD_TYPE}")
message(STATUS "Install Prefix: ${CMAKE_INSTALL_PREFIX}")
message(STATUS "==============================")

# 可选：添加测试支持
option(BUILD_TESTS "Build tests" OFF)
if(BUILD_TESTS)
    enable_testing()
    # 在这里添加测试相关配置
endif()

# 可选：添加文档生成支持
option(BUILD_DOCUMENTATION "Build documentation" OFF)
if(BUILD_DOCUMENTATION)
    find_package(Doxygen)
    if(DOXYGEN_FOUND)
        # 在这里添加文档生成配置
    endif()
endif()