# Introduction [![Test](https://github.com/greatmfc/Simple-File-Transfer-Desktop/actions/workflows/cmake-multi-platform.yml/badge.svg)](https://github.com/greatmfc/Simple-File-Transfer-Desktop/actions)

**Version 2.2** - SFT 1.2 resumable transfer protocol with secure encrypted sessions

An interactive console application that supports receiving and sending files and folders between Simple-File-Transfer-Desktop/Android hosts.

# Features

- **End-to-End Encrypted Transmission**: XChaCha20-Poly1305 authenticated encryption with libsodium
- **Secure Handshake Protocol**: Cryptographic authentication and key exchange
- **SFT 1.2 Transfer Protocol**: Per-file negotiation with range requests, resumable transfers, and permission metadata
- **Legacy Protocol Support**: sft1.1 remains available through explicit command-line selection for forward compatibility
- **Modern Build System**: CMake with vcpkg integration and cross-platform presets
- **Cross-platform** (Windows/Linux/macOS/Android)
- **Automatic Peer Discovery**: Automatically search for available SFT clients in local network via UDP broadcast
- **Batch File Transfer**: Send or receive multiple files or folders (Android version does not support sending folders yet)
- **Asymmetric Encryption**: Public-key cryptography for secure session establishment
- **Command-line Interface**: One-time transfer/receive modes with command-line options
- **Interactive & Drag-and-Drop**: Interactive menu on Windows with file/folder dialog support
- **High Performance**: Chunked streaming transfer with release/profiling build presets
- **Coroutine-based Async I/O**: Non-blocking network operations using C++20 coroutines
- **Unified Error Handling**: Type-safe error propagation with expected-style results

# Deployment

## Prerequisites

- **[vcpkg](https://github.com/microsoft/vcpkg)**: Package manager for dependencies
- **libsodium**: Encryption library (automatically installed via vcpkg)
- **CMake 3.25+**: Build system generator
- **C++20 Compatible Compiler**: GCC 13+, Clang 17+, MSVC 2022 17.0+

## Quick Start

### Using CMake Presets (Recommended)

The project includes pre-configured CMake presets for all major platforms:

```bash
git clone https://github.com/greatmfc/Simple-File-Transfer-Desktop
cd Simple-File-Transfer-Desktop

# Configure using a preset (choose based on your platform)
cmake --preset linux-release          # Linux with GCC
cmake --preset linux-clang-release    # Linux with Clang
cmake --preset x64-release            # Windows 64-bit with MSVC
cmake --preset macos-release          # macOS with AppleClang

# Build
cmake --build --preset <preset-name>

# Run the executable
./build/bin/simple-file-transfer
```

### Manual Configuration

```bash
git clone https://github.com/greatmfc/Simple-File-Transfer-Desktop
cd Simple-File-Transfer-Desktop
mkdir build && cd build

# Configure (set VCPKG_ROOT if vcpkg is not in default location)
cmake .. -DCMAKE_BUILD_TYPE=Release -DCMAKE_TOOLCHAIN_FILE=$VCPKG_ROOT/scripts/buildsystems/vcpkg.cmake

# Build
cmake --build . --config Release -j

# Run
./bin/simple-file-transfer
```

### Running Tests

Build the test target first, then run the CTest suite:

```bash
cmake --build build/linux-debug --target main_transfer_test
ctest --test-dir build/linux-debug --output-on-failure
```

If you configured a different build directory, replace `build/linux-debug` with
that directory.

## Platform-Specific Notes

### Windows
- **Visual Studio 2022** or **Ninja** with MSVC/Clang-CL
- First run requires administrator permission to add firewall exception
- Select network interface on startup for peer discovery
- Drag-and-drop files onto executable supported
- Presets available: `x64-release`, `x64-debug`, `x64-release-profiling`, `x64-clang-release`, `x86-release`

### Linux
- **GCC 13+** or **Clang 17+** recommended
- Install system dependencies: `sudo apt-get install build-essential cmake`
- No special privileges required
- Presets available: `linux-release`, `linux-debug`, `linux-release-profiling`, `linux-clang-release`

### macOS
- **Xcode Command Line Tools** required
- AppleClang (Xcode 14+ recommended)
- Presets available: `macos-release`, `macos-debug`

## Usage Examples

```bash
# Interactive mode (default)
./simple-file-transfer

# One-time receive mode. Add --protocol 1.1 for legacy protocol.
./simple-file-transfer -r

# Direct connection to specific host
./simple-file-transfer -t file1.txt -a 192.168.1.100:10013

# One-time receive and pull files from target. Useful when the receiver is behind NAT or firewall and cannot accept incoming connections.
./simple-file-transfer -rp -a 1.2.3.4:1234

# One-time transfer and waiting for clients to pull.
./simple-file-transfer -tp file1 dir1/

# Use legacy sft1.1 protocol explicitly
./simple-file-transfer -t file1.txt --legacy -a 192.168.1.100:10013

# Select a protocol version explicitly. Protocol 1.2 is the default.
./simple-file-transfer -t file1.txt --protocol 1.2 -a 192.168.1.100:10013

# Show help
./simple-file-transfer -h
```

# Notes

## Transfer Protocols
- **sft1.2 is the default protocol** for command-line transfers.
- **sft1.2** sends one file entry at a time and lets the receiver ACK, reject, or request a byte range for resume.
- **Resume state** is stored in the system temporary directory under `sft-resume` and is removed after a file is fully received.
- **File permissions** are transferred as metadata when the platform exposes them through `std::filesystem`.
- **sft1.1** is preserved for compatibility and can be selected with `--legacy` or `--protocol 1.1`.

## Security
- **Trust-on-First-Use**: Unknown host fingerprints require manual approval on first connection
- **Key Storage**: Cryptographic keys are stored in platform-specific secure directories:
  - Windows: `%APPDATA%\sft\`
  - Linux/macOS: `~/.config/sft/`
- **Encryption**: All data is encrypted with XChaCha20-Poly1305 using libsodium

## Platform Considerations
- **Windows**: Requires administrator permission for firewall exception on first launch
- **Windows**: Network interface selection required for peer discovery (limitation of Windows networking APIs)
- **Linux/macOS**: No special privileges required

## Build System
- **Profiling Builds**: Use `-release-profiling` presets for performance analysis with debug symbols
- **IDE Support**: Automatic `compile_commands.json` symlinking for clangd/LSP support
- **Static Linking**: Release builds are statically linked for portability

# Example

![](./pics/sft-desktop.gif)
