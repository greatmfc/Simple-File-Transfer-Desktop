# Simple File Transfer Desktop

[![CI](https://github.com/greatmfc/Simple-File-Transfer-Desktop/actions/workflows/cmake-multi-platform.yml/badge.svg)](https://github.com/greatmfc/Simple-File-Transfer-Desktop/actions/workflows/cmake-multi-platform.yml)
[![C++20](https://img.shields.io/badge/C%2B%2B-20-00599C.svg)](https://isocpp.org/)
[![License: GPL v2](https://img.shields.io/badge/License-GPL_v2-blue.svg)](LICENSE.txt)

Simple File Transfer Desktop is an encrypted C++20 console application for
transferring files and directories between desktop and Android SFT peers over a
local network or a direct IP connection.

Windows and Linux are the supported desktop platforms.

![Simple File Transfer Desktop](./pics/sft-desktop.gif)

## Highlights

- Authenticated encrypted sessions built with libsodium.
- AEAD negotiation with AEGIS-256 preferred and XChaCha20-Poly1305 available
  for compatibility.
- sft1.3 parallel transfers with multiple authenticated worker connections.
- sft1.2 per-file negotiation, rejection, range requests, permissions, and
  resumable transfers.
- Explicit sft1.1 compatibility mode for older peers.
- File and directory transfer with path traversal protection on receive.
- Support for resuming interrupted downloads.
- LAN peer discovery over UDP or direct connection to a known address.
- Push and pull workflows for different firewall and connectivity layouts.
- Progress reporting with current speed, ETA, and final average speed.
- CMake presets, vcpkg manifest dependencies, and GitHub Actions CI/release
  automation.
- Simple and easy to use.

## Protocols

| Protocol | Status | Capabilities |
| --- | --- | --- |
| **sft1.3** | Default | sft1.2 semantics plus parallel authenticated worker connections |
| **sft1.2** | Supported | Per-file ACK/reject, range resume, permissions, and failure reporting |
| **sft1.1** | Legacy | Compatibility protocol without the newer negotiation and resume features |

Select a protocol with `--protocol 1.1`, `--protocol 1.2`, or
`--protocol 1.3`. `--parallel` selects sft1.3, while `--legacy` selects
sft1.1.

Protocol flow diagrams:

- [sft1.2 flow](./pics/sft1.2-flow.svg)
- [sft1.3 flow](./pics/sft1.3-flow.svg)

## Platform Support

| Platform | Status |
| --- | --- |
| Windows x64 | Built and tested in CI; release archives are published |
| Linux x64 | Built with GCC and Clang in CI; release archives are published |
| Android | Supported as an interoperable SFT peer; sending directories is not yet supported |

## Installation

### Release Packages

Tagged releases are published on the
[GitHub Releases](https://github.com/greatmfc/Simple-File-Transfer-Desktop/releases)
page with Linux x64 and Windows x64 archives plus SHA-256 checksums.

Release binaries are currently unsigned. Windows may therefore display a
SmartScreen warning.

### Build from Source

Requirements:

- CMake 3.25 or newer
- A C++20 compiler with `std::format` support
- GCC 13+, Clang 17+ with a compatible standard library, or Visual Studio 2022
- [vcpkg](https://github.com/microsoft/vcpkg)
- Ninja for the Windows presets

Dependencies are declared in `vcpkg.json` and installed automatically by the
vcpkg toolchain:

- libsodium
- fmt
- BS::thread_pool
- tl::expected

Set `VCPKG_ROOT` before configuring:

```bash
export VCPKG_ROOT=/path/to/vcpkg
```

PowerShell:

```powershell
$env:VCPKG_ROOT = "C:\path\to\vcpkg"
```

#### Linux

```bash
git clone https://github.com/greatmfc/Simple-File-Transfer-Desktop.git
cd Simple-File-Transfer-Desktop

cmake --preset linux-release
cmake --build --preset linux-release --parallel

./build/linux-release/bin/simple-file-transfer
```

Use `linux-clang-release` to build with Clang.

#### Windows

Run these commands from a Visual Studio 2022 developer shell:

```powershell
git clone https://github.com/greatmfc/Simple-File-Transfer-Desktop.git
cd Simple-File-Transfer-Desktop

cmake --preset x64-release
cmake --build --preset x64-release --parallel

.\build\x64-release\bin\simple-file-transfer.exe
```

## Usage

Run without a mode option to open the interactive menu:

```bash
simple-file-transfer
```

Common commands:

```bash
# Wait for one incoming transfer.
simple-file-transfer --receive/-r

# Send files or directories directly to a peer.
simple-file-transfer --transfer/-t file.txt directory/ \
  --addr/-a 192.168.1.100:10013

# Use sequential sft1.2 transfer.
simple-file-transfer --transfer/-t file.txt \
  --protocol 1.2 --addr/-a 192.168.1.100:10013

# Use sft1.3 with at most four worker connections.
simple-file-transfer --transfer/-t directory/ \
  --parallel --workers 4 --addr 192.168.1.100:10013

# Use legacy sft1.1.
simple-file-transfer --transfer/-t file.txt \
  --legacy --addr/-a 192.168.1.100:10013

# Connect to a sender and pull its offered files.
simple-file-transfer -rp/-pr --addr/-a 192.168.1.100:10013

# Offer files and wait for a receiver to pull them.
simple-file-transfer -tp/-pt file.txt directory/
```

### Command-Line Options

| Option | Description |
| --- | --- |
| `-h`, `--help` | Show command-line help |
| `-r`, `--receive` | Receive one transfer and exit |
| `-t`, `--transfer [FILES...]` | Send files or directories and exit |
| `-rp`, `-tp [FILES...]` | Reverse connection direction; combine with receive or transfer |
| `-a`, `--addr <ip:port>` | Connect directly instead of using discovery |
| `--protocol <1.1\|1.2\|1.3>` | Select the transfer protocol; default is 1.3 |
| `--parallel` | Select sft1.3 parallel transfer |
| `--workers <N>` | Limit sft1.3 worker connections |
| `--legacy` | Select the legacy sft1.1 protocol |

For sft1.3, the default worker count is the smaller of the local thread count
and the number of payload files.

## Security

- Peers use signed identity keys and authenticated session establishment.
- The handshake negotiates AEAD support. AEGIS-256 is preferred, with
  XChaCha20-Poly1305 used when required for compatibility.
- Peer identities use trust on first use. An unknown fingerprint must be
  accepted before it is written to `known_hosts`.
- Send and receive keys, nonces, and counters are maintained independently.
- Received paths reject absolute paths, `..` traversal, and paths that escape
  the destination root.

Identity and trust files are stored under:

- Windows: `%APPDATA%\sft\`
- Linux: `~/.config/sft/`

The protocol and implementation have not undergone an independent security
audit. Do not accept an unexpected fingerprint.

## Network

| Purpose | Protocol | Port |
| --- | --- | --- |
| LAN discovery | UDP | `41541` |
| Main transfer connection | TCP | `10013` by default |
| sft1.3 workers | TCP | Dynamically negotiated ports |

Windows may request administrator access on first launch to add a firewall
exception. Interactive Windows mode also asks which network interface should
be used for discovery.

## Resumable Transfers

sft1.2 and sft1.3 maintain receiver-side progress state in the system temporary
directory under `sft-resume`. A matching retry may request only the remaining
byte range. The state file is removed after the file is received successfully.

## Testing

Configure a test build, compile it, and run CTest:

```bash
cmake --preset linux-debug -DBUILD_TESTS=ON
cmake --build --preset linux-debug --parallel
ctest --preset linux-debug
```

The test suite covers transfer framing, path safety, resume behavior, parallel
worker negotiation, failure reporting, and secure-session AEAD negotiation.
CI runs Release builds and CTest with GCC, Clang, and MSVC.

## Contributing

1. Create a focused branch from `main`.
2. Keep protocol, security, and cross-platform behavior compatible with the
   existing implementation.
3. Add or update tests for behavior changes.
4. Run the relevant build and CTest preset.
5. Open a pull request describing the change, compatibility impact, and test
   results.

Do not commit private keys, `known_hosts`, transferred test files, local build
artifacts, or machine-specific configuration.

## Creating a Release

The release workflow is triggered by a semantic version tag that matches the
CMake project version. Replace `X.Y.Z` with the release version:

```bash
git switch main
git pull --ff-only origin main
git tag -a vX.Y.Z -m "Release vX.Y.Z"
git push origin vX.Y.Z
```

After Linux and Windows builds and tests pass, GitHub Actions creates the
release, generates release notes, uploads both platform archives, and publishes
`SHA256SUMS`.

## License

This project is licensed under the
[GNU General Public License version 2](./LICENSE.txt).
