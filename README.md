# Introduction [![Test](https://github.com/greatmfc/Simple-File-Transfer-Desktop/actions/workflows/cmake-multi-platform.yml/badge.svg)](https://github.com/greatmfc/Simple-File-Transfer-Desktop/actions)

An interactive console application that supports both receiving and sending specified file from and to other Simple-File-Transfer-Desktop/Android hosts.

# Features

- End to End data transmission
- Cross-platform (Windows/Linux/Android)
- Automatically search for available SFT clients in local network
- Send or receive multiple files or folders (Android version does not support sending folders yet)
- Supports asymmetric encrypted data transmission.
- High transfer speed
- Simple and easy to use

# Deployment

1. Use the compiled binary executable file in Release page.
2. This project uses package manager [vcpkg](https://github.com/microsoft/vcpkg) and third party library [libsodium](https://doc.libsodium.org/). You will need to install [libsodium](https://doc.libsodium.org/) through [vcpkg](https://github.com/microsoft/vcpkg) first before carrying on the following steps.
3. On Windows, it will need Visual Studio 2022 to build the project.

```bash
git clone https://github.com/greatmfc/Simple-File-Transfer-Desktop
cd Simple-File-Transfer-Desktop
mkdir build && cd build
cmake .. # use '-DCMAKE_BUILD_TYPE=Debug' if you wish to debug it
```

Then open the solution file **Simple-File-Transfer-Desktop.sln** under **build/**, switch to Release mode and build it in Visual Studio.

4. On Linux, install openssl and git clone then make:

```bash
git clone https://github.com/greatmfc/Simple-File-Transfer-Desktop
cd Simple-File-Transfer-Desktop
mkdir build && cd build
cmake .. # use '-DCMAKE_BUILD_TYPE=Debug' if you wish to debug it
make -j
./bin/simple-file-transfer ./first_to_send/ second_to_send.txt ...
# add paths of files or folders as arguments to transfer, or leave it empty
```

# Notes

- On Windows, the program requires administrator permission to add a firewall exception when being launched for the first time.
- For every startup, you need to select a network first in order to find the other SFT hosts due to the limitation on Windows.

# Example

![](./pics/sft-desktop.gif)
