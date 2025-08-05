# Introduction

An interactive console application that supports both receiving and sending specified file from and to other Simple-File-Transfer-Desktop/Android hosts.

# Features
- End to End data transmission
- Cross-platform (Windows/Linux/Android)
- Automatically search for available SFT clients in local network
- Send or receive multiple files or folders (Android version does not support sending folders yet)
- Supports encrypted data transmission using AES-128-GCM (Require both side holding a same password)
- High transfer speed
- Simple and easy to use

# Deployment
1. Use the compiled binary executable file in Release page or build it yourself.
2. On Windows, it will need Visual Studio 2022 to build the project.
```bash
git clone https://github.com/greatmfc/Simple-File-Transfer-Desktop
cd Simple-File-Transfer-Desktop
mkdir build && cd build
cmake .. # use '-DCMAKE_BUILD_TYPE=Debug' if you wish to debug it
```
Then open the solution file **Simple-File-Transfer-Desktop.sln** under **build/**, switch to Release mode and build it in Visual Studio.

3. On Linux, install openssl and git clone then make:
```bash
sudo apt install libssl-dev # install 'zlib1g-dev libzstd-dev' if static-link is needed
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