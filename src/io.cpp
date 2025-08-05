#include <cstring>  // For memset, memcpy
#ifdef _WIN32
#include <WinSock2.h>
#include <WS2tcpip.h>
#include <io.h>
#include <fileapi.h>
#else
#include <dirent.h>
#include <sys/fcntl.h>
#include <cerrno> // For errno
#endif
#include "../include/io.h"

namespace mfcslib {

//--- File implementation ---
File::File() = default;

#ifdef _WIN32
File::File(std::wstring_view path) : _file_path(path) {}
#else
File::File(std::string_view path) : _file_path(path) {}
#endif

File::File(File&& other) noexcept {
    this->close();
    this->_fd        = other._fd;
    this->_file_path = std::move(other._file_path);
#ifdef _WIN32
    other._fd = (size_t)INVALID_HANDLE_VALUE;
#else
    other._fd = -1;
#endif
}

File::~File() = default;

File& File::operator=(const string_type& path) {
    _file_path = path;
    this->close();
	return *this;
}

bool File::open(const string_type& path, bool trunc, int rwmode) {
#ifdef _WIN32
    DWORD DesiredAccess = 0;
    DWORD CreationDisposition = trunc ? CREATE_ALWAYS : OPEN_ALWAYS;
    if (rwmode == RDONLY) {
        DesiredAccess = FILE_GENERIC_READ;
    } else if (rwmode == WRONLY) {
        DesiredAccess = FILE_GENERIC_WRITE;
        if (!trunc) {
            // OPEN_ALWAYS with FILE_APPEND_DATA doesn't work as expected
            // A better way is to open and seek to the end.
            // For simplicity, we stick to the original logic.
            CreationDisposition = OPEN_EXISTING;
            DesiredAccess = FILE_APPEND_DATA;
        }
    } else { // RDWR
        DesiredAccess = FILE_GENERIC_READ | FILE_GENERIC_WRITE;
    }
    
    CREATEFILE2_EXTENDED_PARAMETERS params = { sizeof(CREATEFILE2_EXTENDED_PARAMETERS) };
    params.dwFileAttributes = FILE_ATTRIBUTE_NORMAL;
    
    _fd = (size_t)CreateFile2(path.c_str(), DesiredAccess, FILE_SHARE_READ | FILE_SHARE_WRITE, CreationDisposition, &params);
#else
    int flag = 0;
    switch (rwmode) {
    case RDONLY:
        flag |= O_RDONLY;
        break;
    case WRONLY:
        flag |= O_WRONLY | O_CREAT;
        break;
    default: // RDWR
        flag |= O_RDWR | O_CREAT;
        break;
    }
    if (trunc) {
        flag |= O_TRUNC;
    } else if (rwmode != RDONLY) {
        flag |= O_APPEND;
    }
    _fd = ::open(path.c_str(), flag, 0644);
#endif
    if (_fd == (decltype(_fd))-1) {
        return false;
    }
    _file_path = path;
    return true;
}

bool File::open(bool trunc, int rwmode) {
    return this->open(_file_path, trunc, rwmode);
}

bool File::open_read_only() {
    return this->open(_file_path, false, RDONLY);
}

bool File::is_exist() const { return exists(_file_path); }
bool File::is_open() const { return _fd != (decltype(_fd))-1; }
std::uintmax_t File::size() const { return file_size(_file_path); }
string File::size_string() const { return std::to_string(file_size(_file_path)); }
fs::path::string_type File::get_parent() const { return _file_path.parent_path(); }
fs::path::string_type File::get_absolute() const { return absolute(_file_path); }
string File::filename() const { return _file_path.filename().string(); }
fs::path::string_type File::get_type() const { return _file_path.extension().native(); }
auto File::get_fd() const -> decltype(_fd) { return _fd; }
auto File::get_last_modified_time() const { return last_write_time(_file_path); }


//--- raw_socket implementation ---
raw_socket::raw_socket() {
    _fd = INVALID_SOCKET;
}

raw_socket::raw_socket(raw_socket&& other) noexcept {
    this->_fd = other._fd;
    other._fd = INVALID_SOCKET;
    this->_ip_port = other._ip_port;
    ::memset(&other._ip_port, 0, sizeof(other._ip_port));
}

raw_socket::raw_socket(int fd, const sockaddr_in& addr_info) {
    _fd = fd;
    _ip_port = addr_info;
}

int raw_socket::initialize(int domain, int type, int protocol) {
    if (_fd == INVALID_SOCKET) {
        ::memset(&_ip_port, 0, sizeof(_ip_port));
        _ip_port.sin_family = domain;
        _fd = ::socket(domain, type, protocol);
        return _fd == INVALID_SOCKET ? SOCKET_ERROR : 0;
    }
    return 0;
}

int raw_socket::bind() {
    return ::bind(_fd, (const sockaddr*)&_ip_port, sizeof(_ip_port));
}

int raw_socket::bind(const struct sockaddr* addr, socklen_t len) {
    if (len <= sizeof(_ip_port)) {
        memcpy(&_ip_port, addr, len);
    }
    return this->bind();
}

int raw_socket::setsockopt(int level, int option, const optval_t* val, socklen_t len) {
    return ::setsockopt(_fd, level, option, val, len);
}

raw_socket& raw_socket::operator=(raw_socket&& other) {
    if (this != &other) {
        this->close();
        this->_fd = other._fd;
        other._fd = INVALID_SOCKET;
        this->_ip_port = other._ip_port;
        ::memset(&other._ip_port, 0, sizeof(other._ip_port));
    }
    return *this;
}

SOCKET raw_socket::get_fd() const { return _fd; }
bool raw_socket::available() const { return _fd != INVALID_SOCKET; }

int raw_socket::set_nonblocking() const {
#ifdef _WIN32
    u_long op = 1;
    return ioctlsocket(_fd, FIONBIO, &op);
#else
    int old_option = fcntl(_fd, F_GETFL);
    int new_option = old_option | O_NONBLOCK;
    return fcntl(_fd, F_SETFL, new_option);
#endif
}

int raw_socket::set_blocking() const {
#ifdef _WIN32
    u_long op = 0;
    return ioctlsocket(_fd, FIONBIO, &op);
#else
    int old_option = fcntl(_fd, F_GETFL);
    int new_option = old_option & ~O_NONBLOCK;
    return fcntl(_fd, F_SETFL, new_option);
#endif
}

//--- tcp_socket implementation ---
tcp_socket::tcp_socket() = default;

tcp_socket::tcp_socket(tcp_socket&& other) noexcept : raw_socket(std::move(other)) {}

tcp_socket::tcp_socket(int fd, const sockaddr_in& addr_info) : raw_socket(fd, addr_info) {}

ResType tcp_socket::connect(std::string_view ip, uint16_t port) {
    inet_pton(AF_INET, ip.data(), &_ip_port.sin_addr);
    _ip_port.sin_port = htons(port);
    if (_ip_port.sin_addr.s_addr == INADDR_NONE) {
        return -EINVAL;
    }
    if (initialize(AF_INET, SOCK_STREAM, 0) < 0) {
        return SOCKET_ERROR;
    }
    if (::connect(_fd, (struct sockaddr*)&_ip_port, sizeof(_ip_port)) < 0) {
        return SOCKET_ERROR;
    }
    return 0;
}

ResType tcp_socket::listen(uint16_t port, int n) {
    optval_t flag = 1;
    if (initialize(AF_INET, SOCK_STREAM, 0) < 0) {
        return SOCKET_ERROR;
    }
    _ip_port.sin_addr.s_addr = INADDR_ANY;
    _ip_port.sin_port = htons(port);
    setsockopt(SOL_SOCKET, SO_REUSEADDR, &flag, sizeof(flag));
    if (this->bind() < 0) {
        return SOCKET_ERROR;
    }
    if (::listen(_fd, n) < 0) {
        return SOCKET_ERROR;
    }
    return 0;
}

expected<tcp_socket, int> tcp_socket::accept() {
    sockaddr_in addrs{};
    socklen_t len = sizeof addrs;
    memset(&addrs, 0, len);
    auto ret = ::accept(_fd, (sockaddr*)&addrs, &len);
    if (ret < 0) {
        return std::unexpected(sockerrno);
    }
    return tcp_socket(ret, addrs);
}

in_addr tcp_socket::get_ip() { return _ip_port.sin_addr; }

std::string tcp_socket::get_ip_s() {
    char buf[INET_ADDRSTRLEN];
    return inet_ntop(AF_INET, &_ip_port.sin_addr, buf, INET_ADDRSTRLEN);
}

uint16_t tcp_socket::get_port() { return ntohs(_ip_port.sin_port); }
std::string tcp_socket::get_port_s() { return std::to_string(ntohs(_ip_port.sin_port)); }
std::string tcp_socket::get_ip_port_s() { return get_ip_s() + ':' + get_port_s(); }

tcp_socket& tcp_socket::operator=(tcp_socket&& other) {
    raw_socket::operator=(std::move(other));
    return *this;
}

//--- udp_socket implementation ---
udp_socket::udp_socket() = default;
udp_socket::udp_socket(udp_socket&& other) noexcept : raw_socket(std::move(other)) {}
udp_socket::~udp_socket() = default;

ResType udp_socket::set_local_port(uint16_t port) {
    optval_t flag = 1;
    if (initialize(AF_INET, SOCK_DGRAM, 0) < 0) {
        return SOCKET_ERROR;
    }
    _ip_port.sin_addr.s_addr = INADDR_ANY;
    _ip_port.sin_port = htons(port);
    setsockopt(SOL_SOCKET, SO_REUSEADDR, &flag, sizeof(flag));
#ifdef SO_BROADCAST
    setsockopt(SOL_SOCKET, SO_BROADCAST, &flag, sizeof(flag));
#endif
    if (this->bind() < 0) {
        return SOCKET_ERROR;
    }
    return 0;
}

ResType udp_socket::send_to(std::string_view ip, uint16_t port, std::string_view message) {
    struct sockaddr_in target_udp_addr{};
    memset(&target_udp_addr, 0, sizeof(target_udp_addr));
    target_udp_addr.sin_family = AF_INET;
    target_udp_addr.sin_port = htons(port);
    inet_pton(AF_INET, ip.data(), &target_udp_addr.sin_addr);
    if (target_udp_addr.sin_addr.s_addr == INADDR_NONE) {
        return -EINVAL;
    }

    return ::sendto(_fd, message.data(), message.size(), 0,
                    (const struct sockaddr*)&target_udp_addr,
                    sizeof(struct sockaddr));
}

ResType udp_socket::send_broadcast_message(uint16_t port, std::string_view message) {
    return send_to("255.255.255.255", port, message);
}

} // namespace mfcslib