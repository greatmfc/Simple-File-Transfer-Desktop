#ifndef IO_HPP
#define IO_HPP
#include <stdexcept>
#include <fstream>
#include <fcntl.h>
#include <format>
#include <filesystem>
#ifdef __cpp_lib_expected
#include <expected>
using std::expected;
#else
#include "tl/expected.hpp"
using tl::expected;
using tl::unexpected;
#endif // __cpp_lib_expected
#include "util.hpp"
#ifdef _WIN32
#include <WinSock2.h>
#include <WS2tcpip.h>
#include <io.h>
#include <fileapi.h>
#pragma comment(lib, "ws2_32.lib")
#define sockclose(s) ::closesocket(s)
#define sockerrno    GetLastError()
#define perror(str)  cout << str << ": " << get_winsock_error_str() << endl
extern std::string get_winsock_error_str(int errcode = 0);
using socklen_t = int;
using optval_t  = char;
using ssize_t   = signed long long;
#else
#include <unistd.h>
#include <arpa/inet.h>
#include <dirent.h>
#define sockclose(s)         ::close(s)
#define sockread(...)        ::read(__VA_ARGS__)
#define sockwrite(...)       ::write(__VA_ARGS__)
#define sockerrno            errno
#define INVALID_SOCKET       -1
#define SOCKET_ERROR         -1
#define INVALID_HANDLE_VALUE -1
using SOCKET    = int;
using optval_t  = int;
using HANDLE    = int;
#endif //

namespace mfcslib {
using std::string;
using namespace std::filesystem;
using string_type = path::string_type;
#ifdef _WIN32
using _ResType  = int;
using _SizeType = unsigned long;
#else
using _ResType  = ssize_t;
using _SizeType = size_t;
#endif

template <bool isSocket = false> class basic_io {
	protected:
#ifdef _WIN32
		size_t _fd = -1;
#else
		int _fd = -1;
#endif

	public:
		basic_io() = default;
		~basic_io() {
			this->close();
		}

		ssize_t read(Byte* buf, _SizeType nbytes) {
#ifdef _WIN32
			if constexpr (isSocket) {
				auto ret = ::recv(_fd, buf, nbytes, 0);
				return ret;
			}
			else {
				_SizeType bytes_read = 0;
				bool      success =
					ReadFile((HANDLE)_fd, buf, nbytes, &bytes_read, NULL);
				return success ? bytes_read : -1;
			}
#else
			auto ret = ::read(_fd, buf, nbytes);
			return ret;
#endif
		}
		Byte read_byte() {
			Byte charc = -1;
			this->read(&charc, 1);
			return charc;
		}
		ssize_t read(TypeArray<Byte>& buf, _SizeType pos, _SizeType sz) {
#ifdef DEBUG
			auto len = buf.length();
			if (pos >= len || sz > len || pos + sz > len)
				throw std::out_of_range("In read, pos or sz is out of range.");
#endif // DEBUG
			return this->read(buf.get_ptr() + pos, sz);
		}
		ssize_t read(TypeArray<Byte>& buf) {
			return this->read(buf, 0, buf.length());
		}

		// Returns the number of bytes have been written, -1 if fails.
		ssize_t write(const Byte* buf, _SizeType nbytes) {
#ifdef _WIN32
			if constexpr (isSocket) {
				auto ret = ::send(_fd, buf, nbytes, 0);
				return ret;
			}
			else {
				_SizeType bytes_written = 0;
				bool      success =
					WriteFile((HANDLE)_fd, buf, nbytes, &bytes_written, NULL);
				return success ? bytes_written : -1;
			}
#else
			auto ret = ::write(_fd, buf, nbytes);
			return ret;
#endif
		}
		auto write(TypeArray<Byte>& buf, _SizeType pos, _SizeType sz) {
#ifdef DEBUG
			auto len = buf.length();
			if (pos >= len || sz > len || pos + sz > len)
				throw std::out_of_range("In write, pos or sz is out of range.");
#endif // DEBUG
			return this->write(buf.get_ptr() + pos, sz);
		}
		auto write(TypeArray<Byte>& buf) {
			return this->write(buf, 0, buf.length());
		}
		auto write(const std::string_view& buf) {
			return this->write(buf.data(), buf.length());
		}
		auto write_byte(Byte c) {
			return this->write(&c, 1);
		}
		void close() {
			if (_fd != -1) {
#ifdef _WIN32
				if constexpr (isSocket) {
					::closesocket(SOCKET(_fd));
				}
				else {
					CloseHandle((HANDLE)_fd);
				}
				_fd = -1;
#else
				::close(_fd);
				_fd = -1;
#endif
			}
		}
};

class File : public basic_io<false> {
	public:
		enum iomode {
			RDONLY,
			WRONLY,
			RDWR
		};

		File()            = default;
		File(const File&) = delete;
		File(const string_type& path) : _file_path(path) {
		}
		File(File&& other) {
			this->close();
			this->_fd        = other._fd;
			this->_file_path = std::move(other._file_path);
			other._fd        = -1;
		}
		~File() = default;

		void operator=(const string_type& path) {
			_file_path = path;
			this->close();
		}
		// Returns true for success, false if fails
		bool open(const string_type& path, bool trunc = false,
				  int rwmode = RDWR) {
#ifdef _WIN32
			DWORD DesiredAccess       = 0,
				  CreationDisposition = trunc ? CREATE_ALWAYS : OPEN_ALWAYS;
			if (rwmode == RDONLY) {
				DesiredAccess = FILE_GENERIC_READ;
			}
			else if (rwmode == WRONLY) {
				DesiredAccess = FILE_GENERIC_WRITE;
				if (!trunc) {
					DesiredAccess = FILE_APPEND_DATA | FILE_GENERIC_READ;
				}
			}
			else {
				DesiredAccess = FILE_GENERIC_READ | FILE_GENERIC_WRITE;
				if (!trunc) {
					DesiredAccess = FILE_APPEND_DATA | FILE_GENERIC_READ;
				}
			}
			_fd = (size_t)CreateFile2(path.c_str(), DesiredAccess, 0,
									  CreationDisposition, NULL);
#else
			int flag = 0;
			switch (rwmode) {
			case 0:
				flag |= O_RDONLY;
				break;
			case 1:
				flag |= O_WRONLY | O_CREAT;
				break;
			default:
				flag |= O_RDWR | O_CREAT;
				break;
			}
			if (trunc)
				flag |= O_TRUNC;
			else
				flag |= O_APPEND;
			_fd            = ::open(path.c_str(), flag, 0644);
#endif
			if (_fd == -1) {
				return false;
			}
			_file_path = path;
			return true;
		}
		bool open(bool trunc = false, int rwmode = RDWR) {
			return this->open(_file_path, trunc, rwmode);
		}
		[[nodiscard]] bool open_read_only() {
			return this->open(_file_path, false, RDONLY);
		}

		bool is_exist() const {
			return exists(_file_path);
		}
		bool is_open() const {
			return _fd != -1;
		}
		std::uintmax_t size() const {
			return file_size(_file_path);
		}
		string size_string() const {
			return std::to_string(file_size(_file_path));
		}
		path::string_type get_parent() {
			return _file_path.parent_path();
		}
		path::string_type get_absolute() {
			return absolute(_file_path);
		}
		path::string_type filename() {
			return _file_path.filename();
		}
		path::string_type get_type() {
			return _file_path.extension().c_str();
		}
		size_t get_fd() {
			return _fd;
		}
		auto get_last_modified_time() const {
			return last_write_time(_file_path);
		}

	private:
		path _file_path;
};

class raw_socket : public basic_io<true> {
	public:
		raw_socket()                  = default;
		raw_socket(const raw_socket&) = delete;
		raw_socket(raw_socket&& other) noexcept {
			this->_fd      = other._fd;
			other._fd      = -1;
			this->_ip_port = other._ip_port;
			::memset(&other._ip_port, 0, sizeof(other._ip_port));
		}
		raw_socket(int fd, const sockaddr_in& addr_info) {
			_fd      = fd;
			_ip_port = addr_info;
		}

		// Initialize the socket, returns 0 on success, -1 if fails.
		// Make sure to invoke WSAStartup() first on windows.
		int initialize(int domain, int type, int protocol) {
			if (_fd == INVALID_SOCKET) {
				::memset(&_ip_port, 0, sizeof(_ip_port));
				_ip_port.sin_family = domain;
				_fd                 = ::socket(domain, type, protocol);
				return _fd == SOCKET_ERROR ? -1 : 0;
			}
			return 0;
		}
		int bind() {
			return ::bind(_fd, (const sockaddr*)&_ip_port, sizeof(_ip_port));
		}
		int bind(const struct sockaddr* addr, socklen_t len) {
			memcpy(&_ip_port, addr, len);
			return this->bind();
		}
		int setsockopt(int level, int option, const optval_t* val,
					   socklen_t len) {
			return ::setsockopt(_fd, level, option, val, len);
		}
		mfcslib::raw_socket& operator=(mfcslib::raw_socket&& other) {
			this->_fd      = other._fd;
			other._fd      = -1;
			this->_ip_port = other._ip_port;
			::memset(&other._ip_port, 0, sizeof(other._ip_port));
			return *this;
		}

		SOCKET get_fd() const {
			return _fd;
		}
		auto available() const {
			return _fd != INVALID_SOCKET;
		}
		auto set_nonblocking() const {
#ifdef _WIN32
			int    ret = 0;
			u_long op  = 1;
			ret        = ioctlsocket(_fd, FIONBIO, &op);
			return ret;
#else
			int old_option = fcntl(_fd, F_GETFL);
			int new_option = old_option | O_NONBLOCK;
			old_option     = fcntl(_fd, F_SETFL, new_option);
			return old_option;
#endif
		}
		auto set_blocking() const {
#ifdef _WIN32
			int    ret = 0;
			u_long op  = 0;
			ret        = ioctlsocket(_fd, FIONBIO, &op);
			return ret;
#else
			int old_option = fcntl(_fd, F_GETFL);
			int new_option = old_option & ~O_NONBLOCK;
			old_option     = fcntl(_fd, F_SETFL, new_option);
			return old_option;
#endif
		}

	protected:
		sockaddr_in _ip_port{};
};

class tcp_socket : public raw_socket {
	public:
		tcp_socket()                  = default;
		tcp_socket(const tcp_socket&) = delete;
		tcp_socket(tcp_socket&& other) noexcept {
			this->_fd      = other._fd;
			other._fd      = -1;
			this->_ip_port = other._ip_port;
			::memset(&other._ip_port, 0, sizeof(other._ip_port));
		}
		tcp_socket(int fd, const sockaddr_in& addr_info) {
			_fd      = fd;
			_ip_port = addr_info;
		}

		// Returns -EINVAL for invalid argument, -1 if fails, 0 for success.
		_ResType connect(std::string_view ip, uint16_t port) {
			inet_pton(AF_INET, ip.data(), &_ip_port.sin_addr);
			_ip_port.sin_port = htons(port);
			if (_ip_port.sin_addr.s_addr == INADDR_NONE) {
				return -EINVAL;
			}
			if (initialize(AF_INET, SOCK_STREAM, 0) < 0) {
				goto bad;
			}
			if (::connect(_fd, (struct sockaddr*)&_ip_port, sizeof(_ip_port)) <
				0) {
				goto bad;
			}
			return 0;

		bad:
			return SOCKET_ERROR;
		}

		_ResType listen(uint16_t port, int n = 5) {
			optval_t flag = 1;

			if (initialize(AF_INET, SOCK_STREAM, 0) < 0) {
				goto bad;
			}
			_ip_port.sin_addr.s_addr = INADDR_ANY;
			_ip_port.sin_port        = htons(port);
			setsockopt(SOL_SOCKET, SO_REUSEADDR, &flag, sizeof(flag));
			if (this->bind() < 0) {
				goto bad;
			}
			if (::listen(_fd, n) < 0) {
				goto bad;
			}
			return 0;

		bad:
			return SOCKET_ERROR;
		}
		// Make sure to invoke listen() before accept()
		expected<tcp_socket, int> accept() {
			sockaddr_in addrs{};
			socklen_t   len = sizeof addrs;

			memset(&addrs, 0, len);
			auto ret = ::accept(_fd, (sockaddr*)&addrs, &len);
			if (ret < 0) {
				return tl::unexpected(sockerrno);
			}
			return tcp_socket(ret, addrs);
		}

		in_addr get_ip() {
			return _ip_port.sin_addr;
		}
		std::string get_ip_s() {
			char buf[INET_ADDRSTRLEN];
			return inet_ntop(AF_INET, &_ip_port.sin_addr, buf, INET_ADDRSTRLEN);
		}
		auto get_port() {
			return ntohs(_ip_port.sin_port);
		}
		std::string get_port_s() {
			return std::to_string(ntohs(_ip_port.sin_port));
		}
		std::string get_ip_port_s() {
			return get_ip_s() + ':' + get_port_s();
		}

		mfcslib::tcp_socket& operator=(mfcslib::tcp_socket&& other) {
			this->_fd      = other._fd;
			other._fd      = -1;
			this->_ip_port = other._ip_port;
			::memset(&other._ip_port, 0, sizeof(other._ip_port));
			return *this;
		}
};

class udp_socket : public raw_socket {
	public:
		udp_socket()                  = default;
		udp_socket(const udp_socket&) = delete;
		udp_socket(udp_socket&& other) {
			this->_fd      = other._fd;
			other._fd      = -1;
			this->_ip_port = other._ip_port;
			::memset(&other._ip_port, 0, sizeof(other._ip_port));
		}
		~udp_socket() = default;

		_ResType set_local_port(uint16_t port) {
			optval_t flag = 1;

			if (initialize(AF_INET, SOCK_DGRAM, 0) < 0) {
				goto bad;
			}
			_ip_port.sin_addr.s_addr = INADDR_ANY;
			_ip_port.sin_port        = htons(port);
			setsockopt(SOL_SOCKET, SO_REUSEADDR | SO_BROADCAST, &flag,
					   sizeof(flag));
			if (this->bind() < 0) {
				goto bad;
			}
		bad:
			return SOCKET_ERROR;
		}
		// Returns -EINVAL for invalid argument, -1 if fails, 0 for success.
		_ResType send_to(std::string_view ip, uint16_t port,
						 std::string_view message) {
			struct sockaddr_in target_udp_addr {};
			int                ret = 0;

			memset(&target_udp_addr, 0, sizeof(target_udp_addr));
			target_udp_addr.sin_family = AF_INET;
			target_udp_addr.sin_port   = htons(port);
			inet_pton(AF_INET, ip.data(), &target_udp_addr.sin_addr);
			if (target_udp_addr.sin_addr.s_addr == INADDR_NONE) {
				return -EINVAL;
			}

			ret = ::sendto(_fd, message.data(), message.size(), 0,
						   (const struct sockaddr*)&target_udp_addr,
						   sizeof(struct sockaddr));
			return ret;
		}
		_ResType send_broadcast_message(uint16_t         port,
										std::string_view message) {
			return send_to("255.255.255.255", port, message);
		}
};

}; // namespace mfcslib

#ifdef __unix__
std::vector<std::string> list_all_files_in_directory(const char* path) {
	auto dir_d = opendir(path);
	if (dir_d == nullptr) {
		return {};
	}
	std::vector<std::string> res;
	struct dirent*           ptr   = readdir(dir_d);
	std::string              _path = path;
	if (_path.back() != '/') {
		_path += '/';
	}
	while ((ptr = readdir(dir_d)) != nullptr) {
		if (strcmp(ptr->d_name, ".") == 0 || strcmp(ptr->d_name, "..") == 0) {
			continue;
		}
		if (ptr->d_type == DT_REG) {
			res.emplace_back(std::format("{}{}", _path, ptr->d_name));
		}
		else if (ptr->d_type == DT_DIR) {
			auto son_dir = list_all_files_in_directory(ptr->d_name);
			for (auto& file : son_dir) {
				res.emplace_back(_path + file);
			}
		}
	}
	return res;
}
#endif

#endif // !IO_HPP
