#ifndef IO_HPP
#define IO_HPP
#include <stdexcept>
#include <fstream>
#ifdef _WIN32
#include <filesystem>
#include <WinSock2.h>
#include <io.h>
#include <cerrno>
using ssize_t = SSIZE_T;
using socklen_t = int;
#else
#include <unistd.h>
#include <arpa/inet.h>
#include <dirent.h>
#endif // 
#include <fcntl.h>
#include <format>
#ifdef __cpp_lib_expected
#include <expected>
using std::expected;
#else
#include "tl/expected.hpp"
using tl::expected;
using tl::unexpected;
#endif // __cpp_lib_expected
#include "util.hpp"
#define RETBAD return unexpected(std::errc(errno));

using std::out_of_range;
using std::runtime_error;
using std::string;
using namespace std::filesystem;
using Byte = char;
using string_type = path::string_type;
namespace mfcslib {
	enum {
		RDONLY,
		WRONLY,
		RDWR
	};
	class basic_io {
	protected:
		using _ResType = expected<int, std::errc>;

		basic_io() = default;
		~basic_io() {
			::close(_fd);
		}

	public:
		auto read(Byte* charc) {
			auto ret = ::read(_fd, charc, 1);
			if (ret < 0 && errno != EAGAIN)
				throw IO_exception(strerror(errno));
			return ret;
		}
		auto read(Byte* buf, size_t nbytes) {
			auto ret = ::read(_fd, buf, nbytes);
			if (ret < 0 && errno != EAGAIN)
				throw IO_exception(strerror(errno));
			return ret;
		}
		auto read(TypeArray<Byte>& buf) const {
			auto ret = ::read(_fd, buf.get_ptr(), buf.length());
			if (ret < 0 && errno != EAGAIN)
				throw IO_exception(strerror(errno));
			return ret;
		}
		auto read(TypeArray<Byte>& buf, size_t pos, size_t sz) {
			auto len = buf.length();
			if (pos >= len || sz > len || pos + sz > len)
				throw out_of_range("In read, pos or sz is out of range.");
			auto ret = ::read(_fd, buf.get_ptr() + pos, sz);
			if (ret < 0 && errno != EAGAIN)
				throw IO_exception(strerror(errno));
			return ret;
		}
		auto write(TypeArray<Byte>& buf) {
			auto ret = ::write(_fd, buf.get_ptr(), buf.length());
			if (ret < 0 && errno != EAGAIN)
				throw IO_exception(strerror(errno));
			return ret;
		}
		auto write(TypeArray<Byte>& buf, size_t pos, size_t sz) {
			auto len = buf.length();
			if (pos >= len || sz > len || pos + sz > len)
				throw out_of_range("In write, pos or sz is out of range.");
			auto ret = ::write(_fd, buf.get_ptr() + pos, sz);
			if (ret < 0 && errno != EAGAIN)
				throw IO_exception(strerror(errno));
			return ret;
		}
		auto write(const std::string_view& buf) {
			auto ret = ::write(_fd, buf.data(), buf.length());
			if (ret < 0 && errno != EAGAIN)
				throw IO_exception(strerror(errno));
			return ret;
		}
		auto write(char c) {
			auto ret = ::write(_fd, &c, 1);
			if (ret < 0 && errno != EAGAIN)
				throw IO_exception(strerror(errno));
			return ret;
		}
		void close() {
			::close(_fd);
			_fd = -1;
		}
		auto get_fd() const {
			return _fd;
		}
		auto available() const {
			return _fd != -1;
		}
		auto set_nonblocking() {
			int old_option = fcntl(_fd, F_GETFL);
			int new_option = old_option | O_NONBLOCK;
			fcntl(_fd, F_SETFL, new_option);
			return old_option;
		}

	protected:
		int _fd = -1;
	};

	class File : public basic_io {
	public:
		File() = default;
		File(const File&) = delete;
		File(const string_type& path) : _file_path(path) {
		}
		File(File&& other) {
			this->_fd = other._fd;
			this->_file_path = other._file_path;
			other._file_path.clear();
			other._fd = -1;
		}
		~File() {
		}

		void operator=(const string& path) {
			_file_path = path;
		}
		auto open(const string& path, bool trunc, int rwmode) {
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
			_fd = ::open(path.c_str(), flag, 0644);
			if (_fd < 0)
				throw file_exception(strerror(errno));
			fstat(_fd, &_file_stat);
			if (!S_ISREG(_file_stat.st_mode)) {
				::close(_fd);
				throw std::invalid_argument(
					std::format("'{}' is not a regular file!\n", path));
			}
			_file_path = _get_path_from_fd(_fd);
			return _fd;
		}
		auto open(bool trunc, int rwmode) {
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
			_fd = ::open(_file_path.c_str(), flag, 0644);
			if (_fd < 0)
				throw file_exception(strerror(errno));
			fstat(_fd, &_file_stat);
			if (!S_ISREG(_file_stat.st_mode)) {
				::close(_fd);
				throw std::invalid_argument(
					std::format("'{}' is not a regular file!\n", _file_path));
			}
			_file_path = _get_path_from_fd(_fd);
			return _fd;
		}
		auto open_read_only() {
			_fd = ::open(_file_path.c_str(), O_RDONLY);
			if (_fd < 0)
				throw std::runtime_error(strerror(errno));
			fstat(_fd, &_file_stat);
			if (!S_ISREG(_file_stat.st_mode)) {
				::close(_fd);
				throw std::invalid_argument(
					std::format("'{}' is not a regular file!\n", _file_path));
			}
			_file_path = _get_path_from_fd(_fd);
			return _fd;
		}
		bool is_existing() const {
			return _fd > 0;
		}
		std::uintmax_t size() const {
			return file_size(_file_path);
		}
		string size_string() const {
			return to_string(file_size(_file_path));
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
		auto get_last_modified_time() const {
			return last_write_time(_file_path);
		}

	private:
		path      _file_path;
	};

	class NetworkSocket : public basic_io {
	public:
		NetworkSocket() = default;
		NetworkSocket(const NetworkSocket&) = delete;
		NetworkSocket(NetworkSocket&& other) noexcept {
			this->_fd = other._fd;
			other._fd = -1;
			this->ip_port = other.ip_port;
			::memset(&other.ip_port, 0, sizeof(other.ip_port));
		}
		NetworkSocket(int fd, const sockaddr_in& addr_info) {
			_fd = fd;
			ip_port = addr_info;
		}
		NetworkSocket(const string& ip, uint16_t port) {
			memset(&ip_port, 0, sizeof ip_port);
			ip_port.sin_family = AF_INET;
			ip_port.sin_addr.s_addr = inet_addr(ip.c_str());
			if (ip_port.sin_addr.s_addr == INADDR_NONE) {
				throw std::invalid_argument("Invalid address:");
			}
			ip_port.sin_port = htons(port);
			_fd = socket(AF_INET, SOCK_STREAM, 0);
			int ret = connect(_fd, (struct sockaddr*)&ip_port, sizeof(ip_port));
			if (ret < 0) {
				string error_msg = "Can not connect: ";
				error_msg += strerror(errno);
				throw socket_exception(error_msg);
			}
		}
		in_addr get_ip() {
			return ip_port.sin_addr;
		}
		std::string get_ip_s() {
			return inet_ntoa(ip_port.sin_addr);
		}
		auto get_port() {
			return ntohs(ip_port.sin_port);
		}
		std::string get_port_s() {
			return std::to_string(ntohs(ip_port.sin_port));
		}
		std::string get_ip_port_s() {
			return get_ip_s() + ':' + get_port_s();
		}
		~NetworkSocket() {
		}

		mfcslib::NetworkSocket& operator=(mfcslib::NetworkSocket&& other) {
			this->_fd = other._fd;
			other._fd = -1;
			this->ip_port = other.ip_port;
			::memset(&other.ip_port, 0, sizeof(other.ip_port));
			return *this;
		}

	protected:
		sockaddr_in ip_port;
	};

	class ServerSocket : public NetworkSocket {
	public:
		ServerSocket() = delete;
		ServerSocket(const ServerSocket&) = delete;
		ServerSocket(ServerSocket&& other) noexcept {
			this->_fd = other._fd;
			other._fd = -1;
			this->ip_port = other.ip_port;
			::memset(&other.ip_port, 0, sizeof(other.ip_port));
		}
		ServerSocket(uint16_t port) {
			memset(&ip_port, 0, sizeof ip_port);
			ip_port.sin_family = AF_INET;
			ip_port.sin_addr.s_addr = htonl(INADDR_ANY);
			ip_port.sin_port = htons(port);
			_fd = socket(PF_INET, SOCK_STREAM, IPPROTO_IP);
			if (_fd <= 0) {
				throw socket_exception(strerror(errno));
			}
			int flag = 1;
			setsockopt(_fd, SOL_SOCKET, SO_REUSEADDR, &flag, sizeof(flag));
			int ret = ::bind(_fd, (sockaddr*)&ip_port, sizeof(ip_port));
			if (ret < 0) {
				throw socket_exception(strerror(errno));
			}
			auto rett = ::listen(_fd, 5);
			if (rett < 0) {
				throw socket_exception(strerror(errno));
			}
		}
		NetworkSocket accpet() {
			sockaddr_in addrs{};
			socklen_t   len = sizeof addrs;
			auto        ret = ::accept(_fd, (sockaddr*)&addrs, &len);
			if (ret < 0) {
				if (errno != EAGAIN)
					throw socket_exception(strerror(errno));
				else
					return {};
			}
			return NetworkSocket(ret, addrs);
		}
		~ServerSocket() {
		}
	};

	class raw_socket : public basic_io {
	public:
		raw_socket() = default;
		raw_socket(const raw_socket&) = delete;
		raw_socket(raw_socket&& other) noexcept {
			this->_fd = other._fd;
			other._fd = -1;
			this->_ip_port = other._ip_port;
			::memset(&other._ip_port, 0, sizeof(other._ip_port));
		}
		raw_socket(int fd, const sockaddr_in& addr_info) {
			_fd = fd;
			_ip_port = addr_info;
		}

		// Initialize the socket, returns 0 on success, -1 if fails.
		int initialize(int domain, int type, int protocol) {
			if (_fd == -1) {
				::memset(&_ip_port, 0, sizeof(_ip_port));
				_ip_port.sin_family = domain;
				_fd = ::socket(domain, type, protocol);
				return _fd > 0 ? 0 : -1;
			}
			return 0;
		}
		int bind() {
			return ::bind(_fd, (const sockaddr*)&_ip_port, sizeof(_ip_port));
		}
		int bind(const struct sockaddr* addr, socklen_t len) {
			memcpy(&_ip_port, addr, sizeof(_ip_port));
			return ::bind(_fd, addr, len);
		}
		int setsockopt(int level, int option, const void* val, socklen_t len) {
			return ::setsockopt(_fd, level, option, val, len);
		}
		mfcslib::raw_socket& operator=(mfcslib::raw_socket&& other) {
			this->_fd = other._fd;
			other._fd = -1;
			this->_ip_port = other._ip_port;
			::memset(&other._ip_port, 0, sizeof(other._ip_port));
			return *this;
		}

	protected:
		sockaddr_in _ip_port{};
	};

	class tcp_socket : public raw_socket {
	public:
		tcp_socket() = default;
		tcp_socket(const tcp_socket&) = delete;
		tcp_socket(tcp_socket&& other) noexcept {
			this->_fd = other._fd;
			other._fd = -1;
			this->_ip_port = other._ip_port;
			::memset(&other._ip_port, 0, sizeof(other._ip_port));
		}
		tcp_socket(int fd, const sockaddr_in& addr_info) {
			_fd = fd;
			_ip_port = addr_info;
		}
		~tcp_socket() {
		}

		expected<int, std::errc> connect(std::string_view ip, uint16_t port) {
			_ip_port.sin_addr.s_addr = inet_addr(ip.data());
			_ip_port.sin_port = htons(port);
			if (_ip_port.sin_addr.s_addr == INADDR_NONE) {
				return tl::unexpected(std::errc::invalid_argument);
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
			return tl::unexpected(std::errc(errno));
		}

		expected<int, std::errc> listen(uint16_t port, int n = 5) {
			int flag = 1;

			if (initialize(AF_INET, SOCK_STREAM, 0) < 0) {
				return tl::unexpected(std::errc(errno));
			}
			_ip_port.sin_addr.s_addr = INADDR_ANY;
			_ip_port.sin_port = htons(port);
			setsockopt(SOL_SOCKET, SO_REUSEADDR, &flag, sizeof(flag));
			if (this->bind() < 0) {
				goto bad;
			}
			if (::listen(_fd, n) < 0) {
				goto bad;
			}
			return 0;

		bad:
			return tl::unexpected(std::errc(errno));
		}
		// Make sure to invoke listen() before accept()
		expected<tcp_socket, std::errc> accept() {
			sockaddr_in addrs{};
			socklen_t   len = sizeof addrs;

			memset(&addrs, 0, len);
			auto ret = ::accept(_fd, (sockaddr*)&addrs, &len);
			if (ret < 0) {
				return tl::unexpected(std::errc(errno));
			}
			return tcp_socket(ret, addrs);
		}

		in_addr get_ip() {
			return _ip_port.sin_addr;
		}
		std::string get_ip_s() {
			return inet_ntoa(_ip_port.sin_addr);
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
			this->_fd = other._fd;
			other._fd = -1;
			this->_ip_port = other._ip_port;
			::memset(&other._ip_port, 0, sizeof(other._ip_port));
			return *this;
		}
	};

	class udp_socket : public raw_socket {
	public:
		udp_socket() = default;
		udp_socket(const udp_socket&) = delete;
		udp_socket(udp_socket&& other) {
			this->_fd = other._fd;
			other._fd = -1;
			this->_ip_port = other._ip_port;
			::memset(&other._ip_port, 0, sizeof(other._ip_port));
		}
		~udp_socket() = default;

		_ResType set_local_port(uint16_t port) {
			int flag = 1;

			if (initialize(AF_INET, SOCK_DGRAM, 0) < 0) {
				goto bad;
			}
			_ip_port.sin_addr.s_addr = INADDR_ANY;
			_ip_port.sin_port = htons(port);
			setsockopt(SOL_SOCKET, SO_REUSEADDR | SO_BROADCAST, &flag,
				sizeof(flag));
			if (this->bind() < 0) {
				goto bad;
			}
		bad:
			return tl::unexpected(std::errc(errno));
		}
		_ResType send_to(std::string_view ip, uint16_t port,
			std::string_view message) {
			struct sockaddr_in target_udp_addr {};
			int                ret = 0;

			memset(&target_udp_addr, 0, sizeof(target_udp_addr));
			target_udp_addr.sin_family = AF_INET;
			target_udp_addr.sin_port = htons(port);
			target_udp_addr.sin_addr.s_addr = inet_addr(ip.data());
			if (target_udp_addr.sin_addr.s_addr == INADDR_NONE) {
				return tl::unexpected(std::errc::invalid_argument);
			}

			ret = ::sendto(_fd, message.data(), message.size(), 0,
				(const struct sockaddr*)&target_udp_addr,
				sizeof(struct sockaddr));
			if (ret == -1) {
				return tl::unexpected(std::errc((*__errno_location())));
			}
			return ret;
		}
		_ResType send_broadcast_message(uint16_t         port,
			std::string_view message) {
			return send_to("255.255.255.255", port, message);
		}
	};

}; // namespace mfcslib

std::vector<std::string> list_all_files_in_directory(const char* path) {
	auto dir_d = opendir(path);
	if (dir_d == nullptr) {
		return {};
	}
	std::vector<std::string> res;
	struct dirent* ptr = readdir(dir_d);
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
		} else if (ptr->d_type == DT_DIR) {
			auto son_dir = list_all_files_in_directory(ptr->d_name);
			for (auto& file : son_dir) {
				res.emplace_back(_path + file);
			}
		}
	}
	return res;
}

#endif // !IO_HPP
