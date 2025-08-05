#ifndef IO_H
#define IO_H

#include <stdexcept>
#include <filesystem>
#include <expected>
#include "util.hpp"

#ifdef _WIN32
#pragma comment(lib, "ws2_32.lib")
#define sockclose(s) ::closesocket(s)
#define sockerrno    GetLastError()
#define perror(str)                                                            \
	std::cout << str << ": " << get_winsock_error_str() << std::endl
extern std::string get_winsock_error_str(int errcode = 0);
using socklen_t = int;
using optval_t  = char;
using ssize_t   = signed long long;
#else
#include <unistd.h>
#include <arpa/inet.h>
#define sockclose(s)         ::close(s)
#define sockread(...)        ::read(__VA_ARGS__)
#define sockwrite(...)       ::write(__VA_ARGS__)
#define sockerrno            errno
#define INVALID_SOCKET       -1
#define SOCKET_ERROR         -1
#define INVALID_HANDLE_VALUE -1
using SOCKET   = int;
using optval_t = int;
using HANDLE   = int;
#endif

using std::expected;
namespace fs = std::filesystem;

template <class T>
concept buffer_type = requires(T a) {
	a.data();
	a.size();
	std::is_same_v<typename T::value_type, char>;
};

namespace mfcslib {
using std::string;
using string_type = fs::path::string_type;

// Forward declaration of Byte and TypeArray if they are defined in util.hpp
// For example:
// using Byte = char;
// template<typename T> class TypeArray;

#ifdef _WIN32
using ResType  = int;
using SizeType = unsigned long;
#else
using ResType  = ssize_t;
using SizeType = size_t;
#endif

// Template class definition must remain in the header.
template <bool isSocket = false> class basic_io {
	protected:
#ifdef _WIN32
		size_t _fd = (size_t)INVALID_HANDLE_VALUE;
#else
		int _fd = -1;
#endif

	public:
		basic_io() = default;
		~basic_io() {
			this->close();
		}

		ResType read(Byte* buf, SizeType nbytes) const {
#ifdef _WIN32
			if constexpr (isSocket) {
				auto ret = ::recv(_fd, buf, nbytes, 0);
				return ret;
			}
			else {
				SizeType bytes_read = 0;
				bool     success =
					ReadFile((HANDLE)_fd, buf, nbytes, &bytes_read, NULL);
				return success ? bytes_read : -1;
			}
#else
			return ::read(_fd, buf, nbytes);
#endif
		}

		Byte read_byte() const {
			Byte charc = (Byte)-1;
			this->read(&charc, 1);
			return charc;
		}

		ResType read(TypeArray<Byte>& buf, off_t pos, SizeType sz) const {
#ifdef DEBUG
			auto len = buf.size();
			if (pos >= len || sz > len || pos + sz > len)
				throw std::out_of_range("In read, pos or sz is out of range.");
#endif
			return this->read(buf.data() + pos, sz);
		}

		template <buffer_type T> ResType read(T& buf) const {
			return this->read(buf.data(), buf.size());
		}

		ResType read_buf(TypeArray<Byte>* buf) const {
			return this->read(*buf, 0, buf->size());
		}

		ResType write(const Byte* buf, SizeType nbytes) {
#ifdef _WIN32
			if constexpr (isSocket) {
				auto ret = ::send(_fd, buf, nbytes, 0);
				return ret;
			}
			else {
				SizeType bytes_written = 0;
				bool     success =
					WriteFile((HANDLE)_fd, buf, nbytes, &bytes_written, NULL);
				return success ? bytes_written : -1;
			}
#else
			return ::write(_fd, buf, nbytes);
#endif
		}

		auto write(TypeArray<Byte>& buf, off_t pos, SizeType sz) {
#ifdef DEBUG
			auto len = buf.size();
			if (len != 0 && (pos >= len || sz > len || pos + sz > len))
				throw std::out_of_range("In write, pos or sz is out of range.");
#endif
			return this->write(buf.data() + pos, sz);
		}

		template <buffer_type T> auto write(const T& buf) {
			return this->write(buf.data(), buf.size());
		}

		auto write_buf(TypeArray<Byte>* buf) {
			return this->write(*buf, 0, buf->size());
		}

		auto write_buf_pos(TypeArray<Byte>* buf, off_t pos, SizeType sz) {
			return this->write(*buf, pos, sz);
		}

		auto write_byte(Byte c) {
			return this->write(&c, 1);
		}

		void close() {
			if (_fd != (decltype(_fd))-1) {
#ifdef _WIN32
				if constexpr (isSocket) {
					::closesocket(SOCKET(_fd));
				}
				else {
					CloseHandle((HANDLE)_fd);
				}
				_fd = (size_t)INVALID_HANDLE_VALUE;
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

		File();
		File(const File&) = delete;
#ifdef _WIN32
		File(std::wstring_view path);
#else
		File(std::string_view path);
#endif
		File(File&& other) noexcept;
		~File();

		File&                 operator=(const string_type& path);

		bool                  open(const string_type& path, bool trunc = false,
								   int rwmode = RDWR);
		bool                  open(bool trunc = false, int rwmode = RDWR);
		[[nodiscard]] bool    open_read_only();

		bool                  is_exist() const;
		bool                  is_open() const;
		std::uintmax_t        size() const;
		string                size_string() const;
		fs::path::string_type get_parent() const;
		fs::path::string_type get_absolute() const;
		string                filename() const;
		fs::path::string_type get_type() const;
		auto                  get_fd() const -> decltype(_fd);
		auto                  get_last_modified_time() const;

	private:
		fs::path _file_path;
};

class raw_socket : public basic_io<true> {
	public:
		raw_socket();
		raw_socket(const raw_socket&) = delete;
		raw_socket(raw_socket&& other) noexcept;
		raw_socket(int fd, const sockaddr_in& addr_info);

		int         initialize(int domain, int type, int protocol);
		int         bind();
		int         bind(const struct sockaddr* addr, socklen_t len);
		int         setsockopt(int level, int option, const optval_t* val,
							   socklen_t len);

		raw_socket& operator=(raw_socket&& other);

		SOCKET      get_fd() const;
		bool        available() const;
		int         set_nonblocking() const;
		int         set_blocking() const;

	protected:
		sockaddr_in _ip_port{};
};

class tcp_socket : public raw_socket {
	public:
		tcp_socket();
		tcp_socket(const tcp_socket&) = delete;
		tcp_socket(tcp_socket&& other) noexcept;
		tcp_socket(int fd, const sockaddr_in& addr_info);

		ResType                   connect(std::string_view ip, uint16_t port);
		ResType                   listen(uint16_t port, int n = 5);
		expected<tcp_socket, int> accept();

		in_addr                   get_ip();
		std::string               get_ip_s();
		uint16_t                  get_port();
		std::string               get_port_s();
		std::string               get_ip_port_s();

		tcp_socket&               operator=(tcp_socket&& other);
};

class udp_socket : public raw_socket {
	public:
		udp_socket();
		udp_socket(const udp_socket&) = delete;
		udp_socket(udp_socket&& other) noexcept;
		~udp_socket();

		ResType set_local_port(uint16_t port);
		ResType send_to(std::string_view ip, uint16_t port,
						std::string_view message);
		ResType send_broadcast_message(uint16_t port, std::string_view message);
};

} // namespace mfcslib

#endif // !IO_H