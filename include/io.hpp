#ifndef IO_H
#define IO_H

#include "util.hpp"
#include "ErrorResult.h"
#include "coroutine.hpp"
#include <concepts>
#include <cstring> // For memset, memcpy
#include <utility>
#include <filesystem>
namespace fs = std::filesystem;

namespace kotcpp {

template <class Derived> class io_overloads {
	public:
		auto read(vector<Byte>& buf, SizeType pos, SizeType sz) const {
#ifdef DEBUG
			auto len = buf.size();
			if (pos >= len || sz > len || pos + sz > len) {
				throw std::out_of_range("In read, pos or sz is out of range.");
			}
#endif
			return self().read(buf.data() + pos, sz);
		}

		template <buffer_type T> auto read(T& buf) const {
			return self().read((Byte*)buf.data(), buf.size());
		}

		auto read_buf(vector<Byte>* buf) const {
			return this->read(*buf, 0, buf->size());
		}

		auto write(const vector<Byte>& buf, SizeType pos, SizeType sz) const {
#ifdef DEBUG
			auto len = buf.size();
			if (len != 0 && (pos >= len || sz > len || pos + sz > len)) {
				throw std::out_of_range("In write, pos or sz is out of range.");
			}
#endif
			return self().write(buf.data() + pos, sz);
		}

		template <buffer_type T> auto write(const T& buf) const {
			return self().write((const Byte*)buf.data(), buf.size());
		}

		auto write_buf(vector<Byte>* buf) const {
			return this->write(*buf, 0, buf->size());
		}

		auto write_buf_pos(vector<Byte>* buf, off_t pos, SizeType sz) const {
			return this->write(*buf, pos, sz);
		}

		auto write_byte(Byte c) const {
			return self().write(&c, 1);
		}

	private:
		const Derived& self() const {
			return static_cast<const Derived&>(*this);
		}
};

template <class T>
concept AsyncTransferTarget =
	requires(T target, Byte* read_buf, const Byte* write_buf, SizeType nbytes) {
		{ target.read(read_buf, nbytes) } -> std::same_as<Task<ResType>>;
		{ target.write(write_buf, nbytes) } -> std::same_as<Task<ResType>>;
		{ target.set_blocking() } -> std::convertible_to<int>;
		{ target.set_nonblocking() } -> std::convertible_to<int>;
	};

class File : public io_overloads<File> {
	protected:
		HANDLE _fd = INVALID_HANDLE_VALUE;

	public:
		using io_overloads<File>::read;
		using io_overloads<File>::write;
		enum iomode {
			RDONLY,
			WRONLY,
			RDWR
		};

		File()            = default;
		File(const File&) = delete;
		File(fs::path path) : _file_path(std::move(path)) {
		}
		File(File&& other) noexcept {
			this->close();
			this->_fd        = other._fd;
			this->_file_path = std::move(other._file_path);
			other._fd        = INVALID_HANDLE_VALUE;
		}
		~File() {
			this->close();
		}

		File& operator=(const string_type& path) {
			_file_path = path;
			this->close();
			return *this;
		}

		ResType open(const string_type& path, bool trunc = false,
					 int rwmode = RDWR) {
			if (_fd == INVALID_HANDLE_VALUE) {
				_iomode = rwmode;
#ifdef _WIN32
				DWORD DesiredAccess       = 0;
				DWORD CreationDisposition = 0;
				if (rwmode == RDONLY) {
					DesiredAccess = FILE_GENERIC_READ;
					// Should only open an existing file.
					CreationDisposition = OPEN_EXISTING;
				}
				else {
					DesiredAccess = FILE_GENERIC_READ | FILE_GENERIC_WRITE;
					CreationDisposition = trunc ? CREATE_ALWAYS : OPEN_ALWAYS;
				}

				CREATEFILE2_EXTENDED_PARAMETERS params = {
					sizeof(CREATEFILE2_EXTENDED_PARAMETERS)};
				params.dwFileAttributes = FILE_ATTRIBUTE_NORMAL;
				params.dwFileFlags      = FILE_FLAG_SEQUENTIAL_SCAN;

				_fd                     = CreateFile2(
                    convert_string_to_wstring(path.c_str()).c_str(),
                    DesiredAccess, FILE_SHARE_READ | FILE_SHARE_WRITE,
                    CreationDisposition, &params);
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
				}
				else if (rwmode != RDONLY) {
					flag |= O_APPEND;
				}
				_fd = ::open(path.c_str(), flag, 0644);
#endif
				if (_fd == INVALID_HANDLE_VALUE) {
					return tl::unexpected((int)GetLastError());
				}
				_file_path = path;
			}
			return 0;
		}
		ResType open(bool trunc = false, int rwmode = RDWR) {
			return this->open(_file_path.string(), trunc, rwmode);
		}
		ResType open_read_only() {
			return this->open(_file_path.string(), false, RDONLY);
		}

		bool is_exist() const {
			return exists(_file_path);
		}
		bool is_open() const {
			return _fd != INVALID_HANDLE_VALUE;
		}
		string size_string() const {
			return std::to_string(file_size(_file_path));
		}
		string filename() const {
			return _file_path.filename().string();
		}
		auto get_last_modified_time() const {
			return last_write_time(_file_path);
		}
		void unmap_file() {
#ifdef _WIN32
			if (_pData) {
				UnmapViewOfFile(_pData);
			}
			if (_hMapping) {
				CloseHandle(_hMapping);
			}
			_pData    = nullptr;
			_hMapping = nullptr;
#else
			if (_mmap_ptr == nullptr) {
				munmap(_mmap_ptr, _mmap_len);
				_mmap_ptr = nullptr;
			}
#endif
		}
		std::uintmax_t size() const {
			return file_size(_file_path);
		}
		void close() {
			if (_fd != INVALID_HANDLE_VALUE) {
#ifdef _WIN32
				CloseHandle(_fd);
#else
				::close(_fd);
#endif
				_fd = INVALID_HANDLE_VALUE;
			}
			this->unmap_file();
		}
		expected<std::vector<char>, int> read_all_bytes() {
			std::vector<char> res(this->size());
			auto              ret = this->read(res);
			if (!ret) {
				return tl::unexpected(ret.error());
			}
			return res;
		}
		fs::path::string_type get_parent() const {
			return _file_path.parent_path();
		}
		fs::path::string_type get_absolute() const {
			return absolute(_file_path);
		}
		fs::path::string_type get_type() const {
			return _file_path.extension().native();
		}
		expected<uint8_t*, int> map_file_in_memory() {
			DWORD mmode = 0, pmmode = 0;
#ifdef _WIN32
			if (_iomode == iomode::RDONLY) {
				mmode  = PAGE_READONLY;
				pmmode = FILE_MAP_READ;
			}
			else {
				mmode  = PAGE_READWRITE;
				pmmode = FILE_MAP_WRITE;
			}
			if (_hMapping == nullptr) {
				_hMapping =
					CreateFileMappingA(_fd, nullptr, mmode, 0, 0, nullptr);
				if (_hMapping == nullptr) {
					return tl::unexpected((int)GetLastError());
				}
			}
			if (_pData == nullptr) {
				_pData = MapViewOfFile(_hMapping, pmmode, 0, 0, 0);
				if (_pData == nullptr) {
					CloseHandle(_hMapping);
					return tl::unexpected((int)GetLastError());
				}
			}
			return (uint8_t*)_pData;
#else
			if (_iomode == iomode::RDONLY) {
				mmode  = PROT_READ;
				pmmode = MAP_PRIVATE;
			}
			else {
				mmode  = PROT_READ | PROT_WRITE;
				pmmode = MAP_SHARED;
			}
			if (_mmap_ptr == nullptr) {
				_mmap_len = this->size();
				_mmap_ptr =
					(uint8_t*)mmap(nullptr, _mmap_len, mmode, pmmode, _fd, 0);
				if (_mmap_ptr == nullptr) {
					return tl::unexpected((int)GetLastError());
				}
				madvise(_mmap_ptr, _mmap_len, MADV_SEQUENTIAL);
			}
			return _mmap_ptr;
#endif
		}

		bool available() const {
			return _fd != INVALID_HANDLE_VALUE;
		}
		HANDLE get_fd() const {
			return _fd;
		}
		ResType read(Byte* buf, SizeType nbytes) const {
#ifdef _WIN32
			// Windows DWORD is 32-bit, max ~4GB per call. Use chunks for large
			// reads.
			constexpr DWORD MAX_CHUNK  = 0x7FFFFFFF; // ~2GB per call for safety
			SizeType        total_read = 0;
			while (nbytes > 0) {
				DWORD chunk_size =
					static_cast<DWORD>((std::min<SizeType>)(nbytes, MAX_CHUNK));
				DWORD bytes_read = 0;
				if (!ReadFile(_fd, buf, chunk_size, &bytes_read, nullptr)) {
					return tl::unexpected((int)GetLastError());
				}
				if (bytes_read == 0) {
					break; // EOF
				}
				total_read += bytes_read;
				buf += bytes_read;
				nbytes -= bytes_read;
				if (bytes_read < chunk_size) {
					break; // Short read, likely EOF
				}
			}
			return total_read;
#else
			auto ret = ::read(_fd, buf, nbytes);
			if (ret != -1) {
				return ret;
			}
			else {
				return tl::unexpected((int)GetLastError());
			}
#endif
		}
		// Return success when ret>=0, otherwise unexpected
		ResType write(const Byte* buf, SizeType nbytes) const {
#ifdef _WIN32
			// Windows DWORD is 32-bit, max ~4GB per call. Use chunks for large
			// writes.
			constexpr DWORD MAX_CHUNK = 0x7FFFFFFF; // ~2GB per call for safety
			SizeType        total_written = 0;
			while (nbytes > 0) {
				DWORD chunk_size =
					static_cast<DWORD>((std::min<SizeType>)(nbytes, MAX_CHUNK));
				DWORD bytes_written = 0;
				if (!WriteFile(_fd, buf, chunk_size, &bytes_written, nullptr)) {
					return tl::unexpected((int)GetLastError());
				}
				if (bytes_written == 0) {
					break; // Disk full or other issue
				}
				total_written += bytes_written;
				buf += bytes_written;
				nbytes -= bytes_written;
				if (bytes_written < chunk_size) {
					break; // Short write
				}
			}
			return total_written;
#else
			auto ret = ::write(_fd, buf, nbytes);
			if (ret != -1) {
				return ret;
			}
			else {
				return tl::unexpected((int)GetLastError());
			}
#endif
		}

	private:
		fs::path _file_path;
		int      _iomode = 0;
		// For mmap
#ifdef _WIN32
		// For mmap
		HANDLE _hMapping = nullptr;
		LPVOID _pData    = nullptr;
#else
		uint8_t* _mmap_ptr = nullptr;
		size_t   _mmap_len = 0;
#endif // _WIN32
};

class raw_socket : public io_overloads<raw_socket> {

	public:
		raw_socket()                  = default;
		raw_socket(const raw_socket&) = delete;
		raw_socket(raw_socket&& other) noexcept {
			this->_fd      = other._fd;
			other._fd      = INVALID_SOCKET;
			this->_ip_port = other._ip_port;
			::memset(&other._ip_port, 0, sizeof(other._ip_port));
		}
		raw_socket(SOCKET fd, const sockaddr_in& addr_info) {
			_fd      = fd;
			_ip_port = addr_info;
		}
		~raw_socket() {
			this->close();
		}
		using io_overloads<raw_socket>::read;
		using io_overloads<raw_socket>::write;

		ResType initialize(int domain = AF_INET, int type = SOCK_STREAM,
						   int protocol = IPPROTO_IP) {
			if (_fd == INVALID_SOCKET) {
				_ip_port.sin_family = AF_INET;
				_fd                 = ::socket(domain, type, protocol);
				if (_fd == INVALID_SOCKET) {
					RETERROR;
				}
			}
			return 0;
		}
		ResType bind() {
			auto ret =
				::bind(_fd, (const sockaddr*)&_ip_port, sizeof(_ip_port));
			if (ret == -1) {
				RETERROR;
			}
			return 0;
		}
		ResType bind(const struct sockaddr* addr, socklen_t len) {
			if (std::cmp_less_equal(len, sizeof(_ip_port))) {
				memcpy(&_ip_port, addr, len);
			}
			return this->bind();
		}
		ResType bind(std::string_view hostname, uint16_t port) {
			memset(&_ip_port, 0, sizeof(sockaddr_in));
			_ip_port.sin_family = AF_INET;
			auto ret = inet_pton(AF_INET, hostname.data(), &_ip_port.sin_addr);
			if (ret <= 0) {
				if (ret == 0) {
					return tl::unexpected(EINVAL);
				}
				else {
					return tl::unexpected((int)GetLastError());
				}
			}
			_ip_port.sin_port = htons(port);
			return this->bind();
		}
		ResType setsockopt(int level, int option, const optval_t* val,
						   socklen_t len) {
			auto ret = ::setsockopt(_fd, level, option, val, len);
			if (ret == -1) {
				RETERROR;
			}
			return 0;
		}

		raw_socket& operator=(raw_socket&& other) noexcept {
			if (this != &other) {
				this->close();
				this->_fd      = other._fd;
				other._fd      = INVALID_SOCKET;
				this->_ip_port = other._ip_port;
				::memset(&other._ip_port, 0, sizeof(other._ip_port));
			}
			return *this;
		}

		SOCKET get_fd() const {
			return _fd;
		}
		in_addr get_ip() const {
			return _ip_port.sin_addr;
		}
		std::string get_ip_s() const {
			char buf[INET_ADDRSTRLEN];
			return inet_ntop(AF_INET, &_ip_port.sin_addr, buf, INET_ADDRSTRLEN);
		}
		uint16_t get_port() const {
			return ntohs(_ip_port.sin_port);
		}
		std::string get_port_s() const {
			return std::to_string(ntohs(_ip_port.sin_port));
		}
		std::string get_ip_port_s() const {
			return get_ip_s() + ':' + get_port_s();
		}
		int set_blocking() const {
#ifdef _WIN32
			u_long op = 0;
			return ioctlsocket(_fd, FIONBIO, &op);
#else
			int old_option = fcntl(_fd, F_GETFL);
			int new_option = old_option & ~O_NONBLOCK;
			return fcntl(_fd, F_SETFL, new_option);
#endif
		}
		int set_nonblocking() const {
#ifdef _WIN32
			u_long op = 1;
			return ioctlsocket(_fd, FIONBIO, &op);
#else
			int old_option = fcntl(_fd, F_GETFL);
			int new_option = old_option | O_NONBLOCK;
			return fcntl(_fd, F_SETFL, new_option);
#endif
		}

		bool available() const {
			return _fd != INVALID_SOCKET;
		}
		void close() {
			if (_fd != INVALID_SOCKET) {
#ifdef _WIN32
				::closesocket(_fd);
#else
				::close(_fd);
#endif
				_fd = INVALID_SOCKET;
			}
		}
		ResType read(Byte* buf, SizeType nbytes) const {
			// recv/send use int for length, max ~2GB per call. Use chunks for
			// safety.
			constexpr int MAX_CHUNK  = 0x7FFFFFFF;
			SizeType      total_read = 0;
			while (nbytes > 0) {
				int chunk_size =
					static_cast<int>((std::min<SizeType>)(nbytes, MAX_CHUNK));
				auto ret = ::recv(_fd, (char*)buf, chunk_size, 0);
				if (ret < 0) {
					return tl::unexpected((int)GetLastError());
				}
				if (ret == 0) {
					break; // Connection closed
				}
				total_read += ret;
				buf += ret;
				nbytes -= ret;
				if (ret < chunk_size) {
					break; // Short read
				}
			}
			return total_read;
		}
		ResType write(const Byte* buf, SizeType nbytes) const {
			// recv/send use int for length, max ~2GB per call. Use chunks for
			// safety.
			constexpr int MAX_CHUNK     = 0x7FFFFFFF;
			SizeType      total_written = 0;
			while (nbytes > 0) {
				int chunk_size =
					static_cast<int>((std::min<SizeType>)(nbytes, MAX_CHUNK));
				auto ret = ::send(_fd, (const char*)buf, chunk_size, 0);
				if (ret < 0) {
					return tl::unexpected((int)GetLastError());
				}
				if (ret == 0) {
					break; // Connection issue
				}
				total_written += ret;
				buf += ret;
				nbytes -= ret;
				if (ret < chunk_size) {
					break; // Short write
				}
			}
			return total_written;
		}

	protected:
		SOCKET      _fd = INVALID_SOCKET;
		sockaddr_in _ip_port{};
};

class tcp_socket : public raw_socket {
	public:
		tcp_socket()                  = default;
		tcp_socket(const tcp_socket&) = delete;
		tcp_socket(tcp_socket&& other) noexcept : raw_socket(std::move(other)) {
		}
		tcp_socket(SOCKET fd, const sockaddr_in& addr_info)
			: raw_socket(fd, addr_info) {
		}

		ResType connect(std::string_view ip, uint16_t port) {
			struct sockaddr_in addr{};
			addr.sin_family = AF_INET;
			auto ret        = inet_pton(AF_INET, ip.data(), &addr.sin_addr);
			if (ret <= 0) {
				if (ret == 0) {
					return tl::unexpected(EINVAL);
				}
				else {
					return tl::unexpected((int)GetLastError());
				}
			}
			addr.sin_port = htons(port);
			return this->connect(addr);
		}
		ResType connect(const struct sockaddr_in& addr) {
			auto retval = initialize();
			if (!retval) {
				return retval;
			}
			_ip_port = addr;
			if (::connect(_fd, (struct sockaddr*)&_ip_port, sizeof(_ip_port)) <
				0) {
				return tl::unexpected((int)GetLastError());
			}
			return 0;
		}
		ResType listen(uint16_t port, int n = 5) {
			optval_t flag       = 1;
			_ip_port.sin_family = AF_INET;
			auto ret            = this->initialize();
			if (!ret) {
				return ret;
				// return SOCKET_ERROR;
			}
			_ip_port.sin_addr.s_addr = INADDR_ANY;
			_ip_port.sin_port        = htons(port);
			setsockopt(SOL_SOCKET, SO_REUSEADDR, &flag, sizeof(flag));
			ret = this->bind();
			if (!ret) {
				return ret;
				// return SOCKET_ERROR;
			}
			if (::listen(_fd, n) < 0) {
				return tl::unexpected((int)GetLastError());
				// return SOCKET_ERROR;
			}
			return 0;
		}
		expected<tcp_socket, int> accept() const {
			sockaddr_in addrs{};
			socklen_t   len = sizeof addrs;
			memset(&addrs, 0, len);
			auto ret = ::accept(_fd, (sockaddr*)&addrs, &len);
			if (ret == INVALID_SOCKET) {
				return tl::unexpected((int)GetLastError());
			}
			return tcp_socket(ret, addrs);
		}

		tcp_socket& operator=(tcp_socket&& other) noexcept {
			raw_socket::operator=(std::move(other));
			return *this;
		}
};

class udp_socket : public raw_socket {
	public:
		udp_socket()                  = default;
		udp_socket(const udp_socket&) = delete;
		udp_socket(udp_socket&& other) noexcept : raw_socket(std::move(other)) {
		}
		~udp_socket() = default;

		ResType set_local_port(uint16_t port) {
			optval_t flag = 1;
			auto     ret  = initialize(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
			if (!ret) {
				return ret;
				// return SOCKET_ERROR;
			}
			_ip_port.sin_addr.s_addr = INADDR_ANY;
			_ip_port.sin_port        = htons(port);
			setsockopt(SOL_SOCKET, SO_REUSEADDR, &flag, sizeof(flag));
#ifdef SO_BROADCAST
			setsockopt(SOL_SOCKET, SO_BROADCAST, &flag, sizeof(flag));
#endif
			ret = this->bind();
			if (!ret) {
				return ret;
				// return SOCKET_ERROR;
			}
			return 0;
		}
		ResType send_to(std::string_view ip, uint16_t port,
						std::string_view message) const {
			struct sockaddr_in target_udp_addr{};
			memset(&target_udp_addr, 0, sizeof(target_udp_addr));
			target_udp_addr.sin_family = AF_INET;
			target_udp_addr.sin_port   = htons(port);
			auto ret = inet_pton(AF_INET, ip.data(), &target_udp_addr.sin_addr);
			if (ret <= 0) {
				if (ret == 0) {
					return tl::unexpected(EINVAL);
				}
				else {
					return tl::unexpected((int)GetLastError());
				}
			}

			ret = ::sendto(_fd, message.data(), message.size(), 0,
						   (const struct sockaddr*)&target_udp_addr,
						   sizeof(struct sockaddr));
			if (ret < 0) {
				return tl::unexpected((int)GetLastError());
			}
			return ret;
		}
		ResType send_broadcast_message(uint16_t         port,
									   std::string_view message) const {
			return send_to("255.255.255.255", port, message);
		}
};

} // namespace kotcpp

#endif // !IO_H
