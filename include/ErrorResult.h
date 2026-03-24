#ifndef ERRRES_H
#define ERRRES_H

#include <string>
#include <system_error>
#include <filesystem>
#include <print>
#include <tl/expected.hpp>
using tl::expected;
using tl::unexpected;

#ifdef _WIN32
#include <WS2tcpip.h>
#include <WinSock2.h>
#include <fileapi.h>
#include <io.h>
#pragma comment(lib, "ws2_32.lib")
// extern std::string get_winsock_error_str(int errcode = 0);
// #define perror(str) std::format("{}: {}\n", str, get_winsock_error_str())
extern std::wstring convert_string_to_wstring(const char* str);
extern std::string  convert_wstring_to_string(const wchar_t* wstr);
using socklen_t = int;
using optval_t  = char;
using ssize_t   = int64_t;
#else
#include <arpa/inet.h>
#include <cerrno> // For errno
#include <dirent.h>
#include <sys/fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#define INVALID_SOCKET       (-1)
#define SOCKET_ERROR         (-1)
#define INVALID_HANDLE_VALUE (-1)
#define GetLastError()       errno
#define WSAEWOULDBLOCK       EAGAIN
using SOCKET   = int;
using optval_t = int;
using HANDLE   = int;
using DWORD    = int;
#endif
#define RETERROR return unexpected((int)GetLastError())

namespace kotcpp {

inline std::error_code getLastErrorCode(int code = GetLastError()) {
	return {static_cast<int>(code), std::system_category()};
}

template <class T>
concept buffer_type = requires(T a) {
	a.data();
	a.size();
	requires std::is_same_v<typename T::value_type, char> ||
				 std::is_same_v<typename T::value_type, unsigned char>;
};

namespace fs = std::filesystem;

using std::string;
using string_type = std::string;
using RetType     = int64_t;
using SizeType    = int64_t;
// using ResType                      = expected<RetType, std::error_code>;
using ResType                      = expected<RetType, int>;

template <typename T> using Result = expected<T, std::string>;

inline std::string get_error_str(int errcode = GetLastError()) {
#ifdef _WIN32
	CHAR message[128]{};
	auto ret = FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM, nullptr, errcode,
							  MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
							  message, sizeof(message), nullptr);
	if (ret < 2) {
		return std::format("Unknown error code: {}", errcode);
	}
	message[ret - 2] = 0;
	return std::format("{} {}", message, errcode);
#else
	return std::format("{} {}", std::strerror(errcode), errcode);
#endif
}

inline void print_error(const std::string& msg, const std::error_code& errc) {
#ifdef _WIN32
	std::print(stderr, "{}: {}\n", msg, get_error_str(errc.value()));
#else
	std::print(stderr, "{}: {}\n", msg, errc.message());
#endif
}

inline void print_error(const std::string& msg, int errc = GetLastError()) {
	std::print(stderr, "{}: {}\n", msg, get_error_str(errc));
}

// This overload presumes the given result is an error. It will lead to
// segmentation fault if the result is valid.
inline void print_error(const std::string& msg, const ResType& res) {
	print_error(msg, res.error());
}

template <typename T>
inline void print_error(const std::string& msg, const Result<T>& res) {
	std::print(stderr, "{}: {}\n", msg, res.error());
}
} // namespace kotcpp
#endif