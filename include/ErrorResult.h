#ifndef ERRRES_H
#define ERRRES_H

#include <fmt/core.h>
#include <cstring>
#include <cctype>
#include <string>
#include <string_view>
#include <system_error>
#include <tl/expected.hpp>
#include <format>
#include <utility>
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
#include <sys/mman.h>
#include <unistd.h>
#define INVALID_SOCKET       (-1)
#define SOCKET_ERROR         (-1)
#define INVALID_HANDLE_VALUE (-1)
#define GetLastError()       errno
#define WSAEWOULDBLOCK       EAGAIN
inline void SetLastError(int errcode) {
	errno = errcode;
}
using SOCKET   = int;
using optval_t = int;
using HANDLE   = int;
using DWORD    = int;
#endif

namespace kotcpp {

enum class ErrorSource {
	Os,
	Sft
};

inline std::string trim_error_message(std::string message) {
	while (!message.empty() &&
		   (message.back() == '\r' || message.back() == '\n' ||
			std::isspace(static_cast<unsigned char>(message.back())))) {
		message.pop_back();
	}
	return message;
}

inline std::string format_os_error(int errcode) {
#ifdef _WIN32
	CHAR  message[512]{};
	DWORD ret = FormatMessageA(
		FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, nullptr,
		static_cast<DWORD>(errcode), MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
		message, sizeof(message), nullptr);
	if (ret == 0) {
		return std::format("Unknown error code: {}", errcode);
	}
	return std::format("{} {}", trim_error_message(message), errcode);
#else
	return std::format("{} {}", std::strerror(errcode), errcode);
#endif
}

class Error {
	public:
		Error() = default;

		Error(ErrorSource source, int code, std::string message)
			: _source(source), _code(code), _message(std::move(message)) {
		}

		Error(int code) : Error(ErrorSource::Os, code, format_os_error(code)) {
		}

		Error(const char* message)
			: Error(ErrorSource::Sft, 1,
					message ? std::string(message) : std::string()) {
		}

		Error(std::string message)
			: Error(ErrorSource::Sft, 1, std::move(message)) {
		}

		Error(std::string_view message)
			: Error(ErrorSource::Sft, 1, std::string(message)) {
		}

		ErrorSource source() const noexcept {
			return _source;
		}

		int code() const noexcept {
			return _code;
		}

		int value() const noexcept {
			return _code;
		}

		const std::string& message() const noexcept {
			return _message;
		}

		bool is(ErrorSource source, int code) const noexcept {
			return _source == source && _code == code;
		}

		explicit operator bool() const noexcept {
			return _source == ErrorSource::Sft || _code != 0;
		}

	private:
		ErrorSource _source  = ErrorSource::Os;
		int         _code    = 0;
		std::string _message = {};
};

inline bool operator==(const Error& error, int code) noexcept {
	return error.is(ErrorSource::Os, code);
}

inline bool operator==(int code, const Error& error) noexcept {
	return error == code;
}

inline bool operator!=(const Error& error, int code) noexcept {
	return !(error == code);
}

inline bool operator!=(int code, const Error& error) noexcept {
	return !(error == code);
}

inline Error make_os_error(int code) {
	return {ErrorSource::Os, code, format_os_error(code)};
}

inline Error make_os_error(int code, std::string message) {
	return {ErrorSource::Os, code, std::move(message)};
}

inline Error make_sft_error(std::string message) {
	return {ErrorSource::Sft, 1, std::move(message)};
}

inline Error last_error() {
	return make_os_error(static_cast<int>(GetLastError()));
}

inline void set_last_error(int code) {
	SetLastError(code);
}

inline void capture_socket_error() {
#ifdef _WIN32
	set_last_error(WSAGetLastError());
#endif
}

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

using std::string;
using string_type                  = std::string;
using RetType                      = int64_t;
using SizeType                     = int64_t;

template <typename T> using Result = expected<T, Error>;
using ResType                      = Result<RetType>;

inline std::string get_error_str(int errcode = GetLastError()) {
	return format_os_error(errcode);
}

inline std::string get_error_str(const Error& error) {
	return error.message();
}

inline void print_error(const std::string& msg, const std::error_code& errc) {
	fmt::print(stderr, "{}: {}\n", msg, errc.message());
}

inline void print_error(const std::string& msg, const Error& error) {
	fmt::print(stderr, "{}: {}\n", msg, error.message());
}

inline void print_error(const std::string& msg, int errc = GetLastError()) {
	fmt::print(stderr, "{}: {}\n", msg, get_error_str(errc));
}

// This overload presumes the given result is an error. It will lead to
// segmentation fault if the result is valid.
inline void print_error(const std::string& msg, const ResType& res) {
	print_error(msg, res.error());
}

template <typename T>
inline void print_error(const std::string& msg, const Result<T>& res) {
	print_error(msg, res.error());
}
} // namespace kotcpp

#define RETERROR return tl::unexpected(kotcpp::last_error())
#endif
