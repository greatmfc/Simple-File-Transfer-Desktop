#include <string_view>
#include <string>
#include <format>
#ifdef __unix__
#include <netinet/in.h>
#else
#include <ws2def.h>
using in_port_t = uint16_t;
#endif
#ifndef UTIL_HPP
#include <vector>
#include <ranges>
template <template <typename> typename Container = std::vector,
		  typename StringType                    = std::string>
constexpr Container<StringType> str_split(std::string_view str,
										  std::string_view delim) {
	Container<StringType> cont;
	for (const auto& word : std::views::split(str, delim)) {
		cont.emplace_back(StringType(word.begin(), word.end()));
	}
	return cont;
}

#endif
using std::format;
using std::string;
using std::string_view;
enum {
	DIS,
	RES,
	FIL,
	FIN
};

#define SFT_VER      0
#define SFT_TYPE     1
#define SFT_DIS_HOST 2
#define SFT_DIS_PORT 3
#define SFT_RES_HOST 2
#define SFT_RES_PORT 3
#define SFT_FIL_NAME 2
#define SFT_FIL_SIZE 3

struct sft_respond_struct {
		string      peer_name;
		sockaddr_in peer_addr;
		in_port_t   peer_port;
};

class sft_header {
	private:
		string message;

	public:
		sft_header() {
			message = "sft1.0/";
		}
		sft_header(std::string_view ver) {
			message = format("sft{}/", ver);
		}
		void set_version(const std::string_view& ver) {
			message = "sft";
			message += ver;
			message += '/';
		}
		void set_type(int type) {
			switch (type) {
			case DIS:
				message += "DIS/";
				break;
			case RES:
				message += "RES/";
				break;
			case FIL:
				message += "FIL/";
				break;
			case FIN:
				message += "FIN/";
				break;
			default:
				break;
			}
		}
		string form_discover_header(string_view host, uint16_t port) {
			return format("{}DIS/{}/{}\r\n", message, host, port);
		}
		string form_respond_header(string_view host, uint16_t port) {
			return format("{}RES/{}/{}\r\n", message, host, port);
		}
		string form_file_header(string_view file, size_t size) {
			return format("{}FIL/{}/{}\r\n", message, file, size);
		}
		size_t size() {
			return message.size();
		}
		const string& data() {
			return message;
		}
};
