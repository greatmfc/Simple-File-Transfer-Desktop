#ifndef MAIN_H
#define MAIN_H

#include "sftclass.hpp"
#include <memory>

#define UDP_PORT 41541
#define TCP_PORT 10013
#ifndef VERSION
// The actual version is defined in CMakeLists.txt
#define VERSION 0.1f
#endif

#ifdef _WIN32
// Windows-specific declarations
struct NameIP {
		std::string name;
		std::string ip;
};
extern tl::expected<std::vector<std::string>, std::string>
						   OpenFileOrFolderDialog(bool openFolder = false);
extern bool                ConfigureFirewall();
extern std::vector<NameIP> GetIPv4BroadcastAddresses();
#endif

extern std::vector<std::string> get_utf8_argv(int argc, char** argv);

enum class SftMode {
	Interactive      = -1, // 交互模式
	Receive          = 0,  // 传统接收模式
	TransferFiles    = 1,  // 传输文件
	TransferFolders  = 2,  // 传输文件夹
	ToggleRandomPort = 3,  // 切换随机端口选项
	PullSend         = 4,  // Pull模式：作为发送方等待连接
	PullReceive      = 5   // Pull模式：作为接收方主动连接
};

using std::tuple;
using std::vector;
using namespace kotcpp;

kotcpp::ResType
search_for_sft_peers(const kotcpp::udp_socket& local_host, int retry,
					 std::vector<sft_respond_struct>& all_hosts);

Result<sockaddr_in> connect_to_peer(vector<sft_respond_struct>& all_hosts);

ResType wait_for_peers_to_connect(const kotcpp::udp_socket& local_udp_host,
								  kotcpp::sft_server& receiver, int retry = 15,
								  bool use_random_port = false);

bool    send_file(kotcpp::sft_base&                                   target,
				  const vector<tuple<std::unique_ptr<File>, string>>& files);

void    receive_file(kotcpp::sft_base& target);

Result<sockaddr_in> manual_connect_to_peer();

vector<tuple<std::unique_ptr<File>, string>>
			get_filefd_list(const vector<string_type>& path_list);

SftMode     choose_working_mode(SftMode specified_mode  = SftMode::Interactive,
								bool    use_random_port = false);

// Helper functions for main.cpp
std::string pick_network_interface();
bool        execute_transfer_task(kotcpp::udp_socket&             usocket,
								  kotcpp::sft_client&             sender,
								  const std::vector<std::string>& file_list,
								  const std::string& target_addr, bool is_one_time);
void        execute_receive_task(kotcpp::udp_socket& usocket,
								 kotcpp::sft_server& receiver, bool use_random_port);

#endif // MAIN_H
