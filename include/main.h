#ifndef MAIN_H
#define MAIN_H

#include "sftclass.hpp"
#include <memory>

#define UDP_PORT 41541
#define TCP_PORT 10013
#ifndef VERSION
// The actual version is defined in CMakeLists.txt
#define VERSION "0.1"
#endif

#ifdef _WIN32
// Windows-specific declarations
struct NameIP {
		std::string name;
		std::string ip;
};
extern kotcpp::Result<std::vector<std::string>>
						   OpenFileOrFolderDialog(bool openFolder = false);
extern bool                ConfigureFirewall();
extern std::vector<NameIP> GetIPv4BroadcastAddresses();
#endif

extern std::vector<std::string> get_utf8_argv(int argc, char** argv);

namespace sft_detail {
struct parallel_transfer_options;
}

enum class SftMode : int8_t {
	Interactive      = -1, // Interactive mode
	Receive          = 0,  // Traditional receive mode
	TransferFiles    = 1,  // Transfer files
	TransferFolders  = 2,  // Transfer folders
	ToggleRandomPort = 3,  // Toggle random port option
	PullSend         = 4,  // Pull mode: wait for connection as sender
	PullReceive      = 5,  // Pull mode: actively connect as receiver
	ExportPubKey     = 6,  // Export public key
	ResetKeyPair     = 7,  // Reset key pair
};

#ifndef SFT_PROTOCOL_ENUM_DEFINED
#define SFT_PROTOCOL_ENUM_DEFINED
enum class SftProtocol : uint8_t {
	V11,
	V12,
	V13,
};
#endif

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

template <kotcpp::AsyncTransferTarget Target>
bool send_file(Target&                                             target,
			   const vector<tuple<std::unique_ptr<File>, string>>& files,
			   SftProtocol                                         protocol);

template <kotcpp::AsyncTransferTarget Target>
bool send_file_v11(Target&                                             target,
				   const vector<tuple<std::unique_ptr<File>, string>>& files);

template <kotcpp::AsyncTransferTarget Target>
bool send_file_v12(Target& target, const vector<string>& files);

template <kotcpp::AsyncTransferTarget Target>
bool send_file_v13_parallel(
	Target& target, const vector<string>& files,
	const sft_detail::parallel_transfer_options& options);

template <kotcpp::AsyncTransferTarget Target>
void                                               receive_file(Target&                                      target,
																const sft_detail::parallel_transfer_options& options);

template <kotcpp::AsyncTransferTarget Target> void receive_file(Target& target);

Result<sockaddr_in>                                manual_connect_to_peer();

vector<tuple<std::unique_ptr<File>, string>>
			get_filefd_list(const vector<string>& path_list);

SftMode     choose_working_mode(SftMode specified_mode  = SftMode::Interactive,
								bool    use_random_port = false);

// Helper functions for main.cpp
std::string pick_network_interface();

#endif // MAIN_H
