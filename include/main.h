#include <memory>
#include "sftclass.hpp"

#define UDP_PORT 41541
#define TCP_PORT 10013
#ifndef VERSION
// The actual version is defined in CMakeLists.txt
#define VERSION 0.1f
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

bool    send_file(kotcpp::sft_client&                                 target,
				  const vector<tuple<std::unique_ptr<File>, string>>& files);

void    receive_file(kotcpp::sft_server& target);

Result<sockaddr_in> manual_connect_to_peer();

vector<tuple<std::unique_ptr<File>, string>>
	get_filefd_list(const vector<string_type>& path_list);

int choose_working_mode(int specified_mode = -1, bool use_random_port = false);

// Helper functions for main.cpp
std::string pick_network_interface();
bool        execute_transfer_task(kotcpp::udp_socket&             usocket,
								  kotcpp::sft_client&             sender,
								  const std::vector<std::string>& file_list,
								  const std::string& target_addr, bool is_one_time);
void        execute_receive_task(kotcpp::udp_socket& usocket,
								 kotcpp::sft_server& receiver, bool use_random_port);
