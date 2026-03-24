#include "main.h"
#include <sodium.h>
#include <cstring>
#include <print>
#ifdef _WIN32
#include <WinSock2.h>
#include <fileapi.h>

struct NameIP {
		std::string name;
		std::string ip;
};
extern expected<std::vector<std::string>, std::string>
								OpenFileOrFolderDialog(bool openFolder = false);
extern bool                     ConfigureFirewall();
extern std::vector<NameIP>      GetIPv4BroadcastAddresses();
extern std::vector<std::string> get_utf8_argv(int argc, char** argv);
#else
#include <termios.h>
#include <csignal>
#define WAIT_TIMEOUT ETIMEDOUT

std::vector<std::string> get_utf8_argv(int argc, char** argv) {
	std::vector<std::string> args;
	args.reserve(argc);
	for (int i = 0; i < argc; ++i) {
		args.emplace_back(argv[i]);
	}
	return args;
}
#endif

using namespace std;
using namespace kotcpp;

extern string info;

struct sft_config {
		int specified_mode = -1; // -1: invalid/unset, 0: receive, 1: transfer
		string         target_addr = "";
		vector<string> file_list;
		bool           is_one_time     = false;
		bool           use_random_port = false;
};

void print_help() {
	// clang-format off
    std::println(
		"Usage: simple-file-transfer [OPTION] [FILE](optional)...\n"
		"Options: \n"
		"  -h, --help                Print this message.\n"
		"  -r, --receive             Enable receive mode for one-time task.\n"
		"  -t, --transfer [FILES...] Enable transfer mode for one-time task.\n"
		"  -a, --addr <ip:port>      Directly connect to specified address (skips discovery).\n"
		"\n"
		"Interactive Mode: Run without -r or -t to enter interactive menu.\n"
		"Examples: \n"
		"  simple-file-transfer                           # Interactive mode\n"
		"  simple-file-transfer -r                        # One-time receive\n"
		"  simple-file-transfer -t file1 dir1/       	  # One-time transfer\n"
		"  simple-file-transfer -t file1 -a 1.2.3.4:1234  # Direct transfer"
    );
	// clang-format on
}

sft_config parse_args(const std::vector<std::string>& argv) {
	sft_config config;
	for (size_t i = 1; i < argv.size(); ++i) {
		if (argv[i] == "-h" || argv[i] == "--help") {
			print_help();
			exit(0);
		}
		else if (argv[i] == "-r" || argv[i] == "--receive") {
			config.specified_mode = 0;
			config.is_one_time    = true;
		}
		else if (argv[i] == "-t" || argv[i] == "--transfer") {
			config.specified_mode = 1;
			config.is_one_time    = true;
			// Collect subsequent arguments as files until another flag is met
			while (i + 1 < argv.size() && !argv[i + 1].starts_with("-")) {
				config.file_list.push_back(argv[++i]);
			}
		}
		else if (argv[i] == "-a" || argv[i] == "--addr") {
			if (i + 1 < argv.size()) {
				config.target_addr = argv[++i];
			}
		}
		else if (config.specified_mode == -1) {
			// If no mode set yet, assume transfer mode for drag-and-drop or
			// direct file list
			config.specified_mode = 1;
			// config.is_one_time    = true;
			config.file_list.push_back(argv[i]);
		}
		else if (config.specified_mode == 1) {
			config.file_list.push_back(argv[i]);
		}
	}
	return config;
}

string pick_network_interface() {
#ifdef _WIN32
	auto res = GetIPv4BroadcastAddresses();
	if (res.empty()) {
		return "0.0.0.0";
	}

	std::cout << info << "\n";
	std::cout << "All available networks are listed below.\n";
	for (size_t i = 0; i < res.size(); ++i) {
		cout << format("{}: Adapter: {}. IP: {}", i, res[i].name, res[i].ip)
			 << "\n";
	}
	cout << "\nPlease choose a network to discover other sft hosts: ";
	size_t idx = 0;
	cin >> idx;
	if (idx >= res.size()) {
		idx = 0;
	}
	cout << "\033c";
	return res[idx].ip;
#else
	return "0.0.0.0";
#endif
}

bool execute_transfer_task(udp_socket& usocket, sft_client& sender,
						   const vector<string>& file_list,
						   const string& target_addr, bool is_one_time) {
	auto filefds_paths = get_filefd_list(file_list);
	if (filefds_paths.empty()) {
		std::cerr << "No valid files to send.\n";
		return false;
	}

	Result<sockaddr_in> connect_res;
	if (!target_addr.empty()) {
		// Manual address from CLI
		auto     colon_pos = target_addr.find(':');
		string   ip        = target_addr.substr(0, colon_pos);
		uint16_t port =
			(colon_pos != string::npos)
				? static_cast<uint16_t>(stoi(target_addr.substr(colon_pos + 1)))
				: TCP_PORT;

		sockaddr_in addr{};
		addr.sin_family = AF_INET;
		inet_pton(AF_INET, ip.c_str(), &addr.sin_addr);
		addr.sin_port = htons(port);
		connect_res   = addr;
	}
	else {
		// Discovery Loop
		while (true) {
			vector<sft_respond_struct> all_hosts;
			(void)search_for_sft_peers(usocket, 3, all_hosts);

			if (all_hosts.empty()) {
				std::cerr << "No peers found.\n";
				if (is_one_time) {
					return false;
				}

				std::cout << "\nDiscovery failed. Choose next step:\n"
							 "0. Search again.\t"
							 "1. Input IP and port manually.\t"
							 "2. Return to initial menu.\n"
							 "Enter your choice: ";
				int choice = 0;
				if (!(std::cin >> choice)) {
					std::cin.clear();
					std::cin.ignore(10000, '\n');
					return false;
				}

				if (choice == 0) {
					continue;
				}
				else if (choice == 1) {
					connect_res = manual_connect_to_peer();
					if (connect_res) {
						break;
					}
					// If manual connect failed, loop back to prompt
					continue;
				}
				else {
					return false;
				}
			}
			else {
				connect_res = connect_to_peer(all_hosts);
				if (connect_res) {
					break;
				}
				// If selection failed/canceled, loop back to prompt
				if (is_one_time) {
					return false;
				}
			}
		}
	}

	if (!connect_res) {
		return false;
	}

	auto ret = sender.connect(connect_res.value());
	if (!ret) {
		print_error("Connect failed", ret);
		return false;
	}

	return send_file(sender, filefds_paths);
}

void execute_receive_task(udp_socket& usocket, sft_server& receiver,
						  bool use_random_port) {
	while (true) {
		auto res =
			wait_for_peers_to_connect(usocket, receiver, 15, use_random_port);
		if (!res) {
			if (res.error() == WAIT_TIMEOUT) {
				continue;
			}
			print_error("Wait for connect failed", res);
			break;
		}
		receive_file(receiver);
		break; // Exit after one successful receive in one-time mode
	}
}

int main(int argc, char* argv[]) {
#ifdef _WIN32
	// Set console code page to UTF-8 to properly display messages
	locale::global(locale("en_US.UTF-8"));
#endif
	if (sodium_init() == -1) {
		std::println(stderr, "Initialize sodium fail.");
		return 1;
	}

#ifdef _WIN32
	WSADATA wsaData;
	if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
		print_error("WSAStartup failed");
		return -1;
	}
	ConfigureFirewall();
#else
	signal(SIGPIPE, SIG_IGN);
#endif
	std::ios::sync_with_stdio(false);

	auto   config     = parse_args(get_utf8_argv(argc, argv));
	auto   config_dir = get_secure_app_path("sft");
	auto   hosts_path = config_dir / "known_hosts";
	auto   sec_path   = config_dir / "seckey";
	auto   pub_path   = config_dir / "pubkey";

	string bind_ip =
		(config.is_one_time) ? "0.0.0.0" : pick_network_interface();

	while (true) {
		udp_socket usocket;
		if (!usocket.initialize(AF_INET, SOCK_DGRAM, IPPROTO_UDP) ||
			!usocket.bind(bind_ip, UDP_PORT)) {
			print_error("UDP setup failed");
			return 1;
		}
		optval_t optval = 1;
		(void)usocket.setsockopt(SOL_SOCKET, SO_BROADCAST, &optval,
								 sizeof(optval));

		int mode =
			choose_working_mode(config.specified_mode, config.use_random_port);

		if (mode == 0) { // Receive
			sft_server receiver;
			if (receiver.initialize(sec_path.string(), pub_path.string(),
									hosts_path.string())) {
				if (config.is_one_time) {
					execute_receive_task(usocket, receiver,
										 config.use_random_port);
				}
				else {
					while (true) {
						auto res = wait_for_peers_to_connect(
							usocket, receiver, 15, config.use_random_port);
						if (res) {
							receive_file(receiver);
							break;
						}
						else if (res.error() != WAIT_TIMEOUT) {
							break;
						}
					}
				}
			}
		}
		else if (mode == 1 || mode == 2) { // Transfer
			sft_client sender;
			if (sender.initialize(sec_path.string(), pub_path.string(),
								  hosts_path.string())) {
				vector<string> files = config.file_list;
				if (files.empty()) {
#ifdef _WIN32
					auto diag_res = OpenFileOrFolderDialog(mode == 2);
					if (diag_res) {
						files = diag_res.value();
					}
#else
					std::cout << "Enter paths: ";
					string p;
					while (cin >> p) {
						files.push_back(p);
						if (cin.peek() == '\n') {
							break;
						}
					}
#endif
				}
				if (!files.empty()) {
					execute_transfer_task(usocket, sender, files,
										  config.target_addr,
										  config.is_one_time);
				}
			}
		}
		else if (mode == 3) {
			config.use_random_port = !config.use_random_port;
			std::cout << "\033c";
			continue;
		}

		if (config.is_one_time) {
			break;
		}
		config.specified_mode =
			-1; // Reset for next iteration in interactive mode
		config.file_list.clear();
		config.target_addr = "";
	}

#ifdef _WIN32
	WSACleanup();
#endif
	return 0;
}
