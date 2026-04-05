#include "main.h"
#include "common.hpp"
#include <cstring>
#include <sodium.h>

#ifdef _WIN32
#include <WinSock2.h>
#include <fileapi.h>

extern std::vector<std::string> get_utf8_argv(int argc, char** argv);
#else
#include <csignal>
#include <termios.h>
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
		SftMode        mode        = SftMode::Interactive;
		string         target_addr = "";
		vector<string> file_list;
		bool           is_one_time     = false;
		bool           use_random_port = false;
};

void print_help() {
	// clang-format off
    fmt::println(
		"Usage: simple-file-transfer [OPTION] [FILE](optional)...\n"
		"Options: \n"
		"  -h, --help                Print this message.\n"
		"  -r, --receive             Enable receive mode for one-time task.\n"
		"  -t, --transfer [FILES...] Enable transfer mode for one-time task.\n"
		"  -p, --pull [FILES...]     Enable pull mode: wait for receiver to connect or actively connect to sender to pull files. It must be combined with either -r or -t.\n"
		"  -a, --addr <ip:port>      Directly connect to specified address (skips discovery).\n"
		"\n"
		"Interactive Mode: Run without -r, -t or -p to enter interactive menu.\n"
		"Examples: \n"
		"  simple-file-transfer                           # Interactive mode\n"
		"  simple-file-transfer -r                        # One-time receive\n"
		"  simple-file-transfer -t file1 dir1/       	  # One-time transfer\n"
		"  simple-file-transfer -t file1 -a 1.2.3.4:1234  # Direct transfer\n"
		"  simple-file-transfer -rp -a 1.2.3.4:1234     # One-time receive and pull files from target\n"
		"  simple-file-transfer -tp file1 dir1/         # One-time transfer and waiting for clients to pull"
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
			config.mode        = SftMode::Receive;
			config.is_one_time = true;
		}
		else if (argv[i] == "-t" || argv[i] == "--transfer") {
			config.mode        = SftMode::TransferFiles;
			config.is_one_time = true;
			// Collect subsequent arguments as files until another flag is met
			while (i + 1 < argv.size() && !argv[i + 1].starts_with("-")) {
				config.file_list.push_back(argv[++i]);
			}
		}
		else if (argv[i] == "-tp" || argv[i] == "-pt") {
			config.mode        = SftMode::PullSend;
			config.is_one_time = true;
			// Collect subsequent arguments as files until another flag is met
			while (i + 1 < argv.size() && !argv[i + 1].starts_with("-")) {
				config.file_list.push_back(argv[++i]);
			}
		}
		else if (argv[i] == "-rp" || argv[i] == "-pr") {
			config.mode        = SftMode::PullReceive;
			config.is_one_time = true;
		}
		else if (argv[i] == "-a" || argv[i] == "--addr") {
			if (i + 1 < argv.size()) {
				config.target_addr = argv[++i];
			}
		}
		else if (config.mode == SftMode::Interactive) {
			// If no mode set yet, assume transfer mode for drag-and-drop or
			// direct file list
			config.mode = SftMode::TransferFiles;
			// config.is_one_time    = true;
			while (i < argv.size()) {
				config.file_list.push_back(argv[i++]);
			}
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
						   const string&         target_addr) {
	auto filefds_paths = get_filefd_list(file_list);
	if (filefds_paths.empty()) {
		std::cerr << "No valid files to send.\n";
		return false;
	}

	auto connect_res = sft_common::establish_connection(usocket, target_addr);
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
		auto res = sft_common::wait_for_connection(usocket, receiver,
												   use_random_port, 15);
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

// Maybe the pulling side should know it's target address in advance, so we can
// skip discovery and directly connect to it.
void execute_receiver_pull_task(udp_socket& usocket, sft_client& receiver,
								const string& target_addr) {
	auto connect_res = sft_common::establish_connection(usocket, target_addr);
	if (!connect_res) {
		return;
	}

	auto ret = receiver.connect(connect_res.value());
	if (!ret) {
		print_error("Connect failed", ret);
		return;
	}

	return receive_file(receiver);
}

void execute_sender_pull_task(udp_socket& usocket, sft_server& sender,
							  const vector<string>& file_list,
							  bool                  use_random_port) {
	auto filefds_paths = get_filefd_list(file_list);
	if (filefds_paths.empty()) {
		std::cerr << "No valid files to send.\n";
		return;
	}

	while (true) {
		auto res = sft_common::wait_for_connection(usocket, sender,
												   use_random_port, 15);
		if (!res) {
			if (res.error() == WAIT_TIMEOUT) {
				continue;
			}
			print_error("Wait for connect failed", res);
			break;
		}
		send_file(sender, filefds_paths);
		break; // Exit after one successful receive in one-time mode
	}
}

int main(int argc, char* argv[]) {
#ifdef _WIN32
	// Set console code page to UTF-8 to properly display messages
	locale::global(locale("en_US.UTF-8"));
	WSADATA wsaData;
	if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
		print_error("WSAStartup failed");
		return -1;
	}
	ConfigureFirewall();
#else
	signal(SIGPIPE, SIG_IGN);
#endif
	if (sodium_init() == -1) {
		fmt::println(stderr, "Initialize sodium fail.");
		return 1;
	}

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

		SftMode mode = choose_working_mode(config.mode, config.use_random_port);

		if (mode == SftMode::Receive) {
			sft_server receiver;
			if (receiver.initialize(sec_path.string(), pub_path.string(),
									hosts_path.string())) {
				execute_receive_task(usocket, receiver, config.use_random_port);
			}
		}
		else if (mode == SftMode::TransferFiles ||
				 mode == SftMode::TransferFolders) { // Transfer
			sft_client sender;
			if (config.is_one_time && config.target_addr.empty()) {
				std::cerr
					<< "Transfer mode requires a target address in cli mode.\n";
				break;
			}
			if (sender.initialize(sec_path.string(), pub_path.string(),
								  hosts_path.string())) {
				auto files = sft_common::get_files_from_user(
					config.file_list, mode == SftMode::TransferFolders);
				if (!files.empty()) {
					execute_transfer_task(usocket, sender, files,
										  config.target_addr);
				}
			}
		}
		else if (mode == SftMode::ToggleRandomPort) {
			config.use_random_port = !config.use_random_port;
			std::cout << "\033c";
			continue;
		}
		else if (mode == SftMode::PullSend) {
			sft_server sender;
			if (sender.initialize(sec_path.string(), pub_path.string(),
								  hosts_path.string())) {
				auto files = sft_common::get_files_from_user(
					config.file_list, mode == SftMode::TransferFolders);
				if (!files.empty()) {
					execute_sender_pull_task(usocket, sender, files,
											 config.use_random_port);
				}
			}
		}
		else if (mode == SftMode::PullReceive) {
			sft_client receiver;
			if (config.is_one_time && config.target_addr.empty()) {
				std::cerr << "Pull receive mode requires a target address in "
							 "cli mode.\n";
				break;
			}
			if (receiver.initialize(sec_path.string(), pub_path.string(),
									hosts_path.string())) {
				execute_receiver_pull_task(usocket, receiver,
										   config.target_addr);
			}
		}

		if (config.is_one_time) {
			break;
		}
		config.mode = SftMode::Interactive; // Reset for next iteration in
											// interactive mode
		config.file_list.clear();
		config.target_addr = "";
	}

#ifdef _WIN32
	WSACleanup();
#endif
	return 0;
}
