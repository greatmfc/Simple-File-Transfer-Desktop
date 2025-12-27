#include "main.h"
#include <sodium.h>
#include <cstring>
#ifdef __unix__
#include <termios.h>
#include <csignal>
#define WAIT_TIMEOUT ETIMEDOUT
#else
#include <WinSock2.h>
#include <fileapi.h>
#endif

using namespace std;
using namespace mfcslib;

#ifdef _WIN32
struct NameIP {
		std::string name;
		std::string ip;
};
extern std::expected<std::vector<std::wstring>, std::wstring>
						   OpenFileOrFolderDialog(bool openFolder = false);
extern bool                ConfigureFirewall();
extern std::vector<NameIP> GetIPv4BroadcastAddresses();
extern std::wstring        convert_string_to_wstring(const char* str);
#endif // _WIN32
extern string info;
extern bool   enable_encryption;

void          print_help() {
    // clang-format off
    std::println(
		"Usage: simple-file-transfer [OPTION] [FILE](optional)...\n"
		"Examples: \n"
		"  simple-file-transfer                      # Enable interactive mode.\n"
		"  simple-file-transfer -h                   # Print this message.\n"
		"  simple-file-transfer -r                   # Enable receive mode to constantly receive files.\n"
		"  simple-file-transfer -t file1 directory1/ # Enable one-time transfer mode to send files."
    );
    // clang-format on
}

#ifdef _WIN32
int wmain(int argc, wchar_t* argv[]) {
#else
int main(int argc, char* argv[]) {
#endif
	int                 mode = 0, specified_mode = -1;
	const char*         buf = nullptr;
	vector<string_type> g_file_list;

	locale::global(locale("en_US.UTF-8"));
	if (sodium_init() == -1) {
		std::println(stderr, "Initialize sodium fail.");
		return 1;
	}
	if (argc > 1) {
		string_type::value_type r_str[] = {'-', 'r', 0};
		string_type::value_type t_str[] = {'-', 't', 0};
		if (string_type(argv[1]) == r_str) {
			specified_mode = 0;
		}
		else if (string_type(argv[1]) == t_str) {
			specified_mode = 1;
			for (int i = 2; i < argc; ++i) {
				g_file_list.emplace_back(argv[i]);
			}
		}
		else {
#ifdef _WIN32
			specified_mode = 1;
			for (int i = 1; i < argc; ++i) {
				g_file_list.emplace_back(argv[i]);
			}
#else
			print_help();
			return 0;
#endif
		}
	}
#ifdef __unix__
	signal(SIGPIPE, SIG_IGN);
#else
	WSADATA wsaData;
	if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
		printf("WSAStartup failed: %d\n", WSAGetLastError());
		return -1;
	}
	ConfigureFirewall();
	cout << info << endl;
	auto res = GetIPv4BroadcastAddresses();
	int  idx = 0;
	cout << "All available networks are listed below." << endl;
	for (const auto& value : res) {
		cout << format("{}: Adapter: {}. IP: {}", idx++, value.name, value.ip)
			 << endl;
	}
	cout << "\nPlease choose a network to discover other sft hosts: ";
	cin >> idx;
	idx %= res.size();
	buf = res[idx].ip.c_str();
	cout << "\033c";
#endif
	std::ios::sync_with_stdio(false);
	while (true) {
		socket_type                usocket{};
		vector<sft_respond_struct> all_hosts;

		create_udp_socket(usocket, buf);
	start:
		mode = choose_working_mode(specified_mode);
		if (mode == 3) {
			enable_encryption = !enable_encryption;
			cout << "\033c";
			goto start;
		}
		if (mode) { // Transfer mode
			vector<tuple<File, string>> filefds_paths;
			vector<string>              folder_paths;
			tcp_socket                  tfd;
			char                        choice = 0;
			socket_type                 tsocket{};
			string                      file_name;
			vector<string_type>         file_list;

			if (specified_mode != -1 && !g_file_list.empty()) {
				cout << "Reading file list from program arguments: \n";
				file_list = std::move(g_file_list);
				for (const auto& f : file_list) {
#ifdef _WIN32
					std::wcout << f << '\n';
#else
					std::cout << f << '\n';
#endif
				}
				cout << endl;
			}
			else {
			choose:
#ifdef _WIN32
				auto retVal = OpenFileOrFolderDialog(mode == 2);
				if (retVal.has_value()) {
					file_list = std::move(retVal.value());
				}
				else {
					cerr << "Didn't choose any file." << endl;
					goto start;
				}
#else
				cout << "Please input the path of files or folders"
						", separated by spaces: ";
				while (cin >> file_name) {
					if (file_name.back() == '/') {
						file_name.pop_back();
					}
					file_list.emplace_back(file_name);
					if (cin.peek() == '\n') {
						break;
					}
				}
#endif
			}
			filefds_paths = get_filefd_list(file_list);
			if (filefds_paths.empty()) {
				std::cerr << "Please try again." << endl;
				file_list.clear();
				goto choose;
			}
		again:
			if (search_for_sft_peers(usocket, 3, all_hosts) <= 0) {
				cout << "Didn't find any sft hosts." << endl;
				cout << "Choose next step:\n0. Search again.\t"
						"1. Input ip and port manually.\t"
						"2. Choose another mode.";
				cin >> choice;
				choice %= 3;
				if (choice == 0) {
					goto again;
				}
				else if (choice == 1) {
					if (manual_connect_to_peer(tsocket) == 0) {
						goto send;
					}
				}
				continue;
			}
			if (connect_to_peer(all_hosts, tsocket) == -1) {
				goto again;
				// continue;
			}
		send:
			tfd = tcp_socket(tsocket.fd, tsocket.addr);
			if (enable_encryption) {
				send_file_s(tfd, filefds_paths);
			}
			else {
				send_file(tfd, filefds_paths);
			}
			cout << "Waiting for client to complete.\n";
			if (tfd.read_byte() == '0') {
				cout << "All files have been received by the other side.\n";
			}
			else {
				cout << "Something unexpected happened. Please check the other "
						"side "
						"for file integrity.\n";
			}
			argc = 1;
			// specified_mode = -1;
		}
		else { // Receive mode
			tcp_socket  tfd;
			socket_type tsocket{};

			create_tcp_socket(tsocket, true);
		try_again:
			auto return_value = wait_for_peers_to_connect(usocket, tsocket);
			if (!return_value) {
				if (return_value.error() == WAIT_TIMEOUT) {
					goto try_again;
				}
				continue;
			}

			tfd = std::move(return_value.value());
			if (enable_encryption) {
				receive_file_s(tfd);
			}
			else {
				receive_file(tfd);
			}
			tfd.write_byte('0');
		}
	}
#ifdef _WIN32
	WSACleanup();
	system("pause");
#endif
	return 0;
}