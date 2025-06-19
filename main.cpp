#include "include/main.h"
#ifdef __unix__
#include <csignal>
#define WAIT_TIMEOUT ETIMEDOUT
#endif

using namespace std;
using namespace mfcslib;

extern std::expected<std::vector<std::wstring>, std::wstring>
			OpenFileOrFolderDialog(bool openFolder = false);
extern bool ConfigureFirewall();

int         main() {
    socket_type                usocket{};
    vector<sft_respond_struct> all_hosts;
    int                        mode = 0;

    locale::global(locale("en_US.UTF-8"));
#ifdef __unix__
	signal(SIGPIPE, SIG_IGN);
#else
	WSADATA wsaData;
	if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
		printf("WSAStartup failed: %d\n", WSAGetLastError());
		return -1;
	}
	ConfigureFirewall();
#endif
	std::ios::sync_with_stdio(false);
	create_udp_socket(usocket);
	while (true) {
	start:
		mode = choose_working_mode();
		if (mode) { // Transfer mode
			vector<tuple<File, string>> filefds_paths;
			vector<string>              folder_paths;
			tcp_socket                  tfd;
			char                        choice = 0;
			socket_type                 tsocket{};
			string                      file_name;

		choose:
#ifdef __unix__
			vector<string_type> file_list;
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
			filefds_paths = get_filefd_list(file_list);
			if (filefds_paths.empty()) {
				std::cerr << "Please try again." << endl;
				goto choose;
			}
#else
			auto retVal = OpenFileOrFolderDialog(mode == 2);
			if (retVal.has_value()) {
				filefds_paths = get_filefd_list(retVal.value());
				if (filefds_paths.empty()) {
					std::cerr << "Please try again." << endl;
					goto choose;
				}
			}
			else {
				cerr << "Didn't choose any file." << endl;
				goto start;
			}
#endif
		again:
			all_hosts.erase(all_hosts.begin(), all_hosts.end());
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
				continue;
			}
		send:
			tfd = tcp_socket(tsocket.fd, tsocket.addr);
			send_file(tfd, filefds_paths);
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
				// cout << "Cannot connect to peers." << endl;
				continue;
			}

			tfd = std::move(return_value.value());
			receive_file(tfd);
		}
	}
#ifdef _WIN32
	WSACleanup();
	system("pause");
#endif
	return 0;
}