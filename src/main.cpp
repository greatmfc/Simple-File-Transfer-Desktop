#include "main.h"
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
#endif // _WIN32
extern string info;
extern bool   enable_encryption;

std::string getHiddenInput(const char* prompt = "Enter password: ") {
#ifdef _WIN32
    HANDLE hStdin = GetStdHandle(STD_INPUT_HANDLE);
    DWORD mode;
    GetConsoleMode(hStdin, &mode);
    SetConsoleMode(hStdin, mode & (~ENABLE_ECHO_INPUT));
#else
    termios oldt;
    tcgetattr(STDIN_FILENO, &oldt);
    termios newt = oldt;
    newt.c_lflag &= ~ECHO;
    tcsetattr(STDIN_FILENO, TCSANOW, &newt);
#endif
    std::cout << prompt;
    std::string input;
    std::getline(std::cin, input);
    std::cout << std::endl;

#ifdef _WIN32
    SetConsoleMode(hStdin, mode);
#else
    tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
#endif

    return input;
}

int           main(int argc, char* argv[]) {
    int         mode = 0;
    const char* buf  = nullptr;
	std::unique_ptr<SecureContainer<char>> password = nullptr;

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
		mode = choose_working_mode();
		if (mode == 3) {
			enable_encryption = !enable_encryption;
			if (enable_encryption && password == nullptr) {
				if (cin.peek() == '\n') {
					cin.get();
				}
				auto pass = getHiddenInput();
				password = std::make_unique<SecureContainer<char>>(pass);
				secure_zero_memory(pass.data(), pass.size());
			}
			cout << "\033c";
			goto start;
		}
		else if (mode == 4) {
			password          = nullptr;
			enable_encryption = false;
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

#ifdef __unix__
			vector<string_type> file_list;
			if (argc > 1) {
				cout << "Reading file list from program arguments:";
				for (int i = 1; i < argc; ++i) {
					file_list.emplace_back(argv[i]);
					cout << ' ' << file_list.back();
				}
				cout << endl;
			}
			else {
			choose:
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
			}
			filefds_paths = get_filefd_list(file_list);
			if (filefds_paths.empty()) {
				std::cerr << "Please try again." << endl;
				file_list.clear();
				goto choose;
			}
#else
			choose:
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
			if (enable_encryption) {
				send_file_s(tfd, filefds_paths, password.get());
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
				receive_file_s(tfd, password.get());
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