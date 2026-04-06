#include "main.h"
#include "sftclass.hpp"

#include <cstring>
#include <vector>
#include <array>
#include <string>
#include <sys/types.h>
#include <thread>
#ifdef _WIN32
#include <WinSock2.h>
#include <WS2tcpip.h>
#include <corecrt_io.h>
#ifdef min
#undef min
#endif
#define _SC_HOST_NAME_MAX 180
#undef errno
#define errno GetLastError()
#pragma comment(lib, "mswsock.lib")
extern std::wstring convert_string_to_wstring(const char* str);
extern std::string  convert_wstring_to_string(const wchar_t* wstr);
#else
#include <cassert>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/sendfile.h>
#include <sys/select.h>
#include <unistd.h>
#include <fcntl.h>
#include <cstdio>
#define WAIT_TIMEOUT                    ETIMEDOUT
#define SetLastError(n)                 errno = n
#define GetLastError()                  errno
#define convert_string_to_wstring(str)  str
#define convert_wstring_to_string(wstr) wstr
using optval_t = int;
#endif

using namespace std;
using namespace kotcpp;

static sft_header sh;
#ifdef DEBUG
string info = format("\033[1mSimple File Transfer Desktop version {0:.1f}, "
					 "built in: {1} {2}. Developed by greatmfc. DEBUG\033[0m",
					 VERSION, __DATE__, __TIME__);
#else
string info = format("\033[1mSimple File Transfer Desktop version {0:.1f}, "
					 "built in: {1} {2}. Developed by greatmfc.\033[0m",
					 VERSION, __DATE__, __TIME__);
#endif // DEBUG

// Search for sft peers in local network,
// return the number of responding host on success, -1 if fails.
ResType search_for_sft_peers(const udp_socket& local_host, int retry,
							 vector<sft_respond_struct>& all_hosts) {
	RetType     iRet = -1;
	socklen_t   len  = sizeof(sockaddr_in);
	char        host_name_str[_SC_HOST_NAME_MAX];
	char        recv_buf[64];
	string      respond;
	sockaddr_in target_udp_addr;
	sockaddr_in respond_addr;

	target_udp_addr.sin_family      = AF_INET;
	target_udp_addr.sin_port        = htons(UDP_PORT);
	target_udp_addr.sin_addr.s_addr = INADDR_BROADCAST;
	memset(target_udp_addr.sin_zero, 0, 8);

	iRet = gethostname(host_name_str, _SC_HOST_NAME_MAX);
	if (iRet == -1) {
		return tl::unexpected(GetLastError());
	}
	auto str =
		sh.form_discover_header(host_name_str, htons(local_host.get_port()));
	// local_host.sendto(target_udp_addr, str);
	auto ret = local_host.send_broadcast_message(UDP_PORT, str);
	if (!ret) {
		return ret;
	}
	local_host.set_nonblocking();

	recvfrom(local_host.get_fd(), recv_buf, sizeof(recv_buf), 0,
			 (struct sockaddr*)&respond_addr, &len);
	memset(recv_buf, 0, sizeof(recv_buf));

	cout << "Searching for local sft hosts.";
	cout.flush();
	while (retry--) {
		iRet = recvfrom(local_host.get_fd(), recv_buf, sizeof(recv_buf) - 1, 0,
						(struct sockaddr*)&respond_addr, &len);
		if (iRet == -1) {
			if (errno != WSAEWOULDBLOCK) {
				local_host.set_blocking();
				return tl::unexpected(GetLastError());
			}
			cout << ".";
			cout.flush();
			std::this_thread::sleep_for(1s);
			continue;
		}
		auto      res      = str_split(recv_buf, "/");
		in_port_t port_num = 0;
		from_chars(res[SFT_RES_PORT].data(),
				   res[SFT_RES_PORT].data() + res[SFT_RES_PORT].size(),
				   port_num);
		all_hosts.emplace_back(string(res[SFT_RES_HOST]), respond_addr,
							   port_num);
	}
	cout << "\n";
	local_host.set_blocking();
	return all_hosts.size();
}

SftMode choose_working_mode(SftMode specified_mode, bool use_random_port) {
	int choice = 0;

	// cout << "\033c";
	cout << info << endl;
	if (specified_mode != SftMode::Interactive) {
		return specified_mode;
	}
	cout << "\nChoose a mode for program to work:\n"
			"0. Receive.\t"
			"1. Transfer files.\t"
			"2. Transfer folders.\t";
	cout << (use_random_port ? "3. Disable random receive port.\t"
							 : "3. Enable random receive port.\t");
	cout << "4. Pull send mode.\t"
			"5. Pull receive mode.\n";
	cout << "Enter your choice: ";
	cin >> choice;

	// 映射整数值到SftMode枚举
	switch (choice) {
	case 0:
		return SftMode::Receive;
	case 1:
		return SftMode::TransferFiles;
	case 2:
		return SftMode::TransferFolders;
	case 3:
		return SftMode::ToggleRandomPort;
	case 4:
		return SftMode::PullSend;
	case 5:
		return SftMode::PullReceive;
	default:
		return SftMode::Interactive; // 无效选择
	}
}

// Connect to target sft peer.
// Returns 0 on success, -1 if fails.
Result<sockaddr_in> connect_to_peer(vector<sft_respond_struct>& all_hosts) {
	unsigned                     count        = 1;
	sockaddr_in                  respond_addr = {};
	array<char, INET_ADDRSTRLEN> ipaddr;

	cout << "All active sft hosts:\n";
	for (const auto& i : all_hosts) {
		auto res = inet_ntop(AF_INET, &i.peer_addr.sin_addr, ipaddr.data(),
							 INET_ADDRSTRLEN);
		cout << format("{}. Host: {} IP: {} Port: {}", count++, i.peer_name,
					   res, ntohs(i.peer_port))
			 << endl;
		ipaddr.fill(0);
	}
	while (true) {
		cout << "Enter your choice: ";
		cin >> count;
		if (count <= all_hosts.size()) {
			cout << format("Your choice is: {}\n",
						   all_hosts[--count].peer_name);
			break;
		}
		else {
			cout << "Invalid choice! Please retry." << endl;
			return tl::unexpected("Invalid choice");
		}
	}

	memset(&respond_addr, 0, sizeof(respond_addr));
	respond_addr          = all_hosts[count].peer_addr;
	respond_addr.sin_port = all_hosts[count].peer_port;
	return respond_addr;
}

ResType wait_for_peers_to_connect(const udp_socket& local_udp_host,
								  sft_server& receiver, int retry,
								  bool use_random_port) {
	array<char, 128>   recv_buf;
	struct sockaddr_in responded_addr;
	socklen_t          len = sizeof(responded_addr);
	char               host[_SC_HOST_NAME_MAX + 1];
	char               ip_str[INET_ADDRSTRLEN];
	RetType            iRet = 0;
	size_t             idx  = 0;
	string             str, msg;
	tcp_socket         listener;

	auto               res =
		listener.listen(use_random_port ? generate_random_port() : TCP_PORT);
	if (!res) {
		return res;
	}
	SOCKET udpfd = local_udp_host.get_fd(), tcpfd = listener.get_fd();
	fd_set rfds;

	memset(&responded_addr, 0, sizeof(responded_addr));
	cout << format("Listening on tcp port:{}. Waiting for clients...",
				   listener.get_port())
		 << endl;

	FD_ZERO(&rfds);
	FD_SET(udpfd, &rfds);
	FD_SET(tcpfd, &rfds);
	iRet = select(max(udpfd, tcpfd) + 1, &rfds, nullptr, nullptr, nullptr);
#ifdef __unix__
	assert(iRet < 1024);
#endif
	[[unlikely]] if (iRet == SOCKET_ERROR) {
		print_error("select failed");
		goto bad;
	}
	[[unlikely]] if (FD_ISSET(tcpfd, &rfds)) { goto Accept; }

	recv_buf.fill(0);
	iRet = recvfrom(udpfd, recv_buf.data(), sizeof(recv_buf) - 1, 0,
					(sockaddr*)&responded_addr, &len);
	if (iRet == -1) {
		print_error("recvfrom fail");
		goto bad;
	}
	[[unlikely]] if (inet_ntop(AF_INET, &responded_addr.sin_addr, ip_str,
							   INET_ADDRSTRLEN) == nullptr) {
		print_error("trans fail!");
		goto bad;
	}
#ifdef DEBUG
	cout << format("Receive msg: {}\nFrom: {}", recv_buf.data(), ip_str)
		 << endl;
#endif // DEBUG
	iRet = gethostname(host, _SC_HOST_NAME_MAX);
	[[unlikely]] if (iRet == -1) {
		print_error("gethostname fail");
		goto bad;
	}
	str = sh.form_respond_header(host, htons(listener.get_port()));
	msg = recv_buf.data();
	idx = msg.find_last_of('/') + 1;
	responded_addr.sin_port =
		static_cast<in_port_t>(stoi(msg.substr(idx, msg.size() - idx)));
	iRet = sendto(udpfd, str.c_str(), str.size(), 0,
				  (const sockaddr*)&responded_addr, sizeof(sockaddr));
	if (-1 == iRet) {
		print_error("send error");
		goto bad;
	}

Accept:
	listener.set_nonblocking();
	while (retry--) {
		auto ret = receiver.listen_and_accept(listener);
		if (!ret) {
			if (ret.error() != WSAEWOULDBLOCK) {
				print_error("accept error", ret);
				goto bad;
			}
			std::this_thread::sleep_for(1s);
			continue;
		}
		cout << "TCP connection established! Receiving files..." << endl;
		return ret;
	}
	cerr << "Accept timeout, please try again." << endl;
	listener.set_blocking();
	SetLastError(WAIT_TIMEOUT);
bad:
	return tl::unexpected(GetLastError());
}

// Connect to peer manually.
// Returns 0 on success, -1 if fails.
Result<sockaddr_in> manual_connect_to_peer() {
	string      ip;
	uint16_t    port = 0;
	sockaddr_in respond_addr{};

	while (true) {
		cout << "Please input target ip: ";
		cin >> ip;
		cout << "Please input target port: ";
		cin >> port;

		memset(&respond_addr, 0, sizeof(respond_addr));
		respond_addr.sin_family = AF_INET;
		inet_pton(AF_INET, ip.c_str(), &respond_addr.sin_addr);
		respond_addr.sin_port = htons(port);
		if (respond_addr.sin_addr.s_addr == INADDR_NONE) {
			cout << "Invalid ip address, please try again" << endl;
		}
		else {
			break;
		}
	}
	return respond_addr;
}

// TODO
int configure_options() {
	[[maybe_unused]] bool use_random_tcp_port = false;
	[[maybe_unused]] int  max_retry           = 5;
	return 0;
}

vector<tuple<unique_ptr<File>, string>>
get_filefd_list(const vector<string>& path_list) {
	vector<tuple<unique_ptr<File>, string>> result;
	for (const auto& path : path_list) {
		if (fs::is_directory(path)) {
			// Get folder name using std::filesystem
			string folderName = path;
			if (folderName.back() == '/' || folderName.back() == '\\') {
				folderName.pop_back();
			}
			folderName = fs::path(folderName).filename().string();
			folderName += '\\';

			result.emplace_back(nullptr, folderName);
			for (const auto& entry : fs::recursive_directory_iterator(path)) {
				if (entry.is_regular_file()) {
					auto f = make_unique<File>(entry.path());
					if (auto open_res = f->open_read_only(); open_res) {
						std::string relative =
							fs::relative(entry.path(), path).string();
#ifdef __unix__
						for (auto& c : relative) {
							if (c == '/') {
								c = '\\';
							}
						}
#endif // __unix__
						result.emplace_back(std::move(f),
											folderName + relative);
					}
					else {
						print_error(format("Cannot open file: {}",
										   entry.path().string()),
									open_res);
						continue;
					}
				}
				else if (entry.is_directory()) {
					std::string relative =
						fs::relative(entry.path(), path).string();
#ifdef __unix__
					for (auto& c : relative) {
						if (c == '/') {
							c = '\\';
						}
					}
#endif // __unix__
					result.emplace_back(nullptr, folderName + relative + '\\');
				}
				else {
					cerr << format(
						"The target file: {} is neither regular file "
						"nor a directory. Ignored.\n",
						path);
				}
			}
		}
		else if (fs::is_regular_file(path)) {
			auto f = make_unique<File>(path);
			if (f->open_read_only()) {
				// Get file name using std::filesystem
				string fileName = fs::path(path).filename().string();
				result.emplace_back(std::move(f), fileName);
			}
			else {
				print_error(format("Cannot open file: {}", f->filename()));
			}
		}
		else {
			cerr << format("The target file: {} is neither a regular file "
						   "nor a directory. Ignored.\n",
						   path);
		}
	}
	return result;
}
