#include <iostream>
#include <cstdio>
#include <cstring>
#include <vector>
#include <mutex>
#include <chrono>
#include <thread>
#include <fcntl.h>
#include <array>
#include <random>
#include <string>
#include <csignal>
#include <sys/types.h>
#ifdef __unix__
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/sendfile.h>
#include <unistd.h>
using optval_t = int;
#else
#define _SC_HOST_NAME_MAX 180
#define fcntl()
using optval_t = char;
#endif
#include "include/io.hpp"
#include "include/sftclass.hpp"
#define SERVER_PORT 7897
#define MAXARRSZ    1024'000'000
#define NUMSTOP     20'000
#define UNIXONLY #ifdef __unix__

using namespace std;

static sft_header sh;

struct socket_type {
		int         fd = -1;
		sockaddr_in addr;
		~socket_type() {
			close(fd);
		}
};

uint16_t generate_random_port() {
	std::random_device                      r;
	std::default_random_engine              e1(r());
	std::uniform_int_distribution<uint16_t> uniform_dist(9000, 65535);
	return uniform_dist(e1);
}

// Initialize given socket_type with broadcast option,
// returns 0 on success, -1 if fail.
int create_udp_socket(socket_type& local_udp_host) {
	int iRet = -1;
	optval_t opt = 1;

	local_udp_host.fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (local_udp_host.fd == -1) {
		perror("socket error!\n");
		return {};
	}

	memset(local_udp_host.addr.sin_zero, 0, sizeof(local_udp_host.addr));
	local_udp_host.addr.sin_family      = AF_INET;
	local_udp_host.addr.sin_port        = htons(SERVER_PORT);
	local_udp_host.addr.sin_addr.s_addr = INADDR_ANY;

	iRet = setsockopt(local_udp_host.fd, SOL_SOCKET, SO_BROADCAST | SO_REUSEADDR,
#ifdef __unix__
(const void*)
#endif // __unix__
		&opt, sizeof(opt));
	if (-1 == iRet) {
		perror("set sock option error!\n");
		close(local_udp_host.fd);
		return -1;
	}

	iRet = ::bind(local_udp_host.fd, (const struct sockaddr*)&local_udp_host.addr,
				sizeof(struct sockaddr));
	if (-1 == iRet) {
		perror("bind error!\n");
		close(local_udp_host.fd);
		return -1;
	}
	return 0;
}

// Initialize the given socket_type, returns 0 on success, -1 if fails.
int create_tcp_socket(socket_type& local_tcp_host,
					  bool         use_random_tcp_port = false) {
	int         tcp_fd = -1;
	char        flag   = 1;
	int         ret    = 0;
	sockaddr_in ip_port{};

	memset(&ip_port, 0, sizeof(sockaddr_in));
	tcp_fd                  = socket(PF_INET, SOCK_STREAM, IPPROTO_IP);
	ip_port.sin_family      = AF_INET;
	ip_port.sin_addr.s_addr = htonl(INADDR_ANY);
	ip_port.sin_port =
		htons(use_random_tcp_port ? generate_random_port() : 9007);

	if (tcp_fd <= 0) {
		perror("cannot create socket.\n");
		return -1;
	}
	setsockopt(tcp_fd, SOL_SOCKET, SO_REUSEADDR, &flag, sizeof(flag));
	ret = ::bind(tcp_fd, (sockaddr*)&ip_port, sizeof(sockaddr_in));
	if (ret < 0) {
		perror("cannot bind.\n");
		goto bad;
	}
	ret = listen(tcp_fd, 5);
	if (ret < 0) {
		perror("cannot listen.\n");
		goto bad;
	}
	local_tcp_host.fd   = tcp_fd;
	local_tcp_host.addr = ip_port;
	return 0;

bad:
	close(tcp_fd);
	return -1;
}

// Search for sft peers in local network,
// return the number of responding host on success, -1 if fails.
ssize_t search_for_sft_peers(const socket_type& local_host, int retry,
							 vector<sft_respond_struct>& all_hosts) {
	ssize_t            iRet = -1;
	socklen_t          len  = 0;
	char               host_name_str[_SC_HOST_NAME_MAX];
	char               recv_buf[64];
	string             respond;
	struct sockaddr_in target_udp_addr;
	struct sockaddr_in respond_addr;

	target_udp_addr.sin_family      = AF_INET;
	target_udp_addr.sin_port        = htons(SERVER_PORT);
	target_udp_addr.sin_addr.s_addr = INADDR_BROADCAST;
	memset(target_udp_addr.sin_zero, 0, 8);

	iRet = gethostname(host_name_str, _SC_HOST_NAME_MAX);
	if (iRet == -1) {
		perror("Fail to get host name.\n");
		return -1;
	}
	auto str = sh.form_discover_header(host_name_str, local_host.addr.sin_port);
	iRet     = sendto(local_host.fd, str.c_str(), str.size(), 0,
					  (const struct sockaddr*)&target_udp_addr,
					  sizeof(struct sockaddr));
	if (-1 == iRet) {
		perror("send error!\n");
		return -1;
	}

#ifdef __unix__
	int old_option = fcntl(local_host.fd, F_GETFL);
	fcntl(local_host.fd, F_SETFL, old_option | O_NONBLOCK);
#endif
	recvfrom(local_host.fd, recv_buf, sizeof(recv_buf), 0,
			 (struct sockaddr*)&respond_addr, &len);
	memset(recv_buf, 0, sizeof(recv_buf));

	cout << "Searching for local sft hosts.";
	cout.flush();
	while (retry--) {
		iRet = recvfrom(local_host.fd, recv_buf, sizeof(recv_buf), 0,
						(struct sockaddr*)&respond_addr, &len);
		if (iRet == -1) {
			if (errno != EAGAIN) {
				perror("recv failed!\n");
				fcntl(local_host.fd, F_SETFL, old_option);
				return -1;
			}
			cout << ".";
			cout.flush();
			std::this_thread::sleep_for(1s);
			continue;
		}
		auto res = mfcslib::str_split(string(recv_buf), "/");
		all_hosts.emplace_back(res[SFT_RES_HOST], respond_addr,
							   in_port_t(stoi(res[SFT_RES_PORT])));
	}
	cout << "\n";
	fcntl(local_host.fd, F_SETFL, old_option);
	return all_hosts.size();
}

bool choose_working_mode() {
	bool choice = false;

	// cout << "\033c";
	cout << format("\033[1msft_host version {}, built in: {} {}\033[0m\n", 0.1,
				   __DATE__, __TIME__);
	cout << "\nChoose a mode for program to work:\n0. Receive.       1. "
			"Transfer.\n";
	cout << "Enter your choice: ";
	cin >> choice;
	return choice;
}

// Connect to target sft peer.
// Returns 0 on success, -1 if fails.
int connect_to_peer(vector<sft_respond_struct>& all_hosts, socket_type& tcp) {
	unsigned                     count        = 1;
	sockaddr_in*                 respond_addr = nullptr;
	int                          tcp_fd       = -1;
	int                          ret          = -1;
#ifdef __unix__
	array<char, INET_ADDRSTRLEN> ipaddr;
#endif // __unix__
	for (const auto& i : all_hosts) {
		cout << "All active sft hosts:\n";
#ifdef __unix__
		auto res = inet_ntop(AF_INET, &i.peer_addr.sin_addr, ipaddr.data(), INET_ADDRSTRLEN);
#else
		auto res = inet_ntoa(i.peer_addr.sin_addr);
#endif // __unix__
		cout << format("{}. Host: {} IP: {} Port: {}", count++, i.peer_name, res, ntohs(i.peer_port))
			 << endl;
#ifdef __unix__
		ipaddr.fill(0);
#endif // __unix__
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
			cout << "Invalid choice!" << endl;
		}
	}

	respond_addr = &all_hosts[count].peer_addr;
	tcp_fd       = socket(AF_INET, SOCK_STREAM, 0);
	if (-1 == tcp_fd) {
		perror("cannot create socket!\n");
		return -1;
	}
	respond_addr->sin_port = all_hosts[count].peer_port;
	ret =
		connect(tcp_fd, (const sockaddr*)respond_addr, sizeof(struct sockaddr));
	if (-1 == ret) {
		perror("connect error!\n");
		close(tcp_fd);
		return -1;
	}
	cout << "Connect success! ";
	tcp.fd   = tcp_fd;
	tcp.addr = *respond_addr;
	return 0;
}

expected<mfcslib::tcp_socket, int>
wait_for_peers_to_connect(const socket_type& local_udp_host,
						  socket_type&       local_tcp_host) {
	char               recv_buf[128];
	struct sockaddr_in responded_addr;
	socklen_t          len = sizeof(responded_addr);
	char               host[_SC_HOST_NAME_MAX + 1];
#ifdef __unix__
	char               ip_str[INET_ADDRSTRLEN];
#endif // __unix__
	ssize_t            iRet = 0;
	size_t             idx  = 0;
	string             str, msg;

	memset(&responded_addr, 0, sizeof(responded_addr));
	cout << format("Listening on tcp port:{}. Waiting for clients...",
				   ntohs(local_tcp_host.addr.sin_port))
		 << endl;
	if (recvfrom(local_udp_host.fd, recv_buf, sizeof(recv_buf), 0,
				 (struct sockaddr*)&responded_addr, &len) == -1) {
		perror("recv failed!\n");
	}
#ifdef __unix__
	if (inet_ntop(AF_INET, &responded_addr.sin_addr, ip_str, INET_ADDRSTRLEN) == nullptr) {
		perror("trans fail!\n");
		goto bad;
	}
#endif // __unix__
	// cout << format("Receive msg: {}\nFrom: {}", recv_buf, ip_str) << endl;

	iRet = gethostname(host, _SC_HOST_NAME_MAX);
	if (iRet == -1) {
		perror("gethostname fail.\n");
		goto bad;
	}
	str = sh.form_respond_header(host, local_tcp_host.addr.sin_port);
	msg = recv_buf;
	idx = msg.find_last_of('/') + 1;
	responded_addr.sin_port =
		static_cast<in_port_t>(stoi(msg.substr(idx, msg.size() - idx)));
	iRet = sendto(local_udp_host.fd, str.c_str(), str.size(), 0,
				  (const struct sockaddr*)&responded_addr,
				  sizeof(struct sockaddr));
	if (-1 == iRet) {
		perror("send error!\n");
		goto bad;
	}

	iRet = accept(local_tcp_host.fd, (struct sockaddr*)&responded_addr, &len);
	if (-1 == iRet) {
		perror("accept error!\n");
		goto bad;
	}
	cout << "TCP connection established! Receiving files..." << endl;
	return mfcslib::tcp_socket(iRet, responded_addr);

bad:
	return tl::unexpected(errno);
}

void send_file(mfcslib::tcp_socket& target, mfcslib::File& file) {
	off_t     off       = 0;
	uintmax_t have_send = 0;
	char      code      = 0;
	auto      file_sz   = file.size();
	int       ret       = -1;
	string    request;

	request = sh.form_file_header(file.filename(), file_sz);
	target.write(request);
	while (ret == -1) {
		ret = target.read(&code);
	}
	if (code != '1') {
		string error_msg =
			"Error while receving code from peer in send_file:\n";
		error_msg += strerror(errno);
		throw runtime_error(error_msg);
	}
	target.set_nonblocking();
	cout << "Sending file: " << file.filename() << endl;
	while (have_send < file_sz) {
		auto ret = sendfile(target.get_fd(), file.get_fd(), &off, file_sz);
		if (ret < 0) {
			if (errno != EAGAIN) {
				perror("Sendfile failed");
				break;
			}
			continue;
		}
		have_send += ret;
#ifdef DEBUG
		cout << "have send :" << ret << endl;
#endif // DEBUG
		mfcslib::progress_bar(have_send, file_sz);
	}
	cout << '\n';
}

void receive_file(mfcslib::tcp_socket& target) {
	std::array<char, 128> request;
	size_t                sizeOfFile = 0;

	request.fill(0);
	target.read(request.data(), 128);
	// cout << "Received request:" << request.data() << endl;
	vector<string> res = mfcslib::str_split(string(request.data()), "/");
	target.write('1');
	sizeOfFile = stoull(res[SFT_FIL_SIZE].data());
	cout << format("Receiving file: {}\tSize: {}\n", res[SFT_FIL_NAME],
				   sizeOfFile);

	mfcslib::File file_output_stream(res[SFT_FIL_NAME].c_str());
	file_output_stream.open(true, mfcslib::WRONLY);
	if (sizeOfFile < MAXARRSZ) {
		auto    bufferForFile = mfcslib::make_array<Byte>(sizeOfFile);
		ssize_t ret           = 0;
		auto    bytesLeft     = sizeOfFile;
		while (true) {
			ret += target.read(bufferForFile, ret, bytesLeft);
			bytesLeft = sizeOfFile - ret;
			mfcslib::progress_bar(ret, sizeOfFile);
			if (ret <= 0 || bytesLeft <= 0)
				break;
		}
		file_output_stream.write(bufferForFile);
	}
	else {
		auto bufferForFile = mfcslib::make_array<Byte>(MAXARRSZ);
		auto ret           = 0ull;
		auto bytesWritten  = ret;
		while (true) {
			ssize_t currentReturn = 0;
			while (ret < (MAXARRSZ - NUMSTOP)) {
				currentReturn = target.read(bufferForFile, ret, MAXARRSZ - ret);
				if (currentReturn <= 0) {
					break;
				}
				ret += currentReturn;
				if (ret + bytesWritten >= sizeOfFile)
					break;
			}
			if (currentReturn <= 0)
				break;
			file_output_stream.write(bufferForFile, 0, ret);
			bytesWritten += ret;
			mfcslib::progress_bar(bytesWritten, sizeOfFile);
			if (bytesWritten >= sizeOfFile)
				break;
			bufferForFile.empty_array();
			ret = 0;
		}
	}
	cout << '\n';
}

// Connect to peer manually.
// Returns 0 on success, -1 if fails.
int manual_connect_to_peer(socket_type& tcp) {
	string      ip;
	uint16_t    port = 0;
	sockaddr_in respond_addr{};
	int         tcp_fd = -1;
	int         ret    = -1;

	while (true) {
		cout << "Please input target ip: ";
		cin >> ip;
		cout << "Please input target port: ";
		cin >> port;

		memset(&respond_addr, 0, sizeof(respond_addr));
		respond_addr.sin_family      = AF_INET;
		respond_addr.sin_addr.s_addr = inet_addr(ip.c_str());
		respond_addr.sin_port        = htons(port);
		if (respond_addr.sin_addr.s_addr == INADDR_NONE) {
			cout << "Invalid ip address, please try again" << endl;
		}
		else {
			break;
		}
	}

	tcp_fd = socket(AF_INET, SOCK_STREAM, 0);
	if (-1 == tcp_fd) {
		perror("cannot create socket");
		return -1;
	}
	ret = connect(tcp_fd, reinterpret_cast<const sockaddr*>(&respond_addr),
				  sizeof(struct sockaddr));
	if (-1 == ret) {
		perror("connect error");
		cout << "Press any key to retry.";
		cin.ignore();
		cin.get();
		close(tcp_fd);
		return -1;
	}
	cout << "Connect success!" << endl;
	tcp.fd   = tcp_fd;
	tcp.addr = respond_addr;
	return 0;
}

// TODO
int configure_options() {
	bool use_random_tcp_port = false;
	int  max_retry           = 5;
	return 0;
}

int main() {
	socket_type                usocket{};
	vector<sft_respond_struct> all_hosts;
	string                     file_name;
	bool                       continue_current_mode = false;

	std::ios::sync_with_stdio(false);
	create_udp_socket(usocket);
	signal(SIGPIPE, SIG_IGN);
	// TODO: continue to send and to receive
	while (true) {
		if (choose_working_mode()) { // Transfer mode
			mfcslib::File       file_fd;
			mfcslib::tcp_socket tfd;
			char                choice = 0;
			socket_type         tsocket{};

			while (true) {
				try {
					cout << "Please input the path of file: ";
					cin >> file_name;
					file_fd = file_name;
					file_fd.open_read_only();
					break;
				} catch (const std::exception& e) {
					std::cerr << e.what() << '\n';
				}
				std::cerr << "Error occurs, please try again." << endl;
			}

		again:
			all_hosts.erase(all_hosts.begin(), all_hosts.end());
			if (search_for_sft_peers(usocket, 2, all_hosts) <= 0) {
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
			try {
				tfd = mfcslib::tcp_socket(tsocket.fd, tsocket.addr);
			round:
				send_file(tfd, file_fd);
				cout << "Continue to transfer: 0.no\t1.yes ";
				cin >> continue_current_mode;
				if (continue_current_mode) {
					file_fd.close();
					while (true) {
						try {
							cout << "Please input the path of file: ";
							cin >> file_name;
							file_fd = file_name;
							file_fd.open_read_only();
							break;
						} catch (const std::exception& e) {
							std::cerr << e.what() << '\n';
						}
						std::cerr << "Error occurs, please try again." << endl;
					}
					goto round;
				}
			} catch (const mfcslib::basic_exception& e) {
				cerr << "Exception: " << e.what() << endl;
			}
		}
		else { // Receive mode
			mfcslib::tcp_socket tfd;
			socket_type         tsocket{};

			create_tcp_socket(tsocket);
			auto return_value = wait_for_peers_to_connect(usocket, tsocket);
			if (!return_value) {
				cerr << "Cannot connect to peers because: "
					 << strerror(return_value.error()) << endl;
			}

			tfd = std::move(return_value.value());
			try {
			receive:
				receive_file(tfd);
				cout << "Continue to receive: 0.no\t1.yes ";
				cin >> continue_current_mode;
				if (continue_current_mode) {
					cout << "Pending requests..." << endl;
					goto receive;
				}
			} catch (const mfcslib::basic_exception& e) {
				cerr << "Exception: " << e.what() << endl;
			}
		}
	}
}