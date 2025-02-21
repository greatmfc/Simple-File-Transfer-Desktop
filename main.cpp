#include <cstring>
#include <vector>
#include <chrono>
#include <thread>
#include <array>
#include <random>
#include <string>
#include <sys/types.h>
#include <future>
#include "include/io.hpp"
#include "include/sftclass.hpp"
#ifdef __unix__
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/sendfile.h>
#include <sys/select.h>
#include <unistd.h>
#include <fcntl.h>
#include <csignal>
#include <cstdio>
#define WSAEWOULDBLOCK                  EAGAIN
#define WAIT_TIMEOUT                    ETIMEDOUT
#define SetLastError(n)                 errno = n
#define GetLastError()                  errno
#define convert_string_to_wstring(str)  str
#define convert_wstring_to_string(wstr) wstr
#define min(a, b)                       (((a) < (b)) ? (a) : (b))
#define max(a,b)            (((a) > (b)) ? (a) : (b))
using optval_t = int;
#else
#include <MSWSock.h>
#define _SC_HOST_NAME_MAX 180
#undef errno
#define errno GetLastError()
#pragma comment(lib, "mswsock.lib")
extern std::wstring OpenFileDialog();
extern bool         ConfigureFirewall();
extern std::wstring convert_string_to_wstring(const char* str);
extern std::string  convert_wstring_to_string(const wchar_t* wstr);
struct NameIP {
		std::string name;
		std::string ip;
};
extern std::vector<NameIP> GetIPv4BroadcastAddresses();
#endif
#define SERVER_PORT 7897
#define MAXARRSZ    2048'000'000ull
#define VERSION     1.1f
constexpr size_t bufSize = MAXARRSZ / 2;
string info = format(
	"\033[1msft_host version {0:.1f}, built in: {1} {2}. Developed by greatmfc.\033[0m",
	VERSION, __DATE__, __TIME__);

using namespace std;
using namespace mfcslib;

static sft_header sh;

struct socket_type {
		int         fd = -1;
		sockaddr_in addr;
		~socket_type() {
			sockclose(fd);
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
	int      iRet = -1;
	optval_t opt  = 1;
#ifdef _WIN32
	cout << info << endl;
	u_long      op  = 1;
	auto        res = GetIPv4BroadcastAddresses();
	int         idx = 0;
	const char* buf = nullptr;
	cout << "All available networks are listed below." << endl;
	for (const auto& value : res) {
		cout << format("{}: Adapter: {}. IP: {}", idx++, value.name, value.ip)
			 << endl;
		;
	}
	cout << "\nPlease choose a network to discover other sft hosts: ";
	cin >> idx;
	idx %= res.size();
	buf = res[idx].ip.c_str();
	cout << "\033c";
#endif
	local_udp_host.fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (local_udp_host.fd == -1) {
		perror("socket error");
		return -1;
	}

	memset(&local_udp_host.addr, 0, sizeof(local_udp_host.addr));
	local_udp_host.addr.sin_family = AF_INET;
	local_udp_host.addr.sin_port   = htons(SERVER_PORT);
#ifdef _WIN32
	inet_pton(AF_INET, buf, &local_udp_host.addr.sin_addr);
#else
	local_udp_host.addr.sin_addr.s_addr = INADDR_ANY;
#endif
	iRet = setsockopt(local_udp_host.fd, SOL_SOCKET, SO_BROADCAST,
#ifdef __unix__
					  (const void*)
#endif // __unix__
					  &opt,
					  sizeof(opt));
	if (-1 == iRet) {
		perror("set sock option error");
		goto bad;
	}

	iRet =
		::bind(local_udp_host.fd, (const struct sockaddr*)&local_udp_host.addr,
			   sizeof(struct sockaddr));
	if (-1 == iRet) {
		perror("bind error");
		goto bad;
	}
	return 0;

bad:
	local_udp_host.fd = -1;
	sockclose(local_udp_host.fd);
	return -1;
}

// Initialize the given socket_type, returns 0 on success, -1 if fails.
int create_tcp_socket(socket_type& local_tcp_host,
					  bool         use_random_tcp_port = false) {
	int         tcp_fd = -1;
	char        flag   = 1;
	int         ret    = 0;
	sockaddr_in ip_port{};
	[[maybe_unused]] u_long      op = 1;

	memset(&ip_port, 0, sizeof(sockaddr_in));
	tcp_fd                  = socket(PF_INET, SOCK_STREAM, IPPROTO_IP);
	ip_port.sin_family      = AF_INET;
	ip_port.sin_addr.s_addr = htonl(INADDR_ANY);
	ip_port.sin_port =
		htons(use_random_tcp_port ? generate_random_port() : 9007);

	if (tcp_fd < 0) {
		perror("cannot create tcp socket");
		return -1;
	}
	setsockopt(tcp_fd, SOL_SOCKET, SO_REUSEADDR, &flag, sizeof(flag));
	ret = ::bind(tcp_fd, (sockaddr*)&ip_port, sizeof(sockaddr_in));
	if (ret < 0) {
		perror("cannot bind");
		goto bad;
	}
	ret = listen(tcp_fd, 5);
	if (ret < 0) {
		perror("cannot listen on tcp socket");
		goto bad;
	}
	local_tcp_host.fd   = tcp_fd;
	local_tcp_host.addr = ip_port;
	return 0;

bad:
	sockclose(tcp_fd);
	return -1;
}

// Search for sft peers in local network,
// return the number of responding host on success, -1 if fails.
mfcslib::_ResType search_for_sft_peers(const socket_type& local_host, int retry,
									   vector<sft_respond_struct>& all_hosts) {
	mfcslib::_ResType  iRet = -1;
	socklen_t          len  = sizeof(sockaddr_in);
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
		perror("Fail to get host name");
		return -1;
	}
	auto str = sh.form_discover_header(host_name_str, local_host.addr.sin_port);
	iRet     = sendto(local_host.fd, str.c_str(), str.size(), 0,
					  (const struct sockaddr*)&target_udp_addr,
					  sizeof(struct sockaddr));
	if (-1 == iRet) {
		perror("udp broadcast error");
		return -1;
	}

#ifdef __unix__
	int old_option = fcntl(local_host.fd, F_GETFL);
	fcntl(local_host.fd, F_SETFL, old_option | O_NONBLOCK);
#else
	u_long op = 1;
	ioctlsocket(local_host.fd, FIONBIO, &op);
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
			if (errno != WSAEWOULDBLOCK) {
				perror("recv failed");
#ifdef __unix__
				fcntl(local_host.fd, F_SETFL, old_option);
#else
				op = 0;
				ioctlsocket(local_host.fd, FIONBIO, &op);
#endif
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
#ifdef __unix__
	fcntl(local_host.fd, F_SETFL, old_option);
#else
	op = 0;
	ioctlsocket(local_host.fd, FIONBIO, &op);
#endif
	return all_hosts.size();
}

bool choose_working_mode() {
	int choice = 0;

	// cout << "\033c";
	cout << info << endl;
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
			cout << "Invalid choice!" << endl;
		}
	}

	respond_addr = &all_hosts[count].peer_addr;
	tcp_fd       = socket(AF_INET, SOCK_STREAM, 0);
	if (-1 == tcp_fd) {
		perror("cannot create socket");
		return -1;
	}
	respond_addr->sin_port = all_hosts[count].peer_port;
	ret =
		connect(tcp_fd, (const sockaddr*)respond_addr, sizeof(struct sockaddr));
	if (-1 == ret) {
		perror("connect error");
#ifdef _WIN32
		_close(tcp_fd);
#else
		close(tcp_fd);
#endif
		return -1;
	}
	cout << "Connect success! ";
	tcp.fd   = tcp_fd;
	tcp.addr = *respond_addr;
	return 0;
}

expected<mfcslib::tcp_socket, int>
wait_for_peers_to_connect(const socket_type& local_udp_host,
						  const socket_type& local_tcp_host, int retry = 15) {
	char               recv_buf[128];
	struct sockaddr_in responded_addr;
	socklen_t          len = sizeof(responded_addr);
	char               host[_SC_HOST_NAME_MAX + 1];
	char               ip_str[INET_ADDRSTRLEN];
	_ResType           iRet = 0;
	size_t             idx  = 0;
	string             str, msg;
	int udpfd = local_udp_host.fd, tcpfd = local_tcp_host.fd;
#ifdef _WIN32
	u_long op = 1;
#endif
	fd_set rfds;

	memset(&responded_addr, 0, sizeof(responded_addr));
	cout << format("Listening on tcp port:{}. Waiting for clients...",
				   ntohs(local_tcp_host.addr.sin_port))
		 << endl;

	FD_ZERO(&rfds);
	FD_SET(udpfd, &rfds);
	FD_SET(tcpfd, &rfds);
	iRet = select(max(udpfd, tcpfd) + 1, &rfds, nullptr, nullptr, nullptr);
#ifdef __unix__
	assert(iRet < 1024);
#endif
	[[unlikely]] if (iRet == SOCKET_ERROR) {
		perror("select failed");
		goto bad;
	}
	[[unlikely]] if (FD_ISSET(tcpfd, &rfds)) {
		goto Accept;
	}

	iRet = recvfrom(udpfd, recv_buf, sizeof(recv_buf) - 1, 0, (sockaddr*)&responded_addr, &len);
	[[unlikely]] if (inet_ntop(AF_INET, &responded_addr.sin_addr, ip_str, INET_ADDRSTRLEN) ==
		nullptr) {
		perror("trans fail!\n");
		goto bad;
	}
#ifdef DEBUG
	cout << format("Receive msg: {}\nFrom: {}", recv_buf, ip_str) << endl;
#endif // DEBUG
	iRet = gethostname(host, _SC_HOST_NAME_MAX);
	[[unlikely]] if (iRet == -1) {
		perror("gethostname fail");
		goto bad;
	}
	str = sh.form_respond_header(host, local_tcp_host.addr.sin_port);
	msg = recv_buf;
	idx = msg.find_last_of('/') + 1;
	responded_addr.sin_port =
		static_cast<in_port_t>(stoi(msg.substr(idx, msg.size() - idx)));
	iRet = sendto(udpfd, str.c_str(), str.size(), 0,
				  (const sockaddr*)&responded_addr, sizeof(sockaddr));
	if (-1 == iRet) {
		perror("send error");
		goto bad;
	}

Accept:
#ifdef _WIN32
	ioctlsocket(local_tcp_host.fd, FIONBIO, &op);
#else
	fcntl(local_tcp_host.fd, F_SETFL,
		  fcntl(local_tcp_host.fd, F_GETFL) | O_NONBLOCK);
#endif
	while (retry--) {
		iRet = accept(tcpfd, (struct sockaddr*)&responded_addr, &len);
		if (-1 == iRet) {
			if (errno != WSAEWOULDBLOCK) {
				perror("accept error");
				goto bad;
			}
		}
		else if (iRet > 0) {
			cout << "TCP connection established! Receiving files..." << endl;
			return mfcslib::tcp_socket(iRet, responded_addr);
		}
		std::this_thread::sleep_for(1s);
	}
	cerr << "Accept timeout, please try again." << endl;
#ifdef _WIN32
	op = 0;
	ioctlsocket(local_tcp_host.fd, FIONBIO, &op);
#else
	fcntl(local_tcp_host.fd, F_SETFL,
		  fcntl(local_tcp_host.fd, F_GETFL) & ~O_NONBLOCK);
#endif
	SetLastError(WAIT_TIMEOUT);
bad:
	return tl::unexpected(GetLastError());
}

bool send_file(mfcslib::tcp_socket& target, mfcslib::File& file) {
	off_t     off        = 0;
	_SizeType have_send  = 0;
	char      code       = -1;
	auto      file_sz    = file.size();
	_ResType  ret        = -1;
	[[maybe_unused]] size_t    bytes_left = file_sz;
	string    request;

	request = sh.form_file_header(
		convert_wstring_to_string(file.filename().c_str()), file_sz);
	target.write(request);
	code = target.read_byte();
	if (code != '1') {
		perror("Error while receiving code from peer in send_file");
		return false;
	}
	target.set_nonblocking();
#ifdef __unix__
	cout << "Sending file: " << file.filename() << endl;
	while (have_send < file_sz) {
		ret = sendfile(target.get_fd(), file.get_fd(), &off, file_sz);
		[[likely]] if (ret == -1) {
			[[unlikely]] if (errno != EAGAIN) {
				perror("Sendfile failed");
				break;
			}
			continue;
		}
		have_send += ret;
		mfcslib::progress_bar(have_send, file_sz);
	}
#else
	cout << "Sending file: "
		 << convert_wstring_to_string(file.filename().c_str()) << endl;

	if (file_sz <= MAXARRSZ) {
		auto buf = mfcslib::make_array<Byte>(file_sz);
		ret      = file.read(buf);
		if (ret == -1) {
			perror("Fail to read file");
			return false;
		}
		while (bytes_left > 0) {
			ret = target.write(buf, have_send, bytes_left);
			[[likely]] if (ret == -1) {
				[[unlikely]] if (errno != WSAEWOULDBLOCK) {
					perror("Fail to send file");
					break;
				}
				continue;
			}
			[[unlikely]] if (ret == 0 && bytes_left > 0) {
				cerr << "Connection is closed by peer before transfer is "
						"complete."
					 << endl;
					break;
			}
			have_send += ret;
			bytes_left -= ret;
			mfcslib::progress_bar(have_send, file_sz);
		}
	}
	else {
		int bufferidx = 1;
		auto   buffer1 = mfcslib::make_array<Byte>(bufSize);
		auto   buffer2 = mfcslib::make_array<Byte>(bufSize);
		future<ssize_t> read_res;
		size_t num = 0;
		TypeArray<Byte>* buffer = &buffer1;

		ret = file.read(buffer1);
		if (ret == -1) {
			perror("Fail to read file");
			goto end;
		}
		read_res = std::async(std::launch::async, &File::read_buf, &file, &buffer2);
		num = min(bufSize, bytes_left);
		while (bytes_left > 0) {
			ret = target.write(*buffer, have_send, num - have_send);
			[[likely]] if (ret == -1) {
				[[unlikely]] if (errno != WSAEWOULDBLOCK) {
					perror("Fail to send file");
					cout << '\n';
					break;
				}
				continue;
			}
			[[unlikely]] if (ret == 0 && bytes_left > 0) {
				cerr << "Connection is closed by peer before transfer is "
						"complete."
					 << endl;
				break;
			}
			have_send += ret;
			bytes_left -= ret;
			mfcslib::progress_bar(file_sz - bytes_left, file_sz);
			[[unlikely]] if (have_send == bufSize) {
				read_res.wait();
				ret = read_res.get();
				[[unlikely]] if (ret == -1) {
					perror("Fail to read file");
					cout << '\n';
					break;
				}
				read_res = std::async(std::launch::async, &File::read_buf, &file, buffer);
				num = min(bufSize, bytes_left);
				have_send = 0;
				buffer = ((++bufferidx) % 2) ? &buffer1 : &buffer2;
			}
		}
	}
#endif
end:
	target.set_blocking();
	cout << '\n';
	return true;
}

// No need to close file manually.
void receive_file(mfcslib::tcp_socket& target) {
	std::array<char, 128> request;
	size_t                sizeOfFile    = 0;
	size_t                bytesReceived = 0;
	size_t                bytesLeft     = 0;
	_ResType              ret           = 0;

	request.fill(0);
	target.set_blocking();
	ret = target.read(request.data(), request.size());
	if (ret == SOCKET_ERROR) {
		perror("Error while trying to receive from peer");
		return;
	}
	else if (ret == 0) {
		std::cerr << "Peer connection has been closed." << endl;
		return;
	}
	vector<string> res = mfcslib::str_split(request.data(), "/");
	target.write_byte('1');
	sizeOfFile = stoull(res[SFT_FIL_SIZE].data());
	bytesLeft  = sizeOfFile;
#ifdef DEBUG
	cout << "Received request:" << request.data();
	cout << format("Receiving file: {}\tSize: {}\n", res[SFT_FIL_NAME],
				   sizeOfFile);
#endif // DEBUG
	mfcslib::File file_output_stream(
		convert_string_to_wstring(res[SFT_FIL_NAME].c_str()));
	if (!file_output_stream.open(true, mfcslib::File::iomode::WRONLY)) {
		perror("Fail to create file");
		return;
	}
	target.set_nonblocking();

	if (sizeOfFile < MAXARRSZ) {
		auto bufferForFile = mfcslib::make_array<Byte>(sizeOfFile);
		while (bytesLeft > 0) {
			ret = target.read(bufferForFile, bytesReceived, bytesLeft);
			[[likely]] if (ret == SOCKET_ERROR) {
				[[unlikely]] if (errno != WSAEWOULDBLOCK) {
					perror("Error while trying to receive from peer");
					break;
				}
				continue;
			}
			[[unlikely]] if (ret == 0 && bytesLeft > 0) {
				cerr << "Connection is closed by peer before transfer is "
						"complete."
					 << endl;
				break;
			}
			bytesReceived += ret;
			bytesLeft -= ret;
			mfcslib::progress_bar(bytesReceived, sizeOfFile);
		}
		if (file_output_stream.write(bufferForFile) == -1) {
			perror("Error while trying to write to local");
			cout << '\n';
		}
	}
	else {
		auto   buffer1 = mfcslib::make_array<Byte>(bufSize);
		auto   buffer2 = mfcslib::make_array<Byte>(bufSize);
		size_t bytesRemain   = sizeOfFile;
		auto   num           = min(bufSize, bytesLeft);
		int bufferidx = 1;
		TypeArray<Byte>* buffer = &buffer1;
		future<ssize_t> write_res;

		while (bytesLeft > 0) {
			ret = target.read(*buffer, bytesReceived, num - bytesReceived);
			[[likely]] if (ret == -1) {
				[[unlikely]] if (errno != WSAEWOULDBLOCK) {
					perror("Fail to send file");
					break;
				}
				continue;
			}
			[[unlikely]] if (ret == 0 && bytesLeft > 0) {
				cerr << "Connection is closed by peer before transfer is "
						"complete."
					 << endl;
				break;
			}
			bytesReceived += ret;
			bytesLeft -= ret;
			mfcslib::progress_bar(sizeOfFile - bytesLeft, sizeOfFile);
			[[unlikely]] if (bytesReceived == bufSize) {
				[[likely]] if (bufferidx != 1) {
					write_res.wait();
					ret = write_res.get();
					[[unlikely]] if (ret == -1) {
						perror("Fail to write file");
						break;
					}
				}
				write_res = std::async(std::launch::async, &File::write_buf, &file_output_stream, buffer);
				num           = min(bufSize, bytesLeft);
				bytesRemain   = bytesLeft;
				bytesReceived = 0;
				buffer = ((++bufferidx) % 2) ? &buffer1 : &buffer2;
			}
		}
		file_output_stream.write(*buffer, 0, bytesRemain);
	}
	cout << '\n';
	target.set_blocking();
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
		sockclose(tcp_fd);
		return -1;
	}
	cout << "Connect success!" << endl;
	tcp.fd   = tcp_fd;
	tcp.addr = respond_addr;
	return 0;
}

// TODO
int configure_options() {
	[[maybe_unused]] bool use_random_tcp_port = false;
	[[maybe_unused]] int  max_retry           = 5;
	return 0;
}

int main() {
	socket_type                usocket{};
	vector<sft_respond_struct> all_hosts;
	mfcslib::string_type       file_name;
	int                        continue_current_mode = 0;

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
		if (choose_working_mode()) { // Transfer mode
			mfcslib::File       file_fd;
			mfcslib::tcp_socket tfd;
			char                choice = 0;
			socket_type         tsocket{};

		choose:
#ifdef __unix__
			cout << "Please input the path of file: ";
			cin >> file_name;
#else
			file_name = OpenFileDialog();
#endif
			sockclose(tsocket.fd);
			if (file_name.empty()) {
				cerr << "Didn't choose any file." << endl;
				goto start;
			}
			file_fd = file_name;
			if (file_fd.open_read_only()) {
				goto again;
			}
			perror("Fail to open file");
			std::cerr << "Please try again." << endl;
			goto choose;

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
			tfd = mfcslib::tcp_socket(tsocket.fd, tsocket.addr);
		round:
			send_file(tfd, file_fd);
			cout << "Continue to transfer: 0.no\t1.yes ";
			cin >> continue_current_mode;
			if (continue_current_mode) {
			rechoose:
#ifdef __unix__
				cout << "Please input the path of file: ";
				cin >> file_name;
#else
				file_name = OpenFileDialog();
#endif
				if (file_name.empty()) {
					cerr << "Didn't choose any file." << endl;
					goto start;
				}
				file_fd = file_name;
				if (file_fd.open_read_only()) {
					goto round;
				}
				perror("Fail to open file");
				std::cerr << "Please try again." << endl;
				goto rechoose;
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
				// cout << "Cannot connect to peers." << endl;
				continue;
			}

			tfd = std::move(return_value.value());
		receive:
			receive_file(tfd);
			cout << "Continue to receive: 0.no\t1.yes ";
			cin >> continue_current_mode;
			if (continue_current_mode) {
				cout << "Pending requests..." << endl;
				goto receive;
			}
		}
	}
#ifdef _WIN32
	WSACleanup();
	system("pause");
#endif
	return 0;
}