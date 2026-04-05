#include <cstring>
#include <vector>
#include <array>
#include <string>
#include <sys/types.h>
#include <future>
#include <BS_thread_pool.hpp>
#include "main.h"
#include "sftclass.hpp"
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

static sft_header      sh;
static BS::thread_pool pool(4);
constexpr SizeType     CHUNKSZ = 4'194'304;
// constexpr SizeType     CHUNKSZ = 1'048'576;
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

bool send_file(sft_base&                                      target,
			   const vector<tuple<unique_ptr<File>, string>>& files) {
	[[maybe_unused]] off_t off     = 0;
	SizeType               file_sz = 0, bytes_left = 0, have_send = 0, num = 0;
	RetType                ret     = -1;
	ResType                res     = -1;
	string                 request = "sft1.1/FIL";
	std::array<uint8_t, 1024> ack_buf{};
	progress_bar_with_speed(0, 0, true);

	for (const auto& [fd, file_path] : files) {
		if (fd == nullptr || !fd->is_open()) { // directory
			request += format("/{}/0", file_path);
		}
		else { // regular file
			request += format("/{}/{}", file_path, fd->size());
		}
	}
	target.set_blocking();
	auto sft_io_res = target.write(request);
	res             = sft_io_res.get();
	if (!res) {
		print_error("Fail to send request", res);
		return false;
	}
	sft_io_res = target.read(ack_buf);
	if (!sft_io_res.get() || ack_buf[0] != '1') {
		print_error("Error while receiving code from peer in send_file");
		return false;
	}
	for (const auto& [file, file_path] : files) {
		if (file == nullptr || !file->is_open()) {
			continue;
		}
		std::cout << "Sending file: " << file_path << '\n';
		file_sz    = file->size();
		bytes_left = file_sz;
		have_send  = 0;

		if (file_sz <= CHUNKSZ) {
			auto buf = vector<Byte>(file_sz);
			res      = file->read(buf);
			if (!res) {
				print_error(format("Fail to read file: {}", file_path), res);
				return false;
			}
			sft_io_res = target.write(buf, have_send, bytes_left);
			while (bytes_left > 0) {
				if (sft_io_res.is_yielded()) {
					res = sft_io_res.get_yielded().value();
				}
				else if (sft_io_res.done()) {
					res = sft_io_res.get();
					[[unlikely]] if (!res) {
						print_error(format("Fail to send file: {}", file_path),
									res);
						return false;
					}
				}
				ret = res.value();
				have_send += ret;
				bytes_left -= ret;
				progress_bar_with_speed(have_send, file_sz);
				sft_io_res.resume();
			}
		}
		else {
			int  bufferidx = 1;
			// auto            buffer1   = vector<Byte>(CHUNKSZ);
			// auto            buffer2   = vector<Byte>(CHUNKSZ);
			auto buffer1 = make_unique_for_overwrite<Byte[]>(CHUNKSZ);
			auto buffer2 = make_unique_for_overwrite<Byte[]>(CHUNKSZ);
			future<ResType> read_res;
			Byte*           buffer = buffer1.get();

			res                    = file->read(buffer1.get(), CHUNKSZ);
			if (!res) {
				print_error(
					format("Fail to read file: {}. Reason: ", file_path), res);
				return false;
			}
			read_res   = pool.submit_task([ObjectPtr = file.get(), &buffer2] {
                return ObjectPtr->read(buffer2.get(), CHUNKSZ);
            });
			num        = std::min(CHUNKSZ, bytes_left);
			sft_io_res = target.write(buffer + have_send, num - have_send);
			while (bytes_left > 0) {
				if (sft_io_res.is_yielded()) {
					res = sft_io_res.get_yielded().value();
				}
				else if (sft_io_res.done()) {
					res = sft_io_res.get();
					[[unlikely]] if (!res) {
						print_error(format("Fail to send file: {}", file_path),
									res);
						break;
					}
				}
				ret = res.value();
				have_send += ret;
				bytes_left -= ret;
				progress_bar_with_speed(file_sz - bytes_left, file_sz);
				[[unlikely]] if (have_send == CHUNKSZ) {
					read_res.wait();
					res = read_res.get();
					[[unlikely]] if (!res) {
						print_error(format("Fail to read file: {}", file_path),
									res);
						return false;
					}
					read_res =
						pool.submit_task([ObjectPtr = file.get(), buffer] {
							return ObjectPtr->read(buffer, CHUNKSZ);
						});
					num       = std::min(CHUNKSZ, bytes_left);
					have_send = 0;
					buffer =
						((++bufferidx) % 2) ? buffer1.get() : buffer2.get();
					sft_io_res =
						target.write(buffer + have_send, num - have_send);
					continue;
				}
				sft_io_res.resume();
			}
		}
		cout << '\n';
	}

	cout << "Waiting for client to complete.\n";
	sft_io_res = target.read(ack_buf);
	if (sft_io_res.get() && ack_buf[0] == '0') {
		cout << "All files have been received by the other side.\n";
	}
	else {
		cout << "Something unexpected happened. Please check the other "
				"side "
				"for file integrity.\n";
	}
	return true;
}

// No need to close file manually.
// It is caller's responsibility to initialize target.
void receive_file(sft_base& target) {
	vector<Byte>              buffer(CHUNKSZ);
	// vector<Byte>              request(1024);
	SizeType                  sizeOfFile = 0, bytesReceived = 0, bytesLeft = 0;
	RetType                   ret = -1;
	ResType                   res = -1;
	std::array<uint8_t, 1024> ack_buf{};
	auto                      buf_size = generate_random_port(128, 1024);

	// request.resize(8192);
	progress_bar_with_speed(0, 0, true);
	target.set_blocking();
	auto sft_io_res = target.read(buffer);
	while (!sft_io_res.done()) {
		sft_io_res.resume();
	}
	res = sft_io_res.get();
	if (!res) {
		print_error("Fail to receive request", res);
		return;
	}
	ret = res.value();
	auto requests =
		str_split(string_view((const char*)buffer.data(), ret), "/");
	randombytes_buf(ack_buf.data(), buf_size);
	ack_buf[0] = '1';
	target.write(ack_buf.data(), buf_size);
	// target.write_byte('1');
#ifdef DEBUG
	cout << "Receive request: " << (const char*)buffer.data() << endl;
#endif
	if (requests.size() <= 2) {
		cerr << "Receive unknown request.\n";
	}
	// target.set_nonblocking();
	for (size_t i = SFT_FIL_NAME_START; i < requests.size() - 1; i += 2) {
		string file_name = "./" + string(requests[i]);
		from_chars(requests[i + 1].data(),
				   requests[i + 1].data() + requests[i + 1].size(), sizeOfFile);
		bytesLeft     = sizeOfFile;
		bytesReceived = 0;
#ifdef __unix__
		for (auto& c : file_name) {
			if (c == '\\') {
				c = '/';
			}
		}
#endif // __unix__
		if (file_name.back() == '\\' ||
			file_name.back() == '/') { // it is a directory
			fs::create_directories(file_name);
			continue;
		}
		File file_output_stream(file_name);
		cout << format("Receiving file: {}\tSize: {}", file_name, sizeOfFile)
			 << endl;
		if (auto open_res = file_output_stream.open(true, File::iomode::WRONLY);
			!open_res) {
			print_error("Fail to create file", open_res);
			sft_io_res = target.read(
				buffer.data(), std::min(bytesLeft, (SizeType)buffer.size()));
			while (true) {
				if (sft_io_res.is_yielded()) {
					res = sft_io_res.get_yielded().value();
					bytesLeft -= *res;
					sft_io_res.resume();
				}
				else if (sft_io_res.done()) {
					res = sft_io_res.get();
					[[unlikely]] if (!res) {
						print_error("Error while trying to receive from peer",
									res);
						return;
					}
					bytesLeft -= *res;
					if (bytesLeft == 0) {
						break;
					}
					sft_io_res = target.read(
						buffer.data(),
						std::min(bytesLeft, (SizeType)buffer.size()));
				}
			}
			continue;
		}

		if (sizeOfFile <= CHUNKSZ) {
			auto bufferForFile = vector<Byte>(sizeOfFile);
			sft_io_res = target.read(bufferForFile, bytesReceived, bytesLeft);
			while (bytesLeft > 0) {
				if (sft_io_res.is_yielded()) {
					res = sft_io_res.get_yielded().value();
				}
				else if (sft_io_res.done()) {
					res = sft_io_res.get();
					[[unlikely]] if (!res) {
						print_error("Error while trying to receive from peer",
									res);
						return;
					}
				}
				ret = res.value();
				bytesReceived += ret;
				bytesLeft -= ret;
				progress_bar_with_speed(bytesReceived, sizeOfFile);
				sft_io_res.resume();
			}
			if (file_output_stream.write(bufferForFile) == -1) {
				print_error("Error while trying to write to local");
				cout << '\n';
			}
		}
		else {
			auto     buffer1     = make_unique_for_overwrite<Byte[]>(CHUNKSZ);
			auto     buffer2     = make_unique_for_overwrite<Byte[]>(CHUNKSZ);
			SizeType bytesRemain = sizeOfFile;
			auto     num         = CHUNKSZ;
			int      bufferidx   = 1;
			Byte*    buffer      = buffer1.get();
			future<ResType> write_res;

			sft_io_res =
				target.read(buffer + bytesReceived, num - bytesReceived);
			while (bytesLeft > 0) {
				if (sft_io_res.is_yielded()) {
					res = sft_io_res.get_yielded().value();
				}
				else if (sft_io_res.done()) {
					res = sft_io_res.get();
					[[unlikely]] if (!res) {
						print_error("Error while trying to receive from peer",
									res);
						return;
					}
				}
				ret = res.value();
				bytesReceived += ret;
				bytesLeft -= ret;
				progress_bar_with_speed(sizeOfFile - bytesLeft, sizeOfFile);
				[[unlikely]] if (bytesReceived == CHUNKSZ) {
					[[likely]] if (bufferidx != 1) {
						write_res.wait();
						res = write_res.get();
						[[unlikely]] if (!res) {
							print_error("Error while trying to write to local",
										res);
							break;
						}
					}
					write_res = pool.submit_task(
						[ObjectPtr = &file_output_stream, buffer] {
							return ObjectPtr->write(buffer, CHUNKSZ);
						});
					num           = std::min(CHUNKSZ, bytesLeft);
					bytesRemain   = bytesLeft;
					bytesReceived = 0;
					buffer =
						((++bufferidx) % 2) ? buffer1.get() : buffer2.get();
					sft_io_res = target.read(buffer + bytesReceived,
											 num - bytesReceived);
					continue;
				}
				sft_io_res.resume();
			}
			write_res.wait();
			file_output_stream.write(buffer, bytesRemain);
		}
		cout << '\n';
	}

	buf_size = generate_random_port(128, 1024);
	randombytes_buf(ack_buf.data(), buf_size);
	ack_buf[0] = '0';
	target.write(ack_buf.data(), buf_size);
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
get_filefd_list(const vector<string_type>& path_list) {
	vector<tuple<unique_ptr<File>, string>> result;
	for (const auto& path : path_list) {
		if (fs::is_directory(path)) {
			// Get folder name using std::filesystem
			string folderName = fs::path(path).filename().string();

			result.emplace_back(nullptr, folderName + '\\');
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
											(folderName + '\\') += relative);
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
					result.emplace_back(nullptr,
										folderName + '\\' += relative += '\\');
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