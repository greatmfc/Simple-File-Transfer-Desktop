#include "aes-gcm.h"
#include "io.h"
#include "sftclass.hpp"
#include "SecureContainer.h"

#define SERVER_PORT 7897
#define MAXARRSZ    2'048'000'000ull // 2GB
#define VERSION     1.5f
#define CHUNK_SIZE  20'000'000ull // 20MB
constexpr size_t bufSize = MAXARRSZ / 2;
constexpr auto additional_length = AESGCM_IV_SIZE + AESGCM_TAG_SIZE;
constexpr size_t chunkBufSize = (CHUNK_SIZE / 2) + additional_length;

using mfcslib::File;
using mfcslib::string_type;
using mfcslib::tcp_socket;
using std::tuple;
using std::vector;

struct socket_type {
		int         fd = -1;
		sockaddr_in addr;
		~socket_type() {
			sockclose(fd);
		}
};

int create_udp_socket(socket_type& local_udp_host, const char* buf);

int create_tcp_socket(socket_type& local_tcp_host, bool use_random_tcp_port);

mfcslib::ResType
	search_for_sft_peers(const socket_type& local_host, int retry,
						 std::vector<sft_respond_struct>& all_hosts);

int connect_to_peer(vector<sft_respond_struct>& all_hosts, socket_type& tcp);

std::expected<tcp_socket, int>
	 wait_for_peers_to_connect(const socket_type& local_udp_host,
							   const socket_type& local_tcp_host, int retry = 15);

bool send_file(tcp_socket& target, const vector<tuple<File, string>>& files);

void receive_file(tcp_socket& target);

int  manual_connect_to_peer(socket_type& tcp);

vector<tuple<File, string>>
	get_filefd_list(const vector<string_type>& path_list);

int choose_working_mode();

bool send_file_s(tcp_socket& target, const vector<tuple<File, string>>& files,
				 SecureContainer<char>* password);

void receive_file_s(tcp_socket& target, SecureContainer<char>* password);
