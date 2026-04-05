#ifndef COMMON_HPP
#define COMMON_HPP

#include "main.h"
#include <vector>
#include <string>

namespace sft_common {

using namespace std;
using namespace kotcpp;

/**
 * @brief 处理发现失败的用户交互
 *
 * @param is_one_time 是否是一次性任务
 * @return Result<sockaddr_in> 用户选择的连接方式
 */
Result<sockaddr_in> handle_discovery_failure() {
	std::cout << "\nDiscovery failed. Choose next step:\n"
				 "0. Search again.\t"
				 "1. Input IP and port manually.\t"
				 "2. Return to initial menu.\n"
				 "Enter your choice: ";
	int choice = 0;
	if (!(std::cin >> choice)) {
		std::cin.clear();
		std::cin.ignore(10000, '\n');
		return tl::unexpected<string>(kotcpp::get_error_str(EINVAL));
	}

	if (choice == 0) {
		return tl::unexpected<string>(
			kotcpp::get_error_str(EAGAIN)); // 表示需要重新搜索
	}
	else if (choice == 1) {
		return manual_connect_to_peer();
	}
	else {
		return tl::unexpected<string>(kotcpp::get_error_str(ECANCELED));
	}
}

/**
 * @brief 解析地址字符串为sockaddr_in结构
 *
 * @param addr_str 地址字符串，格式为"IP:port"或"IP"（使用默认端口）
 * @param default_port 默认端口号
 * @return Result<sockaddr_in> 解析结果
 */
Result<sockaddr_in> parse_address(const std::string& addr_str,
								  uint16_t           default_port = TCP_PORT) {
	auto     colon_pos = addr_str.find(':');
	string   ip        = addr_str.substr(0, colon_pos);
	uint16_t port =
		(colon_pos != string::npos)
			? static_cast<uint16_t>(stoi(addr_str.substr(colon_pos + 1)))
			: default_port;

	sockaddr_in addr{};
	addr.sin_family = AF_INET;
	if (inet_pton(AF_INET, ip.c_str(), &addr.sin_addr) != 1) {
		return tl::unexpected<string>(kotcpp::get_error_str(EINVAL));
	}
	addr.sin_port = htons(port);
	return addr;
}

/**
 * @brief 建立连接到对等节点
 *
 * @param usocket UDP socket用于发现
 * @param target_addr 目标地址（如果为空则进行发现）
 * @return Result<sockaddr_in> 连接地址结果
 */
Result<sockaddr_in> establish_connection(kotcpp::udp_socket& usocket,
										 const std::string&  target_addr) {
	if (!target_addr.empty()) {
		return parse_address(target_addr);
	}

	// Discovery Loop
	while (true) {
		vector<sft_respond_struct> all_hosts;
		(void)search_for_sft_peers(usocket, 3, all_hosts);

		if (all_hosts.empty()) {
			std::cerr << "No peers found.\n";
			auto result = handle_discovery_failure();
			if (result) {
				return result;
			}
			// If manual connect failed, loop back to prompt
			continue;
		}
		else {
			auto connect_res = connect_to_peer(all_hosts);
			if (connect_res) {
				return connect_res;
			}
		}
	}
}

/**
 * @brief 等待对等节点连接
 *
 * @param usocket UDP socket用于发现
 * @param receiver 服务器对象
 * @param use_random_port 是否使用随机端口
 * @param timeout_seconds 超时时间（秒）
 * @return ResType 成功返回0，失败返回错误码
 */
ResType wait_for_connection(kotcpp::udp_socket& usocket,
							kotcpp::sft_server& receiver, bool use_random_port,
							int timeout_seconds = 15) {
	return wait_for_peers_to_connect(usocket, receiver, timeout_seconds,
									 use_random_port);
}

/**
 * @brief 获取用户选择的文件列表
 *
 * @param existing_files 现有的文件列表（来自命令行）
 * @param is_folder_mode 是否为文件夹模式
 * @return std::vector<std::string> 文件列表
 */
std::vector<std::string>
get_files_from_user(const std::vector<std::string>& existing_files,
					bool                            is_folder_mode = false) {
	(void)is_folder_mode; // Only used on Windows
	std::vector<std::string> files = existing_files;

	if (files.empty()) {
#ifdef _WIN32
		auto diag_res = OpenFileOrFolderDialog(is_folder_mode);
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

	return files;
}

} // namespace sft_common

#endif // COMMON_HPP