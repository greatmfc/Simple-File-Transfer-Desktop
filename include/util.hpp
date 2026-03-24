#ifndef UTIL_HPP
#define UTIL_HPP
#include <array>
#include <cassert>
#include <cstdio>
#include <cstring>
#include <iostream>
#include <vector>
#include <algorithm>
#include <format>
#include <string>
#include <string_view>
#include <chrono>
#include <random>
using Byte = uint8_t;
using namespace std::chrono_literals;

using std::vector;

namespace kotcpp {

constexpr std::array<std::string_view, 11> all_percent = {
	"\r[----------]", "\r[*---------]", "\r[**--------]", "\r[***-------]",
	"\r[****------]", "\r[*****-----]", "\r[******----]", "\r[*******---]",
	"\r[********--]", "\r[*********-]", "\r[**********]",
};

constexpr std::array<std::string_view, 4> all_speeds = {" B/s", "KB/s", "MB/s",
														"GB/s"};

template <typename T, typename R> void progress_bar(T num1, R num2) noexcept {
	double percent = static_cast<double>(num1) / static_cast<double>(num2);
	if (percent > 1 || percent <= 0) {
		std::cout << std::format("Invalid percentage: {}/{}", num1, num2)
				  << std::endl;
		return;
	}
	uintmax_t index = static_cast<uintmax_t>(percent * 10);
	std::cout << all_percent[index] << ' ' << std::to_string(percent * 100)
			  << '%';
	std::cout.flush();
	return;
}

template <typename T = int, typename R = int>
void progress_bar_with_speed_t(size_t num, size_t total_num,
							   bool restart = false) noexcept {
	static auto   last_num        = 0ull;
	static auto   last_time_point = std::chrono::steady_clock::now();
	static double final_speed     = 0;
	static int    speed_unit      = 0;
	if (restart) {
		last_num        = 0;
		last_time_point = std::chrono::steady_clock::now();
		final_speed     = 0;
		speed_unit      = 0;
		return;
	}

	double percent = static_cast<double>(num) / static_cast<double>(total_num);
	if (percent > 1 || percent <= 0) {
		std::cout << std::format("Invalid percentage: {}/{}", num, total_num)
				  << std::endl;
		return;
	}
	auto now       = std::chrono::steady_clock::now();
	auto diff_time = std::chrono::duration_cast<std::chrono::milliseconds>(
		now - last_time_point);
	auto index       = static_cast<uintmax_t>(percent * 10);
	auto update_time = 500ms;
	if (diff_time >= update_time) {
		double diff_num = num - last_num;
		final_speed     = (diff_num / diff_time.count()) * 1000; // * 1'000;
		last_num        = num;
		last_time_point = now;
		if (final_speed < 1'000) {
		}
		else if (final_speed < 1'000'000) {
			final_speed /= 1000;
			speed_unit = 1;
		}
		else if (final_speed < 1'000'000'000) {
			final_speed /= 1'000'000;
			speed_unit = 2;
		}
		else {
			final_speed /= 1'000'000'000;
			speed_unit = 3;
		}
	}
	std::cout << std::format("{0} {1:.2f}% {2:.2f}{3}", all_percent[index],
							 percent * 100, final_speed,
							 all_speeds[speed_unit]);
	// std::cout << all_percent[index] << ' ' << std::to_string(percent * 100)
	// << '%';
	std::cout.flush();
	return;
}

/**
 * @brief 显示带速度的进度条（优化版）
 * - 降低打印频率：仅在变化超过 1% 或间隔 >= 100ms 时更新
 * - 使用预构建字符串减少 I/O 操作
 * - 避免不必要的临时对象创建
 * @param current 已发送/下载的字节数
 * @param total 总字节数
 * @param restart 是否重置状态（在新传输开始前调用）
 */
inline void progress_bar_with_speed(long long current, long long total,
									bool restart = false) {
	static auto      start_time      = std::chrono::steady_clock::now();
	static auto      last_time       = std::chrono::steady_clock::now();
	static auto      last_print_time = std::chrono::steady_clock::now();
	static long long last_current    = 0;
	static int       last_percent    = -1;
	static double    instant_speed   = 0;
	static char      buffer[128]; // 预分配缓冲区

	if (restart) {
		start_time      = std::chrono::steady_clock::now();
		last_time       = start_time;
		last_print_time = start_time;
		last_current    = 0;
		last_percent    = -1;
		instant_speed   = 0;
		return;
	}

	if (total <= 0)
		return;

	// 1. 计算当前百分比（整数，0-100）
	int  percent = static_cast<int>((current * 100) / total);

	// 2. 节流：仅在百分比变化或超过100ms时更新
	auto now = std::chrono::steady_clock::now();
	auto since_last_print =
		std::chrono::duration_cast<std::chrono::milliseconds>(now -
															  last_print_time);

	// 跳过条件：百分比相同 且 距上次打印不足100ms 且 未完成
	if (percent == last_percent && since_last_print.count() < 100 &&
		current < total) {
		return; // 直接返回，不做任何 I/O
	}

	// 3. 每500ms更新速度计算
	auto diff_time =
		std::chrono::duration_cast<std::chrono::milliseconds>(now - last_time);
	if (diff_time.count() >= 200) {
		double diff_bytes = static_cast<double>(current - last_current);
		instant_speed     = (diff_bytes / diff_time.count()) * 1000.0;
		last_time         = now;
		last_current      = current;
	}

	// 4. 速度单位换算（使用 string_view 避免分配）
	std::string_view unit;
	double           displaySpeed = instant_speed;
	if (instant_speed >= 1024.0 * 1024.0 * 1024.0) {
		displaySpeed /= (1024.0 * 1024.0 * 1024.0);
		unit = "GB/s";
	}
	else if (instant_speed >= 1024.0 * 1024.0) {
		displaySpeed /= (1024.0 * 1024.0);
		unit = "MB/s";
	}
	else if (instant_speed >= 1024.0) {
		displaySpeed /= 1024.0;
		unit = "KB/s";
	}
	else {
		unit = "B/s";
	}

	// 5. 使用 snprintf 一次性格式化到缓冲区
	constexpr int barWidth = 50;
	int           pos      = (barWidth * percent) / 100;

	// 构建进度条部分
	char          bar[barWidth + 1];
	std::memset(bar, ' ', barWidth);
	std::memset(bar, '=', pos);
	if (pos < barWidth)
		bar[pos] = '>';
	bar[barWidth] = '\0';

	// 一次性格式化完整输出
	int len = std::snprintf(buffer, sizeof(buffer), "\r[%s] %3d%% %.2f %s   ",
							bar, percent, displaySpeed, unit.data());

	// 6. 单次 write 调用 + flush（Linux 需要显式刷新）
	std::cout.write(buffer, len);
	std::cout.flush(); // 必须刷新，否则 Linux 终端会缓冲

	// 更新状态
	last_percent    = percent;
	last_print_time = now;

	// 7. 仅在完成时刷新和换行
	if (current >= total) {
		std::cout << std::endl;
		last_percent = -1; // 重置以便下次传输
	}
}

constexpr std::vector<std::string_view> str_split(std::string_view str,
												  std::string_view delims) {
	std::vector<std::string_view> output;
	for (auto first = str.data(), second = str.data(),
			  last                              = first + str.size();
		 second != last && first != last; first = second + 1) {
		second = std::find_first_of(first, last, std::cbegin(delims),
									std::cend(delims));
		if (first != second) {
			output.emplace_back(first, second - first);
		}
	}
	return output;
}

inline uint16_t generate_random_port(uint16_t min = 9000,
									 uint16_t max = 49151) {
	static std::mt19937                     e1(std::random_device{}());
	std::uniform_int_distribution<uint16_t> uniform_dist(min, max);
	return uniform_dist(e1);
}

} // namespace kotcpp
#endif // !UTIL_HPP
