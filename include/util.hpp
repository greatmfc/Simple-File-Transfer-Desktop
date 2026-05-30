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
#include <mutex>
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
 * - 传输中显示预计剩余时间，完成时显示本次传输平均速度
 * @param current 已发送/下载的字节数
 * @param total 总字节数
 * @param restart 是否重置状态（在新传输开始前调用）
 */
inline void progress_bar_with_speed(size_t current, size_t total,
									bool restart = false) {
	// static std::mutex progress_mutex;
	// std::lock_guard   progress_lock(progress_mutex);
	static auto   start_time      = std::chrono::steady_clock::now();
	static auto   last_time       = std::chrono::steady_clock::now();
	static auto   last_print_time = std::chrono::steady_clock::now();
	static size_t start_current   = 0;
	static size_t last_current    = 0;
	static int    last_percent    = -1;
	static double instant_speed   = 0;
	static char   buffer[192]; // 预分配缓冲区

	if (restart) {
		const auto display_current =
			total > 0 ? std::min(current, total) : current;
		start_time      = std::chrono::steady_clock::now();
		last_time       = start_time;
		last_print_time = start_time;
		start_current   = display_current;
		last_current    = display_current;
		last_percent    = -1;
		instant_speed   = 0;
		return;
	}

	if (total == 0) {
		return;
	}

	const auto display_current = std::min(current, total);
	const auto now             = std::chrono::steady_clock::now();
	const int  percent = static_cast<int>(static_cast<double>(display_current) *
										  100.0 / static_cast<double>(total));

	const auto since_last_print =
		std::chrono::duration_cast<std::chrono::milliseconds>(now -
															  last_print_time);
	if (percent == last_percent && since_last_print.count() < 100 &&
		display_current < total) {
		return;
	}

	const auto diff_time =
		std::chrono::duration_cast<std::chrono::milliseconds>(now - last_time);
	if (diff_time.count() >= 200) {
		const auto diff_bytes = display_current >= last_current
									? display_current - last_current
									: 0;
		instant_speed         = static_cast<double>(diff_bytes) /
						static_cast<double>(diff_time.count()) * 1000.0;
		last_time    = now;
		last_current = display_current;
	}

	auto scale_speed = [](double speed, std::string_view& unit) {
		unit = "B/s";
		if (speed >= 1024.0 * 1024.0 * 1024.0) {
			unit = "GB/s";
			return speed / (1024.0 * 1024.0 * 1024.0);
		}
		if (speed >= 1024.0 * 1024.0) {
			unit = "MB/s";
			return speed / (1024.0 * 1024.0);
		}
		if (speed >= 1024.0) {
			unit = "KB/s";
			return speed / 1024.0;
		}
		return speed;
	};

	auto format_duration = [](double seconds, char* output, size_t size) {
		if (seconds <= 0.0) {
			std::snprintf(output, size, "--:--:--");
			return;
		}

		auto total_seconds = static_cast<unsigned long long>(seconds + 0.999);
		const auto hours   = total_seconds / 3600;
		total_seconds %= 3600;
		const auto minutes = total_seconds / 60;
		const auto secs    = total_seconds % 60;
		if (hours > 99) {
			std::snprintf(output, size, "%lluh%02llum", hours, minutes);
			return;
		}
		std::snprintf(output, size, "%02llu:%02llu:%02llu", hours, minutes,
					  secs);
	};

	std::string_view speed_unit;
	const double     display_speed = scale_speed(instant_speed, speed_unit);
	const auto       elapsed_seconds =
		std::chrono::duration<double>(now - start_time).count();
	const auto transferred =
		display_current >= start_current ? display_current - start_current : 0;
	const auto average_speed =
		elapsed_seconds > 0.0
			? static_cast<double>(transferred) / elapsed_seconds
			: 0.0;
	const auto eta_speed = average_speed > 0.0 ? average_speed : instant_speed;
	char       eta[24]{};
	format_duration(eta_speed > 0.0
						? static_cast<double>(total - display_current) /
							  eta_speed
						: 0.0,
					eta, sizeof(eta));

	constexpr int bar_width = 50;
	const int     pos       = (bar_width * percent) / 100;
	char          bar[bar_width + 1];
	std::memset(bar, ' ', sizeof(bar) - 1);
	std::memset(bar, '=', static_cast<size_t>(pos));
	if (pos < bar_width) {
		bar[pos] = '>';
	}
	bar[bar_width] = '\0';

	int len        = 0;
	if (display_current >= total) {
		std::string_view avg_unit;
		const auto display_avg_speed = scale_speed(average_speed, avg_unit);
		len =
			std::snprintf(buffer, sizeof(buffer), "\r[%s] %3d%% avg %.2f %s   ",
						  bar, percent, display_avg_speed, avg_unit.data());
	}
	else {
		len = std::snprintf(buffer, sizeof(buffer),
							"\r[%s] %3d%% %.2f %s ETA %s   ", bar, percent,
							display_speed, speed_unit.data(), eta);
	}
	if (len <= 0) {
		return;
	}
	if (static_cast<size_t>(len) >= sizeof(buffer)) {
		len = static_cast<int>(sizeof(buffer) - 1);
	}

	std::cout.write(buffer, len);
	std::cout.flush();

	last_percent    = percent;
	last_print_time = now;
	if (display_current >= total) {
		std::cout << std::endl;
		last_percent = -1;
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
