#pragma once

#include "io.hpp"
#include "util.hpp"
#include <BS_thread_pool.hpp>
#include <algorithm>
#include <atomic>
#include <charconv>
#include <condition_variable>
#include <cstdint>
#include <deque>
#include <exception>
#include <filesystem>
#include <format>
#include <future>
#include <iostream>
#include <mutex>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <sodium.h>

namespace sft_detail {

inline constexpr kotcpp::SizeType transfer_chunk_size       = 4'194'304;
inline constexpr kotcpp::SizeType frame_buffer_size         = 1024 * 8;
inline constexpr std::size_t      transfer_pipeline_depth   = 4;
inline constexpr kotcpp::SizeType resume_state_update_bytes = 67'108'864;
inline constexpr std::string_view sft12_version             = "sft1.2";
inline constexpr std::string_view sft13_version             = "sft1.3";
inline constexpr std::string_view sft12_type                = "FIL";

enum class parallel_transfer_event_kind : uint8_t {
	Progress,
	WorkerCompleted
};

struct parallel_transfer_event {
		parallel_transfer_event_kind kind =
			parallel_transfer_event_kind::Progress;
		std::size_t worker_index    = 0;
		std::size_t total_delta     = 0;
		std::size_t completed_delta = 0;
};

struct parallel_transfer_event_queue {
		void notify_progress(std::size_t total_delta,
							 std::size_t completed_delta) {
			if (total_delta == 0 && completed_delta == 0) {
				return;
			}
			{
				std::lock_guard lock(mutex);
				pending_total_delta += total_delta;
				pending_completed_delta += completed_delta;
				progress_pending = true;
			}
			cv.notify_one();
		}

		void notify_worker_completed(std::size_t index) {
			{
				std::lock_guard lock(mutex);
				completed_workers.push_back(index);
			}
			cv.notify_one();
		}

		parallel_transfer_event wait() {
			std::unique_lock lock(mutex);
			cv.wait(lock, [&]() {
				return progress_pending || !completed_workers.empty();
			});

			if (progress_pending) {
				const auto total_delta     = pending_total_delta;
				const auto completed_delta = pending_completed_delta;
				pending_total_delta        = 0;
				pending_completed_delta    = 0;
				progress_pending           = false;
				return {
					.kind            = parallel_transfer_event_kind::Progress,
					.total_delta     = total_delta,
					.completed_delta = completed_delta,
				};
			}

			if (!completed_workers.empty()) {
				const auto index = completed_workers.front();
				completed_workers.pop_front();
				return {
					.kind = parallel_transfer_event_kind::WorkerCompleted,
					.worker_index = index,
				};
			}

			return {
				.kind = parallel_transfer_event_kind::Progress,
			};
		}

	private:
		std::mutex              mutex;
		std::condition_variable cv;
		std::deque<std::size_t> completed_workers;
		std::size_t             pending_total_delta     = 0;
		std::size_t             pending_completed_delta = 0;
		bool                    progress_pending        = false;
};

struct parallel_transfer_progress {
		explicit parallel_transfer_progress(
			std::size_t initial_total = 0, bool preannounced_total = false,
			parallel_transfer_event_queue* event_queue = nullptr)
			: total_bytes(initial_total),
			  total_preannounced(preannounced_total), events(event_queue) {
		}

		static std::size_t byte_count(kotcpp::SizeType bytes) {
			return bytes <= 0 ? std::size_t{0}
							  : static_cast<std::size_t>(bytes);
		}

		void add_total(kotcpp::SizeType bytes) {
			if (bytes <= 0) {
				return;
			}
			const auto count = byte_count(bytes);
			if (events != nullptr) {
				events->notify_progress(count, 0);
				return;
			}
			total_bytes.fetch_add(count, std::memory_order_relaxed);
		}

		void add_completed(kotcpp::SizeType bytes) {
			if (bytes <= 0) {
				return;
			}
			const auto count = byte_count(bytes);
			if (events != nullptr) {
				events->notify_progress(0, count);
				return;
			}
			completed_bytes.fetch_add(count, std::memory_order_relaxed);
		}

		void apply_progress_event(const parallel_transfer_event& event) {
			if (event.total_delta > 0) {
				total_bytes.fetch_add(event.total_delta,
									  std::memory_order_relaxed);
			}
			if (event.completed_delta > 0) {
				completed_bytes.fetch_add(event.completed_delta,
										  std::memory_order_relaxed);
			}
		}

		void render(bool finish = false) const {
			const auto total = total_bytes.load(std::memory_order_relaxed);
			if (total == 0) {
				return;
			}

			auto completed = completed_bytes.load(std::memory_order_relaxed);
			completed      = std::min(completed, total);
			if (!finish && completed >= total) {
				completed = total - 1;
			}
			kotcpp::progress_bar_with_speed(completed, total);
		}

		std::atomic_size_t total_bytes{0};
		std::atomic_size_t completed_bytes{0};
		bool               total_preannounced = false;

	private:
		parallel_transfer_event_queue* events = nullptr;
};

inline bool wait_for_transfer_worker(std::future<bool>& worker,
									 std::string_view   context) {
	try {
		return worker.get();
	} catch (const std::exception& ex) {
		std::cerr << context << ": " << ex.what() << '\n';
		return false;
	} catch (...) {
		std::cerr << context << '\n';
		return false;
	}
}

struct transfer_request_entry {
		std::string      path;
		kotcpp::SizeType size         = 0;
		bool             is_directory = false;
};

struct transfer_request_entry_v12 {
		size_t                 id = 0;
		std::string            path;
		kotcpp::SizeType       size         = 0;
		bool                   is_directory = false;
		std::filesystem::perms permissions  = std::filesystem::perms::unknown;
};

struct send_entry_v12 {
		std::filesystem::path  local_path;
		std::string            remote_path;
		kotcpp::SizeType       size         = 0;
		bool                   is_directory = false;
		std::filesystem::perms permissions  = std::filesystem::perms::unknown;
};

inline bool is_path_separator(char c) {
	return c == '/' || c == '\\';
}

inline bool is_directory_marker(std::string_view path) {
	return !path.empty() && is_path_separator(path.back());
}

inline void normalize_remote_path_separators(std::string& path) {
	for (auto& c : path) {
		if (c == '/') {
			c = '\\';
		}
	}
}

inline unsigned permissions_to_mode(std::filesystem::perms permissions) {
	return static_cast<unsigned>(permissions) & 07777u;
}

inline std::string format_permissions(std::filesystem::perms permissions) {
	return std::format("{:04o}", permissions_to_mode(permissions));
}

inline kotcpp::Result<std::filesystem::perms>
parse_permissions(std::string_view value) {
	unsigned mode = 0;
	auto [ptr, ec] =
		std::from_chars(value.data(), value.data() + value.size(), mode, 8);
	if (ec != std::errc{} || ptr != value.data() + value.size() ||
		mode > 07777u) {
		return tl::unexpected(
			kotcpp::make_sft_error("Receive malformed file permissions."));
	}
	return static_cast<std::filesystem::perms>(mode);
}

inline std::string base64url_encode(const Byte* data, size_t size) {
	constexpr int variant = sodium_base64_VARIANT_URLSAFE_NO_PADDING;
	std::string   output(sodium_base64_ENCODED_LEN(size, variant), '\0');
	sodium_bin2base64(output.data(), output.size(), data, size, variant);
	if (auto terminator = output.find('\0'); terminator != std::string::npos) {
		output.resize(terminator);
	}
	return output;
}

inline std::string base64url_encode(std::string_view value) {
	return base64url_encode(reinterpret_cast<const Byte*>(value.data()),
							value.size());
}

inline kotcpp::Result<std::vector<Byte>>
base64url_decode(std::string_view value) {
	constexpr int     variant = sodium_base64_VARIANT_URLSAFE_NO_PADDING;
	std::vector<Byte> output((value.size() * 3) / 4 + 3);
	size_t            output_size = 0;
	const char*       end         = nullptr;
	const auto        ret =
		sodium_base642bin(output.data(), output.size(), value.data(),
						  value.size(), nullptr, &output_size, &end, variant);
	if (ret != 0 || end != value.data() + value.size()) {
		return tl::unexpected(
			kotcpp::make_sft_error("Receive malformed base64url value."));
	}
	output.resize(output_size);
	return output;
}

inline std::array<Byte, crypto_generichash_BYTES>
generic_hash(std::string_view value) {
	std::array<Byte, crypto_generichash_BYTES> hash{};
	crypto_generichash(hash.data(), hash.size(),
					   reinterpret_cast<const Byte*>(value.data()),
					   value.size(), nullptr, 0);
	return hash;
}

inline std::string generic_hash_base64url(std::string_view value) {
	const auto hash = generic_hash(value);
	return base64url_encode(hash.data(), hash.size());
}

inline std::string build_file_request(
	const std::vector<std::tuple<std::unique_ptr<kotcpp::File>, std::string>>&
		files) {
	std::string request = "sft1.1/FIL";
	for (const auto& [file, file_path] : files) {
		const auto size = (file == nullptr || !file->is_open())
							  ? kotcpp::SizeType{0}
							  : static_cast<kotcpp::SizeType>(file->size());
		request += std::format("/{}/{}", file_path, size);
	}
	return request;
}

inline std::filesystem::perms
get_path_permissions_or_unknown(const std::filesystem::path& path) {
	std::error_code ec;
	const auto      status = std::filesystem::status(path, ec);
	if (ec) {
		return std::filesystem::perms::unknown;
	}
	return status.permissions();
}

inline kotcpp::Result<kotcpp::SizeType>
get_file_size_as_size_type(const std::filesystem::path& path) {
	std::error_code ec;
	const auto      raw_size = std::filesystem::file_size(path, ec);
	if (ec) {
		return tl::unexpected(kotcpp::filesystem_error(ec));
	}
	if (raw_size > static_cast<std::uintmax_t>(
					   std::numeric_limits<kotcpp::SizeType>::max())) {
		return tl::unexpected(
			kotcpp::make_sft_error("File is too large to transfer."));
	}
	return static_cast<kotcpp::SizeType>(raw_size);
}

inline void
append_sft12_directory_entry(std::vector<send_entry_v12>& entries,
							 const std::filesystem::path& local_path,
							 std::string                  remote_path) {
	// normalize_remote_path_separators(remote_path);
	if (!is_directory_marker(remote_path)) {
		remote_path += '/';
	}
	entries.emplace_back(local_path, std::move(remote_path), 0, true,
						 get_path_permissions_or_unknown(local_path));
}

inline void append_sft12_file_entry(std::vector<send_entry_v12>& entries,
									const std::filesystem::path& local_path,
									std::string                  remote_path) {
	auto size = get_file_size_as_size_type(local_path);
	if (!size) {
		kotcpp::print_error(
			std::format("Cannot read file size: {}", local_path.string()),
			size);
		return;
	}

	// normalize_remote_path_separators(remote_path);
	entries.emplace_back(local_path, std::move(remote_path), *size, false,
						 get_path_permissions_or_unknown(local_path));
}

inline std::pair<std::vector<send_entry_v12>, size_t>
build_sft12_send_entries(const std::vector<std::string>& path_list) {
	std::vector<send_entry_v12> entries;
	size_t                      total_size = 0;

	for (const auto& path_string : path_list) {
		const std::filesystem::path path(
			is_directory_marker(path_string)
				? path_string.substr(0, path_string.size() - 1)
				: path_string);
		std::error_code ec;
		const auto      status = std::filesystem::status(path, ec);
		if (ec) {
			kotcpp::print_error(
				std::format("Cannot inspect path: {}", path.string()),
				kotcpp::Result<void>(
					tl::unexpected(kotcpp::filesystem_error(ec))));
			continue;
		}

		if (std::filesystem::is_directory(status)) {
			auto folder_name = path.filename().string();
			if (folder_name.empty()) {
				folder_name = path.lexically_normal().filename().string();
			}
			if (folder_name.empty()) {
				std::cerr << "Cannot derive folder name for: " << path << '\n';
				continue;
			}
			folder_name += '/';
			append_sft12_directory_entry(entries, path, folder_name);

			std::filesystem::recursive_directory_iterator iter(path, ec);
			if (ec) {
				kotcpp::print_error(
					std::format("Cannot scan directory: {}", path.string()),
					kotcpp::Result<void>(
						tl::unexpected(kotcpp::filesystem_error(ec))));
				continue;
			}
			const std::filesystem::recursive_directory_iterator end;
			for (; iter != end; iter.increment(ec)) {
				if (ec) {
					kotcpp::print_error(
						std::format("Cannot scan directory: {}", path.string()),
						kotcpp::Result<void>(
							tl::unexpected(kotcpp::filesystem_error(ec))));
					break;
				}

				const auto& entry = *iter;
				if (entry.is_regular_file(ec)) {
					if (ec) {
						kotcpp::print_error(
							std::format("Cannot inspect path: {}",
										entry.path().string()),
							kotcpp::Result<void>(
								tl::unexpected(kotcpp::filesystem_error(ec))));
						ec.clear();
						continue;
					}
					auto relative =
						std::filesystem::relative(entry.path(), path, ec);
					if (ec) {
						kotcpp::print_error(
							std::format("Cannot compute relative path: {}",
										entry.path().string()),
							kotcpp::Result<void>(
								tl::unexpected(kotcpp::filesystem_error(ec))));
						ec.clear();
						continue;
					}
					total_size += entry.file_size(ec);
					append_sft12_file_entry(entries, entry.path(),
											folder_name + relative.string());
				}
				else if (entry.is_directory(ec)) {
					if (ec) {
						kotcpp::print_error(
							std::format("Cannot inspect path: {}",
										entry.path().string()),
							kotcpp::Result<void>(
								tl::unexpected(kotcpp::filesystem_error(ec))));
						ec.clear();
						continue;
					}
					auto relative =
						std::filesystem::relative(entry.path(), path, ec);
					if (ec) {
						kotcpp::print_error(
							std::format("Cannot compute relative path: {}",
										entry.path().string()),
							kotcpp::Result<void>(
								tl::unexpected(kotcpp::filesystem_error(ec))));
						ec.clear();
						continue;
					}
					append_sft12_directory_entry(
						entries, entry.path(), folder_name + relative.string());
				}
			}
		}
		else if (std::filesystem::is_regular_file(status)) {
			total_size += std::filesystem::file_size(path);
			append_sft12_file_entry(entries, path, path.filename().string());
		}
		else {
			std::cerr << std::format("The target file: {} is neither a "
									 "regular file nor a directory. Ignored.\n",
									 path.string());
		}
	}
	return {entries, total_size};
}

inline std::size_t get_local_thread_count() {
	auto local_threads = std::thread::hardware_concurrency();
	return local_threads == 0 ? std::size_t{1}
							  : static_cast<std::size_t>(local_threads);
}

inline std::size_t
get_default_parallel_worker_count(std::size_t payload_file_count,
								  std::size_t configured_max = 0) {
	auto workers = std::min(get_local_thread_count(), payload_file_count);
	if (configured_max != 0) {
		workers = std::min(workers, configured_max);
	}
	return workers;
}

inline std::string random_base64url_token(std::size_t byte_count = 32) {
	std::vector<Byte> bytes(byte_count);
	randombytes_buf(bytes.data(), bytes.size());
	return base64url_encode(bytes.data(), bytes.size());
}

inline std::size_t
total_transfer_bytes(const std::vector<send_entry_v12>& entries) {
	std::size_t total = 0;
	for (const auto& entry : entries) {
		if (!entry.is_directory && entry.size > 0) {
			total += static_cast<std::size_t>(entry.size);
		}
	}
	return total;
}

} // namespace sft_detail
