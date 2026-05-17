#pragma once

#include "sftclass.hpp"
#include <BS_thread_pool.hpp>
#include <algorithm>
#include <array>
#include <charconv>
#include <condition_variable>
#include <deque>
#include <exception>
#include <filesystem>
#include <format>
#include <future>
#include <fstream>
#include <iostream>
#include <limits>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>
#include <sodium.h>

#ifndef SFT_PROTOCOL_ENUM_DEFINED
#define SFT_PROTOCOL_ENUM_DEFINED
enum class SftProtocol {
	V11,
	V12
};
#endif

namespace sft_detail {

inline constexpr kotcpp::SizeType transfer_chunk_size = 4'194'304;
inline constexpr std::size_t      transfer_pipeline_depth = 4;
inline constexpr std::string_view sft12_version       = "sft1.2";
inline constexpr std::string_view sft12_type          = "FIL";

struct transfer_pipeline_buffer {
		explicit transfer_pipeline_buffer(kotcpp::SizeType capacity)
			: data(static_cast<std::size_t>(capacity)) {
		}

		std::vector<Byte> data;
		kotcpp::SizeType  size   = 0;
		kotcpp::SizeType  offset = 0;
};

class transfer_pipeline_queue {
	public:
		transfer_pipeline_queue(std::size_t depth,
								kotcpp::SizeType buffer_size)
			: depth_(depth),
			  buffer_size_(buffer_size) {
			for (std::size_t i = 0; i < depth_; ++i) {
				free_buffers_.push_back(
					std::make_unique<transfer_pipeline_buffer>(buffer_size_));
			}
		}

		void reset() {
			std::lock_guard lock(mutex_);
			while (!ready_buffers_.empty()) {
				auto buffer = std::move(ready_buffers_.front());
				ready_buffers_.pop_front();
				buffer->size   = 0;
				buffer->offset = 0;
				free_buffers_.push_back(std::move(buffer));
			}
			while (free_buffers_.size() < depth_) {
				free_buffers_.push_back(
					std::make_unique<transfer_pipeline_buffer>(buffer_size_));
			}
			cancelled_    = false;
			ready_closed_ = false;
		}

		std::unique_ptr<transfer_pipeline_buffer> acquire_free() {
			std::unique_lock lock(mutex_);
			free_cv_.wait(lock, [&]() {
				return cancelled_ || !free_buffers_.empty();
			});
			if (cancelled_) {
				return nullptr;
			}

			auto buffer = std::move(free_buffers_.front());
			free_buffers_.pop_front();
			return buffer;
		}

		bool push_ready(std::unique_ptr<transfer_pipeline_buffer> buffer) {
			std::lock_guard lock(mutex_);
			if (cancelled_) {
				return false;
			}

			ready_buffers_.push_back(std::move(buffer));
			ready_cv_.notify_one();
			return true;
		}

		std::unique_ptr<transfer_pipeline_buffer> pop_ready() {
			std::unique_lock lock(mutex_);
			ready_cv_.wait(lock, [&]() {
				return cancelled_ || ready_closed_ || !ready_buffers_.empty();
			});
			if (cancelled_ || ready_buffers_.empty()) {
				return nullptr;
			}

			auto buffer = std::move(ready_buffers_.front());
			ready_buffers_.pop_front();
			return buffer;
		}

		void release_free(std::unique_ptr<transfer_pipeline_buffer> buffer) {
			if (buffer == nullptr) {
				return;
			}
			buffer->size   = 0;
			buffer->offset = 0;

			std::lock_guard lock(mutex_);
			if (cancelled_) {
				return;
			}

			free_buffers_.push_back(std::move(buffer));
			free_cv_.notify_one();
		}

		void close_ready() {
			std::lock_guard lock(mutex_);
			ready_closed_ = true;
			ready_cv_.notify_all();
		}

		void cancel() {
			std::lock_guard lock(mutex_);
			cancelled_    = true;
			ready_closed_ = true;
			free_cv_.notify_all();
			ready_cv_.notify_all();
		}

	private:
		std::size_t      depth_;
		kotcpp::SizeType buffer_size_;
		std::mutex mutex_;
		std::condition_variable free_cv_;
		std::condition_variable ready_cv_;
		std::deque<std::unique_ptr<transfer_pipeline_buffer>> free_buffers_;
		std::deque<std::unique_ptr<transfer_pipeline_buffer>> ready_buffers_;
		bool cancelled_    = false;
		bool ready_closed_ = false;
};

struct transfer_pipeline_context {
		transfer_pipeline_context()
			: pipeline(transfer_pipeline_depth, transfer_chunk_size),
			  io_pool(std::size_t{1}) {
		}

		transfer_pipeline_queue pipeline;
		BS::light_thread_pool   io_pool;
};

inline bool wait_for_transfer_worker(std::future<bool>& worker,
									 std::string_view  context) {
	try {
		return worker.get();
	}
	catch (const std::exception& ex) {
		std::cerr << context << ": " << ex.what() << '\n';
		return false;
	}
	catch (...) {
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

struct transfer_resume_identity {
		std::string            path;
		kotcpp::SizeType       size        = 0;
		std::filesystem::perms permissions = std::filesystem::perms::unknown;
		std::string            extra;
};

struct transfer_resume_state {
		kotcpp::SizeType received_bytes = 0;
};

enum class frame_action {
	Req,
	Ack,
	Rej,
	Fin,
	Ok,
	Done,
	Err,
	Unknown
};

struct sft12_frame {
		frame_action                  action = frame_action::Unknown;
		std::string                   action_text;
		std::vector<std::string_view> fields;
		std::unordered_map<std::string, std::string> options;
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

inline void append_hash_field(std::string& material, std::string_view value) {
	material += std::to_string(value.size());
	material += ':';
	material += value;
	material += ';';
}

inline std::string
build_resume_identity_material(const transfer_resume_identity& identity) {
	std::string material;
	append_hash_field(material, "sft1.2-resume");
	append_hash_field(material, identity.path);
	append_hash_field(material, std::to_string(identity.size));
	append_hash_field(material,
					  identity.permissions == std::filesystem::perms::unknown
						  ? "unknown"
						  : format_permissions(identity.permissions));
	append_hash_field(material, identity.extra);
	return material;
}

inline std::string
build_resume_state_filename(const transfer_resume_identity& identity) {
	return "sft12-" +
		   generic_hash_base64url(build_resume_identity_material(identity)) +
		   ".state";
}

inline kotcpp::Result<std::filesystem::path> get_resume_state_directory() {
	std::error_code ec;
	auto            temp_root = std::filesystem::temp_directory_path(ec);
	if (ec) {
		return tl::unexpected(kotcpp::filesystem_error(ec));
	}

	auto state_dir = temp_root / "sft-resume";
	std::filesystem::create_directories(state_dir, ec);
	if (ec) {
		return tl::unexpected(kotcpp::filesystem_error(ec));
	}
	return state_dir;
}

inline kotcpp::Result<std::filesystem::path>
get_resume_state_path(const transfer_resume_identity& identity) {
	auto state_dir = get_resume_state_directory();
	if (!state_dir) {
		return tl::unexpected(state_dir.error());
	}
	return *state_dir / build_resume_state_filename(identity);
}

inline kotcpp::SizeType sanitize_resume_offset(kotcpp::SizeType received_bytes,
											   kotcpp::SizeType total_bytes) {
	if (received_bytes < 0 || received_bytes > total_bytes) {
		return 0;
	}
	return received_bytes;
}

inline kotcpp::Result<std::optional<transfer_resume_state>>
load_resume_state(const std::filesystem::path& state_path) {
	std::error_code ec;
	if (!std::filesystem::exists(state_path, ec)) {
		if (ec) {
			return tl::unexpected(kotcpp::filesystem_error(ec));
		}
		return std::nullopt;
	}

	std::ifstream input(state_path, std::ios::binary);
	if (!input.is_open()) {
		return tl::unexpected(
			kotcpp::make_sft_error("Fail to open resume state file."));
	}

	std::string line;
	std::getline(input, line);
	constexpr std::string_view prefix = "sft1.2/FIL/STATE/";
	if (!line.starts_with(prefix)) {
		return tl::unexpected(
			kotcpp::make_sft_error("Receive malformed resume state file."));
	}

	const auto       number = std::string_view(line).substr(prefix.size());
	kotcpp::SizeType received_bytes = 0;
	auto [ptr, parse_ec]            = std::from_chars(
        number.data(), number.data() + number.size(), received_bytes);
	if (parse_ec != std::errc{} || ptr != number.data() + number.size()) {
		return tl::unexpected(
			kotcpp::make_sft_error("Receive malformed resume byte count."));
	}
	return transfer_resume_state{received_bytes};
}

inline kotcpp::Result<void>
store_resume_state(const std::filesystem::path& state_path,
				   kotcpp::SizeType             received_bytes) {
	std::error_code ec;
	if (state_path.has_parent_path()) {
		std::filesystem::create_directories(state_path.parent_path(), ec);
		if (ec) {
			return tl::unexpected(kotcpp::filesystem_error(ec));
		}
	}

	std::ofstream output(state_path, std::ios::binary | std::ios::trunc);
	if (!output.is_open()) {
		return tl::unexpected(kotcpp::make_sft_error(
			"Fail to open resume state file for writing."));
	}
	output << "sft1.2/FIL/STATE/" << received_bytes << '\n';
	if (!output.good()) {
		return tl::unexpected(
			kotcpp::make_sft_error("Fail to write resume state file."));
	}
	return {};
}

inline kotcpp::Result<void>
remove_resume_state(const std::filesystem::path& state_path) {
	std::error_code ec;
	std::filesystem::remove(state_path, ec);
	if (ec) {
		return tl::unexpected(kotcpp::filesystem_error(ec));
	}
	return {};
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
	normalize_remote_path_separators(remote_path);
	if (!is_directory_marker(remote_path)) {
		remote_path += '\\';
	}
	entries.push_back({local_path, remote_path, 0, true,
					   get_path_permissions_or_unknown(local_path)});
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

	normalize_remote_path_separators(remote_path);
	entries.push_back({local_path, remote_path, *size, false,
					   get_path_permissions_or_unknown(local_path)});
}

inline std::vector<send_entry_v12>
build_sft12_send_entries(const std::vector<std::string>& path_list) {
	std::vector<send_entry_v12> entries;
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
			folder_name += '\\';
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
			append_sft12_file_entry(entries, path, path.filename().string());
		}
		else {
			std::cerr << std::format("The target file: {} is neither a "
									 "regular file nor a directory. Ignored.\n",
									 path.string());
		}
	}
	return entries;
}

inline std::string action_to_string(frame_action action) {
	switch (action) {
	case frame_action::Req:
		return "REQ";
	case frame_action::Ack:
		return "ACK";
	case frame_action::Rej:
		return "REJ";
	case frame_action::Fin:
		return "FIN";
	case frame_action::Ok:
		return "OK";
	case frame_action::Done:
		return "DONE";
	case frame_action::Err:
		return "ERR";
	default:
		return "UNKNOWN";
	}
}

inline frame_action parse_action(std::string_view action) {
	if (action == "REQ") {
		return frame_action::Req;
	}
	if (action == "ACK") {
		return frame_action::Ack;
	}
	if (action == "REJ") {
		return frame_action::Rej;
	}
	if (action == "FIN") {
		return frame_action::Fin;
	}
	if (action == "OK") {
		return frame_action::Ok;
	}
	if (action == "DONE") {
		return frame_action::Done;
	}
	if (action == "ERR") {
		return frame_action::Err;
	}
	return frame_action::Unknown;
}

inline bool is_sft12_frame(std::string_view frame) {
	const auto fields = kotcpp::str_split(frame, "/");
	return fields.size() >= 3 && fields[0] == sft12_version &&
		   fields[1] == sft12_type;
}

inline kotcpp::Result<size_t> parse_size_t(std::string_view value,
										   std::string_view context) {
	size_t parsed = 0;
	auto [ptr, ec] =
		std::from_chars(value.data(), value.data() + value.size(), parsed);
	if (ec != std::errc{} || ptr != value.data() + value.size()) {
		return tl::unexpected(kotcpp::make_sft_error(
			std::format("Receive malformed {}.", context)));
	}
	return parsed;
}

inline kotcpp::Result<kotcpp::SizeType>
parse_size_type(std::string_view value, std::string_view context) {
	kotcpp::SizeType parsed = 0;
	auto [ptr, ec] =
		std::from_chars(value.data(), value.data() + value.size(), parsed);
	if (ec != std::errc{} || ptr != value.data() + value.size() || parsed < 0) {
		return tl::unexpected(kotcpp::make_sft_error(
			std::format("Receive malformed {}.", context)));
	}
	return parsed;
}

inline std::string get_option(const sft12_frame& frame, std::string_view key,
							  std::string_view default_value = {}) {
	auto found = frame.options.find(std::string(key));
	if (found == frame.options.end()) {
		return std::string(default_value);
	}
	return found->second;
}

inline kotcpp::Result<kotcpp::SizeType>
get_size_option(const sft12_frame& frame, std::string_view key) {
	auto found = frame.options.find(std::string(key));
	if (found == frame.options.end()) {
		return tl::unexpected(kotcpp::make_sft_error(
			std::format("Receive missing {} option.", key)));
	}
	return parse_size_type(found->second, key);
}

inline kotcpp::Result<sft12_frame> parse_sft12_frame(std::string_view frame) {
	const auto fields = kotcpp::str_split(frame, "/");
	if (fields.size() < 3) {
		return tl::unexpected(
			kotcpp::make_sft_error("Receive malformed sft1.2 frame."));
	}
	if (fields[0] != sft12_version || fields[1] != sft12_type) {
		return tl::unexpected(
			kotcpp::make_sft_error("Receive unsupported sft1.2 frame."));
	}

	sft12_frame parsed;
	parsed.action      = parse_action(fields[2]);
	parsed.action_text = std::string(fields[2]);
	if (parsed.action == frame_action::Unknown) {
		return tl::unexpected(
			kotcpp::make_sft_error("Receive unknown sft1.2 frame action."));
	}

	for (size_t i = 3; i < fields.size(); ++i) {
		if (const auto eq = fields[i].find('='); eq != std::string_view::npos) {
			parsed.options.emplace(std::string(fields[i].substr(0, eq)),
								   std::string(fields[i].substr(eq + 1)));
		}
		else {
			parsed.fields.push_back(fields[i]);
		}
	}
	return parsed;
}

inline kotcpp::Result<std::string>
decode_base64url_string(std::string_view value, std::string_view /*context*/) {
	auto decoded = base64url_decode(value);
	if (!decoded) {
		return tl::unexpected(decoded.error());
	}
	return std::string(decoded->begin(), decoded->end());
}

inline std::string build_sft12_req(size_t id, const std::string& path,
								   kotcpp::SizeType size, bool is_directory,
								   std::filesystem::perms permissions) {
	std::string frame = std::format("sft1.2/FIL/REQ/{}/{}/{}/type={}", id,
									base64url_encode(path), size,
									is_directory ? "dir" : "file");
	if (permissions != std::filesystem::perms::unknown) {
		frame += "/mode=";
		frame += format_permissions(permissions);
	}
	return frame;
}

inline std::string build_sft12_ack(size_t id, kotcpp::SizeType offset,
								   kotcpp::SizeType length) {
	return std::format("sft1.2/FIL/ACK/{}/offset={}/length={}", id, offset,
					   length);
}

inline std::string build_sft12_rej(size_t id, std::string_view reason) {
	return std::format("sft1.2/FIL/REJ/{}/reason={}", id,
					   base64url_encode(reason));
}

inline std::string build_sft12_fin(size_t id, kotcpp::SizeType sent) {
	return std::format("sft1.2/FIL/FIN/{}/sent={}", id, sent);
}

inline std::string build_sft12_ok(size_t id) {
	return std::format("sft1.2/FIL/OK/{}", id);
}

inline std::string build_sft12_done(size_t count) {
	return std::format("sft1.2/FIL/DONE/count={}", count);
}

inline std::string build_sft12_ok_all() {
	return "sft1.2/FIL/OK/all";
}

inline std::string build_sft12_err(size_t id, std::string_view reason) {
	return std::format("sft1.2/FIL/ERR/{}/reason={}", id,
					   base64url_encode(reason));
}

inline kotcpp::Result<transfer_request_entry_v12>
parse_sft12_req(const sft12_frame& frame) {
	if (frame.action != frame_action::Req || frame.fields.size() < 3) {
		return tl::unexpected(
			kotcpp::make_sft_error("Receive malformed sft1.2 REQ frame."));
	}

	auto id = parse_size_t(frame.fields[0], "file id");
	if (!id) {
		return tl::unexpected(id.error());
	}
	auto path = decode_base64url_string(frame.fields[1], "path");
	if (!path) {
		return tl::unexpected(path.error());
	}
	auto size = parse_size_type(frame.fields[2], "file size");
	if (!size) {
		return tl::unexpected(size.error());
	}

	const auto type = get_option(frame, "type", "file");
	if (type != "file" && type != "dir") {
		return tl::unexpected(
			kotcpp::make_sft_error("Receive unsupported sft1.2 entry type."));
	}

	std::filesystem::perms permissions = std::filesystem::perms::unknown;
	if (auto found = frame.options.find("mode"); found != frame.options.end()) {
		auto parsed_permissions = parse_permissions(found->second);
		if (!parsed_permissions) {
			return tl::unexpected(parsed_permissions.error());
		}
		permissions = *parsed_permissions;
	}

	return transfer_request_entry_v12{.id           = *id,
									  .path         = *path,
									  .size         = *size,
									  .is_directory = type == "dir",
									  .permissions  = permissions};
}

inline kotcpp::Result<size_t> parse_sft12_id_field(const sft12_frame& frame,
												   std::string_view   context) {
	if (frame.fields.empty()) {
		return tl::unexpected(kotcpp::make_sft_error(
			std::format("Receive missing {} id.", context)));
	}
	return parse_size_t(frame.fields[0], context);
}

inline kotcpp::Result<std::vector<transfer_request_entry>>
parse_file_request(std::string_view request) {
	const auto fields = kotcpp::str_split(request, "/");
	if (fields.size() < 2) {
		return tl::unexpected(
			kotcpp::make_sft_error("Receive unknown request."));
	}
	if (fields[SFT_VER] != "sft1.1" || fields[SFT_TYPE] != "FIL") {
		return tl::unexpected(
			kotcpp::make_sft_error("Receive unsupported request header."));
	}
	if (((fields.size() - 2) % 2) != 0) {
		return tl::unexpected(
			kotcpp::make_sft_error("Receive malformed file request."));
	}

	std::vector<transfer_request_entry> entries;
	entries.reserve((fields.size() - 2) / 2);
	for (size_t i = SFT_FIL_NAME_START; i + 1 < fields.size(); i += 2) {
		if (fields[i].empty()) {
			return tl::unexpected(kotcpp::make_sft_error(
				"Receive malformed file path in request."));
		}

		kotcpp::SizeType file_size = 0;
		auto [ptr, ec]             = std::from_chars(
            fields[i + 1].data(), fields[i + 1].data() + fields[i + 1].size(),
            file_size);
		if (ec != std::errc{} ||
			ptr != fields[i + 1].data() + fields[i + 1].size()) {
			return tl::unexpected(kotcpp::make_sft_error(
				"Receive malformed file size in request."));
		}

		entries.push_back({std::string(fields[i]), file_size,
						   is_directory_marker(fields[i])});
	}

	return entries;
}

template <typename TaskT> kotcpp::ResType wait_for_completion(TaskT& io_task) {
	while (!io_task.done()) {
		io_task.resume();
	}
	return io_task.get();
}

template <typename TaskT, typename ProgressFn>
bool finish_exact_transfer(TaskT& io_task, kotcpp::SizeType expected_bytes,
						   kotcpp::SizeType  total_bytes,
						   kotcpp::SizeType& transferred_bytes,
						   std::string_view  error_message,
						   ProgressFn&&      on_progress) {
	kotcpp::SizeType bytes_left = expected_bytes;

	while (bytes_left > 0) {
		kotcpp::ResType step_res = -1;
		if (io_task.is_yielded()) {
			step_res = io_task.get_yielded().value();
		}
		else if (io_task.done()) {
			step_res = io_task.get();
		}
		else {
			io_task.resume();
			continue;
		}

		if (!step_res) {
			kotcpp::print_error(std::string(error_message), step_res);
			return false;
		}

		const auto step = static_cast<kotcpp::SizeType>(step_res.value());
		if (step == 0 || step > bytes_left) {
			std::cerr << error_message << '\n';
			return false;
		}

		bytes_left -= step;
		transferred_bytes += step;
		on_progress(transferred_bytes, total_bytes);

		if (bytes_left > 0) {
			io_task.resume();
		}
	}

	return true;
}

inline bool read_file_exact(kotcpp::File& file, Byte* buffer,
							kotcpp::SizeType bytes_to_read,
							std::string_view file_path) {
	kotcpp::SizeType bytes_read = 0;
	while (bytes_read < bytes_to_read) {
		auto read_res =
			file.read(buffer + bytes_read, bytes_to_read - bytes_read);
		if (!read_res) {
			kotcpp::print_error(std::format("Fail to read file: {}", file_path),
								read_res);
			return false;
		}

		const auto step = static_cast<kotcpp::SizeType>(read_res.value());
		if (step == 0) {
			std::cerr << std::format("Unexpected EOF while reading file: {}\n",
									 file_path);
			return false;
		}
		bytes_read += step;
	}

	return true;
}

inline bool read_file_at_exact(kotcpp::File& file, Byte* buffer,
							   kotcpp::SizeType bytes_to_read,
							   kotcpp::SizeType offset,
							   std::string_view file_path) {
	kotcpp::SizeType bytes_read = 0;
	while (bytes_read < bytes_to_read) {
		auto read_res =
			file.read_at(buffer + bytes_read, bytes_to_read - bytes_read,
						 offset + bytes_read);
		if (!read_res) {
			kotcpp::print_error(std::format("Fail to read file: {}", file_path),
								read_res);
			return false;
		}

		const auto step = static_cast<kotcpp::SizeType>(read_res.value());
		if (step == 0) {
			std::cerr << std::format("Unexpected EOF while reading file: {}\n",
									 file_path);
			return false;
		}
		bytes_read += step;
	}

	return true;
}

inline bool write_file_exact(kotcpp::File& file, const Byte* buffer,
							 kotcpp::SizeType bytes_to_write,
							 std::string_view file_path) {
	kotcpp::SizeType bytes_written = 0;
	while (bytes_written < bytes_to_write) {
		auto write_res =
			file.write(buffer + bytes_written, bytes_to_write - bytes_written);
		if (!write_res) {
			kotcpp::print_error(
				std::format("Error while trying to write to local: {}",
							file_path),
				write_res);
			return false;
		}

		const auto step = static_cast<kotcpp::SizeType>(write_res.value());
		if (step == 0) {
			std::cerr << std::format(
				"Short write while writing local file: {}\n", file_path);
			return false;
		}
		bytes_written += step;
	}

	return true;
}

inline bool write_file_at_exact(kotcpp::File& file, const Byte* buffer,
								kotcpp::SizeType bytes_to_write,
								kotcpp::SizeType offset,
								std::string_view file_path) {
	kotcpp::SizeType bytes_written = 0;
	while (bytes_written < bytes_to_write) {
		auto write_res = file.write_at(buffer + bytes_written,
									   bytes_to_write - bytes_written,
									   offset + bytes_written);
		if (!write_res) {
			kotcpp::print_error(
				std::format("Error while trying to write to local: {}",
							file_path),
				write_res);
			return false;
		}

		const auto step = static_cast<kotcpp::SizeType>(write_res.value());
		if (step == 0) {
			std::cerr << std::format(
				"Short write while writing local file: {}\n", file_path);
			return false;
		}
		bytes_written += step;
	}

	return true;
}

template <kotcpp::AsyncTransferTarget Target>
bool write_exact_to_target(Target& target, const Byte* buffer,
						   kotcpp::SizeType bytes_to_write,
						   std::string_view error_message) {
	if (bytes_to_write == 0) {
		return true;
	}

	kotcpp::SizeType transferred = 0;
	auto             write_task  = target.write(buffer, bytes_to_write);
	return finish_exact_transfer(write_task, bytes_to_write, bytes_to_write,
								 transferred, error_message,
								 [](kotcpp::SizeType, kotcpp::SizeType) {});
}

template <kotcpp::AsyncTransferTarget Target>
kotcpp::Result<std::string> read_control_frame(Target& target) {
	auto buffer = std::vector<Byte>(transfer_chunk_size);
	auto task   = target.read(buffer);
	auto res    = wait_for_completion(task);
	if (!res) {
		return tl::unexpected(res.error());
	}
	if (res.value() <= 0 ||
		res.value() > static_cast<kotcpp::SizeType>(buffer.size())) {
		return tl::unexpected(
			kotcpp::make_sft_error("Receive invalid control frame length."));
	}
	return std::string(reinterpret_cast<const char*>(buffer.data()),
					   static_cast<size_t>(res.value()));
}

template <kotcpp::AsyncTransferTarget Target>
bool write_control_frame(Target& target, std::string_view frame) {
	return write_exact_to_target(target,
								 reinterpret_cast<const Byte*>(frame.data()),
								 static_cast<kotcpp::SizeType>(frame.size()),
								 "Fail to send control frame");
}

template <kotcpp::AsyncTransferTarget Target>
bool stream_file_to_target(Target& target, kotcpp::File& file,
						   std::string_view file_path,
						   transfer_pipeline_context& pipeline_context) {
	const auto file_size        = static_cast<kotcpp::SizeType>(file.size());
	const auto chunk_capacity   = transfer_chunk_size;
	kotcpp::SizeType bytes_sent = 0;
	kotcpp::progress_bar_with_speed(0, file_size, true);

	if (file_size == 0) {
		kotcpp::progress_bar_with_speed(0, 0, true);
		return true;
	}

	auto& pipeline = pipeline_context.pipeline;
	pipeline.reset();
	const std::string path(file_path);
	auto reader = pipeline_context.io_pool.submit_task([&]() -> bool {
		kotcpp::SizeType bytes_read = 0;
		while (bytes_read < file_size) {
			auto buffer = pipeline.acquire_free();
			if (buffer == nullptr) {
				return false;
			}

			const auto chunk_size =
				std::min(chunk_capacity, file_size - bytes_read);
			if (!read_file_exact(file, buffer->data.data(), chunk_size, path)) {
				pipeline.cancel();
				return false;
			}

			buffer->size = chunk_size;
			bytes_read += chunk_size;
			if (!pipeline.push_ready(std::move(buffer))) {
				return false;
			}
		}
		pipeline.close_ready();
		return true;
	});

	bool transfer_ok = true;
	while (auto buffer = pipeline.pop_ready()) {
		auto write_task = target.write(buffer->data.data(), buffer->size);
		if (!finish_exact_transfer(
				write_task, buffer->size, file_size, bytes_sent,
				std::format("Fail to send file: {}", file_path),
				[](kotcpp::SizeType current, kotcpp::SizeType total) {
					kotcpp::progress_bar_with_speed(current, total);
				})) {
			transfer_ok = false;
			pipeline.cancel();
			break;
		}

		pipeline.release_free(std::move(buffer));
	}

	if (!wait_for_transfer_worker(reader, "File reader worker failed")) {
		transfer_ok = false;
	}
	return transfer_ok;
}

inline std::filesystem::perms
get_file_permissions_or_unknown(const std::unique_ptr<kotcpp::File>& file) {
	if (file == nullptr) {
		return std::filesystem::perms::unknown;
	}
	auto permissions = file->get_permissions();
	if (!permissions) {
		return std::filesystem::perms::unknown;
	}
	return *permissions;
}

template <kotcpp::AsyncTransferTarget Target>
bool stream_file_range_to_target(Target& target, kotcpp::File& file,
								 std::string_view   file_path,
								 kotcpp::SizeType   offset,
								 kotcpp::SizeType   length,
								 transfer_pipeline_context& pipeline_context) {
	const auto file_size = static_cast<kotcpp::SizeType>(file.size());
	if (offset < 0 || length < 0 || offset > file_size ||
		length > file_size - offset) {
		std::cerr << "Receive invalid file range request.\n";
		return false;
	}

	const auto chunk_capacity   = transfer_chunk_size;
	kotcpp::SizeType bytes_sent = 0;
	kotcpp::progress_bar_with_speed(offset, file_size, true);

	if (length == 0) {
		kotcpp::progress_bar_with_speed(file_size, file_size, true);
		return true;
	}

	auto& pipeline = pipeline_context.pipeline;
	pipeline.reset();
	const std::string path(file_path);
	auto reader = pipeline_context.io_pool.submit_task([&]() -> bool {
		kotcpp::SizeType bytes_read = 0;
		while (bytes_read < length) {
			auto buffer = pipeline.acquire_free();
			if (buffer == nullptr) {
				return false;
			}

			const auto chunk_size =
				std::min(chunk_capacity, length - bytes_read);
			if (!read_file_at_exact(file, buffer->data.data(), chunk_size,
									offset + bytes_read, path)) {
				pipeline.cancel();
				return false;
			}

			buffer->size = chunk_size;
			bytes_read += chunk_size;
			if (!pipeline.push_ready(std::move(buffer))) {
				return false;
			}
		}
		pipeline.close_ready();
		return true;
	});

	bool transfer_ok = true;
	while (auto buffer = pipeline.pop_ready()) {
		auto write_task = target.write(buffer->data.data(), buffer->size);
		if (!finish_exact_transfer(
				write_task, buffer->size, file_size, bytes_sent,
				std::format("Fail to send file: {}", file_path),
				[offset](kotcpp::SizeType current, kotcpp::SizeType total) {
					kotcpp::progress_bar_with_speed(offset + current, total);
				})) {
			transfer_ok = false;
			pipeline.cancel();
			break;
		}

		pipeline.release_free(std::move(buffer));
	}

	if (!wait_for_transfer_worker(reader, "File range reader worker failed")) {
		transfer_ok = false;
	}
	return transfer_ok;
}

template <kotcpp::AsyncTransferTarget Target>
bool drain_target_bytes(Target& target, kotcpp::SizeType bytes_to_drain,
						std::vector<Byte>& scratch, std::string_view context) {
	const auto scratch_size  = static_cast<kotcpp::SizeType>(scratch.size());
	kotcpp::SizeType drained = 0;
	while (drained < bytes_to_drain) {
		const auto chunk_size =
			std::min(scratch_size, bytes_to_drain - drained);
		auto read_task = target.read(scratch.data(), chunk_size);
		if (!finish_exact_transfer(
				read_task, chunk_size, bytes_to_drain, drained,
				std::format("Error while discarding payload for {}", context),
				[](kotcpp::SizeType, kotcpp::SizeType) {})) {
			return false;
		}
	}
	return true;
}

template <kotcpp::AsyncTransferTarget Target>
bool stream_target_range_to_file(Target& target, kotcpp::File& output_file,
								 std::string_view             file_path,
								 kotcpp::SizeType             offset,
								 kotcpp::SizeType             length,
								 kotcpp::SizeType             total_size,
								 const std::filesystem::path& state_path,
								 transfer_pipeline_context& pipeline_context) {
	if (offset < 0 || length < 0 || total_size < 0 || offset > total_size ||
		length > total_size - offset) {
		std::cerr << "Receive invalid file range.\n";
		return false;
	}

	const auto chunk_capacity = transfer_chunk_size;
	kotcpp::SizeType bytes_received = 0;
	kotcpp::progress_bar_with_speed(offset, total_size, true);

	if (length == 0) {
		kotcpp::progress_bar_with_speed(total_size, total_size, true);
		return true;
	}

	auto& pipeline = pipeline_context.pipeline;
	pipeline.reset();
	const std::string path(file_path);
	auto writer = pipeline_context.io_pool.submit_task([&]() -> bool {
		while (auto buffer = pipeline.pop_ready()) {
			if (!write_file_at_exact(output_file, buffer->data.data(),
									 buffer->size, buffer->offset, path)) {
				pipeline.cancel();
				return false;
			}
			if (auto state_res =
					store_resume_state(state_path, buffer->offset + buffer->size);
				!state_res) {
				kotcpp::print_error("Fail to update resume state", state_res);
				pipeline.cancel();
				return false;
			}
			pipeline.release_free(std::move(buffer));
		}
		return true;
	});

	bool transfer_ok = true;
	while (bytes_received < length) {
		auto buffer = pipeline.acquire_free();
		if (buffer == nullptr) {
			transfer_ok = false;
			break;
		}

		const auto chunk_size =
			std::min(chunk_capacity, length - bytes_received);
		buffer->size         = chunk_size;
		buffer->offset       = offset + bytes_received;
		auto read_task       = target.read(buffer->data.data(), chunk_size);
		if (!finish_exact_transfer(
				read_task, chunk_size, total_size, bytes_received,
				std::format("Error while trying to receive from peer: {}",
							file_path),
				[offset](kotcpp::SizeType current, kotcpp::SizeType total) {
					kotcpp::progress_bar_with_speed(offset + current, total);
				})) {
			transfer_ok = false;
			pipeline.close_ready();
			break;
		}

		if (!pipeline.push_ready(std::move(buffer))) {
			transfer_ok = false;
			break;
		}
	}

	if (transfer_ok) {
		pipeline.close_ready();
	}
	if (!wait_for_transfer_worker(writer, "File writer worker failed")) {
		transfer_ok = false;
	}
	return transfer_ok;
}

template <kotcpp::AsyncTransferTarget Target>
bool stream_target_to_file(Target& target, kotcpp::File& output_file,
						   std::string_view   file_path,
						   kotcpp::SizeType file_size,
						   transfer_pipeline_context& pipeline_context) {
	const auto chunk_capacity = transfer_chunk_size;
	kotcpp::SizeType bytes_received = 0;
	kotcpp::progress_bar_with_speed(0, file_size, true);

	if (file_size == 0) {
		kotcpp::progress_bar_with_speed(0, 0, true);
		return true;
	}

	auto& pipeline = pipeline_context.pipeline;
	pipeline.reset();
	const std::string path(file_path);
	auto writer = pipeline_context.io_pool.submit_task([&]() -> bool {
		while (auto buffer = pipeline.pop_ready()) {
			if (!write_file_exact(output_file, buffer->data.data(),
								  buffer->size, path)) {
				pipeline.cancel();
				return false;
			}
			pipeline.release_free(std::move(buffer));
		}
		return true;
	});

	bool transfer_ok = true;
	while (bytes_received < file_size) {
		auto buffer = pipeline.acquire_free();
		if (buffer == nullptr) {
			transfer_ok = false;
			break;
		}

		const auto chunk_size =
			std::min(chunk_capacity, file_size - bytes_received);
		buffer->size  = chunk_size;
		auto read_task = target.read(buffer->data.data(), chunk_size);
		if (!finish_exact_transfer(
				read_task, chunk_size, file_size, bytes_received,
				std::format("Error while trying to receive from peer: {}",
							file_path),
				[](kotcpp::SizeType current, kotcpp::SizeType total) {
					kotcpp::progress_bar_with_speed(current, total);
				})) {
			transfer_ok = false;
			pipeline.close_ready();
			break;
		}

		if (!pipeline.push_ready(std::move(buffer))) {
			transfer_ok = false;
			break;
		}
	}

	if (transfer_ok) {
		pipeline.close_ready();
	}
	if (!wait_for_transfer_worker(writer, "File writer worker failed")) {
		transfer_ok = false;
	}
	return transfer_ok;
}

template <kotcpp::AsyncTransferTarget Target>
bool send_control_code(Target& target, char code) {
	std::array<uint8_t, 1024> buffer{};
	const auto buffer_size = kotcpp::generate_random_port(128, 1024);
	randombytes_buf(buffer.data(), buffer_size);
	buffer[0] = static_cast<uint8_t>(code);
	return write_exact_to_target(target, buffer.data(), buffer_size,
								 "Fail to send acknowledgement");
}

template <kotcpp::AsyncTransferTarget Target>
bool receive_control_code(Target& target, char expected_code) {
	std::array<uint8_t, 1024> buffer{};
	auto                      read_task = target.read(buffer);
	auto                      read_res  = wait_for_completion(read_task);
	if (!read_res) {
		kotcpp::print_error("Error while receiving code from peer", read_res);
		return false;
	}
	if (read_res.value() <= 0 || buffer[0] != expected_code) {
		std::cerr << "Receive unexpected acknowledgement from peer.\n";
		return false;
	}
	return true;
}

inline kotcpp::Result<std::filesystem::path>
resolve_output_path(const std::filesystem::path& output_root,
					std::string_view             remote_path) {
	if (remote_path.empty()) {
		return tl::unexpected(
			kotcpp::make_sft_error("Receive empty file path in request."));
	}

	std::string normalized_path(remote_path);
#ifdef __unix__
	for (auto& c : normalized_path) {
		if (c == '\\') {
			c = '/';
		}
	}
#endif

	std::filesystem::path relative_path(normalized_path);
	relative_path = relative_path.lexically_normal();
	if (relative_path.empty()) {
		return tl::unexpected(
			kotcpp::make_sft_error("Receive invalid file path in request."));
	}
	if (relative_path.is_absolute() || relative_path.has_root_name() ||
		relative_path.has_root_directory()) {
		return tl::unexpected(
			kotcpp::make_sft_error("Reject absolute path from peer."));
	}
	for (const auto& component : relative_path) {
		if (component == "..") {
			return tl::unexpected(kotcpp::make_sft_error(
				"Reject parent path traversal from peer."));
		}
	}

	return (output_root / relative_path).lexically_normal();
}

} // namespace sft_detail

template <kotcpp::AsyncTransferTarget Target>
bool send_file_v11(
	Target& target,
	const std::vector<std::tuple<std::unique_ptr<kotcpp::File>, std::string>>&
		files) {
	const auto request = sft_detail::build_file_request(files);
	auto       pipeline_context = sft_detail::transfer_pipeline_context();

	target.set_blocking();
	if (!sft_detail::write_exact_to_target(
			target, reinterpret_cast<const Byte*>(request.data()),
			static_cast<kotcpp::SizeType>(request.size()),
			"Fail to send request")) {
		return false;
	}

	if (!sft_detail::receive_control_code(target, '1')) {
		return false;
	}

	for (const auto& [file, file_path] : files) {
		if (file == nullptr || !file->is_open()) {
			continue;
		}

		std::cout << "Sending file: " << file_path << '\n';
		if (!sft_detail::stream_file_to_target(target, *file, file_path,
											   pipeline_context)) {
			return false;
		}
		std::cout << '\n';
	}

	std::cout << "Waiting for client to complete.\n";
	if (sft_detail::receive_control_code(target, '0')) {
		std::cout << "All files have been received by the other side.\n";
	}
	else {
		std::cout << "Something unexpected happened. Please check the other "
					 "side for file integrity.\n";
	}
	return true;
}

template <kotcpp::AsyncTransferTarget Target>
void receive_file_v11(Target& target, std::string_view first_request) {
	auto entries = sft_detail::parse_file_request(first_request);
	if (!entries) {
		kotcpp::print_error("Fail to parse transfer request", entries);
		return;
	}

	auto scratch = std::vector<Byte>(sft_detail::transfer_chunk_size);
	auto pipeline_context = sft_detail::transfer_pipeline_context();
	if (!sft_detail::send_control_code(target, '1')) {
		return;
	}

	const auto output_root = std::filesystem::current_path();
	for (const auto& entry : *entries) {
		auto output_path =
			sft_detail::resolve_output_path(output_root, entry.path);
		if (!output_path) {
			kotcpp::print_error("Reject output path from peer", output_path);
			if (!sft_detail::drain_target_bytes(target, entry.size, scratch,
												entry.path)) {
				return;
			}
			continue;
		}

		if (entry.is_directory) {
			if (entry.size != 0) {
				std::cerr << "Reject directory entry with payload: "
						  << entry.path << '\n';
				if (!sft_detail::drain_target_bytes(target, entry.size, scratch,
													entry.path)) {
					return;
				}
				continue;
			}
			std::error_code ec;
			std::filesystem::create_directories(*output_path, ec);
			if (ec) {
				std::cerr << "Fail to create directory: "
						  << output_path->string() << '\n';
			}
			continue;
		}

		std::error_code ec;
		if (output_path->has_parent_path()) {
			std::filesystem::create_directories(output_path->parent_path(), ec);
			if (ec) {
				std::cerr << "Fail to create parent directory: "
						  << output_path->parent_path().string() << '\n';
				if (!sft_detail::drain_target_bytes(target, entry.size, scratch,
													entry.path)) {
					return;
				}
				continue;
			}
		}

		kotcpp::File file_output_stream(*output_path);
		std::cout << std::format("Receiving file: {}\tSize: {}",
								 output_path->string(), entry.size)
				  << std::endl;
		if (auto open_res =
				file_output_stream.open(true, kotcpp::File::iomode::WRONLY);
			!open_res) {
			kotcpp::print_error("Fail to create file", open_res);
			if (!sft_detail::drain_target_bytes(target, entry.size, scratch,
												entry.path)) {
				return;
			}
			continue;
		}

		if (!sft_detail::stream_target_to_file(
				target, file_output_stream, entry.path, entry.size,
				pipeline_context)) {
			return;
		}
		std::cout << '\n';
	}

	if (!sft_detail::send_control_code(target, '0')) {
		return;
	}
}

template <kotcpp::AsyncTransferTarget Target>
bool send_file_v12(Target& target, const std::vector<std::string>& files) {
	auto entries = sft_detail::build_sft12_send_entries(files);
	if (entries.empty()) {
		std::cerr << "No valid files to send.\n";
		return false;
	}

	auto pipeline_context = sft_detail::transfer_pipeline_context();
	target.set_blocking();

	size_t file_id = 0;
	for (const auto& entry : entries) {
		const auto req =
			sft_detail::build_sft12_req(file_id, entry.remote_path, entry.size,
										entry.is_directory, entry.permissions);
		if (!sft_detail::write_control_frame(target, req)) {
			return false;
		}

		auto response_text = sft_detail::read_control_frame(target);
		if (!response_text) {
			kotcpp::print_error("Fail to receive sft1.2 response",
								response_text);
			return false;
		}
		auto response = sft_detail::parse_sft12_frame(*response_text);
		if (!response) {
			kotcpp::print_error("Fail to parse sft1.2 response", response);
			return false;
		}

		if (response->action == sft_detail::frame_action::Rej) {
			std::cerr << "Peer rejected file: " << entry.remote_path << '\n';
			++file_id;
			continue;
		}
		if (response->action != sft_detail::frame_action::Ack) {
			std::cerr << "Receive unexpected sft1.2 response from peer.\n";
			return false;
		}

		auto ack_id = sft_detail::parse_sft12_id_field(*response, "ACK");
		if (!ack_id || *ack_id != file_id) {
			std::cerr << "Receive mismatched sft1.2 ACK from peer.\n";
			return false;
		}
		auto offset = sft_detail::get_size_option(*response, "offset");
		auto length = sft_detail::get_size_option(*response, "length");
		if (!offset || !length) {
			kotcpp::print_error("Fail to parse sft1.2 ACK",
								!offset ? offset : length);
			return false;
		}
		if (*offset > entry.size || *length > entry.size - *offset) {
			std::cerr << "Peer requested an invalid file range.\n";
			return false;
		}
		if (entry.is_directory && (*offset != 0 || *length != 0)) {
			std::cerr << "Peer requested payload for directory entry.\n";
			return false;
		}

		if (!entry.is_directory) {
			kotcpp::File file(entry.local_path);
			auto         open_res = file.open_read_only();
			if (!open_res) {
				kotcpp::print_error(std::format("Cannot open file: {}",
												entry.local_path.string()),
									open_res);
				return false;
			}

			const auto current_size =
				sft_detail::get_file_size_as_size_type(entry.local_path);
			if (!current_size) {
				kotcpp::print_error(std::format("Cannot read file size: {}",
												entry.local_path.string()),
									current_size);
				return false;
			}
			if (*current_size != entry.size) {
				std::cerr << "File changed before transfer: "
						  << entry.local_path.string() << '\n';
				return false;
			}

			std::cout << "Sending file: " << entry.remote_path << '\n';
			if (!sft_detail::stream_file_range_to_target(
					target, file, entry.remote_path, *offset, *length,
					pipeline_context)) {
				return false;
			}
			std::cout << '\n';
		}

		const auto fin = sft_detail::build_sft12_fin(file_id, *length);
		if (!sft_detail::write_control_frame(target, fin)) {
			return false;
		}

		auto ok_text = sft_detail::read_control_frame(target);
		if (!ok_text) {
			kotcpp::print_error("Fail to receive sft1.2 completion", ok_text);
			return false;
		}
		auto ok = sft_detail::parse_sft12_frame(*ok_text);
		if (!ok) {
			kotcpp::print_error("Fail to parse sft1.2 completion", ok);
			return false;
		}
		auto ok_id = sft_detail::parse_sft12_id_field(*ok, "OK");
		if (ok->action != sft_detail::frame_action::Ok || !ok_id ||
			*ok_id != file_id) {
			std::cerr << "Receive unexpected sft1.2 completion from peer.\n";
			return false;
		}

		++file_id;
	}

	if (!sft_detail::write_control_frame(
			target, sft_detail::build_sft12_done(file_id))) {
		return false;
	}
	auto done_ok_text = sft_detail::read_control_frame(target);
	if (!done_ok_text) {
		kotcpp::print_error("Fail to receive sft1.2 final completion",
							done_ok_text);
		return false;
	}
	auto done_ok = sft_detail::parse_sft12_frame(*done_ok_text);
	if (!done_ok || done_ok->action != sft_detail::frame_action::Ok ||
		done_ok->fields.empty() || done_ok->fields[0] != "all") {
		std::cerr << "Receive unexpected sft1.2 final completion.\n";
		return false;
	}

	std::cout << "All files have been received by the other side.\n";
	return true;
}

template <kotcpp::AsyncTransferTarget Target>
void receive_file_v12(Target& target, std::string_view first_frame) {
	std::string current_frame(first_frame);
	const auto  output_root = std::filesystem::current_path();
	auto        pipeline_context = sft_detail::transfer_pipeline_context();

	auto        read_next_frame = [&]() -> bool {
        auto next_frame = sft_detail::read_control_frame(target);
        if (!next_frame) {
            kotcpp::print_error("Fail to receive sft1.2 frame", next_frame);
            return false;
        }
        current_frame = std::move(*next_frame);
        return true;
	};

	while (true) {
		auto parsed_frame = sft_detail::parse_sft12_frame(current_frame);
		if (!parsed_frame) {
			kotcpp::print_error("Fail to parse sft1.2 frame", parsed_frame);
			return;
		}

		if (parsed_frame->action == sft_detail::frame_action::Done) {
			if (!sft_detail::write_control_frame(
					target, sft_detail::build_sft12_ok_all())) {
				return;
			}
			return;
		}
		if (parsed_frame->action != sft_detail::frame_action::Req) {
			std::cerr << "Receive unexpected sft1.2 frame.\n";
			return;
		}

		auto entry = sft_detail::parse_sft12_req(*parsed_frame);
		if (!entry) {
			kotcpp::print_error("Fail to parse sft1.2 request", entry);
			return;
		}

		auto reject_current = [&](std::string_view reason) {
			return sft_detail::write_control_frame(
				target, sft_detail::build_sft12_rej(entry->id, reason));
		};

		auto output_path =
			sft_detail::resolve_output_path(output_root, entry->path);
		if (!output_path) {
			kotcpp::print_error("Reject output path from peer", output_path);
			if (!reject_current(output_path.error().message())) {
				return;
			}
			if (!read_next_frame()) {
				return;
			}
			continue;
		}

		if (entry->is_directory) {
			if (entry->size != 0) {
				if (!reject_current("Directory entry must not have payload.")) {
					return;
				}
				if (!read_next_frame()) {
					return;
				}
				continue;
			}

			std::error_code ec;
			std::filesystem::create_directories(*output_path, ec);
			if (ec) {
				if (!reject_current(kotcpp::filesystem_error(ec).message())) {
					return;
				}
				if (!read_next_frame()) {
					return;
				}
				continue;
			}

			if (entry->permissions != std::filesystem::perms::unknown) {
				kotcpp::File directory(*output_path);
				(void)directory.set_permissions(entry->permissions);
			}

			if (!sft_detail::write_control_frame(
					target, sft_detail::build_sft12_ack(entry->id, 0, 0))) {
				return;
			}

			auto fin_text = sft_detail::read_control_frame(target);
			if (!fin_text) {
				kotcpp::print_error("Fail to receive sft1.2 FIN", fin_text);
				return;
			}
			auto fin = sft_detail::parse_sft12_frame(*fin_text);
			auto fin_id =
				fin ? sft_detail::parse_sft12_id_field(*fin, "FIN")
					: kotcpp::Result<size_t>(tl::unexpected(fin.error()));
			if (!fin || fin->action != sft_detail::frame_action::Fin ||
				!fin_id || *fin_id != entry->id) {
				std::cerr << "Receive unexpected sft1.2 FIN.\n";
				return;
			}
			if (!sft_detail::write_control_frame(
					target, sft_detail::build_sft12_ok(entry->id))) {
				return;
			}
			if (!read_next_frame()) {
				return;
			}
			continue;
		}

		{
			std::error_code ec;
			if (output_path->has_parent_path()) {
				std::filesystem::create_directories(output_path->parent_path(),
													ec);
				if (ec) {
					if (!reject_current(
							kotcpp::filesystem_error(ec).message())) {
						return;
					}
					if (!read_next_frame()) {
						return;
					}
					continue;
				}
			}

			sft_detail::transfer_resume_identity identity{
				.path        = entry->path,
				.size        = entry->size,
				.permissions = entry->permissions,
				.extra       = "type=file",
			};
			auto state_path = sft_detail::get_resume_state_path(identity);
			if (!state_path) {
				if (!reject_current(state_path.error().message())) {
					return;
				}
				if (!read_next_frame()) {
					return;
				}
				continue;
			}

			kotcpp::SizeType offset = 0;
			auto             state = sft_detail::load_resume_state(*state_path);
			if (!state) {
				kotcpp::print_error("Fail to load resume state", state);
				offset = 0;
			}
			else if (state->has_value()) {
				offset = (*state)->received_bytes;
			}

			if (std::filesystem::exists(*output_path, ec) && !ec) {
				const auto local_size = static_cast<kotcpp::SizeType>(
					std::filesystem::file_size(*output_path, ec));
				if (!ec) {
					offset = std::min(offset, local_size);
				}
			}
			else {
				offset = 0;
			}
			offset = sft_detail::sanitize_resume_offset(offset, entry->size);
			const auto   length = entry->size - offset;

			kotcpp::File output_file(*output_path);
			if (auto open_res = output_file.open_random_access(
					offset == 0, kotcpp::File::iomode::RDWR);
				!open_res) {
				kotcpp::print_error("Fail to create file", open_res);
				if (!reject_current(open_res.error().message())) {
					return;
				}
				if (!read_next_frame()) {
					return;
				}
				continue;
			}

			std::cout << std::format("Receiving file: {}\tSize: {}",
									 output_path->string(), entry->size)
					  << std::endl;
			if (!sft_detail::write_control_frame(
					target,
					sft_detail::build_sft12_ack(entry->id, offset, length))) {
				return;
			}

			if (!sft_detail::stream_target_range_to_file(
					target, output_file, entry->path, offset, length,
					entry->size, *state_path, pipeline_context)) {
				return;
			}
			std::cout << '\n';

			auto fin_text = sft_detail::read_control_frame(target);
			if (!fin_text) {
				kotcpp::print_error("Fail to receive sft1.2 FIN", fin_text);
				return;
			}
			auto fin = sft_detail::parse_sft12_frame(*fin_text);
			if (!fin || fin->action != sft_detail::frame_action::Fin) {
				std::cerr << "Receive unexpected sft1.2 FIN.\n";
				return;
			}
			auto fin_id = sft_detail::parse_sft12_id_field(*fin, "FIN");
			auto sent   = sft_detail::get_size_option(*fin, "sent");
			if (!fin_id || !sent || *fin_id != entry->id || *sent != length) {
				std::cerr << "Receive mismatched sft1.2 FIN.\n";
				return;
			}

			if (auto resize_res = output_file.resize(
					static_cast<std::uintmax_t>(entry->size));
				!resize_res) {
				kotcpp::print_error("Fail to resize received file", resize_res);
				return;
			}
			if (entry->permissions != std::filesystem::perms::unknown) {
				(void)output_file.set_permissions(entry->permissions);
			}
			if (auto remove_res = sft_detail::remove_resume_state(*state_path);
				!remove_res) {
				kotcpp::print_error("Fail to remove resume state", remove_res);
				return;
			}
			if (!sft_detail::write_control_frame(
					target, sft_detail::build_sft12_ok(entry->id))) {
				return;
			}
		}
		if (!read_next_frame()) {
			return;
		}
	}
}

template <kotcpp::AsyncTransferTarget Target>
bool send_file(
	Target& target,
	const std::vector<std::tuple<std::unique_ptr<kotcpp::File>, std::string>>&
				files,
	SftProtocol protocol) {
	if (protocol == SftProtocol::V11) {
		return send_file_v11(target, files);
	}
	std::cerr << "sft1.2 sender requires path strings, not pre-opened files.\n";
	return false;
}

template <kotcpp::AsyncTransferTarget Target>
void receive_file(Target& target) {
	target.set_blocking();
	auto first_frame = sft_detail::read_control_frame(target);
	if (!first_frame) {
		kotcpp::print_error("Fail to receive request", first_frame);
		return;
	}

#ifdef DEBUG
	std::cout << "Receive request: " << *first_frame << std::endl;
#endif

	if (sft_detail::is_sft12_frame(*first_frame)) {
		receive_file_v12(target, *first_frame);
	}
	else {
		receive_file_v11(target, *first_frame);
	}
}
