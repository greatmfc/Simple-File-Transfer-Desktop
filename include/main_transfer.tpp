#pragma once

#include "sftclass.hpp"
#include <array>
#include <charconv>
#include <filesystem>
#include <fstream>
#include <optional>
#include <sodium.h>

namespace sft_detail {

inline constexpr kotcpp::SizeType transfer_chunk_size = 4'194'304;

struct transfer_request_entry {
		std::string      path;
		kotcpp::SizeType size         = 0;
		bool             is_directory = false;
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

inline bool is_path_separator(char c) {
	return c == '/' || c == '\\';
}

inline bool is_directory_marker(std::string_view path) {
	return !path.empty() && is_path_separator(path.back());
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
		return tl::unexpected("Receive malformed file permissions.");
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
		return tl::unexpected("Receive malformed base64url value.");
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
		return tl::unexpected("Fail to open resume state file.");
	}

	std::string line;
	std::getline(input, line);
	constexpr std::string_view prefix = "sft1.2/FIL/STATE/";
	if (!line.starts_with(prefix)) {
		return tl::unexpected("Receive malformed resume state file.");
	}

	const auto       number = std::string_view(line).substr(prefix.size());
	kotcpp::SizeType received_bytes = 0;
	auto [ptr, parse_ec]            = std::from_chars(
        number.data(), number.data() + number.size(), received_bytes);
	if (parse_ec != std::errc{} || ptr != number.data() + number.size()) {
		return tl::unexpected("Receive malformed resume byte count.");
	}
	return transfer_resume_state{received_bytes};
}

inline kotcpp::Result<void>
store_resume_state(const std::filesystem::path& state_path,
				   kotcpp::SizeType             received_bytes) {
	std::error_code ec;
	if (!state_path.has_parent_path()) {
		std::filesystem::create_directories(state_path.parent_path(), ec);
		if (ec) {
			return tl::unexpected(kotcpp::filesystem_error(ec));
		}
	}

	std::ofstream output(state_path, std::ios::binary | std::ios::trunc);
	if (!output.is_open()) {
		return tl::unexpected("Fail to open resume state file for writing.");
	}
	output << "sft1.2/FIL/STATE/" << received_bytes << '\n';
	if (!output.good()) {
		return tl::unexpected("Fail to write resume state file.");
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

inline kotcpp::Result<std::vector<transfer_request_entry>>
parse_file_request(std::string_view request) {
	const auto fields = kotcpp::str_split(request, "/");
	if (fields.size() < 2) {
		return tl::unexpected("Receive unknown request.");
	}
	if (fields[SFT_VER] != "sft1.1" || fields[SFT_TYPE] != "FIL") {
		return tl::unexpected("Receive unsupported request header.");
	}
	if (((fields.size() - 2) % 2) != 0) {
		return tl::unexpected("Receive malformed file request.");
	}

	std::vector<transfer_request_entry> entries;
	entries.reserve((fields.size() - 2) / 2);
	for (size_t i = SFT_FIL_NAME_START; i + 1 < fields.size(); i += 2) {
		if (fields[i].empty()) {
			return tl::unexpected("Receive malformed file path in request.");
		}

		kotcpp::SizeType file_size = 0;
		auto [ptr, ec]             = std::from_chars(
            fields[i + 1].data(), fields[i + 1].data() + fields[i + 1].size(),
            file_size);
		if (ec != std::errc{} ||
			ptr != fields[i + 1].data() + fields[i + 1].size()) {
			return tl::unexpected("Receive malformed file size in request.");
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
bool stream_file_to_target(Target& target, kotcpp::File& file,
						   std::string_view   file_path,
						   std::vector<Byte>& scratch) {
	const auto file_size        = static_cast<kotcpp::SizeType>(file.size());
	const auto scratch_size     = static_cast<kotcpp::SizeType>(scratch.size());
	kotcpp::SizeType bytes_sent = 0;
	kotcpp::progress_bar_with_speed(0, file_size, true);

	while (bytes_sent < file_size) {
		const auto chunk_size = std::min(scratch_size, file_size - bytes_sent);
		if (!read_file_exact(file, scratch.data(), chunk_size, file_path)) {
			return false;
		}

		auto write_task = target.write(scratch.data(), chunk_size);
		if (!finish_exact_transfer(
				write_task, chunk_size, file_size, bytes_sent,
				std::format("Fail to send file: {}", file_path),
				[](kotcpp::SizeType current, kotcpp::SizeType total) {
					kotcpp::progress_bar_with_speed(current, total);
				})) {
			return false;
		}
	}

	if (file_size == 0) {
		kotcpp::progress_bar_with_speed(0, 0, true);
	}
	return true;
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
bool stream_target_to_file(Target& target, kotcpp::File& output_file,
						   std::string_view   file_path,
						   kotcpp::SizeType   file_size,
						   std::vector<Byte>& scratch) {
	const auto scratch_size = static_cast<kotcpp::SizeType>(scratch.size());
	kotcpp::SizeType bytes_received = 0;
	kotcpp::progress_bar_with_speed(0, file_size, true);

	while (bytes_received < file_size) {
		const auto chunk_size =
			std::min(scratch_size, file_size - bytes_received);
		auto read_task = target.read(scratch.data(), chunk_size);
		if (!finish_exact_transfer(
				read_task, chunk_size, file_size, bytes_received,
				std::format("Error while trying to receive from peer: {}",
							file_path),
				[](kotcpp::SizeType current, kotcpp::SizeType total) {
					kotcpp::progress_bar_with_speed(current, total);
				})) {
			return false;
		}

		if (!write_file_exact(output_file, scratch.data(), chunk_size,
							  file_path)) {
			return false;
		}
	}

	if (file_size == 0) {
		kotcpp::progress_bar_with_speed(0, 0, true);
	}
	return true;
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
		return tl::unexpected("Receive empty file path in request.");
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
		return tl::unexpected("Receive invalid file path in request.");
	}
	if (relative_path.is_absolute() || relative_path.has_root_name() ||
		relative_path.has_root_directory()) {
		return tl::unexpected("Reject absolute path from peer.");
	}
	for (const auto& component : relative_path) {
		if (component == "..") {
			return tl::unexpected("Reject parent path traversal from peer.");
		}
	}

	return (output_root / relative_path).lexically_normal();
}

} // namespace sft_detail

template <kotcpp::AsyncTransferTarget Target>
bool send_file(
	Target& target,
	const std::vector<std::tuple<std::unique_ptr<kotcpp::File>, std::string>>&
		files) {
	const auto request = sft_detail::build_file_request(files);
	auto       scratch = std::vector<Byte>(sft_detail::transfer_chunk_size);

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
											   scratch)) {
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
void receive_file(Target& target) {
	auto request_buffer = std::vector<Byte>(sft_detail::transfer_chunk_size);
	auto scratch        = std::vector<Byte>(sft_detail::transfer_chunk_size);

	target.set_blocking();
	auto request_task = target.read(request_buffer);
	auto request_res  = sft_detail::wait_for_completion(request_task);
	if (!request_res) {
		kotcpp::print_error("Fail to receive request", request_res);
		return;
	}

	const auto request_size =
		static_cast<kotcpp::SizeType>(request_res.value());
	const auto request_buffer_size =
		static_cast<kotcpp::SizeType>(request_buffer.size());
	if (request_size == 0 || request_size > request_buffer_size) {
		std::cerr << "Receive invalid request length.\n";
		return;
	}

	const auto request =
		std::string_view(reinterpret_cast<const char*>(request_buffer.data()),
						 static_cast<size_t>(request_size));
#ifdef DEBUG
	std::cout << "Receive request: " << request << std::endl;
#endif

	auto entries = sft_detail::parse_file_request(request);
	if (!entries) {
		kotcpp::print_error("Fail to parse transfer request", entries);
		return;
	}

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
				target, file_output_stream, entry.path, entry.size, scratch)) {
			return;
		}
		std::cout << '\n';
	}

	if (!sft_detail::send_control_code(target, '0')) {
		return;
	}
}
