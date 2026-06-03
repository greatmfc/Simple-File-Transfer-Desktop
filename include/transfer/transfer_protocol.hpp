#pragma once

#include "sftclass.hpp"
#include "transfer_common.hpp"

namespace sft_detail {

enum class frame_action {
	Hello,
	Ready,
	Join,
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
	if (action == "HELLO") {
		return frame_action::Hello;
	}
	if (action == "READY") {
		return frame_action::Ready;
	}
	if (action == "JOIN") {
		return frame_action::Join;
	}
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

inline bool is_sft13_frame(std::string_view frame) {
	const auto fields = kotcpp::str_split(frame, "/");
	return fields.size() >= 3 && fields[0] == sft13_version &&
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

inline kotcpp::Result<size_t> get_size_t_option(const sft12_frame& frame,
												std::string_view   key) {
	auto found = frame.options.find(std::string(key));
	if (found == frame.options.end()) {
		return tl::unexpected(kotcpp::make_sft_error(
			std::format("Receive missing {} option.", key)));
	}
	return parse_size_t(found->second, key);
}

inline kotcpp::Result<sft12_frame> parse_sft_frame(std::string_view frame,
												   std::string_view version) {
	const auto fields = kotcpp::str_split(frame, "/");
	if (fields.size() < 3) {
		return tl::unexpected(
			kotcpp::make_sft_error("Receive malformed sft frame."));
	}
	if (fields[0] != version || fields[1] != sft12_type) {
		return tl::unexpected(
			kotcpp::make_sft_error("Receive unsupported sft frame."));
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

inline kotcpp::Result<sft12_frame> parse_sft12_frame(std::string_view frame) {
	return parse_sft_frame(frame, sft12_version);
}

inline kotcpp::Result<sft12_frame> parse_sft13_frame(std::string_view frame) {
	return parse_sft_frame(frame, sft13_version);
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

inline std::string build_sft13_hello(std::size_t             proposed_workers,
									 std::size_t             payload_files,
									 std::size_t             entry_count,
									 std::size_t             total_bytes,
									 std::optional<uint16_t> worker_port = {},
									 std::string_view        session_id  = {},
									 std::string_view worker_token       = {}) {
	auto frame =
		std::format("sft1.3/FIL/HELLO/workers={}/files={}/count={}/bytes={}",
					proposed_workers, payload_files, entry_count, total_bytes);
	if (worker_port.has_value()) {
		frame += std::format("/port={}/session={}/token={}", *worker_port,
							 session_id, worker_token);
	}
	return frame;
}

inline std::string build_sft13_ready(std::size_t             accepted_workers,
									 std::optional<uint16_t> worker_port = {},
									 std::string_view        session_id  = {},
									 std::string_view worker_token       = {}) {
	auto frame = std::format("sft1.3/FIL/READY/workers={}", accepted_workers);
	if (worker_port.has_value()) {
		frame += std::format("/port={}/session={}/token={}", *worker_port,
							 session_id, worker_token);
	}
	return frame;
}

inline std::string build_sft13_join(std::string_view session_id,
									std::string_view worker_token,
									std::size_t      worker_id) {
	return std::format("sft1.3/FIL/JOIN/session={}/token={}/worker={}",
					   session_id, worker_token, worker_id);
}

inline std::string build_sft13_req(size_t id, const std::string& path,
								   kotcpp::SizeType size, bool is_directory,
								   std::filesystem::perms permissions) {
	std::string frame = std::format("sft1.3/FIL/REQ/{}/{}/{}/type={}", id,
									base64url_encode(path), size,
									is_directory ? "dir" : "file");
	if (permissions != std::filesystem::perms::unknown) {
		frame += "/mode=";
		frame += format_permissions(permissions);
	}
	return frame;
}

inline std::string build_sft13_ack(size_t id, kotcpp::SizeType offset,
								   kotcpp::SizeType length) {
	return std::format("sft1.3/FIL/ACK/{}/offset={}/length={}", id, offset,
					   length);
}

inline std::string build_sft13_rej(size_t id, std::string_view reason) {
	return std::format("sft1.3/FIL/REJ/{}/reason={}", id,
					   base64url_encode(reason));
}

inline std::string build_sft13_fin(size_t id, kotcpp::SizeType sent) {
	return std::format("sft1.3/FIL/FIN/{}/sent={}", id, sent);
}

inline std::string build_sft13_ok(size_t id) {
	return std::format("sft1.3/FIL/OK/{}", id);
}

inline std::string build_sft13_done(std::size_t count) {
	return std::format("sft1.3/FIL/DONE/count={}", count);
}

inline std::string build_sft13_worker_done(std::size_t worker_id) {
	return std::format("sft1.3/FIL/DONE/worker={}", worker_id);
}

inline std::string build_sft13_ok_all() {
	return "sft1.3/FIL/OK/all";
}

inline std::string build_sft13_err(size_t id, std::string_view reason) {
	return std::format("sft1.3/FIL/ERR/{}/reason={}", id,
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

} // namespace sft_detail
