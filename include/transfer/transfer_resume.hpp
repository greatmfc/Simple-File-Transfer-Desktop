#pragma once

#include "transfer_common.hpp"

namespace sft_detail {

struct transfer_resume_identity {
		std::string            path;
		kotcpp::SizeType       size        = 0;
		std::filesystem::perms permissions = std::filesystem::perms::unknown;
		std::string            extra;
};

struct transfer_resume_state {
		kotcpp::SizeType received_bytes = 0;
};

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

inline kotcpp::Result<transfer_resume_state>
load_resume_state(const std::filesystem::path& state_path) {
	std::error_code ec;
	if (!std::filesystem::exists(state_path, ec)) {
		if (ec) {
			return tl::unexpected(kotcpp::filesystem_error(ec));
		}
		return transfer_resume_state{0};
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

} // namespace sft_detail
