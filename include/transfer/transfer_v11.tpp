#pragma once

#include "transfer_protocol.hpp"
#include "transfer_stream.tpp"

template <kotcpp::AsyncTransferTarget Target>
bool send_file_v11(
	Target& target,
	const std::vector<std::tuple<std::unique_ptr<kotcpp::File>, std::string>>&
		files) {
	const auto request          = sft_detail::build_file_request(files);
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
void receive_file_v11(Target& target, std::string_view first_request,
					  const std::string* output_path = nullptr) {
	auto entries = sft_detail::parse_file_request(first_request);
	if (!entries) {
		kotcpp::print_error("Fail to parse transfer request", entries);
		return;
	}

	auto scratch          = std::vector<Byte>(sft_detail::transfer_chunk_size);
	auto pipeline_context = sft_detail::transfer_pipeline_context();
	if (!sft_detail::send_control_code(target, '1')) {
		return;
	}

	const fs::path output_root = output_path == nullptr
									 ? std::filesystem::current_path()
									 : fs::path(*output_path);
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
				  << '\n';
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

		if (!sft_detail::stream_target_to_file(target, file_output_stream,
											   entry.path, entry.size,
											   pipeline_context)) {
			return;
		}
		std::cout << '\n';
	}

	if (!sft_detail::send_control_code(target, '0')) {
		return;
	}
}
