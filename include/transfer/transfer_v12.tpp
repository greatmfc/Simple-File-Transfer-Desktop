#pragma once

#include "transfer_protocol.hpp"
#include "transfer_stream.tpp"

template <kotcpp::AsyncTransferTarget Target>
bool send_file_v12(Target& target, const std::vector<std::string>& files) {
	auto [entries, total_size] = sft_detail::build_sft12_send_entries(files);
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
	const auto  output_root      = std::filesystem::current_path();
	auto        pipeline_context = sft_detail::transfer_pipeline_context();

	auto        read_next_frame  = [&]() -> bool {
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
			else {
				offset = (*state).received_bytes;
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
