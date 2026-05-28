#pragma once

#ifndef SFT_PROTOCOL_ENUM_DEFINED
#define SFT_PROTOCOL_ENUM_DEFINED
enum class SftProtocol {
	V11,
	V12,
	V13
};
#endif

#include "transfer_v11.tpp"
#include "transfer_v12.tpp"
#include "transfer_v13.tpp"

template <kotcpp::AsyncTransferTarget Target>
bool send_file(
	Target& target,
	const std::vector<std::tuple<std::unique_ptr<kotcpp::File>, std::string>>&
				files,
	SftProtocol protocol) {
	if (protocol == SftProtocol::V11) {
		return send_file_v11(target, files);
	}
	std::cerr << "sft1.2/sft1.3 sender requires path strings, not "
				 "pre-opened files.\n";
	return false;
}

template <kotcpp::AsyncTransferTarget Target>
void receive_file(Target&                                      target,
				  const sft_detail::parallel_transfer_options& options) {
	target.set_blocking();
	auto first_frame = sft_detail::read_control_frame(target);
	if (!first_frame) {
		kotcpp::print_error("Fail to receive request", first_frame);
		return;
	}

#ifdef DEBUG
	std::cout << "Receive request: " << *first_frame << std::endl;
#endif

	if (sft_detail::is_sft13_frame(*first_frame)) {
		receive_file_v13_parallel(target, *first_frame, options);
	}
	else if (sft_detail::is_sft12_frame(*first_frame)) {
		receive_file_v12(target, *first_frame);
	}
	else {
		receive_file_v11(target, *first_frame);
	}
}

template <kotcpp::AsyncTransferTarget Target>
void receive_file(Target& target) {
	receive_file(target, sft_detail::parallel_transfer_options{});
}
