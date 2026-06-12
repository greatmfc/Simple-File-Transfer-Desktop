#pragma once

#include "transfer_pipeline.hpp"
#include "transfer_resume.hpp"

namespace sft_detail {

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
	std::array<Byte, frame_buffer_size> buffer;
	auto                                task = target.read(buffer);
	auto                                res  = wait_for_completion(task);
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
						   std::string_view           file_path,
						   transfer_pipeline_context& pipeline_context) {
	const auto       file_size = static_cast<kotcpp::SizeType>(file.size());
	const auto       chunk_capacity = transfer_chunk_size;
	kotcpp::SizeType bytes_sent     = 0;
	kotcpp::progress_bar_with_speed(0, file_size, true);

	if (file_size == 0) {
		// kotcpp::progress_bar_with_speed(0, 0, true);
		return true;
	}

	auto& pipeline = pipeline_context.pipeline;
	pipeline.reset();
	const std::string path(file_path);
	auto reader      = pipeline_context.io_pool.submit_task([&]() -> bool {
        kotcpp::SizeType bytes_read = 0;
        while (bytes_read < file_size) {
            auto buffer = pipeline.acquire_free();
            if (buffer == nullptr) {
                return false;
            }

            const auto chunk_size =
                std::min(chunk_capacity, file_size - bytes_read);
            if (!read_file_exact(file, buffer->data.get(), chunk_size, path)) {
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
		auto write_task = target.write(buffer->data.get(), buffer->size);
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
bool stream_file_range_to_target(
	Target& target, kotcpp::File& file, std::string_view file_path,
	kotcpp::SizeType offset, kotcpp::SizeType length,
	transfer_pipeline_context&  pipeline_context,
	parallel_transfer_progress* progress = nullptr) {
	const auto file_size = static_cast<kotcpp::SizeType>(file.size());
	if (offset < 0 || length < 0 || offset > file_size ||
		length > file_size - offset) {
		std::cerr << "Receive invalid file range request.\n";
		return false;
	}

	const auto       chunk_capacity = transfer_chunk_size;
	kotcpp::SizeType bytes_sent     = 0;
	if (progress == nullptr) {
		kotcpp::progress_bar_with_speed(offset, file_size, true);
	}

	if (length == 0) {
		kotcpp::progress_bar_with_speed(file_size, file_size, true);
		return true;
	}

	auto& pipeline = pipeline_context.pipeline;
	pipeline.reset();
	const std::string path(file_path);
	auto reader      = pipeline_context.io_pool.submit_task([&]() -> bool {
        kotcpp::SizeType bytes_read = 0;
        while (bytes_read < length) {
            auto buffer = pipeline.acquire_free();
            if (buffer == nullptr) {
                return false;
            }

            const auto chunk_size =
                std::min(chunk_capacity, length - bytes_read);
            if (!read_file_at_exact(file, buffer->data.get(), chunk_size,
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
	kotcpp::SizeType reported = 0;
	while (auto buffer = pipeline.pop_ready()) {
		auto write_task = target.write(buffer->data.get(), buffer->size);
		if (!finish_exact_transfer(
				write_task, buffer->size, file_size, bytes_sent,
				std::format("Fail to send file: {}", file_path),
				[&](kotcpp::SizeType current, kotcpp::SizeType total) {
					if (progress != nullptr) {
						progress->add_completed(current - reported);
						reported = current;
						return;
					}
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
bool stream_target_range_to_file(
	Target& target, kotcpp::File& output_file, std::string_view file_path,
	kotcpp::SizeType offset, kotcpp::SizeType length,
	kotcpp::SizeType total_size, const std::filesystem::path& state_path,
	transfer_pipeline_context&  pipeline_context,
	parallel_transfer_progress* progress = nullptr) {
	if (offset < 0 || length < 0 || total_size < 0 || offset > total_size ||
		length > total_size - offset) {
		std::cerr << "Receive invalid file range.\n";
		return false;
	}

	const auto       chunk_capacity = transfer_chunk_size;
	kotcpp::SizeType bytes_received = 0;
	const auto       range_end      = offset + length;
	if (progress == nullptr) {
		kotcpp::progress_bar_with_speed(offset, total_size, true);
	}

	if (length == 0) {
		if (progress == nullptr) {
			kotcpp::progress_bar_with_speed(total_size, total_size, true);
		}
		return true;
	}

	auto& pipeline = pipeline_context.pipeline;
	pipeline.reset();
	const std::string path(file_path);
	auto writer      = pipeline_context.io_pool.submit_task([&]() -> bool {
        kotcpp::SizeType last_state_offset = offset;
        while (auto buffer = pipeline.pop_ready()) {
            if (!write_file_at_exact(output_file, buffer->data.get(),
										  buffer->size, buffer->offset, path)) {
                pipeline.cancel();
                return false;
            }
            const auto completed_offset = buffer->offset + buffer->size;
            if (completed_offset == range_end ||
                completed_offset - last_state_offset >=
                    resume_state_update_bytes) {
                if (auto state_res =
                        store_resume_state(state_path, completed_offset);
                    !state_res) {
                    kotcpp::print_error("Fail to update resume state",
											 state_res);
                    pipeline.cancel();
                    return false;
                }
                last_state_offset = completed_offset;
            }
            pipeline.release_free(std::move(buffer));
        }
        return true;
    });

	bool transfer_ok = true;
	kotcpp::SizeType reported = 0;
	while (bytes_received < length) {
		auto buffer = pipeline.acquire_free();
		if (buffer == nullptr) {
			transfer_ok = false;
			break;
		}

		const auto chunk_size =
			std::min(chunk_capacity, length - bytes_received);
		buffer->size   = chunk_size;
		buffer->offset = offset + bytes_received;
		auto read_task = target.read(buffer->data.get(), chunk_size);
		if (!finish_exact_transfer(
				read_task, chunk_size, total_size, bytes_received,
				std::format("Error while trying to receive from peer: {}",
							file_path),
				[&](kotcpp::SizeType current, kotcpp::SizeType total) {
					if (progress != nullptr) {
						progress->add_completed(current - reported);
						reported = current;
						return;
					}
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
						   std::string_view           file_path,
						   kotcpp::SizeType           file_size,
						   transfer_pipeline_context& pipeline_context) {
	const auto       chunk_capacity = transfer_chunk_size;
	kotcpp::SizeType bytes_received = 0;
	kotcpp::progress_bar_with_speed(0, file_size, true);

	if (file_size == 0) {
		kotcpp::progress_bar_with_speed(0, 0, true);
		return true;
	}

	auto& pipeline = pipeline_context.pipeline;
	pipeline.reset();
	const std::string path(file_path);
	auto writer      = pipeline_context.io_pool.submit_task([&]() -> bool {
        while (auto buffer = pipeline.pop_ready()) {
            if (!write_file_exact(output_file, buffer->data.get(), buffer->size,
									   path)) {
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
		buffer->size   = chunk_size;
		auto read_task = target.read(buffer->data.get(), chunk_size);
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

template <bool IsSFT11 = false>
inline kotcpp::Result<std::filesystem::path>
resolve_output_path(const std::filesystem::path& output_root,
					std::string_view             remote_path) {
	if (remote_path.empty()) {
		return tl::unexpected(
			kotcpp::make_sft_error("Receive empty file path in request."));
	}

	std::string normalized_path(remote_path);
#ifdef __unix__
	if constexpr (IsSFT11) {
		for (auto& c : normalized_path) {
			if (c == '\\') {
				c = '/';
			}
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
