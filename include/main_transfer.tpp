#pragma once

#include "sftclass.hpp"
#include <BS_thread_pool.hpp>
#include <array>
#include <charconv>
#include <future>
#include <sodium.h>

namespace sft_detail {

inline auto& transfer_thread_pool() {
	static BS::thread_pool pool(4);
	return pool;
}

inline constexpr kotcpp::SizeType transfer_chunk_size = 4'194'304;

} // namespace sft_detail

template <kotcpp::AsyncTransferTarget Target>
bool send_file(
	Target& target,
	const std::vector<std::tuple<std::unique_ptr<kotcpp::File>, std::string>>&
		files) {
	kotcpp::SizeType file_sz = 0, bytes_left = 0, have_send = 0, num = 0;
	kotcpp::RetType  ret     = -1;
	kotcpp::ResType  res     = -1;
	std::string      request = "sft1.1/FIL";
	std::array<uint8_t, 1024> ack_buf{};
	kotcpp::progress_bar_with_speed(0, 0, true);

	for (const auto& [fd, file_path] : files) {
		if (fd == nullptr || !fd->is_open()) {
			request += std::format("/{}/0", file_path);
		}
		else {
			request += std::format("/{}/{}", file_path, fd->size());
		}
	}
	target.set_blocking();
	auto sft_io_res = target.write(request);
	res             = sft_io_res.get();
	if (!res) {
		kotcpp::print_error("Fail to send request", res);
		return false;
	}
	sft_io_res = target.read(ack_buf);
	if (!sft_io_res.get() || ack_buf[0] != '1') {
		kotcpp::print_error(
			"Error while receiving code from peer in send_file");
		return false;
	}
	for (const auto& [file, file_path] : files) {
		if (file == nullptr || !file->is_open()) {
			continue;
		}
		std::cout << "Sending file: " << file_path << '\n';
		file_sz    = file->size();
		bytes_left = file_sz;
		have_send  = 0;
		if (file_sz == 0) {
			continue;
		}

		if (file_sz <= sft_detail::transfer_chunk_size) {
			auto buf = std::vector<Byte>(file_sz);
			res      = file->read(buf);
			if (!res) {
				kotcpp::print_error(
					std::format("Fail to read file: {}", file_path), res);
				return false;
			}
			sft_io_res = target.write(buf, have_send, bytes_left);
			while (bytes_left > 0) {
				if (sft_io_res.is_yielded()) {
					res = sft_io_res.get_yielded().value();
				}
				else if (sft_io_res.done()) {
					res = sft_io_res.get();
					[[unlikely]] if (!res) {
						kotcpp::print_error(
							std::format("Fail to send file: {}", file_path),
							res);
						return false;
					}
				}
				ret = res.value();
				have_send += ret;
				bytes_left -= ret;
				kotcpp::progress_bar_with_speed(have_send, file_sz);
				sft_io_res.resume();
			}
		}
		else {
			int  bufferidx = 1;
			auto buffer1   = std::make_unique_for_overwrite<Byte[]>(
                sft_detail::transfer_chunk_size);
			auto buffer2 = std::make_unique_for_overwrite<Byte[]>(
				sft_detail::transfer_chunk_size);
			std::future<kotcpp::ResType> read_res;
			Byte*                        buffer = buffer1.get();

			res = file->read(buffer1.get(), sft_detail::transfer_chunk_size);
			if (!res) {
				kotcpp::print_error(
					std::format("Fail to read file: {}. Reason: ", file_path),
					res);
				return false;
			}
			read_res = sft_detail::transfer_thread_pool().submit_task(
				[ObjectPtr = file.get(), &buffer2] {
					return ObjectPtr->read(buffer2.get(),
										   sft_detail::transfer_chunk_size);
				});
			num        = std::min(sft_detail::transfer_chunk_size, bytes_left);
			sft_io_res = target.write(buffer + have_send, num - have_send);
			while (bytes_left > 0) {
				if (sft_io_res.is_yielded()) {
					res = sft_io_res.get_yielded().value();
				}
				else if (sft_io_res.done()) {
					res = sft_io_res.get();
					[[unlikely]] if (!res) {
						kotcpp::print_error(
							std::format("Fail to send file: {}", file_path),
							res);
						break;
					}
				}
				ret = res.value();
				have_send += ret;
				bytes_left -= ret;
				kotcpp::progress_bar_with_speed(file_sz - bytes_left, file_sz);
				[[unlikely]] if (have_send == sft_detail::transfer_chunk_size) {
					read_res.wait();
					res = read_res.get();
					[[unlikely]] if (!res) {
						kotcpp::print_error(
							std::format("Fail to read file: {}", file_path),
							res);
						return false;
					}
					read_res = sft_detail::transfer_thread_pool().submit_task(
						[ObjectPtr = file.get(), buffer] {
							return ObjectPtr->read(
								buffer, sft_detail::transfer_chunk_size);
						});
					num = std::min(sft_detail::transfer_chunk_size, bytes_left);
					have_send = 0;
					buffer =
						((++bufferidx) % 2) ? buffer1.get() : buffer2.get();
					sft_io_res =
						target.write(buffer + have_send, num - have_send);
					continue;
				}
				sft_io_res.resume();
			}
		}
		std::cout << '\n';
	}

	std::cout << "Waiting for client to complete.\n";
	sft_io_res = target.read(ack_buf);
	if (sft_io_res.get() && ack_buf[0] == '0') {
		std::cout << "All files have been received by the other side.\n";
	}
	else {
		std::cout << "Something unexpected happened. Please check the other "
					 "side "
					 "for file integrity.\n";
	}
	return true;
}

template <kotcpp::AsyncTransferTarget Target>
void receive_file(Target& target) {
	std::vector<Byte>         buffer(sft_detail::transfer_chunk_size);
	kotcpp::SizeType          sizeOfFile = 0, bytesReceived = 0, bytesLeft = 0;
	kotcpp::RetType           ret = -1;
	kotcpp::ResType           res = -1;
	std::array<uint8_t, 1024> ack_buf{};
	auto buf_size = kotcpp::generate_random_port(128, 1024);

	kotcpp::progress_bar_with_speed(0, 0, true);
	target.set_blocking();
	auto sft_io_res = target.read(buffer);
	while (!sft_io_res.done()) {
		sft_io_res.resume();
	}
	res = sft_io_res.get();
	if (!res) {
		kotcpp::print_error("Fail to receive request", res);
		return;
	}
	ret           = res.value();
	auto requests = kotcpp::str_split(
		std::string_view((const char*)buffer.data(), ret), "/");
	randombytes_buf(ack_buf.data(), buf_size);
	ack_buf[0] = '1';
	target.write(ack_buf.data(), buf_size);
#ifdef DEBUG
	std::cout << "Receive request: " << (const char*)buffer.data() << std::endl;
#endif
	if (requests.size() <= 2) {
		std::cerr << "Receive unknown request.\n";
	}
	for (size_t i = SFT_FIL_NAME_START; i < requests.size() - 1; i += 2) {
		std::string file_name = "./" + std::string(requests[i]);
		std::from_chars(requests[i + 1].data(),
						requests[i + 1].data() + requests[i + 1].size(),
						sizeOfFile);
		bytesLeft     = sizeOfFile;
		bytesReceived = 0;
#ifdef __unix__
		for (auto& c : file_name) {
			if (c == '\\') {
				c = '/';
			}
		}
#endif
		if (file_name.back() == '\\' || file_name.back() == '/') {
			std::filesystem::create_directories(file_name);
			continue;
		}
		kotcpp::File file_output_stream(file_name);
		std::cout << std::format("Receiving file: {}\tSize: {}", file_name,
								 sizeOfFile)
				  << std::endl;
		if (auto open_res =
				file_output_stream.open(true, kotcpp::File::iomode::WRONLY);
			!open_res) {
			kotcpp::print_error("Fail to create file", open_res);
			sft_io_res = target.read(
				buffer.data(),
				std::min(bytesLeft, (kotcpp::SizeType)buffer.size()));
			while (true) {
				if (sft_io_res.is_yielded()) {
					res = sft_io_res.get_yielded().value();
					bytesLeft -= *res;
					sft_io_res.resume();
				}
				else if (sft_io_res.done()) {
					res = sft_io_res.get();
					[[unlikely]] if (!res) {
						kotcpp::print_error(
							"Error while trying to receive from peer", res);
						return;
					}
					bytesLeft -= *res;
					if (bytesLeft == 0) {
						break;
					}
					sft_io_res = target.read(
						buffer.data(),
						std::min(bytesLeft, (kotcpp::SizeType)buffer.size()));
				}
			}
			continue;
		}
		if (sizeOfFile == 0) {
			continue;
		}

		if (sizeOfFile <= sft_detail::transfer_chunk_size) {
			auto bufferForFile = std::vector<Byte>(sizeOfFile);
			sft_io_res = target.read(bufferForFile, bytesReceived, bytesLeft);
			while (bytesLeft > 0) {
				if (sft_io_res.is_yielded()) {
					res = sft_io_res.get_yielded().value();
				}
				else if (sft_io_res.done()) {
					res = sft_io_res.get();
					[[unlikely]] if (!res) {
						kotcpp::print_error(
							"Error while trying to receive from peer", res);
						return;
					}
				}
				ret = res.value();
				bytesReceived += ret;
				bytesLeft -= ret;
				kotcpp::progress_bar_with_speed(bytesReceived, sizeOfFile);
				sft_io_res.resume();
			}
			if (auto write_res = file_output_stream.write(bufferForFile);
				!write_res) {
				kotcpp::print_error("Error while trying to write to local",
									write_res);
				std::cout << '\n';
			}
		}
		else {
			auto buffer1 = std::make_unique_for_overwrite<Byte[]>(
				sft_detail::transfer_chunk_size);
			auto buffer2 = std::make_unique_for_overwrite<Byte[]>(
				sft_detail::transfer_chunk_size);
			kotcpp::SizeType             bytesRemain = sizeOfFile;
			auto                         num = sft_detail::transfer_chunk_size;
			int                          bufferidx     = 1;
			Byte*                        active_buffer = buffer1.get();
			std::future<kotcpp::ResType> write_res;

			sft_io_res =
				target.read(active_buffer + bytesReceived, num - bytesReceived);
			while (bytesLeft > 0) {
				if (sft_io_res.is_yielded()) {
					res = sft_io_res.get_yielded().value();
				}
				else if (sft_io_res.done()) {
					res = sft_io_res.get();
					[[unlikely]] if (!res) {
						kotcpp::print_error(
							"Error while trying to receive from peer", res);
						return;
					}
				}
				ret = res.value();
				bytesReceived += ret;
				bytesLeft -= ret;
				kotcpp::progress_bar_with_speed(sizeOfFile - bytesLeft,
												sizeOfFile);
				[[unlikely]] if (bytesReceived ==
								 sft_detail::transfer_chunk_size) {
					[[likely]] if (bufferidx != 1) {
						write_res.wait();
						res = write_res.get();
						[[unlikely]] if (!res) {
							kotcpp::print_error(
								"Error while trying to write to local", res);
							break;
						}
					}
					write_res = sft_detail::transfer_thread_pool().submit_task(
						[ObjectPtr = &file_output_stream, active_buffer] {
							return ObjectPtr->write(
								active_buffer, sft_detail::transfer_chunk_size);
						});
					num = std::min(sft_detail::transfer_chunk_size, bytesLeft);
					bytesRemain   = bytesLeft;
					bytesReceived = 0;
					active_buffer =
						((++bufferidx) % 2) ? buffer1.get() : buffer2.get();
					sft_io_res = target.read(active_buffer + bytesReceived,
											 num - bytesReceived);
					continue;
				}
				sft_io_res.resume();
			}
			write_res.wait();
			file_output_stream.write(active_buffer, bytesRemain);
		}
		std::cout << '\n';
	}

	buf_size = kotcpp::generate_random_port(128, 1024);
	randombytes_buf(ack_buf.data(), buf_size);
	ack_buf[0] = '0';
	target.write(ack_buf.data(), buf_size);
}
