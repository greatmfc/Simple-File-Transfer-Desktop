#include "main_transfer.tpp"

#include <chrono>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <memory>
#include <stdexcept>
#include <string>
#include <tuple>
#include <vector>
#include <sodium.h>

namespace fs = std::filesystem;

namespace {

constexpr kotcpp::SizeType kIoStep = 65'536;

void require(bool condition, const std::string& message) {
	if (!condition) {
		throw std::runtime_error(message);
	}
}

class ScopedCurrentPath {
	public:
		explicit ScopedCurrentPath(const fs::path& new_path)
			: old_path_(fs::current_path()) {
			fs::current_path(new_path);
		}

		~ScopedCurrentPath() {
			fs::current_path(old_path_);
		}

	private:
		fs::path old_path_;
};

class SendFileTarget : public kotcpp::io_overloads<SendFileTarget> {
	public:
		using kotcpp::io_overloads<SendFileTarget>::read;
		using kotcpp::io_overloads<SendFileTarget>::write;

		int set_blocking() {
			return 0;
		}

		int set_nonblocking() {
			return 0;
		}

		Task<kotcpp::ResType> read(Byte* buf, kotcpp::SizeType nbytes) const {
			require(nbytes > 0, "send_file read received zero-sized buffer");
			++read_call_count_;
			const char ack = (read_call_count_ == 1) ? '1' : '0';
			buf[0]         = static_cast<Byte>(ack);
			co_return static_cast<kotcpp::RetType>(1);
		}

		Task<kotcpp::ResType> write(const Byte* buf,
									kotcpp::SizeType nbytes) const {
			++write_call_count_;
			if (write_call_count_ == 1) {
				request_.assign(reinterpret_cast<const char*>(buf),
								static_cast<size_t>(nbytes));
				co_return static_cast<kotcpp::RetType>(nbytes);
			}

			if (nbytes == 0) {
				co_return static_cast<kotcpp::RetType>(0);
			}

			kotcpp::SizeType offset = 0;
			while (nbytes - offset > kIoStep) {
				payload_.insert(payload_.end(), buf + offset,
								buf + offset + kIoStep);
				offset += kIoStep;
				co_yield kotcpp::ResType{kIoStep};
			}

			payload_.insert(payload_.end(), buf + offset, buf + nbytes);
			co_return static_cast<kotcpp::RetType>(nbytes - offset);
		}

		const std::string& request() const {
			return request_;
		}

		const std::vector<Byte>& payload() const {
			return payload_;
		}

	private:
		mutable size_t            read_call_count_  = 0;
		mutable size_t            write_call_count_ = 0;
		mutable std::string       request_;
		mutable std::vector<Byte> payload_;
};

class ReceiveFileTarget : public kotcpp::io_overloads<ReceiveFileTarget> {
	public:
		using kotcpp::io_overloads<ReceiveFileTarget>::read;
		using kotcpp::io_overloads<ReceiveFileTarget>::write;

		ReceiveFileTarget(std::string request, std::vector<Byte> payload)
			: request_(std::move(request)), payload_(std::move(payload)) {
		}

		int set_blocking() {
			return 0;
		}

		int set_nonblocking() {
			return 0;
		}

		Task<kotcpp::ResType> read(Byte* buf, kotcpp::SizeType nbytes) const {
			if (!request_delivered_) {
				require(static_cast<size_t>(nbytes) >= request_.size(),
						"receive_file request buffer is too small");
				std::memcpy(buf, request_.data(), request_.size());
				request_delivered_ = true;
				co_return static_cast<kotcpp::RetType>(request_.size());
			}

			const auto remaining = static_cast<kotcpp::SizeType>(
				payload_.size() - payload_offset_);
			const auto bytes_this_call = std::min(nbytes, remaining);
			if (bytes_this_call == 0) {
				co_return static_cast<kotcpp::RetType>(0);
			}

			kotcpp::SizeType sent_in_call = 0;
			while (bytes_this_call - sent_in_call > kIoStep) {
				std::memcpy(buf + sent_in_call,
							payload_.data() + payload_offset_,
							static_cast<size_t>(kIoStep));
				sent_in_call += kIoStep;
				payload_offset_ += static_cast<size_t>(kIoStep);
				co_yield kotcpp::ResType{kIoStep};
			}

			const auto tail = bytes_this_call - sent_in_call;
			std::memcpy(buf + sent_in_call, payload_.data() + payload_offset_,
						static_cast<size_t>(tail));
			payload_offset_ += static_cast<size_t>(tail);
			co_return static_cast<kotcpp::RetType>(tail);
		}

		Task<kotcpp::ResType> write(const Byte* buf,
									kotcpp::SizeType nbytes) const {
			ack_history_.emplace_back(buf, buf + nbytes);
			co_return static_cast<kotcpp::RetType>(nbytes);
		}

		const std::vector<std::vector<Byte>>& ack_history() const {
			return ack_history_;
		}

	private:
		std::string                              request_;
		std::vector<Byte>                        payload_;
		mutable bool                             request_delivered_ = false;
		mutable size_t                           payload_offset_    = 0;
		mutable std::vector<std::vector<Byte>>   ack_history_;
};

std::vector<Byte> to_bytes(const std::string& value) {
	return {value.begin(), value.end()};
}

std::vector<Byte> make_patterned_bytes(size_t size) {
	std::vector<Byte> bytes(size);
	for (size_t i = 0; i < size; ++i) {
		bytes[i] = static_cast<Byte>(i % 251);
	}
	return bytes;
}

void write_bytes_to_file(const fs::path& path, const std::vector<Byte>& bytes) {
	std::ofstream output(path, std::ios::binary);
	require(output.good(), "failed to create test input file");
	if (!bytes.empty()) {
		output.write(reinterpret_cast<const char*>(bytes.data()),
					 static_cast<std::streamsize>(bytes.size()));
	}
}

std::unique_ptr<kotcpp::File> open_file_for_send(const fs::path& path) {
	auto file = std::make_unique<kotcpp::File>(path);
	auto res  = file->open_read_only();
	require(res.has_value(), "failed to open input file for send_file test");
	return file;
}

std::vector<Byte> read_file_bytes(const fs::path& path) {
	std::ifstream input(path, std::ios::binary);
	require(input.good(), "failed to open output file");
	return {std::istreambuf_iterator<char>(input),
			std::istreambuf_iterator<char>()};
}

std::string build_request_header(
	const std::vector<std::pair<std::string, size_t>>& entries) {
	std::string request = "sft1.1/FIL";
	for (const auto& [name, size] : entries) {
		request += "/" + name + "/" + std::to_string(size);
	}
	return request;
}

std::vector<Byte>
concatenate_bytes(const std::vector<std::vector<Byte>>& parts) {
	std::vector<Byte> joined;
	for (const auto& part : parts) {
		joined.insert(joined.end(), part.begin(), part.end());
	}
	return joined;
}

void require_ack_sequence(const ReceiveFileTarget& target) {
	const auto& acks = target.ack_history();
	require(acks.size() == 2, "receive_file should send two acknowledgements");
	require(!acks[0].empty() && acks[0][0] == '1',
			"receive_file handshake acknowledgement is invalid");
	require(!acks[1].empty() && acks[1][0] == '0',
			"receive_file completion acknowledgement is invalid");
}

void test_send_file_small(const fs::path& temp_root) {
	const auto     file_contents = to_bytes("hello world");
	const fs::path input_path    = temp_root / "send_small.txt";
	write_bytes_to_file(input_path, file_contents);

	std::vector<std::tuple<std::unique_ptr<kotcpp::File>, std::string>> files;
	files.emplace_back(open_file_for_send(input_path), "sample.txt");

	SendFileTarget target;
	require(send_file(target, files), "send_file small test returned false");
	require(target.request() == build_request_header({{"sample.txt", 11}}),
			"send_file generated an unexpected small-file request header");
	require(target.payload() == file_contents,
			"send_file small-file payload mismatch");
}

void test_send_file_empty(const fs::path& temp_root) {
	const fs::path input_path = temp_root / "send_empty.txt";
	write_bytes_to_file(input_path, {});

	std::vector<std::tuple<std::unique_ptr<kotcpp::File>, std::string>> files;
	files.emplace_back(open_file_for_send(input_path), "empty.txt");

	SendFileTarget target;
	require(send_file(target, files), "send_file empty test returned false");
	require(target.request() == build_request_header({{"empty.txt", 0}}),
			"send_file generated an unexpected empty-file request header");
	require(target.payload().empty(),
			"send_file should not write payload for an empty file");
}

void test_send_file_multiple(const fs::path& temp_root) {
	const auto alpha = to_bytes("alpha");
	const auto beta  = to_bytes("beta-data");

	const fs::path alpha_path = temp_root / "send_multi_alpha.txt";
	const fs::path empty_path = temp_root / "send_multi_empty.txt";
	const fs::path beta_path  = temp_root / "send_multi_beta.txt";

	write_bytes_to_file(alpha_path, alpha);
	write_bytes_to_file(empty_path, {});
	write_bytes_to_file(beta_path, beta);

	std::vector<std::tuple<std::unique_ptr<kotcpp::File>, std::string>> files;
	files.emplace_back(open_file_for_send(alpha_path), "alpha.txt");
	files.emplace_back(open_file_for_send(empty_path), "empty.txt");
	files.emplace_back(open_file_for_send(beta_path), "beta.txt");

	SendFileTarget target;
	require(send_file(target, files),
			"send_file multiple-files test returned false");
	require(target.request() == build_request_header(
								 {{"alpha.txt", alpha.size()},
								  {"empty.txt", 0},
								  {"beta.txt", beta.size()}}),
			"send_file generated an unexpected multi-file request header");
	require(target.payload() == concatenate_bytes({alpha, beta}),
			"send_file multi-file payload order mismatch");
}

void test_send_file_large(const fs::path& temp_root) {
	const auto     large_contents =
		make_patterned_bytes(static_cast<size_t>(
			sft_detail::transfer_chunk_size + 257));
	const fs::path input_path = temp_root / "send_large.bin";
	write_bytes_to_file(input_path, large_contents);

	std::vector<std::tuple<std::unique_ptr<kotcpp::File>, std::string>> files;
	files.emplace_back(open_file_for_send(input_path), "large.bin");

	SendFileTarget target;
	require(send_file(target, files), "send_file large test returned false");
	require(target.request() ==
				build_request_header({{"large.bin", large_contents.size()}}),
			"send_file generated an unexpected large-file request header");
	require(target.payload() == large_contents,
			"send_file large-file payload mismatch");
}

void test_send_file_exact_chunk(const fs::path& temp_root) {
	const auto     contents =
		make_patterned_bytes(static_cast<size_t>(
			sft_detail::transfer_chunk_size));
	const fs::path input_path = temp_root / "send_exact_chunk.bin";
	write_bytes_to_file(input_path, contents);

	std::vector<std::tuple<std::unique_ptr<kotcpp::File>, std::string>> files;
	files.emplace_back(open_file_for_send(input_path), "exact_chunk.bin");

	SendFileTarget target;
	require(send_file(target, files),
			"send_file exact-chunk test returned false");
	require(target.request() ==
				build_request_header({{"exact_chunk.bin", contents.size()}}),
			"send_file generated an unexpected exact-chunk request header");
	require(target.payload() == contents,
			"send_file exact-chunk payload mismatch");
}

void test_receive_file_small(const fs::path& temp_root) {
	const auto        file_contents = to_bytes("hello world");
	const std::string request =
		build_request_header({{"received.txt", file_contents.size()}});
	const fs::path output_dir = temp_root / "receive_small";

	fs::create_directories(output_dir);
	ScopedCurrentPath scoped_path(output_dir);

	ReceiveFileTarget target(request, file_contents);
	receive_file(target);

	const fs::path output_path = output_dir / "received.txt";
	require(fs::exists(output_path), "receive_file small test did not create file");
	require(read_file_bytes(output_path) == file_contents,
			"receive_file small-file content mismatch");
	require_ack_sequence(target);
}

void test_receive_file_empty(const fs::path& temp_root) {
	const std::string request = build_request_header({{"empty.txt", 0}});
	const fs::path    output_dir = temp_root / "receive_empty";

	fs::create_directories(output_dir);
	ScopedCurrentPath scoped_path(output_dir);

	ReceiveFileTarget target(request, {});
	receive_file(target);

	const fs::path output_path = output_dir / "empty.txt";
	require(fs::exists(output_path), "receive_file empty test did not create file");
	require(read_file_bytes(output_path).empty(),
			"receive_file empty-file output should stay empty");
	require_ack_sequence(target);
}

void test_receive_file_multiple(const fs::path& temp_root) {
	const auto alpha = to_bytes("alpha");
	const auto beta  = to_bytes("beta-data");
	const auto payload = concatenate_bytes({alpha, beta});
	const std::string request =
		build_request_header({{"alpha.txt", alpha.size()},
							  {"empty.txt", 0},
							  {"beta.txt", beta.size()}});
	const fs::path output_dir = temp_root / "receive_multiple";

	fs::create_directories(output_dir);
	ScopedCurrentPath scoped_path(output_dir);

	ReceiveFileTarget target(request, payload);
	receive_file(target);

	require(read_file_bytes(output_dir / "alpha.txt") == alpha,
			"receive_file multi-file first payload mismatch");
	require(read_file_bytes(output_dir / "empty.txt").empty(),
			"receive_file multi-file empty output should stay empty");
	require(read_file_bytes(output_dir / "beta.txt") == beta,
			"receive_file multi-file second payload mismatch");
	require_ack_sequence(target);
}

void test_receive_file_large(const fs::path& temp_root) {
	const auto large_contents =
		make_patterned_bytes(static_cast<size_t>(
			sft_detail::transfer_chunk_size + 257));
	const std::string request =
		build_request_header({{"large.bin", large_contents.size()}});
	const fs::path output_dir = temp_root / "receive_large";

	fs::create_directories(output_dir);
	ScopedCurrentPath scoped_path(output_dir);

	ReceiveFileTarget target(request, large_contents);
	receive_file(target);

	require(read_file_bytes(output_dir / "large.bin") == large_contents,
			"receive_file large-file content mismatch");
	require_ack_sequence(target);
}

void test_receive_file_exact_chunk(const fs::path& temp_root) {
	const auto contents =
		make_patterned_bytes(static_cast<size_t>(
			sft_detail::transfer_chunk_size));
	const std::string request =
		build_request_header({{"exact_chunk.bin", contents.size()}});
	const fs::path output_dir = temp_root / "receive_exact_chunk";

	fs::create_directories(output_dir);
	ScopedCurrentPath scoped_path(output_dir);

	ReceiveFileTarget target(request, contents);
	receive_file(target);

	require(read_file_bytes(output_dir / "exact_chunk.bin") == contents,
			"receive_file exact-chunk content mismatch");
	require_ack_sequence(target);
}

void test_receive_file_nested_backslash_path(const fs::path& temp_root) {
	const auto        file_contents = to_bytes("nested data");
	const std::string request =
		build_request_header({{"nested\\folder\\received.txt",
							   file_contents.size()}});
	const fs::path output_dir = temp_root / "receive_nested";

	fs::create_directories(output_dir);
	ScopedCurrentPath scoped_path(output_dir);

	ReceiveFileTarget target(request, file_contents);
	receive_file(target);

	require(read_file_bytes(output_dir / "nested" / "folder" / "received.txt") ==
				file_contents,
			"receive_file should create nested directories for backslash paths");
	require_ack_sequence(target);
}

void test_receive_file_rejects_parent_traversal(const fs::path& temp_root) {
	const auto rejected = to_bytes("blocked");
	const auto safe     = to_bytes("safe");
	const auto payload  = concatenate_bytes({rejected, safe});
	const std::string request =
		build_request_header({{"..\\escape.txt", rejected.size()},
							  {"safe.txt", safe.size()}});
	const fs::path output_dir = temp_root / "receive_traversal";

	fs::create_directories(output_dir);
	ScopedCurrentPath scoped_path(output_dir);

	ReceiveFileTarget target(request, payload);
	receive_file(target);

	require(!fs::exists(temp_root / "escape.txt"),
			"receive_file should reject parent traversal paths");
	require(read_file_bytes(output_dir / "safe.txt") == safe,
			"receive_file should continue after rejecting traversal path");
	require_ack_sequence(target);
}

void test_receive_file_invalid_request(const fs::path& temp_root) {
	const std::string request = "sft1.1/FIL/bad.txt/not-a-number";
	const fs::path    output_dir = temp_root / "receive_invalid";

	fs::create_directories(output_dir);
	ScopedCurrentPath scoped_path(output_dir);

	ReceiveFileTarget target(request, {});
	receive_file(target);

	require(target.ack_history().empty(),
			"receive_file should not acknowledge an invalid request");
	require(!fs::exists(output_dir / "bad.txt"),
			"receive_file should not create files for invalid requests");
}

void test_file_random_access_helpers(const fs::path& temp_root) {
	const fs::path path = temp_root / "random_access.bin";
	write_bytes_to_file(path, to_bytes("0123456789"));

	kotcpp::File file(path);
	require(file.open_random_access(false, kotcpp::File::iomode::RDWR)
				.has_value(),
			"failed to open file for random access");

	const auto patch = to_bytes("XYZ");
	auto       write_res =
		file.write_at(patch.data(), static_cast<kotcpp::SizeType>(patch.size()),
					  4);
	require(write_res && write_res.value() == 3,
			"write_at should write the full patch at the requested offset");

	std::array<Byte, 3> read_buf{};
	auto read_res =
		file.read_at(read_buf.data(), static_cast<kotcpp::SizeType>(read_buf.size()),
					 4);
	require(read_res && read_res.value() == 3,
			"read_at should read from the requested offset");
	require(std::vector<Byte>(read_buf.begin(), read_buf.end()) == patch,
			"read_at returned unexpected bytes");

	require(read_file_bytes(path) == to_bytes("0123XYZ789"),
			"write_at should not append when using random-access open");

	require(file.resize(6).has_value(), "resize helper failed");
	file.close();
	require(read_file_bytes(path) == to_bytes("0123XY"),
			"resize helper did not truncate the file");
}

void test_file_permission_helpers(const fs::path& temp_root) {
	const fs::path path = temp_root / "permissions.txt";
	write_bytes_to_file(path, to_bytes("mode"));

	kotcpp::File file(path);
	require(file.set_permissions(static_cast<fs::perms>(0640)).has_value(),
			"set_permissions helper failed");
	auto perms = file.get_permissions();
	require(perms.has_value(), "get_permissions helper failed");
#ifdef __unix__
	require(sft_detail::format_permissions(*perms) == "0640",
			"permission formatting should preserve POSIX permission bits");
#endif

	auto parsed = sft_detail::parse_permissions("0755");
	require(parsed.has_value(), "parse_permissions should accept octal modes");
	require(sft_detail::format_permissions(*parsed) == "0755",
			"parse_permissions returned an unexpected mode");
	require(!sft_detail::parse_permissions("8888").has_value(),
			"parse_permissions should reject invalid octal modes");
}

void test_transfer_encoding_helpers() {
	const std::string input = "nested/path with spaces.bin";
	const auto        encoded = sft_detail::base64url_encode(input);
	require(encoded.find('/') == std::string::npos,
			"base64url encoding should not contain path separators");

	auto decoded = sft_detail::base64url_decode(encoded);
	require(decoded.has_value(), "base64url_decode rejected a valid value");
	require(std::string(decoded->begin(), decoded->end()) == input,
			"base64url round trip changed the input");
	require(!sft_detail::base64url_decode("not valid?").has_value(),
			"base64url_decode should reject malformed input");

	const auto hash_a = sft_detail::generic_hash_base64url("same");
	const auto hash_b = sft_detail::generic_hash_base64url("same");
	const auto hash_c = sft_detail::generic_hash_base64url("different");
	require(hash_a == hash_b, "hash helper should be deterministic");
	require(hash_a != hash_c, "hash helper should distinguish different inputs");
}

void test_resume_state_helpers(const fs::path& temp_root) {
	sft_detail::transfer_resume_identity identity{
		.path        = "folder\\resume.bin",
		.size        = 12345,
		.permissions = static_cast<fs::perms>(0644),
		.extra       = "mtime=42",
	};
	sft_detail::transfer_resume_identity other_identity = identity;
	other_identity.size                                 = 54321;

	const auto filename = sft_detail::build_resume_state_filename(identity);
	require(filename.starts_with("sft12-") &&
			 filename.ends_with(".state"),
			"resume state filename should use the expected wrapper");
	require(filename.find('/') == std::string::npos &&
			 filename.find('\\') == std::string::npos,
			"resume state filename should be safe for a single path component");
	require(filename != sft_detail::build_resume_state_filename(other_identity),
			"resume state filename should change when identity fields change");

	const fs::path state_path = temp_root / filename;
	auto           empty_state = sft_detail::load_resume_state(state_path);
	require(empty_state.has_value() && !empty_state->has_value(),
			"missing resume state should load as empty");

	require(sft_detail::store_resume_state(state_path, 4096).has_value(),
			"store_resume_state failed");
	auto loaded = sft_detail::load_resume_state(state_path);
	require(loaded.has_value() && loaded->has_value() &&
			 (*loaded)->received_bytes == 4096,
			"load_resume_state returned an unexpected byte count");

	require(sft_detail::sanitize_resume_offset(4096, 8192) == 4096,
			"valid resume offset should be preserved");
	require(sft_detail::sanitize_resume_offset(9000, 8192) == 0,
			"oversized resume offset should be reset");
	require(sft_detail::sanitize_resume_offset(-1, 8192) == 0,
			"negative resume offset should be reset");

	require(sft_detail::remove_resume_state(state_path).has_value(),
			"remove_resume_state failed");
	auto removed_state = sft_detail::load_resume_state(state_path);
	require(removed_state.has_value() && !removed_state->has_value(),
			"removed resume state should load as empty");
}

} // namespace

int main() {
	if (sodium_init() < 0) {
		std::cerr << "Failed to initialize libsodium.\n";
		return 1;
	}

	const auto unique_suffix =
		std::to_string(std::chrono::steady_clock::now()
						   .time_since_epoch()
						   .count());
	const fs::path temp_root =
		fs::temp_directory_path() / ("main_transfer_test_" + unique_suffix);

	try {
		fs::create_directories(temp_root);
		test_send_file_small(temp_root);
		test_send_file_empty(temp_root);
		test_send_file_multiple(temp_root);
		test_send_file_large(temp_root);
		test_send_file_exact_chunk(temp_root);
		test_receive_file_small(temp_root);
		test_receive_file_empty(temp_root);
		test_receive_file_multiple(temp_root);
		test_receive_file_large(temp_root);
		test_receive_file_exact_chunk(temp_root);
		test_receive_file_nested_backslash_path(temp_root);
		test_receive_file_rejects_parent_traversal(temp_root);
		test_receive_file_invalid_request(temp_root);
		test_file_random_access_helpers(temp_root);
		test_file_permission_helpers(temp_root);
		test_transfer_encoding_helpers();
		test_resume_state_helpers(temp_root);
		fs::remove_all(temp_root);
		std::cout << "main_transfer_test passed\n";
		return 0;
	}
	catch (const std::exception& ex) {
		fs::remove_all(temp_root);
		std::cerr << "main_transfer_test failed: " << ex.what() << '\n';
		return 1;
	}
}
