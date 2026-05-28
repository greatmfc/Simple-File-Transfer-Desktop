#pragma once

#include "SecureSession.hpp"
#include "io.hpp"
#include <algorithm>
#include <format>
#include <string>
#include <string_view>
#include <unordered_set>
#ifdef __unix__
#include <netinet/in.h>
#else
#include <ws2def.h>
using in_port_t = uint16_t;
#endif

using std::format;
using std::string;
using std::string_view;
enum {
	DIS,
	RES,
	FIL,
	FIN
};

#define SFT_VER            0
#define SFT_TYPE           1
#define SFT_DIS_HOST       2
#define SFT_DIS_PORT       3
#define SFT_RES_HOST       2
#define SFT_RES_PORT       3
#define SFT_FIL_NAME_START 2
#define SFT_FIL_SIZE_START 3

struct sft_respond_struct {
		string      peer_name;
		sockaddr_in peer_addr;
		in_port_t   peer_port;
};

class sft_header {
	private:
		string message;

	public:
		sft_header() {
			message = "sft1.1/";
		}
		sft_header(std::string_view ver) {
			message = format("sft{}/", ver);
		}
		void set_version(const std::string_view& ver) {
			message = "sft";
			message += ver;
			message += '/';
		}
		void set_type(int type) {
			switch (type) {
			case DIS:
				message += "DIS/";
				break;
			case RES:
				message += "RES/";
				break;
			case FIL:
				message += "FIL/";
				break;
			case FIN:
				message += "FIN/";
				break;
			default:
				break;
			}
		}
		template <typename StringT = string>
		string form_discover_header(const StringT& host, uint16_t port) {
			return format("{}DIS/{}/{}\r\n", message, host, port);
		}
		template <typename StringT = string>
		string form_respond_header(const StringT& host, uint16_t port) {
			return format("{}RES/{}/{}\r\n", message, host, port);
		}
		template <typename StringT = string>
		string form_file_header(const StringT& file, size_t size) {
			return format("{0}FIL/{1}/{2}\r\n", message, file, size);
		}
		size_t size() {
			return message.size();
		}
		const string& data() {
			return message;
		}
};

namespace kotcpp {

inline fs::path get_secure_app_path(const std::string& appName) {
	fs::path baseDir;

#ifdef _WIN32
	// Windows 获取环境变量（返回的是宽字符，完美支持中文）
	const wchar_t* appData = _wgetenv(L"APPDATA");
	if (appData) {
		baseDir = fs::path(appData);
	}
	else {
		baseDir = fs::path(_wgetenv(L"USERPROFILE")) / "AppData" / "Roaming";
	}
#else
	// Linux/Unix 默认 UTF-8
	const char* home = std::getenv("HOME");
	baseDir          = fs::path(home) / ".config";
#endif

	fs::path finalPath = baseDir / appName;
	fs::create_directories(finalPath);
	return finalPath;
}

inline std::string vector_to_string(const std::vector<uint8_t>& v) {
	size_t            len = v.size() * 2 + 1;
	std::vector<char> res(len);
	sodium_bin2hex(res.data(), len, v.data(), v.size());
	return res.data();
}

class sft_identity {
	private:
		SecureKey _sec;
		PubKeyArray _pub{};

	public:
		Result<void> initialize(const string_type& sec_path,
								const string_type& pub_path) {
			File sec_file(sec_path);
			File pub_file(pub_path);

			{
				ScopedWriteAccess w(_sec);
				if (sec_file.is_exist() &&
					sec_file.size() == SessionSeckeyBytes &&
					pub_file.is_exist() &&
					pub_file.size() == SessionPubkeyBytes) {
					if (auto ret = sec_file.open_read_only(); !ret) {
						return tl::unexpected(ret.error());
					}
					if (auto ret =
							sec_file.read(_sec.data(), (SizeType)_sec.size());
						!ret) {
						return tl::unexpected(ret.error());
					}
					if (auto ret = pub_file.open_read_only(); !ret) {
						return tl::unexpected(ret.error());
					}
					if (auto ret = pub_file.read(_pub); !ret) {
						return tl::unexpected(ret.error());
					}
				}
				else {
					crypto_sign_keypair(_pub.data(), _sec.data());
					if (auto ret = sec_file.open(true); !ret) {
						return tl::unexpected(ret.error());
					}
					if (auto ret =
							sec_file.write(_sec.data(), (SizeType)_sec.size());
						!ret) {
						return tl::unexpected(ret.error());
					}
					if (auto ret = pub_file.open(true); !ret) {
						return tl::unexpected(ret.error());
					}
					if (auto ret = pub_file.write(_pub); !ret) {
						return tl::unexpected(ret.error());
					}
				}
			}

			return {};
		}

		std::unique_ptr<SessionBase> create_client_session(
			const SecureAeadAlgorithmList& algorithms =
				default_secure_aead_algorithms(),
			bool require_aead_negotiation = false) const {
			ScopedReadAccess r(_sec);
			return std::make_unique<ClientSession>(
				_pub, _sec.data(), algorithms, require_aead_negotiation);
		}

		std::unique_ptr<SessionBase> create_server_session(
			const SecureAeadAlgorithmList& algorithms =
				default_secure_aead_algorithms(),
			bool require_aead_negotiation = false) const {
			ScopedReadAccess r(_sec);
			return std::make_unique<ServerSession>(
				_pub, _sec.data(), algorithms, require_aead_negotiation);
		}

		std::string fingerprint() const {
			return get_fingerprint(_pub.data(), _pub.size());
		}
};

class known_hosts_store {
	private:
		std::unordered_set<std::string> _known_hosts;
		File                            _hosts_file;

	public:
		Result<void> initialize(const string_type& hosts_path) {
			_known_hosts.clear();
			_hosts_file = hosts_path;

			if (_hosts_file.is_exist() && _hosts_file.size() > 0) {
				if (auto ret = _hosts_file.open(); !ret) {
					return tl::unexpected(ret.error());
				}
				auto contents_res = _hosts_file.read_all_bytes();
				if (!contents_res) {
					return tl::unexpected(contents_res.error());
				}
				auto contents = str_split(contents_res.value().data(), "\n");
				for (auto content : contents) {
					auto host = std::string(content.begin(), content.end());
					if (!host.empty()) {
						_known_hosts.insert(host);
					}
				}
			}
			else if (auto ret = _hosts_file.open(true); !ret) {
				return tl::unexpected(ret.error());
			}

			return {};
		}

		bool contains(const std::string& fingerprint) const {
			return _known_hosts.contains(fingerprint);
		}

		bool ensure_trusted(const std::string& fingerprint,
							std::string_view accepted_message = {}) {
			if (this->contains(fingerprint)) {
				return true;
			}

			fmt::print("Can this key be trusted? {}\ty/N\n", fingerprint);
			char choice = std::cin.get();
			while (choice == '\n') {
				choice = std::cin.get();
			}
			std::cin.get();
			if (choice != 'y' && choice != 'Y') {
				return false;
			}

			_known_hosts.insert(fingerprint);
			if (auto ret = _hosts_file.write(fingerprint + '\n'); !ret) {
				print_error("Failed to update known_hosts", ret);
				return false;
			}

			if (!accepted_message.empty()) {
				fmt::print("{}\n", accepted_message);
			}
			return true;
		}
};

class secure_channel : public io_overloads<secure_channel> {
	private:
		tcp_socket                   _conn;
		std::unique_ptr<SessionBase> _session;

	public:
		using IoResult = Task<ResType>;
		using io_overloads<secure_channel>::read;
		using io_overloads<secure_channel>::write;

		void set_session(std::unique_ptr<SessionBase> session) {
			_session = std::move(session);
		}

		SessionBase& session() {
			return *_session;
		}

		const SessionBase& session() const {
			return *_session;
		}

		tcp_socket& socket() {
			return _conn;
		}

		const tcp_socket& socket() const {
			return _conn;
		}

		void attach_socket(tcp_socket&& socket) {
			_conn = std::move(socket);
		}

		static Error channel_error(std::string message) {
			return make_sft_error(std::move(message));
		}

		IoResult write(const Byte* buf, SizeType nbytes) const {
			if (!_conn.available() || !_session) {
				co_return tl::unexpected(
					channel_error("Cannot write: secure channel is not connected."));
			}

			std::vector<uint8_t> ciphertext;
			if (auto ret = _session->encrypt(buf, nbytes); !ret) {
				co_return tl::unexpected(channel_error(
					std::format("Cannot encrypt outgoing secure frame: {}",
								ret.error().message())));
			}
			else {
				ciphertext = std::move(ret.value());
			}

			uint64_t frameSize = ciphertext.size();
			uint64_t encryptedFrameSize =
				_session->encrypt_frame_length(frameSize);

		write_again:
			auto ret = _conn.write((const Byte*)&encryptedFrameSize,
								   sizeof(encryptedFrameSize));
			if (!ret) {
				if (ret.error() == WSAEWOULDBLOCK) {
					goto write_again;
				}
				co_return ret;
			}
			else if (ret.value() != sizeof(frameSize)) {
				co_return tl::unexpected(channel_error(
					"Failed to write complete secure frame length."));
			}

			SizeType bytesWritten = 0, bytesLeft = ciphertext.size(),
					 lastWritten = static_cast<SizeType>(
						 _session->encryption_additional_bytes());
			while (bytesLeft > 0) {
				ret = _conn.write(ciphertext.data() + bytesWritten, bytesLeft);
				[[likely]] if (!ret) {
					[[likely]] if (ret.error() == WSAEWOULDBLOCK) {
						[[likely]] if (bytesWritten >= lastWritten) {
							auto diff   = bytesWritten - lastWritten;
							lastWritten = bytesWritten;
							co_yield diff;
						}
						continue;
					}
					co_return ret;
				}
				[[unlikely]] if (ret.value() == 0) {
					co_return tl::unexpected(
						channel_error("Connection closed while writing secure frame."));
				}
				bytesWritten += ret.value();
				bytesLeft -= ret.value();
			}

			co_return bytesWritten - lastWritten;
		}

		IoResult read(Byte* buf, SizeType nbytes) const {
			if (!_conn.available() || !_session) {
				co_return tl::unexpected(
					channel_error("Cannot read: secure channel is not connected."));
			}

			SizeType headerBytesRead = 0, frameSize = 0;
			uint64_t encryptedFrameSize = 0;
			while (std::cmp_less(headerBytesRead, sizeof(encryptedFrameSize))) {
				auto ret =
					_conn.read((Byte*)(&encryptedFrameSize) + headerBytesRead,
							   sizeof(encryptedFrameSize) - headerBytesRead);
				[[likely]] if (!ret) {
					[[likely]] if (ret.error() == WSAEWOULDBLOCK) {
						co_yield 0;
						continue;
					}
					co_return ret;
				}
				[[unlikely]] if (ret.value() == 0) {
					co_return tl::unexpected(channel_error(
						"Connection closed while reading secure frame length."));
				}
				headerBytesRead += ret.value();
			}

			frameSize = _session->decrypt_frame_length(encryptedFrameSize);
			const auto encryption_overhead = static_cast<SizeType>(
				_session->encryption_additional_bytes());
			if (frameSize > nbytes + encryption_overhead ||
				frameSize == 0) {
				co_return tl::unexpected(channel_error(std::format(
					"Incoming secure frame size {} does not fit destination buffer {}.",
					frameSize, nbytes)));
			}

			std::vector<uint8_t> ciphertext(frameSize);
			SizeType bytesRead = 0, lastRead = encryption_overhead;
			while (bytesRead < frameSize) {
				auto ret = _conn.read(ciphertext.data() + bytesRead,
									  frameSize - bytesRead);
				[[likely]] if (!ret) {
					[[likely]] if (ret.error() == WSAEWOULDBLOCK) {
						[[likely]] if (bytesRead >= lastRead) {
							auto diff = bytesRead - lastRead;
							lastRead  = bytesRead;
							co_yield diff;
						}
						continue;
					}
					co_return ret;
				}
				[[unlikely]] if (ret.value() == 0) {
					co_return tl::unexpected(
						channel_error("Connection closed while reading secure frame."));
				}
				bytesRead += ret.value();
			}

			if (auto ret = _session->decrypt(ciphertext.data(),
											 ciphertext.size(), (uint8_t*)buf);
				!ret) {
				co_return tl::unexpected(channel_error(
					std::format("Cannot decrypt incoming secure frame: {}",
								ret.error().message())));
			}

			co_return bytesRead - lastRead;
		}

		void close() {
			_conn.close();
		}

		bool available() const {
			return _conn.available() && _session && _session->is_established();
		}

		int set_nonblocking() const {
			return _conn.set_nonblocking();
		}

		int set_blocking() const {
			return _conn.set_blocking();
		}
};

class sft_client : public io_overloads<sft_client> {
	private:
		sft_identity           _identity;
		known_hosts_store      _known_hosts;
		secure_channel         _channel;
		SecureAeadAlgorithmList _aead_algorithms =
			default_secure_aead_algorithms();
		bool                   _require_aead_negotiation = false;

		void reset_session() {
			_channel.set_session(_identity.create_client_session(
				_aead_algorithms, _require_aead_negotiation));
		}

	public:
		using IoResult = secure_channel::IoResult;
		using io_overloads<sft_client>::read;
		using io_overloads<sft_client>::write;

		void set_supported_encryption_algorithms(
			SecureAeadAlgorithmList algorithms) {
			_aead_algorithms =
				normalize_secure_aead_algorithms(std::move(algorithms));
		}

		void require_encryption_algorithm_negotiation(bool required = true) {
			_require_aead_negotiation = required;
		}

		Result<void> initialize(const string_type& sec_path,
								const string_type& pub_path,
								const string_type& hosts_path,
								bool print_local_fingerprint = true) {
			if (auto ret = _identity.initialize(sec_path, pub_path); !ret) {
				return ret;
			}
			if (auto ret = _known_hosts.initialize(hosts_path); !ret) {
				return ret;
			}
			this->reset_session();
			if (print_local_fingerprint) {
				fmt::println("The fingerprint of local public key is {}",
							 _identity.fingerprint());
			}
			return {};
		}

		IoResult read(Byte* buf, SizeType nbytes) const {
			return _channel.read(buf, nbytes);
		}

		IoResult write(const Byte* buf, SizeType nbytes) const {
			return _channel.write(buf, nbytes);
		}

		void close() {
			_channel.close();
		}

		bool available() const {
			return _channel.available();
		}

		int set_nonblocking() const {
			return _channel.set_nonblocking();
		}

		int set_blocking() const {
			return _channel.set_blocking();
		}

		ResType connect(const sockaddr_in& addr) {
			this->reset_session();
			auto& conn = _channel.socket();
			auto& session = _channel.session();
			if (!conn.available()) {
				if (auto ret = conn.initialize(); !ret) {
					return ret;
				}
			}
			auto ret = conn.connect(addr);
			if (!ret) {
				return ret;
			}
			std::size_t               buf_size = generate_random_port(128, 1024);
			std::array<uint8_t, 1024> buf;
			randombytes_buf(buf.data(), buf_size);
			auto hello_msg1 = session.step1_generate_hello();
			if (hello_msg1.size() > buf.size()) {
				conn.close();
				return tl::unexpected(make_sft_error(
					"Secure client handshake hello is too large."));
			}
			buf_size = std::max(buf_size, hello_msg1.size());
			std::ranges::copy(hello_msg1, buf.begin());
			if (auto write_res =
					conn.write(buf.data(), static_cast<SizeType>(buf_size));
				!write_res) {
				conn.close();
				return write_res;
			}
			if (auto read_res = conn.read(buf); !read_res) {
				conn.close();
				return read_res;
			}
			auto res = session.step2_handle_response(
				buf, [&](const std::string& fp) {
					return _known_hosts.ensure_trusted(
						fp, "Please check the other side to accept the connection.");
				});
			if (!res) {
				conn.close();
				return tl::unexpected(make_sft_error(std::format(
					"Secure client handshake failed while handling server response: {}",
					res.error().message())));
			}
			std::vector<uint8_t> client_response = std::move(res.value());
			buf_size = generate_random_port(128, 1024);
			randombytes_buf(buf.data(), buf_size);
			if (client_response.size() > buf.size()) {
				conn.close();
				return tl::unexpected(make_sft_error(
					"Secure client handshake response is too large."));
			}
			buf_size = std::max(buf_size, client_response.size());
			std::ranges::copy(client_response, buf.begin());
			if (auto write_res =
					conn.write(buf.data(), static_cast<SizeType>(buf_size));
				!write_res) {
				conn.close();
				return write_res;
			}
			if (auto read_res = conn.read(buf); !read_res) {
				conn.close();
				return read_res;
			}
			std::vector<uint8_t> last_ok;
			if (auto decrypt_res =
					session.decrypt(
						buf.data(),
						static_cast<SizeType>(
							1 + session.encryption_additional_bytes()));
				!decrypt_res) {
				conn.close();
				return tl::unexpected(make_sft_error(std::format(
					"Secure client handshake failed: cannot decrypt final server acknowledgement: {}",
					decrypt_res.error().message())));
			}
			else {
				last_ok = std::move(decrypt_res.value());
			}
			if (last_ok[0] != 1) {
				conn.close();
				return tl::unexpected(make_sft_error(
					"Secure client handshake was rejected by peer."));
			}

			return {};
		}

		ResType connect(std::string_view ip, uint16_t port) {
			struct sockaddr_in addr{};
			addr.sin_family = AF_INET;
			auto ret        = inet_pton(AF_INET, ip.data(), &addr.sin_addr);
			if (ret <= 0) {
				if (ret == 0) {
					return tl::unexpected(make_sft_error(
						std::format("Invalid IPv4 address: {}", ip)));
				}
				capture_socket_error();
				return tl::unexpected(last_error());
			}
			addr.sin_port = htons(port);
			return this->connect(addr);
		}
};

class sft_server : public io_overloads<sft_server> {
	private:
		sft_identity           _identity;
		known_hosts_store      _known_hosts;
		secure_channel         _channel;
		SecureAeadAlgorithmList _aead_algorithms =
			default_secure_aead_algorithms();
		bool                   _require_aead_negotiation = false;

		void reset_session() {
			_channel.set_session(_identity.create_server_session(
				_aead_algorithms, _require_aead_negotiation));
		}

	public:
		using IoResult = secure_channel::IoResult;
		using io_overloads<sft_server>::read;
		using io_overloads<sft_server>::write;

		void set_supported_encryption_algorithms(
			SecureAeadAlgorithmList algorithms) {
			_aead_algorithms =
				normalize_secure_aead_algorithms(std::move(algorithms));
		}

		void require_encryption_algorithm_negotiation(bool required = true) {
			_require_aead_negotiation = required;
		}

		Result<void> initialize(const string_type& sec_path,
								const string_type& pub_path,
								const string_type& hosts_path,
								bool print_local_fingerprint = true) {
			if (auto ret = _identity.initialize(sec_path, pub_path); !ret) {
				return ret;
			}
			if (auto ret = _known_hosts.initialize(hosts_path); !ret) {
				return ret;
			}
			this->reset_session();
			if (print_local_fingerprint) {
				fmt::println("The fingerprint of local public key is {}",
							 _identity.fingerprint());
			}
			return {};
		}

		IoResult read(Byte* buf, SizeType nbytes) const {
			return _channel.read(buf, nbytes);
		}

		IoResult write(const Byte* buf, SizeType nbytes) const {
			return _channel.write(buf, nbytes);
		}

		void close() {
			_channel.close();
		}

		bool available() const {
			return _channel.available();
		}

		int set_nonblocking() const {
			return _channel.set_nonblocking();
		}

		int set_blocking() const {
			return _channel.set_blocking();
		}

		ResType listen_and_accept(tcp_socket& listner) {
			this->reset_session();
			auto accept_res = listner.accept();
			if (!accept_res) {
				return tl::unexpected(accept_res.error());
			}
			_channel.attach_socket(std::move(*accept_res));
			auto& conn = _channel.socket();
			auto& session = _channel.session();
			std::size_t               buf_size = generate_random_port(128, 1024);
			std::array<uint8_t, 1024> buf{};
			conn.set_blocking();
			auto ret = conn.read(buf);
			if (!ret) {
				return ret;
			}
			auto server_response = session.step1_handle_hello(buf);
			if (!server_response) {
				return tl::unexpected(make_sft_error(std::format(
					"Secure server handshake failed while handling client hello: {}",
					server_response.error().message())));
			}
			randombytes_buf(buf.data(), buf_size);
			if (server_response->size() > buf.size()) {
				conn.close();
				return tl::unexpected(make_sft_error(
					"Secure server handshake response is too large."));
			}
			buf_size = std::max(buf_size, server_response->size());
			std::copy(server_response->begin(), server_response->end(),
					  buf.begin());
				ret = conn.write(buf.data(), static_cast<SizeType>(buf_size));
			if (!ret) {
				return ret;
			}
			ret = conn.read(buf);
			if (!ret) {
				return ret;
			}
			auto res = session.step2_handle_auth(
				buf, [&](const std::string& fp) -> bool {
					return _known_hosts.ensure_trusted(fp);
				});
			if (!res) {
				conn.close();
				return tl::unexpected(make_sft_error(std::format(
					"Secure server handshake failed while authenticating client: {}",
					res.error().message())));
			}
			uint8_t ok     = 1;
			auto    ok_msg = session.encrypt(&ok, sizeof(ok));
			if (!ok_msg) {
				conn.close();
				return tl::unexpected(make_sft_error(std::format(
					"Secure server handshake failed: cannot encrypt final acknowledgement: {}",
					ok_msg.error().message())));
			}
			buf_size = generate_random_port(128, 1024);
			randombytes_buf(buf.data(), buf_size);
			if (ok_msg->size() > buf.size()) {
				conn.close();
				return tl::unexpected(make_sft_error(
					"Secure server handshake acknowledgement is too large."));
			}
			buf_size = std::max(buf_size, ok_msg->size());
			std::copy(ok_msg->begin(), ok_msg->end(), buf.begin());
				ret = conn.write(buf.data(), static_cast<SizeType>(buf_size));
			if (!ret) {
				return ret;
			}
			return {};
		}

		ResType listen_and_accept(uint16_t port, int n = 5) {
			tcp_socket listner;
			auto       ret = listner.listen(port, n);
			if (!ret) {
				return ret;
			}
			return this->listen_and_accept(listner);
		}
};
} // namespace kotcpp
