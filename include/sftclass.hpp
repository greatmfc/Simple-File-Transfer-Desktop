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

// This base class guarantees transparent transmission that all encryption is
// done within the member function.
class sft_base : public basic_io<true> {

	protected:
		static inline std::unordered_set<std::string> _known_hosts;
		static inline File                            _hosts_file;
		static inline bool                            _is_init = false;
		static inline PubKeyArray                     _pub{};

		SecureKey                                     _sec;
		tcp_socket                                    _conn;
		std::unique_ptr<SessionBase>                  _session;

		Result<void> _initialize(const string_type& sec_path,
								 const string_type& pub_path,
								 const string_type& hosts_path,
								 bool               is_client) {
			File sec_file(sec_path);
			if (_is_init) {
				ScopedWriteAccess w(_sec);
				sec_file.open_read_only();
				sec_file.read(_sec.data(), _sec.size());
				if (is_client) {
					_session =
						std::make_unique<ClientSession>(_pub, _sec.data());
				}
				else {
					_session =
						std::make_unique<ServerSession>(_pub, _sec.data());
				}
				return {};
			}
			File pub_file(pub_path);

			_hosts_file = hosts_path;
			{
				ScopedWriteAccess w(_sec);
				if (sec_file.is_exist() &&
					sec_file.size() == SessionSeckeyBytes &&
					pub_file.is_exist() &&
					pub_file.size() == SessionPubkeyBytes) {
					sec_file.open_read_only();
					pub_file.open_read_only();
					sec_file.read(_sec.data(), _sec.size());
					pub_file.read(_pub);
				}
				else {
					crypto_sign_keypair(_pub.data(), _sec.data());
					sec_file.open(true);
					pub_file.open(true);
					sec_file.write(_sec.data(), _sec.size());
					pub_file.write(_pub);
				}
				if (is_client) {
					_session =
						std::make_unique<ClientSession>(_pub, _sec.data());
				}
				else {
					_session =
						std::make_unique<ServerSession>(_pub, _sec.data());
				}
			}

			if (_hosts_file.is_exist() && _hosts_file.size() > 0) {
				_hosts_file.open();
				auto ret = _hosts_file.read_all_bytes();
				if (!ret) {
					return tl::unexpected(get_error_str(ret.error()));
				}
				auto contents = str_split(ret.value().data(), "\n");
				for (auto content : contents) {
					auto host = std::string(content.begin(), content.end());
					_known_hosts.insert(host);
				}
			}
			else {
				_hosts_file.open(true);
			}
			_is_init = true;
			fmt::println("The fingerprint of local public key is {}",
						 get_fingerprint(_pub.data(), _pub.size()));
			return {};
		}

	public:
		using basic_io::read;
		using basic_io::write;

		virtual ~sft_base() = default;
		virtual Result<void> initialize(const string_type& sec_path,
										const string_type& pub_path,
										const string_type& hosts_path) = 0;

		// Yield 0 when the connection is not available
		IoResult write(const Byte* buf, SizeType nbytes) const override {
			if (!_conn.available()) {
				co_return tl::unexpected(ENOTCONN);
			}

			std::vector<uint8_t> ciphertext;
			if (auto ret = _session->encrypt(buf, nbytes); !ret) {
				co_return tl::unexpected(EBADMSG);
			}
			else {
				ciphertext = std::move(ret.value());
			}

			// 加密帧长度以隐藏真实数据大小
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
				co_return tl::unexpected(EIO);
			}

			SizeType bytesWritten = 0, bytesLeft = ciphertext.size(),
					 lastWritten = EncryptionAdditionalBytes;
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
					co_return tl::unexpected(ECONNRESET);
				}
				bytesWritten += ret.value();
				bytesLeft -= ret.value();
			}

			co_return bytesWritten - lastWritten;
		}

		// Yield bytes read when the connection is not available
		IoResult read(Byte* buf, SizeType nbytes) const override {
			if (!_conn.available()) {
				co_return tl::unexpected(ENOTCONN);
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
					co_return tl::unexpected(ECONNRESET);
				}
				headerBytesRead += ret.value();
			}

			// 解密帧长度
			frameSize = _session->decrypt_frame_length(encryptedFrameSize);

			if (frameSize > nbytes + EncryptionAdditionalBytes ||
				frameSize == 0) {
				co_return tl::unexpected(EMSGSIZE);
			}

			std::vector<uint8_t> ciphertext(frameSize);
			SizeType bytesRead = 0, lastRead = EncryptionAdditionalBytes;
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
					co_return tl::unexpected(ECONNRESET);
				}
				bytesRead += ret.value();
			}

			if (auto ret = _session->decrypt(ciphertext.data(),
											 ciphertext.size(), (uint8_t*)buf);
				!ret) {
				co_return tl::unexpected(EBADMSG);
			}

			co_return bytesRead - lastRead;
		}

		void close() override {
			_conn.close();
		}

		bool available() const override {
			return _conn.available() && _session->is_established();
		}

		int set_nonblocking() const {
			return _conn.set_nonblocking();
		}

		int set_blocking() const {
			return _conn.set_blocking();
		}
};

class sft_client : public sft_base {
	public:
		Result<void> initialize(const string_type& sec_path,
								const string_type& pub_path,
								const string_type& hosts_path) override {
			return this->_initialize(sec_path, pub_path, hosts_path, true);
		}

		ResType connect(const sockaddr_in& addr) {
			if (!_conn.available()) {
				_conn.initialize();
			}
			auto ret = _conn.connect(addr);
			if (!ret) {
				return ret;
			}
			auto buf_size = generate_random_port(128, 1024);
			std::array<uint8_t, 1024> buf;
			randombytes_buf(buf.data(), buf_size);
			auto hello_msg1 = _session->step1_generate_hello();
			std::ranges::copy(hello_msg1, buf.begin());
			_conn.write(buf.data(), buf_size);
			_conn.read(buf);
			auto res = _session->step2_handle_response(
				buf, [&](const std::string& fp) {
					if (!(_known_hosts.contains(fp))) {
						fmt::print("Can this key be trusted? {}\ty/N\n", fp);
						char choice = std::cin.get();
						while (choice == '\n') {
							choice = std::cin.get();
						}
						std::cin.get(); // Drop the '\n'
						if (choice == 'y' || choice == 'Y') {
							_known_hosts.insert(fp);
							_hosts_file.write(fp + '\n');
							fmt::print("Please check the other side to accept "
									   "the connection.\n");
							return true;
						}
						else {
							return false;
							//_conn.close();
							// return tl::unexpected(ECANCELED);
						}
					}
					else {
						return true;
					}
				});
			if (!res) {
				_conn.close();
				return tl::unexpected(ECONNABORTED);
			}
			std::vector<uint8_t> client_response = std::move(res.value());
			buf_size = generate_random_port(128, 1024);
			randombytes_buf(buf.data(), buf_size);
			std::ranges::copy(client_response, buf.begin());
			_conn.write(buf.data(), buf_size);
			_conn.read(buf);
			std::vector<uint8_t> last_ok;
			if (auto res = _session->decrypt(buf.data(),
											 1 + EncryptionAdditionalBytes);
				!res) {
				_conn.close();
				return tl::unexpected(ECONNREFUSED);
			}
			else {
				last_ok = std::move(res.value());
			}
			if (last_ok[0] != 1) {
				_conn.close();
				return tl::unexpected(ECONNREFUSED);
			}

			return {};
		}

		ResType connect(std::string_view ip, uint16_t port) {
			struct sockaddr_in addr{};
			addr.sin_family = AF_INET;
			auto ret        = inet_pton(AF_INET, ip.data(), &addr.sin_addr);
			if (ret <= 0) {
				if (ret == 0) {
					return tl::unexpected(EINVAL);
				}
				else {
					return tl::unexpected((int)GetLastError());
				}
			}
			addr.sin_port = htons(port);
			return this->connect(addr);
		}
};

class sft_server : public sft_base {
	public:
		Result<void> initialize(const string_type& sec_path,
								const string_type& pub_path,
								const string_type& hosts_path) override {
			return this->_initialize(sec_path, pub_path, hosts_path, false);
		}

		ResType listen_and_accept(tcp_socket& listner) {
			auto accept_res = listner.accept();
			if (!accept_res) {
				return tl::unexpected(accept_res.error());
			}
			_conn         = std::move(*accept_res);
			auto buf_size = generate_random_port(128, 1024);
			std::array<uint8_t, 1024> buf{};
			_conn.set_blocking();
			auto ret = _conn.read(buf);
			if (!ret) {
				return ret;
			}
			auto server_response = _session->step1_handle_hello(buf);
			if (!server_response) {
				return tl::unexpected(EBADMSG);
			}
			randombytes_buf(buf.data(), buf_size);
			std::copy(server_response->begin(), server_response->end(),
					  buf.begin());
			ret = _conn.write(buf.data(), buf_size);
			if (!ret) {
				return ret;
			}
			ret = _conn.read(buf);
			if (!ret) {
				return ret;
			}
			auto res = _session->step2_handle_auth(
				buf, [&](const std::string& fp) -> bool {
					if (!(_known_hosts.contains(fp))) {
						fmt::print("Can this key be trusted? {}\ty/N\n", fp);
						char choice = std::cin.get();
						while (choice == '\n') {
							choice = std::cin.get();
						}
						std::cin.get(); // Drop the '\n'
						if (choice == 'y' || choice == 'Y') {
							_known_hosts.insert(fp);
							_hosts_file.write(fp + '\n');
							return true;
						}
						else {
							return false;
						}
					}
					else {
						return true;
					}
				});
			if (!res) {
				_conn.close();
				return tl::unexpected(ECONNABORTED);
			}
			uint8_t ok     = 1;
			auto    ok_msg = _session->encrypt(&ok, sizeof(ok));
			if (!ok_msg) {
				_conn.close();
				return tl::unexpected(EBADMSG);
			}
			buf_size = generate_random_port(128, 1024);
			randombytes_buf(buf.data(), buf_size);
			std::copy(ok_msg->begin(), ok_msg->end(), buf.begin());
			ret = _conn.write(buf.data(), buf_size);
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