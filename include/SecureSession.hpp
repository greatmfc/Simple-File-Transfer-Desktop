#ifndef SECURE_SESSION_HPP
#define SECURE_SESSION_HPP

#include "ErrorResult.h"
#include <cstring>
#include <functional>
#include <memory>
#include <sodium.h>
#include <stdexcept>
#include <vector>
#include <array>

constexpr auto SessionPubkeyBytes = crypto_sign_PUBLICKEYBYTES;
constexpr auto SessionSeckeyBytes = crypto_sign_SECRETKEYBYTES;
constexpr auto ServerToClientResponseLength =
	crypto_kx_PUBLICKEYBYTES + crypto_sign_PUBLICKEYBYTES + crypto_sign_BYTES;
constexpr auto EncryptionAdditionalBytes =
	crypto_aead_xchacha20poly1305_ietf_ABYTES;
constexpr auto ClientToServerResponseLength =
	crypto_kx_PUBLICKEYBYTES + crypto_sign_BYTES + EncryptionAdditionalBytes;
constexpr auto NonceBytes = crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;
inline auto    EncryptionFunction =
	std::function(crypto_aead_xchacha20poly1305_ietf_encrypt);
inline auto DecryptionFunction =
	std::function(crypto_aead_xchacha20poly1305_ietf_decrypt);

using PubKeyArray = std::array<uint8_t, SessionPubkeyBytes>;
using SecKeyArray = std::array<uint8_t, SessionSeckeyBytes>;

namespace kotcpp {

inline std::string get_fingerprint(const uint8_t* public_key, size_t len) {
	// 1. 准备 32 字节的哈希缓冲区
	unsigned char hash[crypto_generichash_BYTES]; // 默认 32 字节

	// 2. 调用 libsodium 的 BLAKE2b 实现
	crypto_generichash(hash, sizeof(hash), public_key, len, nullptr,
					   0); // 不需要 Key 模式

	// 3. 转换为 Base64 方便用户查看
	char b64[sodium_base64_ENCODED_LEN(sizeof(hash),
									   sodium_base64_VARIANT_ORIGINAL)];
	sodium_bin2base64(b64, sizeof(b64), hash, sizeof(hash),
					  sodium_base64_VARIANT_ORIGINAL);

	return std::string(b64);
}

// ============================================================================
// 1. 安全内存封装 (RAII)
// ============================================================================
// 自动管理 sodium_allocarray / sodium_free / sodium_mprotect
class SecureKey {
	private:
		uint8_t* ptr_  = nullptr;
		size_t   size_ = 0;

	public:
		SecureKey(size_t size = crypto_sign_SECRETKEYBYTES) : size_(size) {
			// 分配并清零，且内存页是对齐的
			ptr_ = (uint8_t*)sodium_allocarray(size_, 1);
			if (!ptr_) {
				throw std::runtime_error("sodium_allocarray failed");
			}
			// 初始状态：完全不可访问 (No Access)
			sodium_mprotect_noaccess(ptr_);
		}

		~SecureKey() {
			if (ptr_) {
				sodium_free(ptr_); // 会自动清零内存
			}
		}

		// 禁止拷贝，只能移动 (防止密钥多处副本)
		SecureKey(const SecureKey&)            = delete;
		SecureKey& operator=(const SecureKey&) = delete;

		SecureKey(SecureKey&& other) noexcept
			: ptr_(other.ptr_), size_(other.size_) {
			other.ptr_  = nullptr;
			other.size_ = 0;
		}

		size_t size() const {
			return size_;
		}

		// --- 临时访问权限控制 ---

		// 写入模式：暂时允许读写
		void unlock_for_write() {
			sodium_mprotect_readwrite(ptr_);
		}

		// 只读模式：暂时允许读取
		void unlock_for_read() const {
			sodium_mprotect_readonly(ptr_);
		}

		// 锁定模式：禁止一切访问
		void lock() const {
			sodium_mprotect_noaccess(ptr_);
		}

		// 获取原始指针 (必须在解锁状态下使用)
		uint8_t* data() {
			return ptr_;
		}
		const uint8_t* data() const {
			return ptr_;
		}
};

// 辅助类：作用域内自动解锁，离开作用域自动上锁
// 用于确保密钥只有在计算的那一瞬间是可读的
class ScopedReadAccess {
		const SecureKey& key_;

	public:
		ScopedReadAccess(const SecureKey& key) : key_(key) {
			key_.unlock_for_read();
		}
		~ScopedReadAccess() {
			key_.lock();
		}
};

class ScopedWriteAccess {
		SecureKey& key_;

	public:
		ScopedWriteAccess(SecureKey& key) : key_(key) {
			key_.unlock_for_write();
		}
		~ScopedWriteAccess() {
			key_.lock();
		} // 写完立刻锁死
};

// ============================================================================
// 2. 基础会话类
// ============================================================================
class SessionBase {
	protected:
		// 会话密钥 (Rx: 收, Tx: 发)
		std::unique_ptr<SecureKey>                  rx_key_;
		std::unique_ptr<SecureKey>                  tx_key_;

		// Nonce (24 字节 for XChaCha20)
		// 策略：前 16 字节为从握手材料派生的随机前缀，后 8 字节为递增计数器
		uint8_t                                     nonce_tx_[NonceBytes] = {0};
		uint8_t                                     nonce_rx_[NonceBytes] = {0};

		// 帧长度加密密钥和计数器 (发送/接收分别使用不同密钥)
		std::array<uint8_t, crypto_stream_KEYBYTES> tx_length_key_{};
		std::array<uint8_t, crypto_stream_KEYBYTES> rx_length_key_{};
		uint64_t                                    length_counter_tx_ = 0;
		uint64_t                                    length_counter_rx_ = 0;

		// 长期身份密钥
		SecureKey                                   identity_sk_;
		PubKeyArray                identity_pk_; // 公钥不需要保护

		// 握手过程中的临时数据
		std::unique_ptr<SecureKey> ephemeral_sk_;
		std::vector<uint8_t>       ephemeral_pk_;

		bool                       is_ready_ = false; // 是否握手完成

	public:
		virtual ~SessionBase() = default;

		bool is_established() const {
			return is_ready_;
		}

		virtual std::vector<uint8_t> step1_generate_hello() {
			throw std::runtime_error("Invalid function call from base.");
		}

		virtual Result<std::vector<uint8_t>>
		step1_handle_hello(const uint8_t* /*client_msg*/, size_t /*len*/) {
			throw std::runtime_error("Invalid function call from base.");
		}

		virtual Result<std::vector<uint8_t>> step2_handle_response(
			const uint8_t* /*server_msg*/, size_t /*len*/,
			std::function<bool(const std::string&)> check_pubkey) {
			throw std::runtime_error("Invalid function call from base.");
		}

		virtual Result<std::vector<uint8_t>> step2_handle_auth(
			const uint8_t* /*encrypted_auth*/, size_t /*len*/,
			std::function<bool(const std::string&)> check_pubkey) {
			throw std::runtime_error("Invalid function call from base.");
		}

		template <buffer_type T> auto step1_handle_hello(const T& client_msg) {
			return this->step1_handle_hello(client_msg.data(),
											client_msg.size());
		}

		template <buffer_type T>
		auto step2_handle_response(
			const T&                                server_msg,
			std::function<bool(const std::string&)> check_pubkey) {
			return this->step2_handle_response(server_msg.data(),
											   server_msg.size(), check_pubkey);
		}

		template <buffer_type T>
		auto step2_handle_auth(
			const T&                                encrypted_auth,
			std::function<bool(const std::string&)> check_pubkey) {
			return this->step2_handle_auth(encrypted_auth.data(),
										   encrypted_auth.size(), check_pubkey);
		}

		// This function assumes output_pt has at least MESSAGE_LEN +
		// EncryptionAdditionalBytes space.
		// Returns the length of the ciphertext.
		Result<SizeType> encrypt(const uint8_t* plaintext,
								 SizeType plaintextLen, uint8_t* output_pt) {
			if (!is_ready_) {
				return unexpected("Handshake not completed");
			}

			unsigned long long clen;

			{
				ScopedReadAccess access(*tx_key_);

				EncryptionFunction(output_pt, &clen, plaintext, plaintextLen,
								   nullptr,
								   0,       // No AD
								   nullptr, // No Secret Nonce
								   nonce_tx_, tx_key_->data());
			}

			// Increment Nonce TX
			sodium_increment(nonce_tx_, NonceBytes);

			return clen;
		}

		Result<std::vector<uint8_t>> encrypt(const uint8_t* plaintext,
											 SizeType       plaintextLen) {
			std::vector<uint8_t> ciphertext(plaintextLen +
											EncryptionAdditionalBytes);
			if (auto res =
					this->encrypt(plaintext, plaintextLen, ciphertext.data());
				!res) {
				return unexpected(res.error());
			}
			return ciphertext;
		}

		template <buffer_type T> auto encrypt(const T& plaintext) {
			return this->encrypt(plaintext.data(), plaintext.size());
		}

		Result<SizeType> decrypt(const uint8_t* ciphertext,
								 SizeType ciphertextLen, uint8_t* output_pt) {
			if (!is_ready_) {
				return unexpected("Handshake not completed");
			}
			if (ciphertextLen < EncryptionAdditionalBytes) {
				return unexpected("Ciphertext too short");
			}

			unsigned long long mlen;

			{
				ScopedReadAccess access(*rx_key_);

				if ((DecryptionFunction(output_pt, &mlen, nullptr, ciphertext,
										ciphertextLen, nullptr, 0, nonce_rx_,
										rx_key_->data()) != 0)) {
					return unexpected(
						"Decryption failed: Tag mismatch (Tampering detected)");
				}
			}

			sodium_increment(nonce_rx_, NonceBytes);

			return mlen;
		}

		Result<std::vector<uint8_t>> decrypt(const uint8_t* ciphertext,
											 SizeType       ciphertextLen) {
			std::vector<uint8_t> plaintext(ciphertextLen -
										   EncryptionAdditionalBytes);

			if (auto res =
					this->decrypt(ciphertext, ciphertextLen, plaintext.data());
				!res) {
				return unexpected(res.error());
			}
			return plaintext;
		}

		template <buffer_type T> auto decrypt(const T& ciphertext) {
			return this->decrypt(ciphertext.data(), ciphertext.size());
		}

		void init_nonce(const uint8_t* client_eph_pk,
						const uint8_t* server_eph_pk, bool is_client) {
			uint8_t key_material[crypto_kx_PUBLICKEYBYTES * 2];
			memcpy(key_material, client_eph_pk, crypto_kx_PUBLICKEYBYTES);
			memcpy(key_material + crypto_kx_PUBLICKEYBYTES, server_eph_pk,
				   crypto_kx_PUBLICKEYBYTES);

			uint8_t hash[32];
			crypto_generichash(hash, 32, key_material, sizeof(key_material),
							   nullptr, 0);

			if (is_client) {
				memcpy(nonce_tx_, hash, 16);
				memcpy(nonce_rx_, hash + 16, 16);
			}
			else {
				memcpy(nonce_tx_, hash + 16, 16);
				memcpy(nonce_rx_, hash, 16);
			}

			memset(nonce_tx_ + 16, 0, 8);
			memset(nonce_rx_ + 16, 0, 8);

			uint8_t length_context[] = "SFT_LEN_";
			{
				ScopedReadAccess r_tx(*tx_key_);
				ScopedReadAccess r_rx(*rx_key_);
				crypto_generichash(tx_length_key_.data(), 32, tx_key_->data(),
								   crypto_kx_SESSIONKEYBYTES, length_context,
								   sizeof(length_context) - 1);
				crypto_generichash(rx_length_key_.data(), 32, rx_key_->data(),
								   crypto_kx_SESSIONKEYBYTES, length_context,
								   sizeof(length_context) - 1);
			}

			length_counter_tx_ = 0;
			length_counter_rx_ = 0;

			sodium_memzero(key_material, sizeof(key_material));
			sodium_memzero(hash, sizeof(hash));
		}

		uint64_t encrypt_frame_length(uint64_t plaintext_len) {
			uint8_t keystream[8];
			uint8_t nonce[24] = {0};

			memcpy(nonce, &length_counter_tx_, sizeof(length_counter_tx_));

			crypto_stream_xsalsa20(keystream, 8, nonce, tx_length_key_.data());

			uint64_t encrypted_len = plaintext_len;
			for (int i = 0; i < 8; i++) {
				((uint8_t*)&encrypted_len)[i] ^= keystream[i];
			}

			length_counter_tx_++;
			return encrypted_len;
		}

		uint64_t decrypt_frame_length(uint64_t encrypted_len) {
			uint8_t keystream[8];
			uint8_t nonce[24] = {0};

			memcpy(nonce, &length_counter_rx_, sizeof(length_counter_rx_));
			if (crypto_stream_xsalsa20(keystream, 8, nonce,
									   rx_length_key_.data()) != 0) {
				return 0;
			}

			uint64_t plaintext_len = encrypted_len;
			for (int i = 0; i < 8; i++) {
				((uint8_t*)&plaintext_len)[i] ^= keystream[i];
			}

			length_counter_rx_++;
			return plaintext_len;
		}

		std::string get_pubkey_fingerprint() {
			return get_fingerprint(identity_pk_.data(), identity_pk_.size());
		}
};

class ClientSession : public SessionBase {
	public:
		ClientSession(const PubKeyArray& identity_pk,
					  const SecKeyArray& identity_sk) {
			identity_pk_ = identity_pk;
			ScopedWriteAccess w(identity_sk_); // 解锁写入
			std::memcpy(identity_sk_.data(), identity_sk.data(),
						identity_sk.size());
		}

		ClientSession(const PubKeyArray& identity_pk,
					  const uint8_t*     identity_sk) {
			identity_pk_ = identity_pk;
			ScopedWriteAccess w(identity_sk_); // 解锁写入
			std::memcpy(identity_sk_.data(), identity_sk, identity_sk_.size());
		}

		// --- Step 1: 生成 Client Hello 数据包 ---
		std::vector<uint8_t> step1_generate_hello() override {
			ephemeral_sk_ =
				std::make_unique<SecureKey>(crypto_kx_SECRETKEYBYTES);
			ephemeral_pk_.resize(crypto_kx_PUBLICKEYBYTES);

			{
				ScopedWriteAccess w(*ephemeral_sk_);
				crypto_kx_keypair(ephemeral_pk_.data(), ephemeral_sk_->data());
			}

			// 发送: [Client Ephemeral PK (32)]
			return ephemeral_pk_;
		}

		// --- Step 2: 处理 Server Response 并生成 Auth 包 ---
		// 输入: Server Response Packet
		// 输出: Client Auth Packet (已加密)
		Result<std::vector<uint8_t>> step2_handle_response(
			const uint8_t* server_msg, size_t len,
			std::function<bool(const std::string&)> check_pubkey) override {
			if (len < ServerToClientResponseLength) {
				return unexpected("Invalid server response size");
			}

			// 解析包结构
			const uint8_t* s_eph_pk = server_msg;
			const uint8_t* s_id_pk  = server_msg + crypto_kx_PUBLICKEYBYTES;
			const uint8_t* s_sig    = s_id_pk + crypto_sign_PUBLICKEYBYTES;

			std::vector<uint8_t> yielded_pk(
				server_msg + crypto_kx_PUBLICKEYBYTES,
				server_msg + crypto_kx_PUBLICKEYBYTES +
					crypto_sign_PUBLICKEYBYTES);
			if (!check_pubkey(
					get_fingerprint(yielded_pk.data(), yielded_pk.size()))) {
				return unexpected("Server public key verification failed");
			}

			// 2. 验证服务器签名 (Client Eph PK + Server Eph PK)
			std::vector<uint8_t> verify_data;
			verify_data.insert(verify_data.end(), ephemeral_pk_.begin(),
							   ephemeral_pk_.end());
			verify_data.insert(verify_data.end(), s_eph_pk,
							   s_eph_pk + crypto_kx_PUBLICKEYBYTES);

			if (crypto_sign_verify_detached(s_sig, verify_data.data(),
											verify_data.size(), s_id_pk) != 0) {
				return unexpected("Server signature verification failed");
			}

			// 3. 计算会话密钥
			rx_key_ = std::make_unique<SecureKey>(crypto_kx_SESSIONKEYBYTES);
			tx_key_ = std::make_unique<SecureKey>(crypto_kx_SESSIONKEYBYTES);

			{
				ScopedReadAccess  r_sk(*ephemeral_sk_);
				ScopedWriteAccess w_rx(*rx_key_);
				ScopedWriteAccess w_tx(*tx_key_);

				if (crypto_kx_client_session_keys(
						rx_key_->data(), tx_key_->data(), ephemeral_pk_.data(),
						ephemeral_sk_->data(), s_eph_pk) != 0) {
					return unexpected("Session key generation failed");
				}
			}

			// 销毁临时私钥 (PFS)
			ephemeral_sk_.reset();

			// 状态转为 Ready，准备加密
			is_ready_ = true;
			init_nonce(ephemeral_pk_.data(), s_eph_pk, true);

			// 4. 生成 Client Auth 包 (加密发送)
			// 内容: [Client ID PK (32)] + [Signature (64)]
			std::vector<uint8_t> auth_payload;
			auth_payload.insert(auth_payload.end(), identity_pk_.begin(),
								identity_pk_.end());

			// 签名 (Server Eph PK + Client Eph PK) - 顺序通常反过来签
			std::vector<uint8_t> sign_data;
			sign_data.insert(sign_data.end(), s_eph_pk,
							 s_eph_pk + crypto_kx_PUBLICKEYBYTES);
			sign_data.insert(sign_data.end(), ephemeral_pk_.begin(),
							 ephemeral_pk_.end());

			std::vector<uint8_t> my_sig(crypto_sign_BYTES);
			{
				ScopedReadAccess r_id(identity_sk_);
				crypto_sign_detached(my_sig.data(), NULL, sign_data.data(),
									 sign_data.size(), identity_sk_.data());
			}
			auth_payload.insert(auth_payload.end(), my_sig.begin(),
								my_sig.end());

			// 使用刚建立的 TX Key 加密这个包
			return encrypt(auth_payload);
		}
};

// ============================================================================
// 4. 服务端 (Server)
// ============================================================================
class ServerSession : public SessionBase {
		std::vector<uint8_t> client_ephemeral_pk_cache_;

	public:
		ServerSession(const PubKeyArray& identity_pk,
					  const SecKeyArray& identity_sk) {
			identity_pk_ = identity_pk;
			ScopedWriteAccess w(identity_sk_); // 解锁写入
			std::memcpy(identity_sk_.data(), identity_sk.data(),
						identity_sk.size());
		}
		ServerSession(const PubKeyArray& identity_pk,
					  const uint8_t*     identity_sk) {
			identity_pk_ = identity_pk;
			ScopedWriteAccess w(identity_sk_); // 解锁写入
			std::memcpy(identity_sk_.data(), identity_sk, identity_sk_.size());
		}

		// --- Step 1: 处理 Client Hello ---
		// 输入: Client Ephemeral PK
		// 输出: Server Response Packet
		Result<std::vector<uint8_t>>
		step1_handle_hello(const uint8_t* client_msg, size_t len) override {
			if (len < crypto_kx_PUBLICKEYBYTES) {
				return unexpected("Invalid client hello size");
			}
			client_ephemeral_pk_cache_.assign(
				client_msg, client_msg + crypto_kx_PUBLICKEYBYTES);

			// 1. 生成 Server 临时密钥
			ephemeral_sk_ =
				std::make_unique<SecureKey>(crypto_kx_SECRETKEYBYTES);
			ephemeral_pk_.resize(crypto_kx_PUBLICKEYBYTES);
			{
				ScopedWriteAccess w(*ephemeral_sk_);
				crypto_kx_keypair(ephemeral_pk_.data(), ephemeral_sk_->data());
			}

			// 2. 计算会话密钥
			rx_key_ = std::make_unique<SecureKey>(crypto_kx_SESSIONKEYBYTES);
			tx_key_ = std::make_unique<SecureKey>(crypto_kx_SESSIONKEYBYTES);
			{
				ScopedReadAccess  r_sk(*ephemeral_sk_);
				ScopedWriteAccess w_rx(*rx_key_);
				ScopedWriteAccess w_tx(*tx_key_);
				if (crypto_kx_server_session_keys(
						rx_key_->data(), tx_key_->data(), ephemeral_pk_.data(),
						ephemeral_sk_->data(), client_msg) != 0) {
					return unexpected("Server key exchange failed");
				}
			}
			ephemeral_sk_.reset(); // 销毁临时私钥

			// 3. 构造回复包
			// [Server Eph PK (32)] + [Server ID PK (32)] + [Signature (64)]
			std::vector<uint8_t> response;
			response.insert(response.end(), ephemeral_pk_.begin(),
							ephemeral_pk_.end());
			response.insert(response.end(), identity_pk_.begin(),
							identity_pk_.end());

			// 签名 (Client Eph PK + Server Eph PK)
			std::vector<uint8_t> sign_data;
			sign_data.insert(sign_data.end(), client_msg,
							 client_msg + crypto_kx_PUBLICKEYBYTES);
			sign_data.insert(sign_data.end(), ephemeral_pk_.begin(),
							 ephemeral_pk_.end());

			std::vector<uint8_t> sig(crypto_sign_BYTES);
			{
				ScopedReadAccess r_id(identity_sk_);
				auto             a = *(identity_sk_.data() + 30);
				crypto_sign_detached(sig.data(), nullptr, sign_data.data(),
									 sign_data.size(), identity_sk_.data());
			}
			response.insert(response.end(), sig.begin(), sig.end());

			// 此时我们有 Key 了，但握手还没完，还差客户端的鉴权
			// 但我们不能置 is_ready_ = true，因为下一个包是鉴权包，逻辑不同
			return response;
		}

		// --- Step 2: 处理 Client Auth (加密包) ---
		// 输入: Encrypted Client Auth Packet
		// 返回: true (认证成功), false (认证失败)
		Result<std::vector<uint8_t>> step2_handle_auth(
			const uint8_t* encrypted_auth, size_t len,
			std::function<bool(const std::string&)> check_pubkey) override {
			if (len < ClientToServerResponseLength) {
				return unexpected("Invalid auth packet length");
			}
			// 临时开启解密能力 (为了解开 Auth 包)
			is_ready_ = true;
			init_nonce(client_ephemeral_pk_cache_.data(), ephemeral_pk_.data(),
					   false);

			std::vector<uint8_t> plaintext;
			if (auto res =
					decrypt(encrypted_auth, ClientToServerResponseLength);
				!res) {
				is_ready_ = false;
				return unexpected(res.error()); // 解密失败
			}
			else {
				plaintext = std::move(res.value());
			}

			if (plaintext.size() !=
				crypto_sign_PUBLICKEYBYTES + crypto_sign_BYTES) {
				is_ready_ = false;
				return unexpected("Invalid auth packet length"); // 格式错误
			}

			const uint8_t* c_id_pk = plaintext.data();
			const uint8_t* c_sig =
				plaintext.data() + crypto_sign_PUBLICKEYBYTES;

			std::vector<uint8_t> yielded_pk(plaintext.begin(),
											plaintext.begin() +
												crypto_kx_PUBLICKEYBYTES);
			if (!check_pubkey(
					get_fingerprint(yielded_pk.data(), yielded_pk.size()))) {
				is_ready_ = false;
				return unexpected("Server public key verification failed");
			}

			// 2. 验证签名 (Server Eph PK + Client Eph PK)
			std::vector<uint8_t> verify_data;
			verify_data.insert(verify_data.end(), ephemeral_pk_.begin(),
							   ephemeral_pk_.end());
			verify_data.insert(verify_data.end(),
							   client_ephemeral_pk_cache_.begin(),
							   client_ephemeral_pk_cache_.end());

			if (crypto_sign_verify_detached(c_sig, verify_data.data(),
											verify_data.size(), c_id_pk) != 0) {
				is_ready_ = false;
				return unexpected("Invalid auth packet signature"); // 签名错误
			}

			// 握手彻底完成，通道保持打开
			return {};
		}
};

} // namespace kotcpp

#endif // SECURE_SESSION_HPP