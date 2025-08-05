#pragma once

#include <vector>
#include <stdexcept>
#include <functional>
#include <string_view>

#ifdef _WIN32
#include <Windows.h>
#include <dpapi.h>
#pragma comment(lib, "crypt32.lib")
#else
#include <cstring>
#include <sys/mman.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#endif

// 安全地擦除内存的函数
inline void secure_zero_memory(void* ptr, size_t size) {
#ifdef _WIN32
	SecureZeroMemory(ptr, size);
#else
	explicit_bzero(ptr, size);
#endif
}

template <typename _Type = char>
class SecureBuffer : public std::vector<_Type> {
public:
	using std::vector<_Type>::vector;

	~SecureBuffer() {
		if (!this->empty()) {
			secure_zero_memory(this->data(), this->size());
		}
	}
};

//Note that the caller is responsible for using secure_zero_memory() to erase giving data.
template <typename _Type = char>
class SecureContainer {
public:
	// 构造函数：接收一个字符串，然后立即加密并锁定内存
	explicit SecureContainer(std::string_view password) {
		if (password.empty()) {
			return;
		}

		// 临时将明文放入 SecureBuffer 以便在作用域结束时自动擦除
		initialize(password.data(), password.size());
	}
	explicit SecureContainer(const _Type* password, size_t sz) {
		// 临时将明文放入 SecureBuffer 以便在作用域结束时自动擦除
		initialize(password, sz);
	}

	~SecureContainer() {
		// m_encryptedData 是 SecureBuffer，其析构函数会自动擦除内存
#ifdef _WIN32
		if (!m_encryptedData.empty()) {
			// 解锁内存页
			VirtualUnlock(m_encryptedData.data(), m_encryptedData.size());
		}
#endif
	}

	// 禁用拷贝构造和赋值
	SecureContainer(const SecureContainer&) = delete;
	SecureContainer& operator=(const SecureContainer&) = delete;

	// 提供一个安全访问器，它会在一个很小的作用域内提供明文访问
	// 使用 lambda 函数作为参数，确保明文只在回调函数执行期间存在
	void
	access(const std::function<void(const _Type* pt, size_t len)>& accessor) {
		if (m_encryptedData.empty()) {
			accessor(nullptr, 0);
			return;
		}

		SecureBuffer<_Type> decrypted_data;

#ifdef _WIN32
		if (!CryptUnprotectMemory(m_encryptedData.data(),
								  m_encryptedData.capacity(),
								  CRYPTPROTECTMEMORY_SAME_PROCESS)) {
			throw std::runtime_error("Failed to decrypt memory");
		}
		
		decrypted_data = m_encryptedData;

#else // Linux with OpenSSL
		decrypted_data.resize(m_encryptedData.size());
		EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
		if (!ctx) throw std::runtime_error("Failed to create EVP_CIPHER_CTX");

		if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, m_key.data(), m_iv.data())) {
			EVP_CIPHER_CTX_free(ctx);
			throw std::runtime_error("Failed to initialize decryption");
		}

		int len;
		if (1 != EVP_DecryptUpdate(ctx, 
								 reinterpret_cast<unsigned char*>(decrypted_data.data()), &len, 
								 reinterpret_cast<const unsigned char*>(m_encryptedData.data()), m_encryptedData.size())) {
			EVP_CIPHER_CTX_free(ctx);
			throw std::runtime_error("Failed to decrypt data");
		}
		int plaintext_len = len;

		if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, m_tag.data())) {
			 EVP_CIPHER_CTX_free(ctx);
			throw std::runtime_error("Failed to set GCM tag");
		}

		if (1 != EVP_DecryptFinal_ex(ctx, reinterpret_cast<unsigned char*>(decrypted_data.data()) + len, &len)) {
			EVP_CIPHER_CTX_free(ctx);
			throw std::runtime_error("Decryption failed: incorrect tag?");
		}
		plaintext_len += len;
		decrypted_data.resize(plaintext_len);
		
		EVP_CIPHER_CTX_free(ctx);
#endif
		
		// 调用访问器，传递一个临时的明文 std::string
		accessor(decrypted_data.data(), decrypted_data.size());
		// decrypted_data 在离开作用域时会被其析构函数安全擦除
	}

	void
	access(const std::function<void(std::string_view)>& accessor) {
		if (m_encryptedData.empty()) {
			accessor("");
			return;
		}

		SecureBuffer<_Type> decrypted_data;

#ifdef _WIN32
		if (!CryptUnprotectMemory(m_encryptedData.data(),
								  m_encryptedData.capacity(),
								  CRYPTPROTECTMEMORY_SAME_PROCESS)) {
			throw std::runtime_error("Failed to decrypt memory");
		}
		
		decrypted_data = m_encryptedData;

#else // Linux with OpenSSL
		decrypted_data.resize(m_encryptedData.size());
		EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
		if (!ctx) throw std::runtime_error("Failed to create EVP_CIPHER_CTX");

		if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, m_key.data(), m_iv.data())) {
			EVP_CIPHER_CTX_free(ctx);
			throw std::runtime_error("Failed to initialize decryption");
		}

		int len;
		if (1 != EVP_DecryptUpdate(ctx, 
								 reinterpret_cast<unsigned char*>(decrypted_data.data()), &len, 
								 reinterpret_cast<const unsigned char*>(m_encryptedData.data()), m_encryptedData.size())) {
			EVP_CIPHER_CTX_free(ctx);
			throw std::runtime_error("Failed to decrypt data");
		}
		int plaintext_len = len;

		if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, m_tag.data())) {
			 EVP_CIPHER_CTX_free(ctx);
			throw std::runtime_error("Failed to set GCM tag");
		}

		if (1 != EVP_DecryptFinal_ex(ctx, reinterpret_cast<unsigned char*>(decrypted_data.data()) + len, &len)) {
			EVP_CIPHER_CTX_free(ctx);
			throw std::runtime_error("Decryption failed: incorrect tag?");
		}
		plaintext_len += len;
		decrypted_data.resize(plaintext_len);
		
		EVP_CIPHER_CTX_free(ctx);
#endif
		
		// 调用访问器，传递一个临时的明文 std::string
		accessor({decrypted_data.data(), decrypted_data.size()});
		// decrypted_data 在离开作用域时会被其析构函数安全擦除
	}
private:
	SecureBuffer<_Type> m_encryptedData;

#ifndef _WIN32
	// Linux/OpenSSL 需要自己管理密钥、IV 和认证标签
	SecureBuffer<unsigned char> m_key;
	SecureBuffer<unsigned char> m_iv;
	SecureBuffer<unsigned char> m_tag;
#endif

	void initialize(const _Type* data, size_t size) {
#ifdef _WIN32
		// 1. 复制数据
		constexpr auto mod = CRYPTPROTECTMEMORY_BLOCK_SIZE;
		m_encryptedData.reserve(size + (mod - size % mod));
		m_encryptedData.assign(data, data + size);
		
		// 2. 锁定内存，防止被换出到磁盘
		if (!VirtualLock(m_encryptedData.data(), m_encryptedData.size())) {
			throw std::runtime_error("Failed to lock memory (VirtualLock)");
		}

		// 3. 使用 DPAPI 加密内存
		if (!CryptProtectMemory(
				m_encryptedData.data(), m_encryptedData.capacity(),
				CRYPTPROTECTMEMORY_SAME_PROCESS)) {
			VirtualUnlock(m_encryptedData.data(), m_encryptedData.size());
			throw std::runtime_error("Failed to encrypt memory (CryptProtectMemory)");
		}
#else // Linux with OpenSSL
		// 1. 生成随机密钥和IV
		m_key.resize(32); // AES-256
		m_iv.resize(12);  // GCM 推荐
		if (!RAND_bytes(reinterpret_cast<unsigned char*>(m_key.data()), m_key.size()) ||
			!RAND_bytes(reinterpret_cast<unsigned char*>(m_iv.data()), m_iv.size())) {
			throw std::runtime_error("Failed to generate random key/iv");
		}

		m_encryptedData.resize(size); // 密文和明文大小一样
		m_tag.resize(16); // GCM 认证标签

		// 2. 锁定所有敏感内存页
		mlock(m_key.data(), m_key.size());
		mlock(m_iv.data(), m_iv.size());
		mlock(m_tag.data(), m_tag.size());
		mlock(m_encryptedData.data(), m_encryptedData.size());

		// 3. 使用 AES-256-GCM 加密
		EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
		if (!ctx) throw std::runtime_error("Failed to create EVP_CIPHER_CTX");

		if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, 
								   reinterpret_cast<const unsigned char*>(m_key.data()), 
								   reinterpret_cast<const unsigned char*>(m_iv.data()))) {
			EVP_CIPHER_CTX_free(ctx);
			throw std::runtime_error("Failed to initialize encryption");
		}

		int len;
		if (1 != EVP_EncryptUpdate(ctx, 
								 reinterpret_cast<unsigned char*>(m_encryptedData.data()), &len, 
								 reinterpret_cast<const unsigned char*>(data), size)) {
			EVP_CIPHER_CTX_free(ctx);
			throw std::runtime_error("Failed to encrypt data");
		}

		if (1 != EVP_EncryptFinal_ex(ctx, reinterpret_cast<unsigned char*>(m_encryptedData.data()) + len, &len)) {
			EVP_CIPHER_CTX_free(ctx);
			throw std::runtime_error("Failed to finalize encryption");
		}

		if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, m_tag.data())) {
			EVP_CIPHER_CTX_free(ctx);
			throw std::runtime_error("Failed to get GCM tag");
		}

		EVP_CIPHER_CTX_free(ctx);
#endif
	}
};
