#ifndef AsymCrypt_H
#define AsymCrypt_H

#include <array>
#include <vector>
#include <cstring>
#include <stdexcept>
#include <sodium.h>

static constexpr size_t AsymCrypt_NONCE_SIZE = crypto_box_NONCEBYTES;
static constexpr size_t AsymCrypt_TAG_SIZE   = crypto_box_MACBYTES;
static constexpr size_t AsymCrypt_KEY_SIZE   = crypto_box_PUBLICKEYBYTES;

#ifndef IO_H
template <class T>
concept buffer_type = requires(T a) {
	a.data();
	a.size();
	requires std::is_same_v<typename T::value_type, char> ||
				 std::is_same_v<typename T::value_type, unsigned char>;
};
#endif

std::string bin_to_hex_string(const unsigned char* data, size_t len) {
	size_t            hex_len = len * 2 + 1;
	std::vector<char> res(hex_len, 0);
	sodium_bin2hex(res.data(), hex_len, data, len);
	return res.data();
}

#define MOVEBYTES(dst, src, sz)                                                \
	struct temp {                                                              \
			unsigned char a[sz];                                               \
	};                                                                         \
	*reinterpret_cast<temp*>(dst) = *reinterpret_cast<const temp*>(src)

class AsymCrypt {
	private:
		uint8_t* m_sec_key = nullptr;

	public:
		std::array<unsigned char, AsymCrypt_KEY_SIZE> m_pub_key{};
		std::array<unsigned char, AsymCrypt_KEY_SIZE> m_other_pub_key{};

		AsymCrypt();
		~AsymCrypt();

		AsymCrypt(AsymCrypt&&) noexcept;
		AsymCrypt(const AsymCrypt&)                   = delete;
		AsymCrypt&        operator=(const AsymCrypt&) = delete;
		AsymCrypt&        operator=(AsymCrypt&&) noexcept;

		std::vector<char> encrypt(const char* data, size_t dataSize) const;
		int encrypt(const char* data, size_t dataSize, char* result) const;
		std::vector<char> decrypt(const char* encryptedData,
								  size_t      encryptedSize) const;
		int         decrypt(const char* encryptedData, size_t encryptedSize,
							char* result) const;
		bool        is_ready();
		std::string get_hex_pub_key() {
			return bin_to_hex_string(m_pub_key.data(), m_pub_key.size());
		}
		template <buffer_type T>
		std::vector<char> encrypt(const T& data) const {
			return this->encrypt(data.data(), data.size());
		}
		template <buffer_type T>
		std::vector<char> decrypt(const T& data) const {
			return this->decrypt(data.data(), data.size());
		}
};

AsymCrypt::AsymCrypt() {
	m_sec_key = static_cast<uint8_t*>(
		sodium_allocarray(crypto_box_SECRETKEYBYTES, sizeof(uint8_t)));
	crypto_box_keypair(m_pub_key.data(), m_sec_key);
	sodium_mprotect_noaccess(m_sec_key);
}

AsymCrypt::~AsymCrypt() {
	sodium_free(m_sec_key);
}

AsymCrypt::AsymCrypt(AsymCrypt&& other) noexcept {
	m_sec_key       = other.m_sec_key;
	m_pub_key       = other.m_pub_key;
	other.m_sec_key = nullptr;
	sodium_mprotect_noaccess(m_sec_key);
}

AsymCrypt& AsymCrypt::operator=(AsymCrypt&& other) noexcept {
	m_sec_key       = other.m_sec_key;
	m_pub_key       = other.m_pub_key;
	other.m_sec_key = nullptr;
	sodium_mprotect_noaccess(m_sec_key);
	return *this;
}

std::vector<char> AsymCrypt::encrypt(const char* data, size_t dataSize) const {
	std::vector<char> result(dataSize + AsymCrypt_NONCE_SIZE +
							 AsymCrypt_TAG_SIZE);
	this->encrypt(data, dataSize, result.data());
	return result;
}

int AsymCrypt::encrypt(const char* data, size_t dataSize, char* result) const {
	if (!data || dataSize <= 0) {
		throw std::invalid_argument("Invalid input data");
	}

	std::array<unsigned char, AsymCrypt_NONCE_SIZE> nonce;
	randombytes_buf(nonce.data(), nonce.size());
	std::memcpy(result, nonce.data(), nonce.size());
	sodium_mprotect_readonly(m_sec_key);
	auto ret = crypto_box_easy(
		reinterpret_cast<unsigned char*>(result) + AsymCrypt_NONCE_SIZE,
		reinterpret_cast<const unsigned char*>(data), dataSize, nonce.data(),
		m_other_pub_key.data(), m_sec_key);
	sodium_mprotect_noaccess(m_sec_key);
	if (ret == -1) {
		throw std::runtime_error("Fail to encrypt data.");
	}
	return ret;
}

std::vector<char> AsymCrypt::decrypt(const char* encryptedData,
									 size_t      encryptedSize) const {
	size_t            ciphertextSize = encryptedSize - AsymCrypt_NONCE_SIZE;
	std::vector<char> result(ciphertextSize - AsymCrypt_TAG_SIZE);
	this->decrypt(encryptedData, encryptedSize, result.data());
	return result;
}

int AsymCrypt::decrypt(const char* encryptedData, size_t encryptedSize,
					   char* result) const {
	if (!encryptedData || encryptedSize < AsymCrypt_NONCE_SIZE) {
		throw std::invalid_argument("Invalid encrypted data");
	}

	unsigned long long ciphertextSize = encryptedSize - AsymCrypt_NONCE_SIZE;
	const char*        ciphertext     = encryptedData + AsymCrypt_NONCE_SIZE;
	const char*        nonce          = encryptedData;

	sodium_mprotect_readonly(m_sec_key);
	auto ret = crypto_box_open_easy(
		reinterpret_cast<unsigned char*>(result),
		reinterpret_cast<const unsigned char*>(ciphertext), ciphertextSize,
		reinterpret_cast<const unsigned char*>(nonce), m_other_pub_key.data(),
		m_sec_key);
	sodium_mprotect_noaccess(m_sec_key);
	if (ret != 0) {
		throw std::runtime_error("Fail to decrypt data.");
	}
	return ret;
}

bool AsymCrypt::is_ready() {
	return m_sec_key != nullptr;
}

#endif // !AsymCrypt_H
