#include "aes-gcm.h"
#include <cstring>
#include <stdexcept>

#ifdef _WIN32
#include <WinSock2.h>
#include <wincrypt.h>
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "bcrypt.lib")
#else
#include <openssl/aes.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#endif

#ifdef _WIN32
void AesGcm::initializeWindows() {
	NTSTATUS status;

	status = BCryptOpenAlgorithmProvider(&hAlgorithm_,
										 BCRYPT_AES_ALGORITHM, NULL, 0);
	if (!BCRYPT_SUCCESS(status)) {
		throw std::runtime_error(
			"Failed to open AES algorithm provider");
	}

	status = BCryptSetProperty(hAlgorithm_, BCRYPT_CHAINING_MODE,
							   (PUCHAR)BCRYPT_CHAIN_MODE_GCM,
							   sizeof(BCRYPT_CHAIN_MODE_GCM), 0);
	if (!BCRYPT_SUCCESS(status)) {
		BCryptCloseAlgorithmProvider(hAlgorithm_, 0);
		throw std::runtime_error("Failed to set GCM mode");
	}

	status = BCryptGenerateSymmetricKey(
		hAlgorithm_, &hKey_, NULL, 0, (PUCHAR)key_.data(), AESGCM_KEY_SIZE, 0);
	if (!BCRYPT_SUCCESS(status)) {
		BCryptCloseAlgorithmProvider(hAlgorithm_, 0);
		throw std::runtime_error("Failed to generate symmetric key");
	}
}

void AesGcm::cleanupWindows() {
	if (hKey_) {
		BCryptDestroyKey(hKey_);
		hKey_ = nullptr;
	}
	if (hAlgorithm_) {
		BCryptCloseAlgorithmProvider(hAlgorithm_, 0);
		hAlgorithm_ = nullptr;
	}
}
#endif

void AesGcm::generateRandomBytes(char* buffer, size_t size) {
#ifdef _WIN32
	NTSTATUS status = BCryptGenRandom(NULL, (PUCHAR)buffer, size,
									  BCRYPT_USE_SYSTEM_PREFERRED_RNG);
	if (!BCRYPT_SUCCESS(status)) {
		throw std::runtime_error("Failed to generate random bytes");
	}
#else
	if (RAND_bytes((unsigned char*)buffer, size) != 1) {
		throw std::runtime_error("Failed to generate random bytes");
	}
#endif
}

inline void AesGcm::erase_local_key() {
#ifdef _WIN32
	SecureZeroMemory(key_.data(), key_.size());
#else
	explicit_bzero(key_.data(), key_.size());
#endif
}

AesGcm::AesGcm(const unsigned char* keyData, size_t keySize)
{
	if (!keyData || keySize < AESGCM_KEY_SIZE) {
		throw std::invalid_argument(
			"Key must be larger than 16 bytes for AES-128");
	}
	MOVEBYTES(key_.data(), keyData, AESGCM_KEY_SIZE);
#ifdef _WIN32
	initializeWindows();
#endif
}

AesGcm::AesGcm(std::string_view pass,
			   const std::array<unsigned char, SALT_SIZE>& s) {
	salt_value = s;
	key_       = generate_key(pass.data(), pass.size(), salt_value);
#ifdef _WIN32
	initializeWindows();
#endif
}

AesGcm::~AesGcm() {
	erase_local_key();
#ifdef _WIN32
	cleanupWindows();
#endif
}

AesGcm::AesGcm(AesGcm&& other) {
	key_       = other.key_;
	salt_value = other.salt_value;
#ifdef _WIN32
	cleanupWindows();
	hAlgorithm_       = other.hAlgorithm_;
	hKey_             = other.hKey_;
	other.hAlgorithm_ = nullptr;
	other.hKey_       = nullptr;
#endif
	other.erase_local_key();
	other.salt_value.fill(0);
}

AesGcm& AesGcm::operator=(AesGcm&& other) {
	key_ = other.key_;
	salt_value = other.salt_value;
#ifdef _WIN32
	cleanupWindows();
	hAlgorithm_       = other.hAlgorithm_;
	hKey_             = other.hKey_;
	other.hAlgorithm_ = nullptr;
	other.hKey_       = nullptr;
#endif
	other.erase_local_key();
	other.salt_value.fill(0);
	return *this;
}

std::vector<char> AesGcm::encrypt(const char* data, size_t dataSize) {
	if (!data || dataSize == 0) {
		throw std::invalid_argument("Invalid input data");
	}

	std::array<char, AESGCM_IV_SIZE> iv{};
	generateRandomBytes(iv.data(), AESGCM_IV_SIZE);
	std::vector<char> result(AESGCM_IV_SIZE + dataSize + AESGCM_TAG_SIZE);
	std::memcpy(result.data(), iv.data(), AESGCM_IV_SIZE);

#ifdef _WIN32
	BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
	BCRYPT_INIT_AUTH_MODE_INFO(authInfo);
	authInfo.pbNonce = (PUCHAR)iv.data();
	authInfo.cbNonce = AESGCM_IV_SIZE;
	authInfo.pbTag   = (PUCHAR)(result.data() + AESGCM_IV_SIZE + dataSize);
	authInfo.cbTag   = AESGCM_TAG_SIZE;

	ULONG    bytesEncrypted;
	NTSTATUS status =
		BCryptEncrypt(hKey_, (PUCHAR)data, dataSize, &authInfo, NULL, 0,
					  (PUCHAR)(result.data() + AESGCM_IV_SIZE), dataSize,
					  &bytesEncrypted, 0);

	if (!BCRYPT_SUCCESS(status)) {
		throw std::runtime_error("Encryption failed");
	}
#else
	EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
	if (!ctx) {
		throw std::runtime_error("Failed to create cipher context");
	}

	try {
		if (EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL,
							   NULL) != 1) {
			throw std::runtime_error("Failed to initialize encryption");
		}
		if (EVP_EncryptInit_ex(ctx, NULL, NULL,
							   (unsigned char*)key_.data(),
							   (unsigned char*)iv.data()) != 1) {
			throw std::runtime_error("Failed to set key and IV");
		}
		int len;
		if (EVP_EncryptUpdate(
				ctx, (unsigned char*)(result.data() + AESGCM_IV_SIZE), &len,
				(unsigned char*)data, dataSize) != 1) {
			throw std::runtime_error("Encryption failed");
		}
		if (EVP_EncryptFinal_ex(
				ctx, (unsigned char*)(result.data() + AESGCM_IV_SIZE + len),
				&len) != 1) {
			throw std::runtime_error("Failed to finalize encryption");
		}
		if (EVP_CIPHER_CTX_ctrl(
				ctx, EVP_CTRL_GCM_GET_TAG, AESGCM_TAG_SIZE,
				(unsigned char*)(result.data() + AESGCM_IV_SIZE + dataSize)) !=
			1) {
			throw std::runtime_error(
				"Failed to get authentication tag");
		}
		EVP_CIPHER_CTX_free(ctx);
	} catch (...) {
		EVP_CIPHER_CTX_free(ctx);
		throw;
	}
#endif
	return result;
}

std::vector<char> AesGcm::decrypt(const char* encryptedData,
								  size_t      encryptedSize) {
	if (!encryptedData || encryptedSize < AESGCM_IV_SIZE + AESGCM_TAG_SIZE) {
		throw std::invalid_argument("Invalid encrypted data");
	}

	size_t ciphertextSize = encryptedSize - AESGCM_IV_SIZE - AESGCM_TAG_SIZE;
	std::vector<char> result(ciphertextSize);
	const char*       iv         = encryptedData;
	const char*       ciphertext = encryptedData + AESGCM_IV_SIZE;
	const char*       tag = encryptedData + AESGCM_IV_SIZE + ciphertextSize;

#ifdef _WIN32
	BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
	BCRYPT_INIT_AUTH_MODE_INFO(authInfo);
	authInfo.pbNonce = (PUCHAR)iv;
	authInfo.cbNonce = AESGCM_IV_SIZE;
	authInfo.pbTag   = (PUCHAR)tag;
	authInfo.cbTag   = AESGCM_TAG_SIZE;

	ULONG    bytesDecrypted;
	NTSTATUS status = BCryptDecrypt(
		hKey_, (PUCHAR)ciphertext, ciphertextSize, &authInfo, NULL, 0,
		(PUCHAR)result.data(), ciphertextSize, &bytesDecrypted, 0);

	if (!BCRYPT_SUCCESS(status)) {
		throw std::runtime_error(
			"Decryption failed - authentication verification failed");
	}
#else
	EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
	if (!ctx) {
		throw std::runtime_error("Failed to create cipher context");
	}
	try {
		if (EVP_DecryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL,
							   NULL) != 1) {
			throw std::runtime_error("Failed to initialize decryption");
		}
		if (EVP_DecryptInit_ex(ctx, NULL, NULL,
							   (unsigned char*)key_.data(),
							   (unsigned char*)iv) != 1) {
			throw std::runtime_error("Failed to set key and IV");
		}
		int len;
		if (EVP_DecryptUpdate(ctx, (unsigned char*)result.data(), &len,
							  (unsigned char*)ciphertext,
							  ciphertextSize) != 1) {
			throw std::runtime_error("Decryption failed");
		}
		if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, AESGCM_TAG_SIZE,
								(void*)tag) != 1) {
			throw std::runtime_error(
				"Failed to set authentication tag");
		}
		int ret = EVP_DecryptFinal_ex(
			ctx, (unsigned char*)(result.data() + len), &len);
		if (ret <= 0) {
			throw std::runtime_error(
				"Decryption failed - authentication verification "
				"failed");
		}
		EVP_CIPHER_CTX_free(ctx);
	} catch (...) {
		EVP_CIPHER_CTX_free(ctx);
		throw;
	}
#endif
	return result;
}

bool AesGcm::is_ready() {
	return (*((uint_least64_t*)key_.data()) != 0) &&
		   (*(((uint_least64_t*)key_.data()) + 1) != 0);
}

std::array<char, AESGCM_KEY_SIZE> AesGcm::generateRandomKey() {
	std::array<char, AESGCM_KEY_SIZE> key;
#ifdef _WIN32
	NTSTATUS status =
		BCryptGenRandom(NULL, (PUCHAR)key.data(), AESGCM_KEY_SIZE,
						BCRYPT_USE_SYSTEM_PREFERRED_RNG);
	if (!BCRYPT_SUCCESS(status)) {
		throw std::runtime_error("Failed to generate random key");
	}
#else
	if (RAND_bytes((unsigned char*)key.data(), AESGCM_KEY_SIZE) != 1) {
		throw std::runtime_error("Failed to generate random key");
	}
#endif
	return key;
}

std::array<char, 64> calculateSHA512(const char* data, size_t size) {
    std::array<char, 64> result{};
    
#ifdef _WIN32
    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;
    DWORD hashLen = 64;
    
    if (CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        if (CryptCreateHash(hProv, CALG_SHA_512, 0, 0, &hHash)) {
            if (CryptHashData(hHash, reinterpret_cast<const BYTE*>(data), static_cast<DWORD>(size), 0)) {
                CryptGetHashParam(hHash, HP_HASHVAL, reinterpret_cast<BYTE*>(result.data()), &hashLen, 0);
            }
            CryptDestroyHash(hHash);
        }
        CryptReleaseContext(hProv, 0);
    }
#else
	SHA512(reinterpret_cast<const unsigned char*>(data), size,
		   reinterpret_cast<unsigned char*>(result.data()));
#endif
	return result;
}

std::array<unsigned char, AESGCM_KEY_SIZE>
generate_key(const char* data, size_t size, std::array<unsigned char, SALT_SIZE>& salt) {
	if (data == nullptr || size <= 0) {
        throw std::invalid_argument("Invalid input parameters");
    }

	constexpr auto                             iterations = 600'000;
    std::array<unsigned char, AESGCM_KEY_SIZE> key{};
	bool use_random_salt = (*((uint_least64_t*)salt.data()) == 0) &&
						   (*(((uint_least64_t*)salt.data()) + 1) == 0);
	
#ifdef _WIN32
    // Windows implementation using BCrypt API
    BCRYPT_ALG_HANDLE hAlg = nullptr;
    NTSTATUS status;
    
    // Open algorithm provider
    status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA512_ALGORITHM, nullptr, BCRYPT_ALG_HANDLE_HMAC_FLAG);
    if (!BCRYPT_SUCCESS(status)) {
        throw std::runtime_error("Failed to open PBKDF2 algorithm provider");
    }
	if (use_random_salt) {
		// Generate random salt
		status = BCryptGenRandom(nullptr, salt.data(),
								 static_cast<ULONG>(salt.size()),
								 BCRYPT_USE_SYSTEM_PREFERRED_RNG);
		if (!BCRYPT_SUCCESS(status)) {
			throw std::runtime_error("Failed to generate random salt");
		}
	}
    
    try {
        // Derive key using PBKDF2
        status = BCryptDeriveKeyPBKDF2(
            hAlg,
            reinterpret_cast<PUCHAR>(const_cast<char*>(data)),
            static_cast<ULONG>(size),
            salt.data(),
            static_cast<ULONG>(salt.size()),
            iterations,
            reinterpret_cast<PUCHAR>(key.data()),
            static_cast<ULONG>(AESGCM_KEY_SIZE),
            0
        );
        
        if (!BCRYPT_SUCCESS(status)) {
            throw std::runtime_error("Failed to derive PBKDF2 key");
        }
    } catch (...) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        throw;
    }
    
    BCryptCloseAlgorithmProvider(hAlg, 0);
#else
    // Linux implementation using OpenSSL
	if (use_random_salt) {
		// Generate random salt
		if (RAND_bytes(salt.data(), static_cast<int>(salt.size())) != 1) {
			throw std::runtime_error("Failed to generate random salt");
		}
	}
    
    // Derive key using PBKDF2 with SHA-512
    int result = PKCS5_PBKDF2_HMAC(
        data,
        static_cast<int>(size),
        salt.data(),
        static_cast<int>(salt.size()),
        iterations,
        EVP_sha512(),
        static_cast<int>(AESGCM_KEY_SIZE),
        reinterpret_cast<unsigned char*>(key.data())
    );
    
    if (result != 1) {
        throw std::runtime_error("Failed to derive PBKDF2 key using OpenSSL");
    }
    
#endif
    return key;
}
