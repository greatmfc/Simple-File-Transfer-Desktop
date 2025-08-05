#ifndef AESGCM_H
#define AESGCM_H

#include <array>
#include <vector>
#include <string_view>
#ifdef _WIN32
#include <WinSock2.h>
#include <bcrypt.h>
#endif

static constexpr size_t AESGCM_IV_SIZE  = 12;
static constexpr size_t AESGCM_TAG_SIZE = 16;
static constexpr size_t AESGCM_KEY_SIZE = 16;
//The sender will send salt first before request header.
//The receiver will extract salt from request then create a temporary AesGcm object for current transmission.
static constexpr size_t SALT_SIZE = 16;

#define MOVEBYTES(dst,src,sz) \
	struct temp { unsigned char a[sz]; }; \
	*reinterpret_cast<temp*>(dst) = *reinterpret_cast<const temp*>(src)

class AesGcm {
	public:
		std::array<unsigned char, SALT_SIZE> salt_value{};
	private:
		std::array<unsigned char, AESGCM_KEY_SIZE> key_{};
#ifdef _WIN32
		BCRYPT_ALG_HANDLE hAlgorithm_ = nullptr;
		BCRYPT_KEY_HANDLE hKey_       = nullptr;

		void initializeWindows();
		void cleanupWindows();
#endif
		void generateRandomBytes(char* buffer, size_t size);
		inline void erase_local_key();

	public:
		AesGcm() = default;
		AesGcm(const unsigned char* keyData, size_t keySize);
		AesGcm(std::string_view pass, const std::array<unsigned char, SALT_SIZE>& s);
		~AesGcm();

		AesGcm(AesGcm&&);
		AesGcm(const AesGcm&)                      = delete;
		AesGcm& operator=(const AesGcm&)           = delete;
		AesGcm& operator=(AesGcm&&);
		
		std::vector<char> encrypt(const char* data, size_t dataSize);
		std::vector<char> decrypt(const char* encryptedData, size_t encryptedSize);
		bool is_ready();

		static std::array<char, AESGCM_KEY_SIZE> generateRandomKey();
};

std::array<char, 64> calculateSHA512(const char* data, size_t size);

std::array<unsigned char, AESGCM_KEY_SIZE>
generate_key(const char* data, size_t size,
			 std::array<unsigned char, SALT_SIZE>& s);
#endif // !AESGCM_H
