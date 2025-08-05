#ifndef UTIL_HPP
#define UTIL_HPP
#include <array>
#include <iostream>
#include <vector>
#include <algorithm>
#include <format>
using Byte = char;
namespace mfcslib {
template <typename Type = Byte>
	class TypeArray {

	public:
		using size_type = size_t;
		using value_type=Type;

		TypeArray() = delete;
		TypeArray(const TypeArray& arg) = delete;
		constexpr ~TypeArray() {
			if (m_DATA != nullptr) {
				delete[] m_DATA;
				m_SIZE = 0;
				m_DATA = nullptr;
			}
		}
		constexpr explicit TypeArray(size_t sz) : m_SIZE(sz) {
			m_DATA = new Type[sz];
			memset(m_DATA, 0, sz);
		}
		constexpr explicit TypeArray(TypeArray&& arg) {
			m_DATA = arg.m_DATA;
			arg.m_DATA = nullptr;
			m_SIZE = arg.m_SIZE;
			arg.m_SIZE = 0;
		}
		constexpr Type& operator[](int arg) {
#ifdef DEBUG
			if (arg < 0 || arg >= m_SIZE){
				throw std::out_of_range("In [].");
			}
#endif
			return m_DATA[arg];
		}
		constexpr bool empty() {
			return m_DATA == nullptr;
		}
		constexpr void fill(Type val, size_t start, size_t end) {
#ifdef DEBUG
			if (start >= end) {
				throw std::out_of_range(
					"In fill, start is greater or equal to end.");
			}
#endif
			memset(m_DATA + start, val, end - start);
		}
		constexpr void empty_array() {
			fill(0, 0, m_SIZE);
		}
		constexpr size_type size() const{
			return m_SIZE;
		}
		constexpr void destroy() {
			this->~TypeArray();
		}
		constexpr auto data() {
			return m_DATA;
		}
		constexpr const auto data() const{
			return m_DATA;
		}
		constexpr auto to_string() {
			return std::string(m_DATA);
		}
		friend constexpr std::basic_ostream<Type>&
			operator<<(std::basic_ostream<Type>& os, TypeArray<Type>& str) {
			os << str.m_DATA;
			return os;
		}

	private:
		Type* m_DATA = nullptr;
		size_type m_SIZE = 0;
	};
	template <typename T = Byte> auto make_array(size_t sz) {
		return TypeArray<T>(sz);
	}

	constexpr std::array<std::string_view, 11> all_percent = {
		"\r[----------]", "\r[*---------]", "\r[**--------]", "\r[***-------]",
		"\r[****------]", "\r[*****-----]", "\r[******----]", "\r[*******---]",
		"\r[********--]", "\r[*********-]", "\r[**********]",
	};
	template <typename T, typename R> void progress_bar(T num1, R num2) noexcept {
		double percent = static_cast<double>(num1) / static_cast<double>(num2);
		if (percent > 1 || percent <= 0) {
			std::cout << std::format("Invalid percentage: {}/{}", num1, num2)
				<< std::endl;
			return;
		}
		uintmax_t index = uintmax_t(percent * 10);
		std::cout << all_percent[index] << ' ' << std::to_string(percent * 100)
			<< '%';
		std::cout.flush();
		return;
	}

	constexpr std::vector<std::string_view> str_split(std::string_view str,std::string_view delims) {
		std::vector<std::string_view> output;
		for (auto first = str.data(), second = str.data(),
				  last  = first + str.size();
			 second != last && first != last; first = second + 1) {
			second = std::find_first_of(first, last, std::cbegin(delims), std::cend(delims));
			if (first != second) {
				output.emplace_back(first, second - first);
			}
		}
		return output;
	}
} // namespace mfcslib
#endif // !UTIL_HPP
