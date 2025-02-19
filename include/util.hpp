#ifndef UTIL_HPP
#define UTIL_HPP
#include <array>
#include <chrono>
#include <cstring>
#include <iostream>
#include <ranges>
#include <unordered_map>
#include <vector>
#include <format>
using Byte = char;
namespace sc = std::chrono;
using namespace std::chrono_literals;
namespace mfcslib {
	template <typename _Type>
	class TypeArray {
#ifdef _WIN32
		using _SizeType = int;
#else
		using _SizeType = size_t;
#endif

	public:
		TypeArray() = delete;
		TypeArray(const TypeArray& arg) = delete;
		constexpr ~TypeArray() {
			if (_DATA != nullptr) {
				delete[] _DATA;
				_SIZE = 0;
				_DATA = nullptr;
			}
		};
		constexpr explicit TypeArray(size_t sz) : _SIZE(sz) {
			_DATA = new _Type[sz];
			memset(_DATA, 0, sz);
		}
		constexpr explicit TypeArray(TypeArray&& arg) {
			_DATA = arg._DATA;
			arg._DATA = nullptr;
			_SIZE = arg._SIZE;
			arg._SIZE = 0;
		}
		constexpr _Type& operator[](int arg) {
#ifdef DEBUG
			if (arg < 0 || arg >= _SIZE)
				throw std::out_of_range("In [].");
#endif
			return _DATA[arg];
		}
		constexpr bool empty() {
			return _DATA == nullptr;
		}
		constexpr void fill(_Type val, size_t start, size_t end) {
#ifdef DEBUG
			if (start >= end)
				throw std::out_of_range(
					"In fill, start is greater or equal to end.");
#endif
			memset(_DATA + start, val, end - start);
		}
		constexpr void empty_array() {
			fill(0, 0, _SIZE);
		}
		constexpr _SizeType length() {
			return _SIZE;
		}
		constexpr void destroy() {
			this->~TypeArray();
		}
		constexpr auto get_ptr() {
			return _DATA;
		}
		constexpr auto to_string() {
			return std::string(_DATA);
		}
		friend constexpr std::basic_ostream<_Type>&
			operator<<(std::basic_ostream<_Type>& os, TypeArray<_Type>& str) {
			os << str._DATA;
			return os;
		}

	private:
		_Type* _DATA = nullptr;
		_SizeType _SIZE = 0;
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

	template <uint16_t N> class Range {
	public:
		constexpr Range() {
			for (uint16_t i = 0; i < N; ++i) {
				data[i] = i;
			}
		}
		constexpr Range(intmax_t start) {
			for (auto& d : data) {
				d = start++;
			}
		}
		constexpr ~Range() = default;

		constexpr auto begin() {
			return data;
		}
		constexpr auto end() {
			return &data[N];
		}

	private:
		intmax_t data[N];
	};

	template <typename T> class timer {
	public:
		timer() = default;
		timer(const sc::seconds& time) : _interval(time) {
		}
		~timer() = default;
		void setup_interval(const sc::seconds& time) {
			_interval = time;
		}
		void insert_or_update(T value) {
			_data[value] = sc::system_clock::now();
		}
		void erase_value(T value) {
			_data.erase(value);
		}
		std::vector<T> clear_expired() {
			auto           cur_time = sc::system_clock::now();
			std::vector<T> res;
			for (auto ite = _data.begin(); ite != _data.end();) {
				if (cur_time - ite->second >= _interval) {
					res.emplace_back(ite->first);
					_data.erase(ite++);
					continue;
				}
				break;
			}
			return res;
		}

	private:
		std::unordered_map<T, sc::time_point<sc::system_clock>> _data;
		sc::seconds _interval = 300s;
	};

	template <template <typename> typename Container = std::vector,
		typename StringType = std::string>
	constexpr Container<StringType> str_split(std::string str,
		std::string_view delim) {
		Container<StringType> cont;
		for (const auto& word : std::views::split(str, delim)) {
			cont.emplace_back(StringType(word.begin(), word.end()));
		}
		return cont;
	}

	template <typename P, typename T>
	constexpr int64_t strchr_c(const P* str, const T ch) {
		int64_t idx = 0;
		while (*str) {
			if (*str == ch)
				return idx;
			++str;
			++idx;
		}
		return -1;
	}

	constexpr inline char _single_hex_to_char(char h) {
		if (h >= '0' && h <= '9')
			return h - 48;
		else
			return h - 55;
	}
	constexpr inline char hex_str_to_char(const std::string_view& str) {
		return char((_single_hex_to_char(str[0]) << 4) +
			_single_hex_to_char(str[1]));
	}

} // namespace mfcslib
#define _var const auto& s
#define _in :
#define _range(_) mfcslib::Range<(uint16_t)_>()
#endif // !UTIL_HPP
