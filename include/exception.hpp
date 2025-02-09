#ifndef EXCEPTION_HPP
#define EXCEPTION_HPP

#include <string>
using std::string;

namespace mfcslib {
	class basic_exception 
	{
	public:
		basic_exception() = default;
		~basic_exception() = default;
		std::string what() const {
			return error_message;
		}

	protected:
		std::string error_message;
	};

	class out_of_range_exception :public basic_exception
	{
	public:
		out_of_range_exception() = default;
		out_of_range_exception(const std::string& str) {
			error_message = str;
		}
		~out_of_range_exception() = default;

	private:

	};


	class IO_exception :public basic_exception
	{
	public:
		IO_exception() = default;
		IO_exception(const std::string& str) {
			error_message = str;
		}
		IO_exception(const char* str){
			error_message = str;
		}
		~IO_exception() = default;

	private:

	};

	class socket_exception :public IO_exception
	{
	public:
		socket_exception() = default; 
		socket_exception(const std::string& str) {
			error_message = str;
		}
		~socket_exception() = default; 

	};

	class file_exception :public IO_exception
	{
	public:
		file_exception() = default; 
		file_exception(const std::string& str) {
			error_message = str;
		}
		~file_exception() = default; 

	};

	class peer_exception : public socket_exception
	{
	public:
		peer_exception() = default;
		peer_exception(const std::string& str) {
			error_message = str;
		}
		~peer_exception() = default;

	private:

	};


}
#endif // !EXCEPTION_HPP
