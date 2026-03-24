#ifndef SIMPLE_COROUTINE_HPP
#define SIMPLE_COROUTINE_HPP

#include <coroutine>
#include <exception>
#include <optional>
#include <utility>
#include <stdexcept>

// ============================================================================
// Generator - 类似 std::generator，支持 co_yield
// ============================================================================
template <typename T> class Generator {
	public:
		struct promise_type {
				std::optional<T>   current_value;
				std::exception_ptr exception;

				Generator          get_return_object() {
                    return Generator{
                        std::coroutine_handle<promise_type>::from_promise(
                            *this)};
				}

				std::suspend_always initial_suspend() {
					return {};
				}
				std::suspend_always final_suspend() noexcept {
					return {};
				}

				std::suspend_always yield_value(T value) {
					current_value = std::move(value);
					return {};
				}

				void return_void() {
				}

				void unhandled_exception() {
					exception = std::current_exception();
				}
		};

		struct iterator {
				std::coroutine_handle<promise_type> handle;
				bool                                done;

				iterator(std::coroutine_handle<promise_type> h, bool d)
					: handle(h), done(d) {
					if (!done && handle) {
						handle.resume();
						done = handle.done();
					}
				}

				iterator& operator++() {
					if (handle && !done) {
						handle.resume();
						done = handle.done();
					}
					return *this;
				}

				bool operator!=(const iterator& other) const {
					return done != other.done;
				}

				const T& operator*() const {
					return *handle.promise().current_value;
				}
		};

		explicit Generator(std::coroutine_handle<promise_type> h) : handle_(h) {
		}

		~Generator() {
			if (handle_) {
				handle_.destroy();
			}
		}

		Generator(const Generator&)            = delete;
		Generator& operator=(const Generator&) = delete;

		Generator(Generator&& other) noexcept : handle_(other.handle_) {
			other.handle_ = nullptr;
		}

		Generator& operator=(Generator&& other) noexcept {
			if (this != &other) {
				if (handle_) {
					handle_.destroy();
				}
				handle_       = other.handle_;
				other.handle_ = nullptr;
			}
			return *this;
		}

		iterator begin() {
			return iterator{handle_, false};
		}

		iterator end() {
			return iterator{nullptr, true};
		}

	private:
		std::coroutine_handle<promise_type> handle_;
};

// ============================================================================
// Awaitable - 用于 co_await 的等待器，支持协程挂起和恢复
// ============================================================================
struct Suspend {
		bool await_ready() const noexcept {
			return false;
		}
		void await_suspend(std::coroutine_handle<>) const noexcept {
		}
		void await_resume() const noexcept {
		}
};

// ============================================================================
// Task - 支持 co_return、co_yield 和 co_await 的协程
// ============================================================================
template <typename T = void> class Task {
	public:
		struct promise_type {
				std::optional<T>   result;
				std::exception_ptr exception;
				std::optional<T> yielded_value; // 用于存储 co_yield 的值
				bool             is_yielded = false;

				Task             get_return_object() {
                    return Task{
                        std::coroutine_handle<promise_type>::from_promise(
                            *this)};
				}

				std::suspend_never initial_suspend() {
					return {};
				}
				std::suspend_always final_suspend() noexcept {
					return {};
				}

				// 支持 co_return
				void return_value(T value) {
					result = std::move(value);
				}

				// 支持 co_yield (中途挂起并返回值)
				std::suspend_always yield_value(T value) {
					yielded_value = std::move(value);
					is_yielded    = true;
					return {};
				}

				// 支持 co_await
				template <typename U> auto await_transform(U&& awaitable) {
					return std::forward<U>(awaitable);
				}

				void unhandled_exception() {
					exception = std::current_exception();
				}
		};

		explicit Task(std::coroutine_handle<promise_type> h) : handle_(h) {
		}

		~Task() {
			if (handle_) {
				handle_.destroy();
			}
		}

		Task(const Task&)            = delete;
		Task& operator=(const Task&) = delete;

		Task(Task&& other) noexcept : handle_(other.handle_) {
			other.handle_ = nullptr;
		}

		Task& operator=(Task&& other) noexcept {
			if (this != &other) {
				if (handle_) {
					handle_.destroy();
				}
				handle_       = other.handle_;
				other.handle_ = nullptr;
			}
			return *this;
		}

		// 恢复协程执行（从挂起点继续）
		bool resume() {
			if (!handle_ || handle_.done()) {
				return false;
			}

			auto& promise      = handle_.promise();
			promise.is_yielded = false; // 清除 yield 标志
			promise.yielded_value.reset();

			handle_.resume();
			return !handle_.done();
		}

		// 获取 co_yield 产生的值
		std::optional<T> get_yielded() const {
			if (!handle_) {
				return std::nullopt;
			}

			auto& promise = handle_.promise();
			if (promise.is_yielded && promise.yielded_value) {
				return promise.yielded_value;
			}
			return std::nullopt;
		}

		// 检查是否在 yield 状态
		bool is_yielded() const {
			return handle_ && handle_.promise().is_yielded;
		}

		// 获取最终返回值（co_return）
		T get() {
			if (!handle_) {
				throw std::runtime_error("Invalid coroutine handle");
			}

			// 继续执行直到完成
			while (!handle_.done()) {
				handle_.resume();
			}

			auto& promise = handle_.promise();

			if (promise.exception) {
				std::rethrow_exception(promise.exception);
			}

			if (!promise.result) {
				throw std::runtime_error("No return value");
			}

			return std::move(*promise.result);
		}

		// 检查是否完成
		bool done() const {
			return handle_ && handle_.done();
		}

		// 检查是否有效
		bool valid() const {
			return handle_ != nullptr;
		}

	private:
		std::coroutine_handle<promise_type> handle_;
};

// Task<void> 特化版本
template <> class Task<void> {
	public:
		struct promise_type {
				std::exception_ptr exception;
				bool               is_yielded = false;

				Task               get_return_object() {
                    return Task{
                        std::coroutine_handle<promise_type>::from_promise(
                            *this)};
				}

				std::suspend_always initial_suspend() {
					return {};
				}
				std::suspend_always final_suspend() noexcept {
					return {};
				}

				void return_void() {
				}

				// 支持无值的 co_yield
				std::suspend_always yield_value() {
					is_yielded = true;
					return {};
				}

				template <typename U> auto await_transform(U&& awaitable) {
					return std::forward<U>(awaitable);
				}

				void unhandled_exception() {
					exception = std::current_exception();
				}
		};

		explicit Task(std::coroutine_handle<promise_type> h) : handle_(h) {
		}

		~Task() {
			if (handle_) {
				handle_.destroy();
			}
		}

		Task(const Task&)            = delete;
		Task& operator=(const Task&) = delete;

		Task(Task&& other) noexcept : handle_(other.handle_) {
			other.handle_ = nullptr;
		}

		Task& operator=(Task&& other) noexcept {
			if (this != &other) {
				if (handle_) {
					handle_.destroy();
				}
				handle_       = other.handle_;
				other.handle_ = nullptr;
			}
			return *this;
		}

		bool resume() {
			if (!handle_ || handle_.done()) {
				return false;
			}

			auto& promise      = handle_.promise();
			promise.is_yielded = false;

			handle_.resume();
			return !handle_.done();
		}

		bool is_yielded() const {
			return handle_ && handle_.promise().is_yielded;
		}

		void get() {
			if (!handle_) {
				throw std::runtime_error("Invalid coroutine handle");
			}

			while (!handle_.done()) {
				handle_.resume();
			}

			auto& promise = handle_.promise();

			if (promise.exception) {
				std::rethrow_exception(promise.exception);
			}
		}

		bool done() const {
			return handle_ && handle_.done();
		}

		bool valid() const {
			return handle_ != nullptr;
		}

	private:
		std::coroutine_handle<promise_type> handle_;
};

#endif // SIMPLE_COROUTINE_HPP