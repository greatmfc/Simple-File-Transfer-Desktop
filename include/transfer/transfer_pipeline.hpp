#pragma once

#include "transfer_common.hpp"

namespace sft_detail {

struct transfer_pipeline_buffer {
		explicit transfer_pipeline_buffer(kotcpp::SizeType capacity)
			: data(static_cast<std::size_t>(capacity)) {
		}

		std::vector<Byte> data;
		kotcpp::SizeType  size   = 0;
		kotcpp::SizeType  offset = 0;
};

class transfer_pipeline_queue {
	public:
		transfer_pipeline_queue(std::size_t depth, kotcpp::SizeType buffer_size)
			: depth_(depth), buffer_size_(buffer_size) {
			for (std::size_t i = 0; i < depth_; ++i) {
				free_buffers_.push_back(
					std::make_unique<transfer_pipeline_buffer>(buffer_size_));
			}
		}

		void reset() {
			std::lock_guard lock(mutex_);
			while (!ready_buffers_.empty()) {
				auto buffer = std::move(ready_buffers_.front());
				ready_buffers_.pop_front();
				buffer->size   = 0;
				buffer->offset = 0;
				free_buffers_.push_back(std::move(buffer));
			}
			while (free_buffers_.size() < depth_) {
				free_buffers_.push_back(
					std::make_unique<transfer_pipeline_buffer>(buffer_size_));
			}
			cancelled_    = false;
			ready_closed_ = false;
		}

		std::unique_ptr<transfer_pipeline_buffer> acquire_free() {
			std::unique_lock lock(mutex_);
			free_cv_.wait(
				lock, [&]() { return cancelled_ || !free_buffers_.empty(); });
			if (cancelled_) {
				return nullptr;
			}

			auto buffer = std::move(free_buffers_.front());
			free_buffers_.pop_front();
			return buffer;
		}

		bool push_ready(std::unique_ptr<transfer_pipeline_buffer> buffer) {
			std::lock_guard lock(mutex_);
			if (cancelled_) {
				return false;
			}

			ready_buffers_.push_back(std::move(buffer));
			ready_cv_.notify_one();
			return true;
		}

		std::unique_ptr<transfer_pipeline_buffer> pop_ready() {
			std::unique_lock lock(mutex_);
			ready_cv_.wait(lock, [&]() {
				return cancelled_ || ready_closed_ || !ready_buffers_.empty();
			});
			if (cancelled_ || ready_buffers_.empty()) {
				return nullptr;
			}

			auto buffer = std::move(ready_buffers_.front());
			ready_buffers_.pop_front();
			return buffer;
		}

		void release_free(std::unique_ptr<transfer_pipeline_buffer> buffer) {
			if (buffer == nullptr) {
				return;
			}
			buffer->size   = 0;
			buffer->offset = 0;

			std::lock_guard lock(mutex_);
			if (cancelled_) {
				return;
			}

			free_buffers_.push_back(std::move(buffer));
			free_cv_.notify_one();
		}

		void close_ready() {
			std::lock_guard lock(mutex_);
			ready_closed_ = true;
			ready_cv_.notify_all();
		}

		void cancel() {
			std::lock_guard lock(mutex_);
			cancelled_    = true;
			ready_closed_ = true;
			free_cv_.notify_all();
			ready_cv_.notify_all();
		}

	private:
		std::size_t                                           depth_;
		kotcpp::SizeType                                      buffer_size_;
		std::mutex                                            mutex_;
		std::condition_variable                               free_cv_;
		std::condition_variable                               ready_cv_;
		std::deque<std::unique_ptr<transfer_pipeline_buffer>> free_buffers_;
		std::deque<std::unique_ptr<transfer_pipeline_buffer>> ready_buffers_;
		bool cancelled_    = false;
		bool ready_closed_ = false;
};

struct transfer_pipeline_context {
		transfer_pipeline_context()
			: pipeline(transfer_pipeline_depth, transfer_chunk_size),
			  io_pool(std::size_t{1}) {
		}

		transfer_pipeline_queue pipeline;
		BS::light_thread_pool   io_pool;
};

} // namespace sft_detail
