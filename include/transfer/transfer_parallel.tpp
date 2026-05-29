#pragma once

#include "transfer_protocol.hpp"
#include "transfer_stream.tpp"

namespace sft_detail {

enum class parallel_worker_endpoint {
	Connector,
	Listener
};

struct parallel_transfer_options {
		parallel_worker_endpoint worker_endpoint =
			parallel_worker_endpoint::Connector;
		sockaddr_in peer_addr{};
		std::string sec_path;
		std::string pub_path;
		std::string hosts_path;
		std::size_t max_workers = 0;

		bool        has_identity_paths() const;
		bool        initialize_worker(kotcpp::sft_client& worker) const;
		bool        initialize_worker(kotcpp::sft_server& worker) const;
		bool        accept_worker(kotcpp::sft_server&     worker,
								  kotcpp::tcp_socket&     listener,
								  const std::atomic_bool& cancelled) const;
		bool        connect_worker(kotcpp::sft_client& worker,
								   uint16_t            worker_port) const;
};

struct parallel_send_task {
		size_t         id = 0;
		send_entry_v12 entry;
};

struct parallel_receive_plan {
		transfer_request_entry_v12 entry;
		std::filesystem::path      output_path;
		std::filesystem::path      state_path;
		kotcpp::SizeType           offset      = 0;
		kotcpp::SizeType           length      = 0;
		bool                       in_progress = false;
		bool                       completed   = false;
};

struct parallel_receive_failure {
		size_t      id = 0;
		std::string path;
		std::string reason;
};

struct parallel_receive_state {
		std::mutex                            mutex;
		std::unordered_set<size_t>            seen_ids;
		std::unordered_set<std::string>       seen_paths;
		std::vector<parallel_receive_failure> failures;
		std::size_t                           processed_entries = 0;
		std::size_t                           completed_entries = 0;
		std::size_t                           rejected_entries  = 0;
};

enum class parallel_entry_registration {
	Accepted,
	DuplicateId,
	DuplicatePath
};

inline kotcpp::Result<uint16_t>
open_parallel_worker_listener(kotcpp::tcp_socket& listener,
							  int                 backlog = SOMAXCONN) {
	kotcpp::Error last =
		kotcpp::make_sft_error("Fail to open worker listener.");
	for (int attempt = 0; attempt < 32; ++attempt) {
		kotcpp::tcp_socket candidate;
		auto ret = candidate.listen(kotcpp::generate_random_port(), backlog);
		if (ret) {
			candidate.set_nonblocking();
			const auto port = candidate.get_port();
			listener        = std::move(candidate);
			return port;
		}
		last = ret.error();
	}
	return tl::unexpected(last);
}

inline sockaddr_in make_worker_peer_addr(sockaddr_in peer_addr,
										 uint16_t    worker_port) {
	peer_addr.sin_port = htons(worker_port);
	return peer_addr;
}

inline bool parallel_transfer_options::has_identity_paths() const {
	return !sec_path.empty() && !pub_path.empty() && !hosts_path.empty();
}

inline bool
parallel_transfer_options::initialize_worker(kotcpp::sft_client& worker) const {
	if (!has_identity_paths()) {
		std::cerr << "Parallel transfer requires identity paths.\n";
		return false;
	}
	auto ret = worker.initialize(sec_path, pub_path, hosts_path, false);
	if (!ret) {
		kotcpp::print_error("Fail to initialize parallel client", ret);
		return false;
	}
	return true;
}

inline bool
parallel_transfer_options::initialize_worker(kotcpp::sft_server& worker) const {
	if (!has_identity_paths()) {
		std::cerr << "Parallel transfer requires identity paths.\n";
		return false;
	}
	auto ret = worker.initialize(sec_path, pub_path, hosts_path, false);
	if (!ret) {
		kotcpp::print_error("Fail to initialize parallel server", ret);
		return false;
	}
	return true;
}

inline bool parallel_transfer_options::accept_worker(
	kotcpp::sft_server& worker, kotcpp::tcp_socket& listener,
	const std::atomic_bool& cancelled) const {
	if (!initialize_worker(worker)) {
		return false;
	}
	while (!cancelled.load()) {
		auto ret = worker.listen_and_accept(listener);
		if (ret) {
			return true;
		}
		if (ret.error() != WSAEWOULDBLOCK) {
			kotcpp::print_error("Parallel worker accept failed", ret);
			return false;
		}
		std::this_thread::sleep_for(std::chrono::milliseconds(20));
	}
	return false;
}

inline bool
parallel_transfer_options::connect_worker(kotcpp::sft_client& worker,
										  uint16_t worker_port) const {
	if (!initialize_worker(worker)) {
		return false;
	}
	auto ret = worker.connect(make_worker_peer_addr(peer_addr, worker_port));
	if (!ret) {
		kotcpp::print_error("Parallel worker connect failed", ret);
		return false;
	}
	return true;
}

template <kotcpp::AsyncTransferTarget Target>
bool send_parallel_join(Target& target, std::string_view session_id,
						std::string_view worker_token, std::size_t worker_id) {
	if (!write_control_frame(
			target, build_sft13_join(session_id, worker_token, worker_id))) {
		return false;
	}
	auto ready_text = read_control_frame(target);
	if (!ready_text) {
		kotcpp::print_error("Fail to receive parallel worker READY",
							ready_text);
		return false;
	}
	auto ready = parse_sft13_frame(*ready_text);
	if (!ready || ready->action != frame_action::Ready) {
		std::cerr << "Receive unexpected parallel worker READY.\n";
		return false;
	}
	return true;
}

template <kotcpp::AsyncTransferTarget Target>
bool receive_parallel_join(Target& target, std::string_view session_id,
						   std::string_view worker_token) {
	auto join_text = read_control_frame(target);
	if (!join_text) {
		kotcpp::print_error("Fail to receive parallel worker JOIN", join_text);
		return false;
	}
	auto join = parse_sft13_frame(*join_text);
	if (!join || join->action != frame_action::Join) {
		std::cerr << "Receive unexpected parallel worker JOIN.\n";
		return false;
	}
	if (get_option(*join, "session") != session_id ||
		get_option(*join, "token") != worker_token) {
		std::cerr << "Reject parallel worker with invalid session token.\n";
		return false;
	}
	return write_control_frame(target, build_sft13_ready(0));
}

inline kotcpp::Result<std::pair<kotcpp::SizeType, kotcpp::SizeType>>
parse_parallel_range(const sft12_frame& frame) {
	auto offset = get_size_option(frame, "offset");
	if (!offset) {
		return tl::unexpected(offset.error());
	}
	auto length = get_size_option(frame, "length");
	if (!length) {
		return tl::unexpected(length.error());
	}
	return std::pair{*offset, *length};
}

inline bool wait_for_parallel_futures(
	std::vector<std::future<bool>>& futures, std::atomic_bool& cancelled,
	kotcpp::tcp_socket& listener, std::string_view context,
	parallel_transfer_progress* progress = nullptr) {
	std::vector<bool> completed(futures.size(), false);
	std::size_t       remaining = futures.size();
	bool              all_ok    = true;
	kotcpp::progress_bar_with_speed(0, 0, true);
	while (remaining > 0) {
		bool progressed = false;
		for (std::size_t i = 0; i < futures.size(); ++i) {
			if (completed[i]) {
				continue;
			}
			if (futures[i].wait_for(std::chrono::milliseconds(0)) !=
				std::future_status::ready) {
				continue;
			}

			completed[i] = true;
			--remaining;
			progressed = true;
			if (!wait_for_transfer_worker(futures[i], context)) {
				all_ok = false;
				cancelled.store(true);
				listener.close();
			}
			if (progress != nullptr) {
				progress->render();
			}
		}
		if (progress != nullptr) {
			progress->render();
		}
		if (!progressed) {
			std::this_thread::sleep_for(std::chrono::milliseconds(20));
		}
	}
	if (progress != nullptr) {
		progress->render(all_ok);
	}
	return all_ok;
}

template <kotcpp::AsyncTransferTarget Target>
bool transfer_parallel_sender_tasks(
	Target& target, const std::vector<parallel_send_task>& tasks,
	std::atomic_size_t& next_task, std::size_t worker_id,
	parallel_transfer_progress* progress = nullptr) {
	auto pipeline_context = transfer_pipeline_context();
	while (true) {
		const auto task_index = next_task.fetch_add(1);
		if (task_index >= tasks.size()) {
			break;
		}

		const auto& task  = tasks[task_index];
		const auto& entry = task.entry;
		if (!write_control_frame(target,
								 build_sft13_req(task.id, entry.remote_path,
												 entry.size, entry.is_directory,
												 entry.permissions))) {
			return false;
		}

		auto response_text = read_control_frame(target);
		if (!response_text) {
			kotcpp::print_error("Fail to receive parallel file response",
								response_text);
			return false;
		}
		auto response = parse_sft13_frame(*response_text);
		if (!response) {
			kotcpp::print_error("Fail to parse parallel file response",
								response);
			return false;
		}
		if (response->action == frame_action::Rej) {
			auto rej_id = parse_sft12_id_field(*response, "REJ");
			if (!rej_id || *rej_id != task.id) {
				std::cerr << "Receive mismatched parallel file rejection.\n";
				return false;
			}
			std::cerr << "Peer rejected file: " << entry.remote_path << '\n';
			if (progress != nullptr) {
				progress->add_completed(entry.size);
			}
			continue;
		}
		if (response->action != frame_action::Ack) {
			std::cerr << "Receive unexpected parallel file response.\n";
			return false;
		}

		auto ack_id = parse_sft12_id_field(*response, "ACK");
		auto range  = parse_parallel_range(*response);
		if (!ack_id || !range || *ack_id != task.id) {
			std::cerr << "Receive malformed parallel file ACK.\n";
			return false;
		}
		const auto [offset, length] = *range;
		if (offset > entry.size || length > entry.size - offset) {
			std::cerr << "Peer requested an invalid parallel file range.\n";
			return false;
		}
		if (entry.is_directory && (offset != 0 || length != 0)) {
			std::cerr << "Peer requested payload for directory entry.\n";
			return false;
		}
		if (progress != nullptr) {
			progress->add_completed(offset);
		}

		if (!entry.is_directory) {
			const auto current_size =
				get_file_size_as_size_type(entry.local_path);
			if (!current_size) {
				kotcpp::print_error(std::format("Cannot read file size: {}",
												entry.local_path.string()),
									current_size);
				return false;
			}
			if (*current_size != entry.size) {
				std::cerr << "File changed before transfer: "
						  << entry.local_path.string() << '\n';
				return false;
			}
		}

		if (!entry.is_directory && length > 0) {
			kotcpp::File file(entry.local_path);
			auto         open_res = file.open_read_only();
			if (!open_res) {
				kotcpp::print_error(std::format("Cannot open file: {}",
												entry.local_path.string()),
									open_res);
				return false;
			}

			if (!stream_file_range_to_target(target, file, entry.remote_path,
											 offset, length, pipeline_context,
											 progress)) {
				return false;
			}
		}

		if (!write_control_frame(target, build_sft13_fin(task.id, length))) {
			return false;
		}

		auto ok_text = read_control_frame(target);
		if (!ok_text) {
			kotcpp::print_error("Fail to receive parallel file OK", ok_text);
			return false;
		}
		auto ok    = parse_sft13_frame(*ok_text);
		auto ok_id = ok ? parse_sft12_id_field(*ok, "OK")
						: kotcpp::Result<size_t>(tl::unexpected(ok.error()));
		if (!ok || ok->action != frame_action::Ok || !ok_id ||
			*ok_id != task.id) {
			std::cerr << "Receive unexpected parallel file OK.\n";
			return false;
		}
	}

	return write_control_frame(target, build_sft13_worker_done(worker_id));
}

inline parallel_entry_registration
register_parallel_receive_entry(parallel_receive_state&           state,
								const transfer_request_entry_v12& entry) {
	std::lock_guard lock(state.mutex);
	if (!state.seen_ids.emplace(entry.id).second) {
		return parallel_entry_registration::DuplicateId;
	}
	if (!state.seen_paths.emplace(entry.path).second) {
		return parallel_entry_registration::DuplicatePath;
	}
	return parallel_entry_registration::Accepted;
}

inline void
record_parallel_receive_failure(parallel_receive_state&           state,
								const transfer_request_entry_v12& entry,
								std::string_view                  reason) {
	std::lock_guard lock(state.mutex);
	state.failures.push_back(parallel_receive_failure{
		.id     = entry.id,
		.path   = entry.path,
		.reason = std::string(reason),
	});
}

inline void
mark_parallel_receive_rejected(parallel_receive_state&           state,
							   const transfer_request_entry_v12& entry,
							   std::string_view                  reason) {
	std::lock_guard lock(state.mutex);
	state.failures.push_back(parallel_receive_failure{
		.id     = entry.id,
		.path   = entry.path,
		.reason = std::string(reason),
	});
	++state.processed_entries;
	++state.rejected_entries;
}

inline void mark_parallel_receive_completed(parallel_receive_state& state) {
	std::lock_guard lock(state.mutex);
	++state.processed_entries;
	++state.completed_entries;
}

inline std::vector<parallel_receive_failure>
get_parallel_receive_failures(parallel_receive_state& state) {
	std::lock_guard lock(state.mutex);
	return state.failures;
}

inline void print_parallel_receive_failures(parallel_receive_state& state) {
	auto failures = get_parallel_receive_failures(state);
	if (failures.empty()) {
		return;
	}

	std::sort(failures.begin(), failures.end(),
			  [](const auto& lhs, const auto& rhs) {
				  if (lhs.id != rhs.id) {
					  return lhs.id < rhs.id;
				  }
				  return lhs.path < rhs.path;
			  });

	std::cerr << "sft1.3 receive failures:\n";
	for (const auto& failure : failures) {
		std::cerr << "  [" << failure.id << "] " << failure.path << ": "
				  << failure.reason << '\n';
	}
}

inline bool complete_parallel_receive_plan(parallel_receive_plan& plan,
										   kotcpp::File&          output_file) {
	if (auto resize_res =
			output_file.resize(static_cast<std::uintmax_t>(plan.entry.size));
		!resize_res) {
		kotcpp::print_error("Fail to resize received file", resize_res);
		return false;
	}
	if (plan.entry.permissions != std::filesystem::perms::unknown) {
		(void)output_file.set_permissions(plan.entry.permissions);
	}
	if (auto remove_res = remove_resume_state(plan.state_path); !remove_res) {
		kotcpp::print_error("Fail to remove resume state", remove_res);
		return false;
	}
	return true;
}

template <kotcpp::AsyncTransferTarget Target>
bool receive_parallel_fin(Target& target, size_t entry_id,
						  kotcpp::SizeType sent) {
	auto fin_text = read_control_frame(target);
	if (!fin_text) {
		kotcpp::print_error("Fail to receive parallel FIN", fin_text);
		return false;
	}
	auto fin = parse_sft13_frame(*fin_text);
	if (!fin || fin->action != frame_action::Fin) {
		std::cerr << "Receive unexpected parallel FIN.\n";
		return false;
	}
	auto fin_id   = parse_sft12_id_field(*fin, "FIN");
	auto fin_sent = get_size_option(*fin, "sent");
	if (!fin_id || !fin_sent || *fin_id != entry_id || *fin_sent != sent) {
		std::cerr << "Receive mismatched parallel FIN.\n";
		return false;
	}
	return true;
}

template <kotcpp::AsyncTransferTarget Target>
bool receive_parallel_worker_tasks(
	Target& target, parallel_receive_state& receive_state,
	const std::filesystem::path& output_root, std::size_t worker_id,
	parallel_transfer_progress* progress = nullptr) {
	(void)worker_id;
	auto pipeline_context = transfer_pipeline_context();
	while (true) {
		auto request_text = read_control_frame(target);
		if (!request_text) {
			kotcpp::print_error("Fail to receive parallel worker request",
								request_text);
			return false;
		}
		auto request = parse_sft13_frame(*request_text);
		if (!request) {
			kotcpp::print_error("Fail to parse parallel worker frame", request);
			return false;
		}
		if (request->action == frame_action::Done) {
			return true;
		}
		if (request->action != frame_action::Req) {
			std::cerr << "Receive unexpected parallel worker frame.\n";
			return false;
		}

		auto entry = parse_sft12_req(*request);
		if (!entry) {
			kotcpp::print_error("Fail to parse parallel worker request", entry);
			return false;
		}

		bool total_accounted = false;
		auto account_total   = [&]() {
            if (progress != nullptr && !progress->total_preannounced &&
                !total_accounted) {
                progress->add_total(entry->size);
                total_accounted = true;
            }
		};
		auto reject_current = [&](std::string_view reason) {
			account_total();
			if (progress != nullptr) {
				progress->add_completed(entry->size);
			}
			mark_parallel_receive_rejected(receive_state, *entry, reason);
			return write_control_frame(target,
									   build_sft13_rej(entry->id, reason));
		};

		switch (register_parallel_receive_entry(receive_state, *entry)) {
		case parallel_entry_registration::Accepted:
			break;
		case parallel_entry_registration::DuplicateId:
			record_parallel_receive_failure(receive_state, *entry,
											"Duplicate parallel file id.");
			std::cerr << "Receive duplicate parallel file id.\n";
			return false;
		case parallel_entry_registration::DuplicatePath:
			if (!reject_current("Duplicate parallel output path.")) {
				return false;
			}
			continue;
		}

		account_total();
		auto output_path = resolve_output_path(output_root, entry->path);
		if (!output_path) {
			kotcpp::print_error("Reject output path from peer", output_path);
			if (!reject_current(output_path.error().message())) {
				return false;
			}
			continue;
		}

		if (entry->is_directory) {
			if (entry->size != 0) {
				if (!reject_current("Directory entry must not have payload.")) {
					return false;
				}
				continue;
			}

			std::error_code ec;
			std::filesystem::create_directories(*output_path, ec);
			if (ec) {
				if (!reject_current(kotcpp::filesystem_error(ec).message())) {
					return false;
				}
				continue;
			}
			if (entry->permissions != std::filesystem::perms::unknown) {
				kotcpp::File directory(*output_path);
				(void)directory.set_permissions(entry->permissions);
			}
			if (!write_control_frame(target,
									 build_sft13_ack(entry->id, 0, 0))) {
				record_parallel_receive_failure(receive_state, *entry,
												"Failed to send ACK.");
				return false;
			}
			if (!receive_parallel_fin(target, entry->id, 0)) {
				record_parallel_receive_failure(
					receive_state, *entry,
					"Failed to receive matching FIN for directory entry.");
				return false;
			}
			mark_parallel_receive_completed(receive_state);
			if (!write_control_frame(target, build_sft13_ok(entry->id))) {
				record_parallel_receive_failure(receive_state, *entry,
												"Failed to send OK.");
				return false;
			}
			continue;
		}

		std::error_code ec;
		if (output_path->has_parent_path()) {
			std::filesystem::create_directories(output_path->parent_path(), ec);
			if (ec) {
				if (!reject_current(kotcpp::filesystem_error(ec).message())) {
					return false;
				}
				continue;
			}
		}

		transfer_resume_identity identity{
			.path        = entry->path,
			.size        = entry->size,
			.permissions = entry->permissions,
			.extra       = "type=file",
		};
		auto state_path = get_resume_state_path(identity);
		if (!state_path) {
			if (!reject_current(state_path.error().message())) {
				return false;
			}
			continue;
		}

		kotcpp::SizeType offset = 0;
		auto             state  = load_resume_state(*state_path);
		if (!state) {
			kotcpp::print_error("Fail to load resume state", state);
			offset = 0;
		}
		else {
			offset = (*state).received_bytes;
		}

		if (std::filesystem::exists(*output_path, ec) && !ec) {
			const auto local_size = static_cast<kotcpp::SizeType>(
				std::filesystem::file_size(*output_path, ec));
			if (!ec) {
				offset = std::min(offset, local_size);
			}
		}
		else {
			offset = 0;
		}
		offset              = sanitize_resume_offset(offset, entry->size);
		const auto   length = entry->size - offset;

		kotcpp::File output_file(*output_path);
		if (auto open_res = output_file.open_random_access(
				offset == 0, kotcpp::File::iomode::RDWR);
			!open_res) {
			kotcpp::print_error("Fail to create file", open_res);
			if (!reject_current(open_res.error().message())) {
				return false;
			}
			continue;
		}

		if (!write_control_frame(target,
								 build_sft13_ack(entry->id, offset, length))) {
			record_parallel_receive_failure(receive_state, *entry,
											"Failed to send ACK.");
			return false;
		}
		if (progress != nullptr) {
			progress->add_completed(offset);
		}
		if (length > 0 &&
			!stream_target_range_to_file(
				target, output_file, entry->path, offset, length, entry->size,
				*state_path, pipeline_context, progress)) {
			record_parallel_receive_failure(receive_state, *entry,
											"Payload receive/write failed.");
			return false;
		}

		if (!receive_parallel_fin(target, entry->id, length)) {
			record_parallel_receive_failure(
				receive_state, *entry,
				"Failed to receive matching FIN for file entry.");
			return false;
		}
		parallel_receive_plan plan{
			.entry       = *entry,
			.output_path = *output_path,
			.state_path  = *state_path,
			.offset      = offset,
			.length      = length,
		};
		if (!complete_parallel_receive_plan(plan, output_file)) {
			record_parallel_receive_failure(
				receive_state, *entry, "Failed to finalize received file.");
			return false;
		}

		mark_parallel_receive_completed(receive_state);
		if (!write_control_frame(target, build_sft13_ok(entry->id))) {
			record_parallel_receive_failure(receive_state, *entry,
											"Failed to send OK.");
			return false;
		}
	}
}

inline bool
all_parallel_receive_entries_processed(parallel_receive_state& receive_state,
									   std::size_t expected_entries) {
	std::lock_guard lock(receive_state.mutex);
	return receive_state.seen_ids.size() == expected_entries &&
		   receive_state.processed_entries == expected_entries;
}

} // namespace sft_detail
