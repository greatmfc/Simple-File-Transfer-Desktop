#pragma once

#include "transfer_parallel.tpp"

template <kotcpp::AsyncTransferTarget Target>
bool send_file_v13_parallel(
	Target& target, const std::vector<std::string>& files,
	const sft_detail::parallel_transfer_options& options) {
	const auto [entries, total_bytes] =
		sft_detail::build_sft12_send_entries(files);
	if (entries.empty()) {
		std::cerr << "No valid files to send.\n";
		return false;
	}

	std::vector<sft_detail::parallel_send_task> tasks;
	tasks.reserve(entries.size());
	for (size_t file_id = 0; file_id < entries.size(); ++file_id) {
		tasks.emplace_back(file_id, entries[file_id]);
	}

	const auto proposed_workers = sft_detail::get_default_parallel_worker_count(
		tasks.size(), options.max_workers);

	kotcpp::tcp_socket      worker_listener;
	std::optional<uint16_t> local_worker_port;
	std::string             session_id;
	std::string             worker_token;
	if (options.worker_endpoint ==
			sft_detail::parallel_worker_endpoint::Listener &&
		proposed_workers > 0) {
		auto port = sft_detail::open_parallel_worker_listener(worker_listener);
		if (!port) {
			kotcpp::print_error("Fail to open parallel worker listener", port);
			return false;
		}
		local_worker_port = *port;
		session_id        = sft_detail::random_base64url_token();
		worker_token      = sft_detail::random_base64url_token();
	}

	target.set_blocking();
	if (!sft_detail::write_control_frame(
			target,
			sft_detail::build_sft13_hello(
				proposed_workers, tasks.size(), tasks.size(), total_bytes,
				local_worker_port, session_id, worker_token))) {
		return false;
	}

	auto ready_text = sft_detail::read_control_frame(target);
	if (!ready_text) {
		kotcpp::print_error("Fail to receive sft1.3 READY", ready_text);
		return false;
	}
	auto ready = sft_detail::parse_sft13_frame(*ready_text);
	if (!ready || ready->action != sft_detail::frame_action::Ready) {
		std::cerr << "Receive unexpected sft1.3 READY.\n";
		return false;
	}
	auto accepted_workers_res =
		sft_detail::get_size_t_option(*ready, "workers");
	if (!accepted_workers_res || *accepted_workers_res > proposed_workers) {
		std::cerr << "Receive invalid sft1.3 worker count.\n";
		return false;
	}
	auto     accepted_workers = *accepted_workers_res;

	uint16_t worker_port      = local_worker_port.value_or(0);
	if (options.worker_endpoint ==
			sft_detail::parallel_worker_endpoint::Connector &&
		accepted_workers > 0) {
		auto port_res = sft_detail::get_size_t_option(*ready, "port");
		if (!port_res || *port_res == 0 ||
			*port_res > std::numeric_limits<uint16_t>::max()) {
			std::cerr << "Receive invalid sft1.3 worker port.\n";
			return false;
		}
		worker_port  = static_cast<uint16_t>(*port_res);
		session_id   = sft_detail::get_option(*ready, "session");
		worker_token = sft_detail::get_option(*ready, "token");
		if (session_id.empty() || worker_token.empty()) {
			std::cerr << "Receive invalid sft1.3 worker credentials.\n";
			return false;
		}
	}

	const auto actual_workers = std::min(accepted_workers, tasks.size());
	if (actual_workers == 0) {
		std::cerr << "Peer accepted no parallel workers for transfer tasks.\n";
		return false;
	}

	if (actual_workers > 0) {
		BS::light_thread_pool                  pool(actual_workers);
		std::atomic_size_t                     next_task{0};
		std::atomic_bool                       cancelled{false};
		sft_detail::parallel_transfer_progress progress(total_bytes, true);
		std::vector<std::future<bool>>         futures;
		futures.reserve(actual_workers);

		for (std::size_t worker_id = 0; worker_id < actual_workers;
			 ++worker_id) {
			futures.push_back(pool.submit_task([&, worker_id]() -> bool {
				if (options.worker_endpoint ==
					sft_detail::parallel_worker_endpoint::Listener) {
					kotcpp::sft_server worker;
					if (!options.accept_worker(worker, worker_listener,
											   cancelled)) {
						return false;
					}
					if (!sft_detail::receive_parallel_join(worker, session_id,
														   worker_token)) {
						return false;
					}
					return sft_detail::transfer_parallel_sender_tasks(
						worker, tasks, next_task, worker_id, &progress);
				}

				kotcpp::sft_client worker;
				if (!options.connect_worker(worker, worker_port)) {
					return false;
				}
				if (!sft_detail::send_parallel_join(worker, session_id,
													worker_token, worker_id)) {
					return false;
				}
				return sft_detail::transfer_parallel_sender_tasks(
					worker, tasks, next_task, worker_id, &progress);
			}));
		}

		const auto workers_ok = sft_detail::wait_for_parallel_futures(
			futures, cancelled, worker_listener,
			"Parallel sender worker failed", &progress);
		worker_listener.close();
		if (!workers_ok) {
			return false;
		}
	}

	if (!sft_detail::write_control_frame(
			target, sft_detail::build_sft13_done(tasks.size()))) {
		return false;
	}
	auto done_ok_text = sft_detail::read_control_frame(target);
	if (!done_ok_text) {
		kotcpp::print_error("Fail to receive sft1.3 final completion",
							done_ok_text);
		return false;
	}
	auto done_ok = sft_detail::parse_sft13_frame(*done_ok_text);
	if (!done_ok || done_ok->action != sft_detail::frame_action::Ok ||
		done_ok->fields.empty() || done_ok->fields[0] != "all") {
		std::cerr << "Receive unexpected sft1.3 final completion.\n";
		return false;
	}

	std::cout << "All files have been received by the other side.\n";
	return true;
}

template <kotcpp::AsyncTransferTarget Target>
void receive_file_v13_parallel(
	Target& target, std::string_view first_frame,
	const sft_detail::parallel_transfer_options& options) {
	auto hello = sft_detail::parse_sft13_frame(first_frame);
	if (!hello || hello->action != sft_detail::frame_action::Hello) {
		kotcpp::print_error("Fail to parse sft1.3 HELLO", hello);
		return;
	}
	auto proposed_workers_res =
		sft_detail::get_size_t_option(*hello, "workers");
	auto payload_files_res  = sft_detail::get_size_t_option(*hello, "files");
	auto entry_count_res    = sft_detail::get_size_t_option(*hello, "count");
	std::size_t total_bytes = 0;
	bool        total_preannounced = false;
	if (hello->options.contains("bytes")) {
		auto total_bytes_res = sft_detail::get_size_t_option(*hello, "bytes");
		if (!total_bytes_res) {
			std::cerr << "Receive malformed sft1.3 byte count.\n";
			return;
		}
		total_bytes        = *total_bytes_res;
		total_preannounced = true;
	}
	if (!proposed_workers_res || !payload_files_res || !entry_count_res) {
		std::cerr << "Receive malformed sft1.3 HELLO.\n";
		return;
	}

	const auto local_workers = sft_detail::get_default_parallel_worker_count(
		*payload_files_res, options.max_workers);
	const auto accepted_workers =
		std::min(*proposed_workers_res, local_workers);

	kotcpp::tcp_socket      worker_listener;
	std::optional<uint16_t> local_worker_port;
	uint16_t                worker_port = 0;
	std::string             session_id;
	std::string             worker_token;
	if (options.worker_endpoint ==
			sft_detail::parallel_worker_endpoint::Listener &&
		accepted_workers > 0) {
		auto port = sft_detail::open_parallel_worker_listener(worker_listener);
		if (!port) {
			kotcpp::print_error("Fail to open parallel worker listener", port);
			return;
		}
		local_worker_port = *port;
		worker_port       = *port;
		session_id        = sft_detail::random_base64url_token();
		worker_token      = sft_detail::random_base64url_token();
	}
	else if (accepted_workers > 0) {
		auto port_res = sft_detail::get_size_t_option(*hello, "port");
		if (!port_res || *port_res == 0 ||
			*port_res > std::numeric_limits<uint16_t>::max()) {
			std::cerr << "Receive invalid sft1.3 worker port.\n";
			return;
		}
		worker_port  = static_cast<uint16_t>(*port_res);
		session_id   = sft_detail::get_option(*hello, "session");
		worker_token = sft_detail::get_option(*hello, "token");
		if (session_id.empty() || worker_token.empty()) {
			std::cerr << "Receive invalid sft1.3 worker credentials.\n";
			return;
		}
	}

	if (!sft_detail::write_control_frame(
			target,
			sft_detail::build_sft13_ready(accepted_workers, local_worker_port,
										  session_id, worker_token))) {
		return;
	}

	const auto output_root = std::filesystem::current_path();
	sft_detail::parallel_receive_state receive_state;
	auto                               print_receive_failures = [&]() {
        sft_detail::print_parallel_receive_failures(receive_state);
	};

	const auto actual_workers = std::min(accepted_workers, *entry_count_res);
	if (*entry_count_res > 0 && actual_workers == 0) {
		std::cerr << "Parallel transfer has tasks but no worker.\n";
		return;
	}

	if (actual_workers > 0) {
		BS::light_thread_pool                  pool(actual_workers);
		std::atomic_bool                       cancelled{false};
		sft_detail::parallel_transfer_progress progress(total_bytes,
														total_preannounced);
		std::vector<std::future<bool>>         futures;
		futures.reserve(actual_workers);

		for (std::size_t worker_id = 0; worker_id < actual_workers;
			 ++worker_id) {
			futures.push_back(pool.submit_task([&, worker_id]() -> bool {
				if (options.worker_endpoint ==
					sft_detail::parallel_worker_endpoint::Listener) {
					kotcpp::sft_server worker;
					if (!options.accept_worker(worker, worker_listener,
											   cancelled)) {
						return false;
					}
					if (!sft_detail::receive_parallel_join(worker, session_id,
														   worker_token)) {
						return false;
					}
					return sft_detail::receive_parallel_worker_tasks(
						worker, receive_state, output_root, worker_id,
						&progress);
				}

				kotcpp::sft_client worker;
				if (!options.connect_worker(worker, worker_port)) {
					return false;
				}
				if (!sft_detail::send_parallel_join(worker, session_id,
													worker_token, worker_id)) {
					return false;
				}
				return sft_detail::receive_parallel_worker_tasks(
					worker, receive_state, output_root, worker_id, &progress);
			}));
		}

		const auto workers_ok = sft_detail::wait_for_parallel_futures(
			futures, cancelled, worker_listener,
			"Parallel receiver worker failed", &progress);
		worker_listener.close();
		if (!workers_ok) {
			print_receive_failures();
			return;
		}
	}

	auto done_text = sft_detail::read_control_frame(target);
	if (!done_text) {
		kotcpp::print_error("Fail to receive sft1.3 DONE", done_text);
		print_receive_failures();
		return;
	}
	auto done = sft_detail::parse_sft13_frame(*done_text);
	if (!done || done->action != sft_detail::frame_action::Done) {
		std::cerr << "Receive unexpected sft1.3 DONE.\n";
		print_receive_failures();
		return;
	}
	auto done_count = sft_detail::get_size_t_option(*done, "count");
	if (!done_count || *done_count != *entry_count_res ||
		!sft_detail::all_parallel_receive_entries_processed(receive_state,
															*done_count)) {
		std::cerr << "Receive incomplete sft1.3 transfer.\n";
		print_receive_failures();
		return;
	}
	(void)sft_detail::write_control_frame(target,
										  sft_detail::build_sft13_ok_all());
	print_receive_failures();
}
