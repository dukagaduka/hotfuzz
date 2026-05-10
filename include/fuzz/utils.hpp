#ifndef FUZZ_UTILS_HPP
#define FUZZ_UTILS_HPP

#include <algorithm>
#include <cstdint>
#include <exception>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <optional>
#include <stdexcept>
#include <thread>
#include <tuple>
#include <utility>
#include <vector>

#include "data/base_provider.hpp"
#include "serialization/api.hpp"

#include "fuzz/failure_recorder.hpp"
#include "fuzz/calling_utils.hpp"
#include "fuzz/specs.h"
#include "verbosity/dashboard.hpp"

#ifndef _WIN32
#include "worker/worker_pool.hpp"
#endif

namespace hotfuzz
{
    /**
     * @brief Load serialized fuzz arguments from a .args artifact.
     */
    template <typename... Ts>
    [[nodiscard]] std::tuple<Ts...> load_fuzz_args(const std::filesystem::path& path)
    {
        static_assert(
            (serializable_v<Ts> && ...),
            "hotfuzz::load_fuzz_args requires all argument types to be serializable"
        );

        std::ifstream in(path, std::ios::binary);

        if (!in)
            throw std::runtime_error("failed to open fuzz args file: " + path.string());

        std::vector<std::uint8_t> bytes(
            (std::istreambuf_iterator<char>(in)),
            std::istreambuf_iterator<char>()
        );

        return from_bytes<std::tuple<Ts...>>(bytes);
    }


    namespace utils
    {
        [[nodiscard]] inline failure_event make_exception_event(
            std::uint64_t task_id,
            const std::string& text,
            const std::optional<recorded_failure>& artifact = std::nullopt
        )
        {
            failure_event event {
                .kind = failure_kind::exception,
                .task_id = task_id,
                .text = text
            };

            if (artifact)
            {
                event.record_id = artifact->record_id;
                event.has_record_id = true;
                event.artifact_path = artifact->artifact_path;
            }

            return event;
        }


#ifndef _WIN32
        template <typename... Ts>
        [[nodiscard]] failure_event make_isolated_failure_event(
            const isolated_result<Ts...>& result,
            const std::optional<recorded_failure>& artifact = std::nullopt
        )
        {
            failure_event event {
                .task_id = result.task_id
            };

            switch (result.status)
            {
                case isolated_status::exception:
                    event.kind = failure_kind::exception;
                    event.text = result.message;
                    break;
                case isolated_status::crash:
                    event.kind = failure_kind::crash;
                    event.text = signal_name(result.signal_number);
                    break;
                case isolated_status::timeout:
                    event.kind = failure_kind::timeout;
                    event.text = result.message.empty() ? "timeout" : result.message;
                    break;
                case isolated_status::protocol_error:
                    event.kind = failure_kind::protocol_error;
                    event.text = result.message.empty() ? "protocol error" : result.message;
                    break;
                case isolated_status::ipc_error:
                    event.kind = failure_kind::ipc_error;
                    event.text = result.message.empty() ? "ipc error" : result.message;
                    break;
                case isolated_status::internal_error:
                    event.kind = failure_kind::internal_error;
                    event.text = result.message.empty() ? "internal error" : result.message;
                    break;
                default:
                    event.kind = failure_kind::internal_error;
                    event.text = isolated_status_name(result.status);
                    break;
            }

            if (artifact)
            {
                event.record_id = artifact->record_id;
                event.has_record_id = true;
                event.artifact_path = artifact->artifact_path;
            }

            return event;
        }
#endif

        // ---------------------------------------------------------------------
        // Isolated fuzzing modes implementations
        // ---------------------------------------------------------------------



        /**
         * @brief Recursive implementation of Cartesian-product isolated fuzzing.
         */
        template <std::size_t I = 0, typename Pool, typename ProvidersTuple, typename StorageTuple>
        void isolated_fuzz_grid_impl(Pool& pool, ProvidersTuple& providers, StorageTuple& storage)
        {
            auto& provider = std::get<I>(providers);
            provider.reset();

            while (true)
            {
                try
                {
                    std::get<I>(storage) = provider.iter();

                    if constexpr (I + 1 == std::tuple_size_v<StorageTuple>)
                    {
                        auto args = materialize_args(storage);
                        (void)pool.submit(std::move(args));
                    }
                    else
                    {
                        isolated_fuzz_grid_impl<I + 1>(pool, providers, storage);
                    }
                }
                catch (const exhaustion_signal&)
                {
                    provider.reset();
                    break;
                }
            }
        }


        template <typename Pool, typename... Ts>
        void isolated_fuzz_zip_impl(Pool& pool, base_provider<Ts>&... providers)
        {
            while (true)
            {
                try
                {
                    auto args = std::tuple<Ts...>{ providers.iter()... };
                    (void)pool.submit(std::move(args));
                }
                catch (const exhaustion_signal&)
                {
                    break;
                }
            }
        }



        // ---------------------------------------------------------------------
        // In-process fuzzing modes implementations
        // ---------------------------------------------------------------------



        template <typename F, typename Tuple>
        void invoke_in_process(F& fn, const Tuple& args)
        {
            call_with_tuple(fn, args);
        }


        template <typename F, typename Tuple>
        void invoke_in_process(
            F& fn,
            const Tuple& args,
            std::uint64_t task_id,
            failure_recorder* recorder,
            console_dashboard* dashboard
        )
        {
            try
            {
                invoke_in_process(fn, args);
            }
            catch (const std::exception& e)
            {
                std::optional<recorded_failure> artifact;

                if (recorder != nullptr)
                    artifact = recorder->record_exception(task_id, args, e.what());

                if (dashboard != nullptr)
                    dashboard->publish(make_exception_event(task_id, e.what(), artifact));
            }
            catch (...)
            {
                constexpr const char* text = "unknown non-std exception";
                std::optional<recorded_failure> artifact;

                if (recorder != nullptr)
                    artifact = recorder->record_exception(task_id, args, text);

                if (dashboard != nullptr)
                    dashboard->publish(make_exception_event(task_id, text, artifact));
            }
        }


        /**
         * @brief Recursive implementation of Cartesian-product in-process fuzzing.
         */
        template <std::size_t I = 0, typename F, typename ProvidersTuple, typename StorageTuple>
        void in_process_fuzz_grid_impl(
            F& f,
            ProvidersTuple& providers,
            StorageTuple& storage,
            failure_recorder* recorder,
            console_dashboard* dashboard,
            std::uint64_t& task_id
        )
        {
            auto& provider = std::get<I>(providers);
            provider.reset();

            while (true)
            {
                try
                {
                    std::get<I>(storage) = provider.iter();

                    if constexpr (I + 1 == std::tuple_size_v<StorageTuple>)
                    {
                        auto invocation_args = materialize_args(storage);
                        invoke_in_process(f, invocation_args, task_id++, recorder, dashboard);
                    }
                    else
                    {
                        in_process_fuzz_grid_impl<I + 1>(f, providers, storage, recorder, dashboard, task_id);
                    }
                }
                catch (const exhaustion_signal&)
                {
                    provider.reset();
                    break;
                }
            }
        }


        template <typename F, typename... Ts>
        void in_process_fuzz_zip_impl(
            F& f,
            failure_recorder* recorder,
            console_dashboard* dashboard,
            std::uint64_t& task_id,
            base_provider<Ts>&... providers
        )
        {
            while (true)
            {
                try
                {
                    auto args = std::tuple<Ts...>{ providers.iter()... };
                    invoke_in_process(f, args, task_id++, recorder, dashboard);
                }
                catch (const exhaustion_signal&)
                {
                    break;
                }
            }
        }

        

        // ---------------------------------------------------------------------
        // Mode specific fuzzing entrypoints
        // ---------------------------------------------------------------------



        template <typename F, typename... Ts>
        void run_in_process_fuzz(
            F& fn,
            run_mode mode,
            const fuzz_options& options,
            failure_recorder* recorder,
            console_dashboard* dashboard,
            base_provider<Ts>&... providers
        )
        {
            std::uint64_t task_id = 1;

            if (mode == run_mode::bin)
            {
                auto args = load_fuzz_args<Ts...>(options.input_bin);
                invoke_in_process(fn, args, task_id, recorder, dashboard);

                return;
            }

            if (mode == run_mode::zip)
            {
                in_process_fuzz_zip_impl(fn, recorder, dashboard, task_id, providers...);

                return;
            }

            if constexpr (sizeof...(Ts) > 0)
            {
                auto provider_refs = std::forward_as_tuple(providers...);
                auto storage = std::tuple<std::optional<Ts>...>{};

                in_process_fuzz_grid_impl(fn, provider_refs, storage, recorder, dashboard, task_id);
            }
            else
            {
                auto args = std::tuple<>{};
                invoke_in_process(fn, args, task_id, recorder, dashboard);
            }
        }


#ifndef _WIN32
        template <typename F, typename... Ts>
        void run_isolated_fuzz(
            F& fn,
            run_mode mode,
            const fuzz_options& options,
            failure_recorder* recorder,
            console_dashboard* dashboard,
            base_provider<Ts>&... providers
        )
        {
            const unsigned concurrency = std::thread::hardware_concurrency();

            const std::size_t worker_count = options.num_workers < 0
                ? std::max<std::size_t>(1, concurrency == 0 ? 1u : concurrency)
                : std::max<std::size_t>(1, static_cast<std::size_t>(options.num_workers));

            worker_pool<F, Ts...> pool(
                fn,
                worker_pool_options {
                    .worker_count = worker_count,
                    .max_dispatch_attempts = options.max_dispatch_attempts,
                    .poll_timeout = options.poll_timeout,
                    .timeouts = options.timeouts
                }
            );

            std::exception_ptr consumer_exception;
            std::thread consumer(
                [&pool, recorder, dashboard, &consumer_exception]
                {
                    try
                    {
                        while (true)
                        {
                            auto result = pool.wait_one();
                            std::optional<recorded_failure> artifact;

                            if (recorder != nullptr)
                                artifact = recorder->record_result(result);

                            if (dashboard != nullptr && result.status != isolated_status::ok)
                                dashboard->publish(make_isolated_failure_event(result, artifact));
                        }
                    }
                    catch (const std::runtime_error&)
                    {
                        if (!pool.drained())
                            consumer_exception = std::current_exception();
                    }
                    catch (...)
                    {
                        consumer_exception = std::current_exception();
                    }
                }
            );

            try
            {
                if (mode == run_mode::bin)
                {
                    auto args = load_fuzz_args<Ts...>(options.input_bin);
                    (void)pool.submit(std::move(args));
                }
                else if constexpr (sizeof...(Ts) == 0)
                {
                    (void)pool.submit(std::tuple<>{});
                }
                else if (mode == run_mode::zip)
                {
                    isolated_fuzz_zip_impl(pool, providers...);
                }
                else
                {
                    auto provider_refs = std::forward_as_tuple(providers...);
                    auto storage = std::tuple<std::optional<Ts>...>{};
                    isolated_fuzz_grid_impl(pool, provider_refs, storage);
                }

                pool.stop();
            }
            catch (...)
            {
                pool.stop_immediately();
                consumer.join();
                throw;
            }

            consumer.join();

            if (consumer_exception)
            {
                pool.stop_immediately();
                std::rethrow_exception(consumer_exception);
            }
        }
#endif
    }

}

#endif // FUZZ_UTILS_HPP
