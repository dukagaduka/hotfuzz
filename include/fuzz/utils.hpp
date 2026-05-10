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
        // ---------------------------------------------------------------------
        // Isolated fuzzing modes implemenatations
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
        // In-process fuzzing modes implemenatations
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
            failure_recorder* recorder
        )
        {
            try
            {
                invoke_in_process(fn, args);
            }
            catch (const std::exception& e)
            {
                if (recorder != nullptr)
                    recorder->record_exception(task_id, args, e.what());
            }
            catch (...)
            {
                if (recorder != nullptr)
                    recorder->record_exception(task_id, args, "unknown non-std exception");
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
                        invoke_in_process(f, invocation_args, task_id++, recorder);
                    }
                    else
                    {
                        in_process_fuzz_grid_impl<I + 1>(f, providers, storage, recorder, task_id);
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
            std::uint64_t& task_id,
            base_provider<Ts>&... providers
        )
        {
            while (true)
            {
                try
                {
                    auto args = std::tuple<Ts...>{ providers.iter()... };
                    invoke_in_process(f, args, task_id++, recorder);
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
            base_provider<Ts>&... providers
        )
        {
            std::uint64_t task_id = 1;

            if (mode == run_mode::bin)
            {
                auto args = load_fuzz_args<Ts...>(options.input_bin);
                invoke_in_process(fn, args, task_id, recorder);

                return;
            }

            if (mode == run_mode::zip)
            {
                in_process_fuzz_zip_impl(fn, recorder, task_id, providers...);

                return;
            }

            if constexpr (sizeof...(Ts) > 0)
            {
                auto provider_refs = std::forward_as_tuple(providers...);
                auto storage = std::tuple<std::optional<Ts>...>{};

                in_process_fuzz_grid_impl(fn, provider_refs, storage, recorder, task_id);
            }
            else
            {
                auto args = std::tuple<>{};
                invoke_in_process(fn, args, task_id, recorder);
            }
        }


#ifndef _WIN32
        template <typename F, typename... Ts>
        void run_isolated_fuzz(
            F& fn,
            run_mode mode,
            const fuzz_options& options,
            failure_recorder* recorder,
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
                [&pool, recorder, &consumer_exception]
                {
                    try
                    {
                        while (true)
                        {
                            auto result = pool.wait_one();

                            if (recorder != nullptr)
                                recorder->record_result(result);
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
