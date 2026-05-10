#pragma once

#include <algorithm>
#include <chrono>
#include <concepts>
#include <exception>
#include <functional>
#include <iostream>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <thread>
#include <tuple>
#include <type_traits>
#include <utility>

#include "utils.hpp"
#include "data/base_provider.hpp"
#include "serialization/specs.h"

#ifdef _WIN32
// Макросы для выражений зависимых от OS
#define WIN(exp) exp
#define NIX(exp)

#else
// Макросы для выражений зависимых от OS
#define WIN(exp)
#define NIX(exp) exp

#include "worker/worker_pool.hpp"

#endif


namespace hotfuzz
{
    enum class run_mode : std::uint8_t
    {
        zip  = 1,
        grid = 2
    };

    template <std::size_t I = 0, typename Pool, typename ProvidersTuple, typename StorageTuple>
    void fuzz_grid_submit_impl(Pool& pool, ProvidersTuple& providers, StorageTuple& storage)
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
                    fuzz_grid_submit_impl<I + 1>(pool, providers, storage);
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
    void fuzz_zip_submit(Pool& pool, base_provider<Ts>&... providers)
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

    template <typename F, typename... Ts>
    void fuzz_isolated(F& fn, run_mode mode, base_provider<Ts>&... providers)
    {
        const unsigned concurrency = std::thread::hardware_concurrency();

        worker_pool<F, Ts...> pool(
            fn,
            worker_pool_options {
                .worker_count = std::max<std::size_t>(1, concurrency == 0 ? 1u : concurrency),
                .max_dispatch_attempts = 3,
                .poll_timeout = std::chrono::milliseconds { 10 },
                .timeouts = worker_timeouts {}
            }
        );

        std::exception_ptr consumer_exception;
        std::thread consumer(
            [&pool, &consumer_exception]
            {
                try
                {
                    while (true)
                        (void)pool.wait_one();
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
            if constexpr (sizeof...(Ts) == 0)
            {
                (void)pool.submit(std::tuple<>{});
            }
            else if (mode == run_mode::zip)
            {
                fuzz_zip_submit(pool, providers...);
            }
            else
            {
                auto provider_refs = std::forward_as_tuple(providers...);
                auto storage = std::tuple<std::optional<Ts>...>{};
                fuzz_grid_submit_impl(pool, provider_refs, storage);
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

    /**
     * @brief Recursive implementation of Cartesian-product fuzzing.
     */
    template <std::size_t I = 0, typename F, typename ProvidersTuple, typename StorageTuple>
    void fuzz_grid_impl(F& f, ProvidersTuple& providers, StorageTuple& storage)
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
                    call_with_tuple(f, invocation_args);
                }
                else
                {
                    fuzz_grid_impl<I + 1>(f, providers, storage);
                }
            }
            catch (const exhaustion_signal&)
            {
                provider.reset();
                break;
            }
        }
    }

    /**
     * @brief Run fuzzing in selected mode.
     *
     * isolation_mode == false keeps the original in-process execution path.
     * isolation_mode == true runs each invocation through worker_pool. Not supported on Windows.
     */
    template <typename F, typename... Ts>
    requires std::invocable<F&, Ts...>
    void fuzz(F&& f, run_mode mode, base_provider<Ts>&... providers, bool isolation_mode)
    {
        static_assert(
            (serializable_v<Ts> && ...),
            "hotfuzz::fuzz requires all argument types to be serializable"
        );

        auto& fn = f;

        if (!isolation_mode)
        {
            if (mode == run_mode::zip)
            {
                while (true)
                {
                    try
                    {
                        auto args = std::tuple<Ts...>{ providers.iter()... };
                        call_with_tuple(fn, args);
                    }
                    catch (const exhaustion_signal&)
                    {
                        break;
                    }
                }

                return;
            }

            if constexpr (sizeof...(Ts) > 0)
            {
                auto provider_refs = std::forward_as_tuple(providers...);
                auto storage = std::tuple<std::optional<Ts>...>{};

                fuzz_grid_impl(fn, provider_refs, storage);
            }
            else
            {
                call_any(fn);
            }

            return;
        }

        else
        {
            WIN(
                throw std::runtime_error("hotfuzz isolation mode is not supported on WIN32");
            )

            fuzz_isolated(fn, mode, providers...);
        }
    }
}
