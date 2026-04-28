#pragma once

#include <concepts>
#include <functional>
#include <optional>
#include <tuple>
#include <utility>

#include "base_provider.hpp"
#include "specs.h"

namespace hotfuzz
{
    /**
     * @brief Invoke callable object with arbitrary arguments.
     *
     * Callable is intentionally accepted as lvalue reference semantics inside fuzzing flow,
     * because fuzz() may invoke the same callable many times. This avoids accidental moving
     * from the callable if the user passed a temporary functor.
     *
     * @tparam F Callable type.
     * @tparam Args Argument types.
     * @param f Callable object.
     * @param args Arguments to pass into callable.
     * @return Result of std::invoke.
     */
    template <typename F, typename... Args>
    requires std::invocable<F&, Args...>
    decltype(auto) call_any(F& f, Args&&... args)
    {
        return std::invoke(f, std::forward<Args>(args)...);
    }

    /**
     * @brief Invoke callable with arguments stored in tuple-like object.
     *
     * This helper unwraps tuple elements via std::apply and forwards them into call_any().
     *
     * @tparam F Callable type.
     * @tparam Tuple Tuple-like type.
     * @param f Callable object.
     * @param args Tuple with invocation arguments.
     * @return Result of callable invocation.
     */
    template <typename F, typename Tuple>
    decltype(auto) call_with_tuple(F& f, Tuple&& args)
    {
        return std::apply(
            [&f](auto&&... unpacked) -> decltype(auto)
            {
                return call_any(f, std::forward<decltype(unpacked)>(unpacked)...);
            },
            std::forward<Tuple>(args)
        );
    }

    /**
     * @brief Convert tuple of std::optional<Ts>... into plain std::tuple<Ts...>.
     *
     * This function assumes that all optionals are engaged.
     *
     * Important:
     * returned tuple is materialized by value. This is deliberate, because it isolates
     * each fuzz invocation from mutations performed by the callable.
     *
     * @tparam Ts Stored value types.
     * @param storage Tuple with engaged std::optional values.
     * @return Plain tuple of values.
     */
    template <typename... Ts>
    std::tuple<Ts...> materialize_args(const std::tuple<std::optional<Ts>...>& storage)
    {
        return std::apply(
            [](const auto&... xs)
            {
                return std::tuple<Ts...>{ xs.value()... };
            },
            storage
        );
    }

    /**
     * @brief Recursive implementation of Cartesian-product fuzzing.
     *
     * The recursion depth is encoded in template parameter I, so tuple access remains
     * fully compile-time and valid for std::get<I>.
     *
     * Algorithm:
     * 1. Reset current provider before iterating its sequence.
     * 2. Repeatedly fetch next value from provider I.
     * 3. Store it into current argument storage.
     * 4. If this is the last provider, materialize arguments and invoke callable.
     * 5. Otherwise recurse into next provider.
     * 6. When current provider is exhausted, reset it and return to previous depth.
     *
     * @tparam I Current provider index.
     * @tparam F Callable type.
     * @tparam ProvidersTuple Tuple of provider references.
     * @tparam StorageTuple Tuple of std::optional argument slots.
     * @param f Callable object.
     * @param providers Tuple of provider references.
     * @param storage Current argument storage.
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
     * Supported modes:
     * - run_mode::zip  : providers are advanced in lockstep
     * - run_mode::grid : full Cartesian product of provider outputs
     *
     * Notes:
     * - grid mode uses compile-time recursion over providers
     * - grid mode stores intermediate values in std::optional slots to avoid requiring
     *   immediate construction of all arguments before they are actually produced
     * - callable is treated as reusable object and invoked many times
     *
     * @tparam F Callable type.
     * @tparam Ts Provider value types.
     * @param f Callable object.
     * @param mode Fuzzing mode.
     * @param providers Providers producing argument values.
     */
    template <typename F, typename... Ts>
    requires std::invocable<F&, Ts...>
    void fuzz(F&& f, run_mode mode, base_provider<Ts>&... providers)
    {
        auto& fn = f;

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
    }
}