#ifndef FUZZ_CALLING_UTILS_HPP
#define FUZZ_CALLING_UTILS_HPP

#include <concepts>
#include <functional>
#include <optional>
#include <tuple>
#include <utility>

namespace hotfuzz
{
    namespace utils
    {
        /**
         * @brief Invoke callable object with arbitrary arguments.
         *
         * Callable is intentionally accepted as lvalue reference semantics inside fuzzing flow,
         * because hotfuzz may invoke the same callable many times.
         */
        template <typename F, typename... Args>
        requires std::invocable<F&, Args...>
        decltype(auto) call_any(F& f, Args&&... args)
        {
            return std::invoke(f, std::forward<Args>(args)...);
        }

        /**
         * @brief Invoke callable with arguments stored in tuple-like object.
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
    }
}

#endif // FUZZ_CALLING_UTILS_HPP
