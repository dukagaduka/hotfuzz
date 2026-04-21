#include <functional>
#include <concepts>
#include <utility>
#include <iostream>

#include "base_provider.hpp"
#include "specs.h"


namespace hotfuzz
{
    template <typename F, typename... Args>
    requires std::invocable<F, Args...>
    decltype(auto) call_any(F&& f, Args&&... args)
    {
        return std::invoke(std::forward<F>(f), std::forward<Args>(args)...);
    }

    template <typename F, typename... Ts>
    requires std::invocable<F&, Ts...>
    decltype(auto) call_with_tuple(F&& f, std::tuple<Ts...>& args)
    {
        return std::apply(
            [&](auto&&... unpacked)
            {
                call_any(f, std::forward<decltype(unpacked)>(unpacked)...);
            },
            std::move(args)
        );
    }

    template <typename... Ts>
    std::tuple<Ts...> build_base_args(std::tuple<base_provider<Ts>&...>& providers)
    {

    }

    template <typename F, typename... Ts>
    requires std::invocable<F&, Ts...>
    void fuzz(F&& f, run_mode mode, base_provider<Ts>&... providers)
    {
        if (mode == run_mode::zip)
        {
            while (true)
            {
                try
                {
                    auto args = std::tuple<Ts...>{ providers.iter()... };
                    auto d = call_with_tuple(f, args);
                    std::cout << d << std::endl;
                }
                catch (const exhaustion_signal&)
                {
                    break;
                }
            }
        }

        else if (mode == run_mode::grid)
        {
            auto ps = std::forward_as_tuple(providers...);

            
            // TODO: implement full grid 
        }
    }

}