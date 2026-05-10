#include <csignal>
#include <iostream>
#include <stdexcept>
#include <vector>

#include "data/providers.hpp"
#include "hotfuzz.hpp"

int main()
{
    std::vector<int> xs { -1, 1 };
    std::vector<int> ys { 3, 5 };

    hotfuzz::iterable_provider<decltype(xs)> x_provider(xs.size(), xs);
    hotfuzz::iterable_provider<decltype(ys)> y_provider(ys.size(), ys);

    std::cout << "in-process zip\n";

    hotfuzz::fuzz(
        [](int x, int y)
        {
            std::cout << "value: " << (x + y) << '\n';
        },
        hotfuzz::run_mode::zip,
        hotfuzz::fuzz_options {
            .isolation_mode = false
        },
        x_provider,
        y_provider
    );

    x_provider.reset();
    y_provider.reset();

    std::cout << "\nisolated grid\n";

    hotfuzz::fuzz(
        [](int x, int y)
        {
            if (y == 3)
                throw std::runtime_error("demo exception");

            if (x < 0 && y == 5)
                ::raise(SIGSEGV);
        },
        hotfuzz::run_mode::grid,
        hotfuzz::fuzz_options {
            .isolation_mode = true
        },
        x_provider,
        y_provider
    );

    return 0;
}
