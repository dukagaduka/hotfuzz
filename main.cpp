#include <iostream>
#include <vector>

#include "generators.hpp"
#include "providers.hpp"
#include "hotfuzz.hpp"


int main()
{
    hotfuzz::std_random_generator<int> g(56, -7, 9);

    for (int i = 0; i != 5; ++i)
        std::cout << g() << std::endl;

    for (auto i : g(10))
        std::cout << i << " [*] ";

    std::cout << std::endl;

    hotfuzz::std_random_provider<float> p(23, 67, 0.9, 67.4);

    while (true)
    {
        try
        {
            std::cout << p.iter() << " ";
        }
        catch(const hotfuzz::exhaustion_signal& e)
        {
            std::cout << e.what() << '\n';
            break;
        }
    }

    std::vector<int> v{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12};
    hotfuzz::iterable_provider<decltype(v)> p1(15, v);

    while (true)
    {
        try
        {
            std::cout << p1.iter() << " ";
        }
        catch(const hotfuzz::exhaustion_signal& e)
        {
            std::cout << e.what() << '\n';
            break;
        }
    }

    p.reset(); p1.reset();

    hotfuzz::fuzz(
        [](float x, int y) -> float { return x + y; },
        hotfuzz::run_mode::zip,
        p,
        p1
    );

    p.reset(); p1.reset();

    hotfuzz::fuzz(
        [](float x, int y) -> float { auto b = x + y; std::cout << b << std::endl; return b; },
        hotfuzz::run_mode::grid,
        p,
        p1
    );
    
    return 0;
}