#ifndef SPECS_H
#define SPECS_H

#include <concepts>
#include <ranges>
#include <stdexcept>
#include <type_traits>
#include <utility>

namespace hotfuzz
{
    template <typename T>
    concept boolean = std::same_as<std::remove_cv_t<T>, bool>;

    template <typename T>
    concept not_boolean_integral = std::integral<T> && !boolean<T>;

    template <typename T>
    concept standard_type = std::is_arithmetic_v<std::remove_cv_t<T>>;

    enum class run_mode : std::uint8_t
    {
        zip  = 1,
        grid = 2
    };
}


#endif // SPECS_H