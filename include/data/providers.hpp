#ifndef PROVIDERS_HPP
#define PROVIDERS_HPP

#include <concepts>
#include <cstdint>
#include <vector>
#include <ranges>

#include "base_provider.hpp"
#include "specs.h"
#include "generators.hpp"

namespace hotfuzz
{
    /**
     * @brief Argument provider over random generator for built-in arithmetic types.
     *
     * Params:
     * - bool                 
     * - integral except bool  
     * - floating point        
     *
     * For bool type constructor with `true` probability must be used or max_idx with seed only.
     * For other types constructor with `low` and `high` range must be used or max_idx with seed only.
     *
     * @tparam T Arithmetic built-in type.
     */
    template <standard_type T>
    class std_random_provider : public base_provider<T>
    {
    public:
        std_random_provider(std::size_t max_idx, std::uint32_t seed);
        std_random_provider(std::size_t max_idx, std::uint32_t seed, T low, T high) requires (!boolean<T>);
        std_random_provider(std::size_t max_idx, std::uint32_t seed, double true_probability) requires (boolean<T>);

        T next() override;

    private:
        std_random_generator<T> m_generator;

    };

    template <standard_type T>
    std_random_provider<T>::std_random_provider(std::size_t max_idx, std::uint32_t seed) 
        : base_provider<T>(max_idx), m_generator(seed) {}

    template <standard_type T> 
    std_random_provider<T>::std_random_provider(std::size_t max_idx, std::uint32_t seed, T low, T high) requires (!boolean<T>) 
        : base_provider<T>(max_idx), m_generator(seed, low, high) {}

    template <standard_type T> 
    std_random_provider<T>::std_random_provider(std::size_t max_idx, std::uint32_t seed, double true_probability) requires (boolean<T>) 
        : base_provider<T>(max_idx), m_generator(seed, true_probability) {}

    template <standard_type T>
    T std_random_provider<T>::next() 
    {
        return m_generator();
    }

    /**
     * @brief Argument provider over any iterable object of type T.
     *
     * @tparam R - iterable object type.
     */
    template <std::ranges::range R>
    class iterable_provider : public base_provider<std::ranges::range_value_t<R>>
    {
    public:
        using value_type = std::ranges::range_value_t<R>;
        using iterator = std::ranges::iterator_t<R>;
        using sentinel = std::ranges::sentinel_t<R>;

        iterable_provider(std::size_t max_idx, R& object);

        void reset() override;
        value_type next() override;

    private:
        R* m_object;
        iterator m_current;
        sentinel m_end;

    };

    template <std::ranges::range R>
    iterable_provider<R>::iterable_provider(std::size_t max_idx, R& object)
        : base_provider<std::ranges::range_value_t<R>>(max_idx),
        m_object(&object),
        m_current(std::ranges::begin(object)),
        m_end(std::ranges::end(object))
    {
        if (m_current == m_end)
        {
            throw std::invalid_argument("iterable_provider requires a non-empty iterable object.");
        }
    }

    template <std::ranges::range R>
    void iterable_provider<R>::reset()
    {
        base_provider<value_type>::reset();
        m_current = std::ranges::begin(*m_object);
    }

    template <std::ranges::range R>
    typename iterable_provider<R>::value_type iterable_provider<R>::next()
    {
        value_type value = static_cast<value_type>(*m_current);
        ++m_current;

        if (m_current == m_end)
        {
            m_current = std::ranges::begin(*m_object);
        }

        return value;
    }
}

#endif // PROVIDERS_HPP