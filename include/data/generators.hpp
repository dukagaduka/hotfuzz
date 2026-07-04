#ifndef DATA_GENERATORS_HPP
#define DATA_GENERATORS_HPP

#include <algorithm>
#include <cmath>
#include <concepts>
#include <cstdint>
#include <limits>
#include <random>
#include <stdexcept>
#include <string>
#include <type_traits>
#include <vector>

#include "data/specs.h"

namespace hotfuzz
{
    /**
     * @brief Random generator for built-in arithmetic types.
     *
     * Supports:
     * - bool                  -> std::bernoulli_distribution
     * - integral except bool  -> std::uniform_int_distribution
     * - floating point        -> std::uniform_real_distribution
     *
     * Default ranges:
     * - integral: [numeric_limits<T>::lowest(), numeric_limits<T>::max()]
     * - floating: [0, 1]
     * - bool: p(true) = 0.5
     *
     * @tparam T Arithmetic built-in type.
     */
    template <standard_type T>
    class std_random_generator
    {
    public:
        using value_type = T;

        std_random_generator();
        explicit std_random_generator(std::uint32_t seed);

        std_random_generator(T low, T high) requires (!boolean<T>);
        std_random_generator(std::uint32_t seed, T low, T high) requires (!boolean<T>);

        explicit std_random_generator(double true_probability) requires boolean<T>;
        std_random_generator(std::uint32_t seed, double true_probability) requires boolean<T>;

        T operator()();
        std::vector<T> operator()(std::size_t size);

        T low() const noexcept;
        T high() const noexcept;
        std::uint32_t seed() const noexcept;

    private:
        template <typename U>
        struct distribution_selector;

        template <boolean U>
        struct distribution_selector<U>
        {
            using type = std::bernoulli_distribution;
        };

        template <not_boolean_integral U>
        struct distribution_selector<U>
        {
            using type = std::uniform_int_distribution<U>;
        };

        template <std::floating_point U>
        struct distribution_selector<U>
        {
            using type = std::uniform_real_distribution<U>;
        };

        using distribution_type = typename distribution_selector<T>::type;

        static std::uint32_t make_seed();
        static void validate_range(T low, T high) requires (!boolean<T>);
        static void validate_probability(double true_probability) requires boolean<T>;

        void init_default_distribution();
        void init_range_distribution(T low, T high) requires (!boolean<T>);
        void init_bool_distribution(double true_probability) requires boolean<T>;

    private:
        std::uint32_t m_seed {};
        std::mt19937 m_generator {};

        T m_low {};
        T m_high {};

        distribution_type m_dist {};
    };

    template <standard_type T>
    inline std::uint32_t std_random_generator<T>::make_seed()
    {
        return std::random_device{}();
    }

    template <standard_type T>
    inline void std_random_generator<T>::validate_range(T low, T high) requires (!boolean<T>)
    {
        if constexpr (std::floating_point<T>)
        {
            if (!std::isfinite(low) || !std::isfinite(high))
            {
                throw std::invalid_argument(
                    "Floating-point bounds must be finite in std_random_generator");
            }
        }

        if (low > high)
        {
            throw std::invalid_argument(
                "`low` must be lower than or equal to `high` in std_random_generator");
        }
    }

    template <standard_type T>
    inline void std_random_generator<T>::validate_probability(double true_probability) requires boolean<T>
    {
        if (!std::isfinite(true_probability) || true_probability < 0.0 || true_probability > 1.0)
        {
            throw std::invalid_argument(
                "`true_probability` must be in range [0.0, 1.0] in std_random_generator");
        }
    }

    template <standard_type T>
    inline void std_random_generator<T>::init_default_distribution()
    {
        if constexpr (not_boolean_integral<T>)
        {
            m_low = std::numeric_limits<T>::lowest();
            m_high = std::numeric_limits<T>::max();
            m_dist = distribution_type(m_low, m_high);
        }
        else if constexpr (std::floating_point<T>)
        {
            m_low = static_cast<T>(0);
            m_high = static_cast<T>(1);
            m_dist = distribution_type(m_low, m_high);
        }
        else if constexpr (boolean<T>)
        {
            m_low = false;
            m_high = true;
            m_dist = distribution_type(0.5);
        }
        else
        {
            static_assert(standard_type<T>, "Unsupported type in std_random_generator");
        }
    }

    template <standard_type T>
    inline void std_random_generator<T>::init_range_distribution(T low, T high) requires (!boolean<T>)
    {
        validate_range(low, high);

        m_low = low;
        m_high = high;

        if constexpr (not_boolean_integral<T>)
        {
            m_dist = distribution_type(m_low, m_high);
        }
        else if constexpr (std::floating_point<T>)
        {
            m_dist = distribution_type(m_low, m_high);
        }
    }

    template <standard_type T>
    inline void std_random_generator<T>::init_bool_distribution(double true_probability) requires boolean<T>
    {
        validate_probability(true_probability);

        m_low = false;
        m_high = true;
        m_dist = distribution_type(true_probability);
    }

    template <standard_type T>
    std_random_generator<T>::std_random_generator()
        : m_seed(make_seed()),
          m_generator(m_seed)
    {
        init_default_distribution();
    }

    template <standard_type T>
    std_random_generator<T>::std_random_generator(std::uint32_t seed)
        : m_seed(seed),
          m_generator(m_seed)
    {
        init_default_distribution();
    }

    template <standard_type T>
    std_random_generator<T>::std_random_generator(T low, T high) requires (!boolean<T>)
        : m_seed(make_seed()),
          m_generator(m_seed)
    {
        init_range_distribution(low, high);
    }

    template <standard_type T>
    std_random_generator<T>::std_random_generator(std::uint32_t seed, T low, T high) requires (!boolean<T>)
        : m_seed(seed),
          m_generator(m_seed)
    {
        init_range_distribution(low, high);
    }

    template <standard_type T>
    std_random_generator<T>::std_random_generator(double true_probability) requires boolean<T>
        : m_seed(make_seed()),
          m_generator(m_seed)
    {
        init_bool_distribution(true_probability);
    }

    template <standard_type T>
    std_random_generator<T>::std_random_generator(std::uint32_t seed, double true_probability) requires boolean<T>
        : m_seed(seed),
          m_generator(m_seed)
    {
        init_bool_distribution(true_probability);
    }

    template <standard_type T>
    inline T std_random_generator<T>::operator()()
    {
        if constexpr (boolean<T>)
        {
            return static_cast<T>(m_dist(m_generator));
        }
        else
        {
            return m_dist(m_generator);
        }
    }

    template <standard_type T>
    inline std::vector<T> std_random_generator<T>::operator()(std::size_t size)
    {
        std::vector<T> values(size);
        std::generate(values.begin(), values.end(), [this]() { return this->operator()(); });
        return values;
    }

    template <standard_type T>
    inline T std_random_generator<T>::low() const noexcept
    {
        return m_low;
    }

    template <standard_type T>
    inline T std_random_generator<T>::high() const noexcept
    {
        return m_high;
    }

    template <standard_type T>
    inline std::uint32_t std_random_generator<T>::seed() const noexcept
    {
        return m_seed;
    }

} 

#endif // DATA_GENERATORS_HPP