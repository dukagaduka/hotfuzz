#include <chrono>
#include <algorithm>
#include <cstdlib>
#include <filesystem>
#include <iostream>
#include <random>
#include <stdexcept>
#include <string>
#include <tuple>
#include <utility>
#include <vector>

#include "hotfuzz.hpp"

namespace demo
{
    /**
     * Simple user-defined object for the demo.
     *
     * The class is intentionally tiny: it stores only a human-readable name and
     * the divisor value itself. The important part is that the fuzz target does
     * not work with a raw `int`, but with a real domain object that owns the
     * division logic.
     */
    class divider
    {
    public:
        divider() = default;

        divider(std::string name, int value)
            : m_name(std::move(name)),
              m_value(value)
        {
        }

        [[nodiscard]] const std::string& name() const noexcept
        {
            return m_name;
        }

        [[nodiscard]] int value() const noexcept
        {
            return m_value;
        }

        [[nodiscard]] int divide(int dividend) const
        {
            if (m_value == 0)
                throw std::runtime_error("divider::divide detected division by zero");

            return dividend / m_value;
        }

    private:
        std::string m_name;
        int m_value {};
    };


    /**
     * Custom provider for the user-defined divider class.
     *
     * Construction rule is deliberately simple and explicit:
     * - generate `max` random divisor values in range [1, 40]
     * - pick several random positions
     * - overwrite those positions with zero-valued dividers
     *
     * This keeps the demo simple while still producing several failures during
     * the run instead of only one failure at the very end.
     */
    class divider_provider : public hotfuzz::base_provider<divider>
    {
    public:
        divider_provider(std::size_t max_idx, std::uint32_t seed)
            : hotfuzz::base_provider<divider>(max_idx)
        {
            if (max_idx == 0)
                throw std::invalid_argument("divider_provider requires max_idx > 0");

            hotfuzz::std_random_generator<int> generator(seed, 1, 40);
            auto values = generator(max_idx);

            m_dividers.reserve(max_idx);

            for (std::size_t i = 0; i < values.size(); ++i)
            {
                m_dividers.emplace_back(
                    "divider_" + std::to_string(i + 1),
                    values[i]
                );
            }

            const std::size_t zero_count = std::min<std::size_t>(5, max_idx);
            std::vector<bool> zero_slots(max_idx, false);
            std::mt19937 shuffle(seed + 1);
            std::uniform_int_distribution<std::size_t> pick_slot(0, max_idx - 1);

            std::size_t placed_zeroes = 0;

            while (placed_zeroes < zero_count)
            {
                const std::size_t index = pick_slot(shuffle);

                if (zero_slots[index])
                    continue;

                zero_slots[index] = true;
                m_dividers[index] = divider("divider_zero_" + std::to_string(placed_zeroes + 1), 0);
                ++placed_zeroes;
            }
        }

    protected:
        divider next() override
        {
            return m_dividers[this->idx()];
        }

    private:
        std::vector<divider> m_dividers;
    };


    std::ostream& operator<<(std::ostream& out, const divider& value)
    {
        out << "divider{name=" << value.name()
            << ", value=" << value.value()
            << '}';
        return out;
    }


    /**
     * First fuzz target: demonstrates an ordinary exception path.
     *
     * The function accepts exactly what a user would expect from the public
     * API: one built-in type and one custom serializable object. The actual
     * failure is produced by the object's own method when the provider reaches
     * any divider with value 0.
     */
    void exception_target(int dividend, const divider& current_divider)
    {
        (void)current_divider.divide(dividend);
    }


    /**
     * Second fuzz target: demonstrates a hard crash path.
     *
     * This target is intentionally explicit. When the provider reaches any
     * divider with value 0, we abort the process on purpose. That gives a very
     * clear isolated crash example without hiding the reason behind complicated
     * business logic.
     */
    void crash_target(int dividend, const divider& current_divider)
    {
        if (current_divider.value() == 0)
            std::abort();

        (void)current_divider.divide(dividend);
    }


    void run_zip_exception_demo()
    {
        constexpr std::size_t divider_count = 6000000;
        constexpr std::uint32_t divider_seed = 7;
        constexpr std::uint32_t dividend_seed = 11;
        const std::filesystem::path output_dir = "demo_output/zip_exception";

        std::cout << "zip demo: exception flow\n";

        std::filesystem::remove_all(output_dir);

        // Provider sizes are intentionally different:
        // - divider_provider produces N objects
        // - std_random_provider<int> produces 2 * N integers
        //
        // zip mode stops as soon as one provider is exhausted, so this run will
        // execute exactly N pairs. That makes the zip semantics visible in the
        // smallest possible example.
        divider_provider divisors(divider_count, divider_seed);
        hotfuzz::std_random_provider<int> dividends(divider_count * 2, dividend_seed, 10, 200);

        hotfuzz::fuzz(
            exception_target,
            hotfuzz::run_mode::zip,
            hotfuzz::fuzz_options {
                .isolation_mode = false,
                .use_recorder = true,
                .output_dir = output_dir,
                .verbosity = hotfuzz::verbosity_options {
                    .enabled = true,
                    .recent_failure_limit = 6,
                    .refresh_interval = std::chrono::milliseconds { 150 },
                    .colors = hotfuzz::color_mode::auto_detect
                }
            },
            dividends,
            divisors
        );

        const auto artifact_path = output_dir / "bin" / "exception_1.args";
        auto [saved_dividend, saved_divider] =
            hotfuzz::load_fuzz_args<int, divider>(artifact_path);

        std::cout << "saved failure artifact: " << artifact_path << '\n';
        std::cout << "  dividend=" << saved_dividend << '\n';
        std::cout << "  " << saved_divider << '\n';
        std::cout << '\n';
    }


    void run_zip_crash_demo()
    {
        constexpr std::size_t divider_count = 600;
        constexpr std::uint32_t divider_seed = 19;
        constexpr std::uint32_t dividend_seed = 23;
        const std::filesystem::path output_dir = "demo_output/zip_crash";

#ifdef _WIN32
        std::cout << "zip demo: crash flow skipped on WIN32 because isolation mode is not supported\n\n";
#else
        std::cout << "zip demo: isolated crash flow\n";

        std::filesystem::remove_all(output_dir);

        // Same provider shape, but now we run through isolated mode so every
        // divider_zero element is reported as a crash artifact instead of
        // terminating the whole fuzzing process.
        divider_provider divisors(divider_count, divider_seed);
        hotfuzz::std_random_provider<int> dividends(divider_count * 2, dividend_seed, 10, 200);

        hotfuzz::fuzz(
            crash_target,
            hotfuzz::run_mode::grid,
            hotfuzz::fuzz_options {
                .isolation_mode = true,
                .use_recorder = true,
                .output_dir = output_dir,
                .num_workers = 10,
                .timeouts = hotfuzz::worker_timeouts {
                    .task_timeout = std::chrono::milliseconds { 20000 },
                },
                .verbosity = hotfuzz::verbosity_options {
                    .enabled = true,
                    .recent_failure_limit = 6,
                    .refresh_interval = std::chrono::milliseconds { 150 },
                    .colors = hotfuzz::color_mode::auto_detect
                }
            },
            dividends,
            divisors
        );

        const auto artifact_path = output_dir / "bin" / "crash_1.args";
        auto [saved_dividend, saved_divider] =
            hotfuzz::load_fuzz_args<int, divider>(artifact_path);

        std::cout << "saved crash artifact: " << artifact_path << '\n';
        std::cout << "  dividend=" << saved_dividend << '\n';
        std::cout << "  " << saved_divider << '\n';
        std::cout << '\n';
#endif
    }
}

namespace hotfuzz
{
    template <>
    struct serializer<demo::divider>
    {
        static std::vector<std::uint8_t> to_bytes(const demo::divider& value)
        {
            // User-facing serializer code should stay on the public API:
            // convert the object into a serializable tuple and let hotfuzz
            // serialize that tuple.
            return hotfuzz::to_bytes(
                std::tuple<std::string, int> {
                    value.name(),
                    value.value()
                }
            );
        }

        static demo::divider from_bytes(const std::vector<std::uint8_t>& bytes)
        {
            auto [name, current_value] =
                hotfuzz::from_bytes<std::tuple<std::string, int>>(bytes);

            return demo::divider(std::move(name), current_value);
        }
    };
}

int main()
{
    // This demo is intentionally narrow:
    // 1. one simple custom class
    // 2. one serializer for it
    // 3. one custom provider for that class
    // 4. one zip fuzzing pass that produces an exception
    // 5. one isolated zip fuzzing pass that produces a crash
    //
    // The goal is to make the public flow obvious at a glance.
    demo::run_zip_exception_demo();
    demo::run_zip_crash_demo();
    return 0;
}
