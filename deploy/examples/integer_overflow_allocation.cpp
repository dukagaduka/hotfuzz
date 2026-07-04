/*
 * hotfuzz example: integer overflow that becomes a heap buffer overflow.
 *
 * Bug class
 * ---------
 * This file models an image thumbnail decoder. The decoder receives width and
 * height, computes width * height, allocates a pixel buffer, then fills one
 * byte per pixel.
 *
 * The vulnerability is the allocation size calculation. It stores the product
 * in a 16-bit integer. Large but still plausible dimensions wrap the product
 * to a smaller value, so the allocation is too small for the later write loop.
 *
 * How the failure happens
 * -----------------------
 * For width=256 and height=256:
 *
 *   real pixel count: 65536
 *   16-bit count:    0
 *
 * The decoder allocates a zero-sized vector, then writes 65536 bytes through
 * operator[]. In a plain build this is undefined behavior and may manifest as a crash,
 * allocator failure, or silent memory corruption depending on the platform.
 *
 * How hotfuzz helps
 * -----------------
 * The width and height providers contain normal small dimensions, exact edge
 * values, and overflow-triggering values. grid mode tests their Cartesian
 * product, so hotfuzz exercises combinations that a hand-written unit test
 * often misses.
 *
 * The target runs in isolated workers. When a worker crashes, recorder writes:
 *
 *   HOTFUZZ_OUTPUT_DIR/integer_overflow_allocation/errors_and_crashes.json
 *   HOTFUZZ_OUTPUT_DIR/integer_overflow_allocation/bin/crash_*.args
 *
 * How to analyze a result
 * -----------------------
 * Start from errors_and_crashes.json and find the .args file for the first
 * crash. Replay it with:
 *
 *   HOTFUZZ_INPUT_BIN=/workspace/hotfuzz_output/integer_overflow_allocation/bin/crash_1.args
 *
 * If you want to inspect the exact dimensions without running the target, call:
 *
 *   auto [width, height] = hotfuzz::load_fuzz_args<std::uint16_t, std::uint16_t>(path);
 *
 * A correct fix is to compute the product in a wide type, check it against a
 * maximum, and allocate exactly that checked size.
 */

#include "hotfuzz.hpp"

#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <iostream>
#include <vector>

namespace
{
    std::filesystem::path recorder_dir()
    {
        if (const char* root = std::getenv("HOTFUZZ_OUTPUT_DIR"); root != nullptr && *root != '\0')
            return std::filesystem::path(root) / "integer_overflow_allocation";

        return std::filesystem::path("hotfuzz_output") / "integer_overflow_allocation";
    }

    void decode_thumbnail(std::uint16_t width, std::uint16_t height)
    {
        if (width == 0 || height == 0)
            return;

        if (width > 512 || height > 512)
            return;

        // Bug trigger: 256 * 256 is 65536, which wraps to 0 in uint16_t.
        const std::uint16_t allocated_pixels = static_cast<std::uint16_t>(width * height);
        const std::uint32_t real_pixels = static_cast<std::uint32_t>(width) * height;

        // The wrapped value controls allocation, so pixels can be much too small.
        std::vector<std::uint8_t> pixels(allocated_pixels);

        // The real value controls writes, so overflowed dimensions write past pixels.
        for (std::uint32_t i = 0; i < real_pixels; ++i)
            pixels[i] = static_cast<std::uint8_t>(i);

        volatile std::uint8_t first_pixel = pixels.empty() ? 0 : pixels[0];
        (void)first_pixel;
    }

    hotfuzz::fuzz_options options()
    {
        hotfuzz::fuzz_options opts;
        opts.isolation_mode = true;
        opts.use_recorder = true;
        opts.output_dir = recorder_dir();
        opts.num_workers = 5;
        opts.timeouts.task_timeout = std::chrono::milliseconds { 200 };
        opts.verbosity = hotfuzz::verbosity_options {
            .enabled = true,
            .recent_failure_limit = 6,
            .refresh_interval = std::chrono::milliseconds { 150 },
            .colors = hotfuzz::color_mode::auto_detect
        };
        return opts;
    }
}

int main()
{
    // grid mode will try pairs like 256 x 256 and 512 x 512.
    std::vector<std::uint16_t> widths { 1, 16, 255, 256, 300, 512 };
    std::vector<std::uint16_t> heights { 1, 16, 255, 256, 300, 512 };

    hotfuzz::iterable_provider width_provider(widths.size(), widths);
    hotfuzz::iterable_provider height_provider(heights.size(), heights);

    auto opts = options();

    if (const char* replay = std::getenv("HOTFUZZ_INPUT_BIN"); replay != nullptr && *replay != '\0')
    {
        opts.input_bin = replay;
        std::cout << "Replaying " << replay << '\n';
        hotfuzz::fuzz(decode_thumbnail, hotfuzz::run_mode::bin, opts, width_provider, height_provider);
        return 0;
    }

    std::cout << "Recorder output: " << opts.output_dir << '\n';
    hotfuzz::fuzz(decode_thumbnail, hotfuzz::run_mode::grid, opts, width_provider, height_provider);
    return 0;
}
