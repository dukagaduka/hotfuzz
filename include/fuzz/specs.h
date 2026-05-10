#ifndef FUZZ_SPECS_H
#define FUZZ_SPECS_H

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <filesystem>

#include "worker/specs.h"

namespace hotfuzz
{
    /**
     * @brief Argument traversal mode for fuzz().
     */
    enum class run_mode : std::uint8_t
    {
        zip = 1,
        grid = 2,
        bin = 3
    };


    /**
     * @brief Public fuzzing runtime options.
     *
     * num_workers == -1 keeps the default hardware_concurrency() based sizing.
     * use_recorder enables errors_and_crashes.json and serialized argument blobs.
     * output_dir receives recorder artifacts when use_recorder == true.
     * input_bin is used only by run_mode::bin.
     */
    struct fuzz_options
    {
        bool isolation_mode { false };
        bool use_recorder { true };
        std::filesystem::path output_dir { "hotfuzz_output" };
        std::filesystem::path input_bin {};
        int num_workers { -1 };
        std::size_t max_dispatch_attempts { 3 };
        std::chrono::milliseconds poll_timeout { 10 };
        worker_timeouts timeouts {};
    };
}

#endif // FUZZ_SPECS_H
