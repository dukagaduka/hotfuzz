#ifndef VERBOSITY_SPECS_H
#define VERBOSITY_SPECS_H

#include <cstdint>

namespace hotfuzz
{
    /**
     * @brief Point-in-time OS and current-process resource usage.
     *
     * CPU usage is delta-based, so cpu_available is false until scraper has at
     * least two samples. Memory counters are filled independently.
     */
    struct system_metrics
    {
        bool cpu_available { false };
        double cpu_total_percent {};
        double cpu_process_percent {};

        bool memory_available { false };
        std::uint64_t ram_total_bytes {};
        std::uint64_t ram_available_bytes {};
        std::uint64_t ram_used_bytes {};
        std::uint64_t process_rss_bytes {};
    };
}

#endif // VERBOSITY_SPECS_H
