#ifndef VERBOSITY_SPECS_H
#define VERBOSITY_SPECS_H

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <string>

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


    /**
     * @brief Failure categories shown in the live console dashboard.
     */
    enum class failure_kind : std::uint8_t
    {
        exception,
        crash,
        timeout,
        protocol_error,
        ipc_error,
        internal_error
    };


    /**
     * @brief One recent failure displayed by the dashboard.
     */
    struct failure_event
    {
        failure_kind kind { failure_kind::exception };
        std::uint64_t task_id {};
        std::uint64_t record_id {};
        bool has_record_id { false };
        std::string text;
        std::string artifact_path;
    };


    /**
     * @brief Color policy for the live console dashboard.
     */
    enum class color_mode : std::uint8_t
    {
        auto_detect,
        always,
        never
    };


    /**
     * @brief Runtime options for the live console dashboard.
     */
    struct verbosity_options
    {
        bool enabled { false };
        std::size_t recent_failure_limit { 10 };
        std::chrono::milliseconds refresh_interval { 250 };
        color_mode colors { color_mode::auto_detect };
    };
}

#endif // VERBOSITY_SPECS_H
