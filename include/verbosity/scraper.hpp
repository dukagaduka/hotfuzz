#ifndef VERBOSITY_SCRAPER_HPP
#define VERBOSITY_SCRAPER_HPP

#include <algorithm>
#include <cstdint>
#include <fstream>
#include <optional>
#include <sstream>
#include <string>
#include <string_view>
#include <thread>

#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <windows.h>
#include <psapi.h>
#endif

#include "verbosity/specs.h"

namespace hotfuzz
{
    /**
     * @brief Small cross-platform scraper for system and current-process metrics.
     *
     * sample() is stateful: CPU percentages are computed from the previous
     * sample, while memory values are read directly on every call.
     */
    class system_scraper
    {
    public:
        [[nodiscard]] system_metrics sample()
        {
            system_metrics metrics;

            fill_memory_metrics(metrics);
            fill_cpu_metrics(metrics);

            return metrics;
        }

    private:
#ifdef _WIN32
        struct cpu_snapshot
        {
            std::uint64_t idle {};
            std::uint64_t system {};
            std::uint64_t process {};
        };

        static std::uint64_t filetime_to_uint64(const FILETIME& value)
        {
            ULARGE_INTEGER result;
            result.LowPart = value.dwLowDateTime;
            result.HighPart = value.dwHighDateTime;

            return result.QuadPart;
        }

        static std::optional<cpu_snapshot> read_cpu_snapshot()
        {
            FILETIME idle_time {};
            FILETIME kernel_time {};
            FILETIME user_time {};

            if (GetSystemTimes(&idle_time, &kernel_time, &user_time) == 0)
                return std::nullopt;

            FILETIME creation_time {};
            FILETIME exit_time {};
            FILETIME process_kernel_time {};
            FILETIME process_user_time {};

            if (GetProcessTimes(
                    GetCurrentProcess(),
                    &creation_time,
                    &exit_time,
                    &process_kernel_time,
                    &process_user_time
                ) == 0)
            {
                return std::nullopt;
            }

            const std::uint64_t process_time =
                filetime_to_uint64(process_kernel_time) + filetime_to_uint64(process_user_time);

            return cpu_snapshot {
                .idle = filetime_to_uint64(idle_time),
                .system = filetime_to_uint64(kernel_time) + filetime_to_uint64(user_time),
                .process = process_time
            };
        }

        void fill_memory_metrics(system_metrics& metrics) const
        {
            MEMORYSTATUSEX memory_status {};
            memory_status.dwLength = sizeof(memory_status);

            if (GlobalMemoryStatusEx(&memory_status) == 0)
                return;

            metrics.memory_available = true;
            metrics.ram_total_bytes = memory_status.ullTotalPhys;
            metrics.ram_available_bytes = memory_status.ullAvailPhys;
            metrics.ram_used_bytes = metrics.ram_total_bytes - metrics.ram_available_bytes;

            PROCESS_MEMORY_COUNTERS_EX process_memory {};

            if (GetProcessMemoryInfo(
                    GetCurrentProcess(),
                    reinterpret_cast<PROCESS_MEMORY_COUNTERS*>(&process_memory),
                    sizeof(process_memory)
                ) != 0)
            {
                metrics.process_rss_bytes =
                    static_cast<std::uint64_t>(process_memory.WorkingSetSize);
            }
        }

        void fill_cpu_metrics(system_metrics& metrics)
        {
            auto current = read_cpu_snapshot();

            if (!current)
                return;

            if (m_previous_cpu)
            {
                const std::uint64_t system_delta = current->system - m_previous_cpu->system;
                const std::uint64_t idle_delta = current->idle - m_previous_cpu->idle;
                const std::uint64_t process_delta = current->process - m_previous_cpu->process;

                if (system_delta > 0)
                {
                    metrics.cpu_available = true;
                    metrics.cpu_total_percent =
                        100.0 * static_cast<double>(system_delta - idle_delta) /
                        static_cast<double>(system_delta);
                    metrics.cpu_process_percent =
                        100.0 * static_cast<double>(process_delta) /
                        static_cast<double>(system_delta);
                }
            }

            m_previous_cpu = current;
        }
#elif defined(__linux__)
        struct cpu_snapshot
        {
            std::uint64_t total {};
            std::uint64_t idle {};
            std::uint64_t process {};
        };

        static std::optional<cpu_snapshot> read_cpu_snapshot()
        {
            std::ifstream stat("/proc/stat");

            if (!stat)
                return std::nullopt;

            std::string cpu_label;
            std::uint64_t user {};
            std::uint64_t nice {};
            std::uint64_t system {};
            std::uint64_t idle {};
            std::uint64_t iowait {};
            std::uint64_t irq {};
            std::uint64_t softirq {};
            std::uint64_t steal {};

            stat >> cpu_label >> user >> nice >> system >> idle >> iowait >>
                irq >> softirq >> steal;

            if (!stat || cpu_label != "cpu")
                return std::nullopt;

            auto process_ticks = read_process_cpu_ticks();

            if (!process_ticks)
                return std::nullopt;

            return cpu_snapshot {
                .total = user + nice + system + idle + iowait + irq + softirq + steal,
                .idle = idle + iowait,
                .process = *process_ticks
            };
        }

        static std::optional<std::uint64_t> parse_uint64(const std::string& value)
        {
            std::istringstream in(value);
            std::uint64_t result {};

            if (in >> result)
                return result;

            return std::nullopt;
        }

        static std::optional<std::uint64_t> read_process_cpu_ticks()
        {
            std::ifstream stat("/proc/self/stat");
            std::string line;

            if (!std::getline(stat, line))
                return std::nullopt;

            const auto command_end = line.rfind(')');

            if (command_end == std::string::npos || command_end + 2 >= line.size())
                return std::nullopt;

            std::istringstream fields(line.substr(command_end + 2));
            std::string field;
            std::optional<std::uint64_t> user_ticks;

            for (std::size_t index = 3; fields >> field; ++index)
            {
                if (index == 14)
                {
                    user_ticks = parse_uint64(field);

                    if (!user_ticks)
                        return std::nullopt;
                }
                else if (index == 15)
                {
                    auto system_ticks = parse_uint64(field);

                    if (!user_ticks || !system_ticks)
                        return std::nullopt;

                    return *user_ticks + *system_ticks;
                }
            }

            return std::nullopt;
        }

        static std::optional<std::uint64_t> read_meminfo_kib(std::string_view key)
        {
            std::ifstream meminfo("/proc/meminfo");
            std::string name;
            std::uint64_t value {};
            std::string unit;

            while (meminfo >> name >> value >> unit)
            {
                if (!name.empty() && name.back() == ':')
                    name.pop_back();

                if (name == key)
                    return value;
            }

            return std::nullopt;
        }

        static std::optional<std::uint64_t> read_process_rss_bytes()
        {
            std::ifstream status("/proc/self/status");
            std::string line;

            while (std::getline(status, line))
            {
                if (!line.starts_with("VmRSS:"))
                    continue;

                std::istringstream fields(line);
                std::string name;
                std::uint64_t value {};
                std::string unit;

                if (fields >> name >> value >> unit)
                    return value * 1024;
            }

            return std::nullopt;
        }

        void fill_memory_metrics(system_metrics& metrics) const
        {
            auto total_kib = read_meminfo_kib("MemTotal");
            auto available_kib = read_meminfo_kib("MemAvailable");

            if (!total_kib || !available_kib)
                return;

            metrics.memory_available = true;
            metrics.ram_total_bytes = *total_kib * 1024;
            metrics.ram_available_bytes = *available_kib * 1024;
            metrics.ram_used_bytes = metrics.ram_total_bytes - metrics.ram_available_bytes;

            if (auto rss = read_process_rss_bytes())
                metrics.process_rss_bytes = *rss;
        }

        void fill_cpu_metrics(system_metrics& metrics)
        {
            auto current = read_cpu_snapshot();

            if (!current)
                return;

            if (m_previous_cpu)
            {
                const std::uint64_t total_delta = current->total - m_previous_cpu->total;
                const std::uint64_t idle_delta = current->idle - m_previous_cpu->idle;
                const std::uint64_t process_delta = current->process - m_previous_cpu->process;

                if (total_delta > 0)
                {
                    metrics.cpu_available = true;
                    metrics.cpu_total_percent =
                        100.0 * static_cast<double>(total_delta - idle_delta) /
                        static_cast<double>(total_delta);
                    metrics.cpu_process_percent =
                        100.0 * static_cast<double>(process_delta) /
                        static_cast<double>(total_delta);
                }
            }

            m_previous_cpu = current;
        }
#else
        struct cpu_snapshot
        {
        };

        void fill_memory_metrics(system_metrics&) const
        {
        }

        void fill_cpu_metrics(system_metrics&)
        {
        }
#endif

    private:
        std::optional<cpu_snapshot> m_previous_cpu;
    };
}

#endif // VERBOSITY_SCRAPER_HPP
