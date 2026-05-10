#ifndef VERBOSITY_CONSOLE_FORMATTER_HPP
#define VERBOSITY_CONSOLE_FORMATTER_HPP

#include <cstdio>
#include <cstddef>
#include <cstdint>
#include <iomanip>
#include <ios>
#include <sstream>
#include <span>
#include <string>

#ifdef _WIN32
#include <io.h>
#else
#include <unistd.h>
#endif

#include "verbosity/specs.h"

namespace hotfuzz
{
    /**
     * @brief Renders the live verbosity frame for terminal output.
     */
    class console_formatter
    {
    public:
        explicit console_formatter(color_mode colors)
            : m_use_color(resolve_color_support(colors))
        {
        }

        [[nodiscard]] std::string render(
            const system_metrics& metrics,
            std::span<const failure_event> failures
        ) const
        {
            std::ostringstream out;
            std::ostringstream row;

            append_line(out, "hotfuzz live");
            append_line(out, "+---------------+---------------+---------------+---------------+---------------+");
            append_line(out, "| CPU total     | CPU process   | RAM used      | RAM total     | RSS           |");
            append_line(out, "+---------------+---------------+---------------+---------------+---------------+");
            row << "| " << cell_text(format_percent(metrics.cpu_total_percent, metrics.cpu_available))
                << "| " << cell_text(format_percent(metrics.cpu_process_percent, metrics.cpu_available))
                << "| " << cell_text(format_bytes(metrics.ram_used_bytes, metrics.memory_available))
                << "| " << cell_text(format_bytes(metrics.ram_total_bytes, metrics.memory_available))
                << "| " << cell_text(format_bytes(metrics.process_rss_bytes, metrics.memory_available))
                << "|";
            append_line(out, row.str());
            append_line(out, "+---------------+---------------+---------------+---------------+---------------+");
            append_line(out, "Recent failures (" + std::to_string(failures.size()) + ")");

            if (failures.empty())
            {
                append_line(out, "  <none>");
                return out.str();
            }

            for (const auto& failure : failures)
                append_line(out, format_failure_line(failure));

            return out.str();
        }

    private:
        static void append_line(std::ostringstream& out, const std::string& text)
        {
            out << text << "\x1b[K\n";
        }

        static bool resolve_color_support(color_mode mode)
        {
            if (mode == color_mode::always)
                return true;

            if (mode == color_mode::never)
                return false;

#ifdef _WIN32
            return _isatty(_fileno(stdout)) != 0;
#else
            return isatty(fileno(stdout)) != 0;
#endif
        }

        static std::string cell_text(const std::string& value)
        {
            constexpr int width = 13;
            std::ostringstream out;
            out << std::left << std::setw(width) << value;
            return out.str();
        }

        static std::string format_percent(double value, bool available)
        {
            if (!available)
                return "n/a";

            std::ostringstream out;
            out << std::fixed << std::setprecision(1) << value << '%';
            return out.str();
        }

        static std::string format_bytes(std::uint64_t value, bool available)
        {
            if (!available)
                return "n/a";

            constexpr const char* suffixes[] { "B", "KiB", "MiB", "GiB", "TiB" };
            constexpr std::size_t suffix_count = sizeof(suffixes) / sizeof(suffixes[0]);
            double current = static_cast<double>(value);
            std::size_t suffix_index = 0;

            while (current >= 1024.0 && suffix_index + 1 < suffix_count)
            {
                current /= 1024.0;
                ++suffix_index;
            }

            std::ostringstream out;

            if (suffix_index == 0)
                out << static_cast<std::uint64_t>(current) << ' ' << suffixes[suffix_index];
            else
                out << std::fixed << std::setprecision(1) << current << ' ' << suffixes[suffix_index];

            return out.str();
        }

        std::string format_failure_line(const failure_event& failure) const
        {
            std::ostringstream out;

            out << "  " << colorize(kind_tag(failure.kind), kind_color(failure.kind))
                << " task=" << failure.task_id;

            if (failure.has_record_id)
                out << " record=" << failure.record_id;

            out << ' ' << failure.text;

            if (!failure.artifact_path.empty())
                out << " -> " << failure.artifact_path;

            return out.str();
        }

        static const char* kind_tag(failure_kind kind)
        {
            switch (kind)
            {
                case failure_kind::exception: return "[EXCEPTION]";
                case failure_kind::crash: return "[CRASH]";
                case failure_kind::timeout: return "[TIMEOUT]";
                case failure_kind::protocol_error: return "[PROTOCOL]";
                case failure_kind::ipc_error: return "[IPC]";
                case failure_kind::internal_error: return "[INTERNAL]";
                default: return "[FAILURE]";
            }
        }

        static const char* kind_color(failure_kind kind)
        {
            switch (kind)
            {
                case failure_kind::exception: return "\x1b[38;5;214m";
                case failure_kind::crash: return "\x1b[31m";
                case failure_kind::timeout: return "\x1b[35m";
                case failure_kind::protocol_error: return "\x1b[36m";
                case failure_kind::ipc_error: return "\x1b[34m";
                case failure_kind::internal_error: return "\x1b[33m";
                default: return "\x1b[0m";
            }
        }

        std::string colorize(const char* text, const char* color) const
        {
            if (!m_use_color)
                return text;

            return std::string(color) + text + "\x1b[0m";
        }

    private:
        bool m_use_color { false };
    };
}

#endif // VERBOSITY_CONSOLE_FORMATTER_HPP
