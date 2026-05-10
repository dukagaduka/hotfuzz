#ifndef FUZZ_FAILURE_RECORDER_HPP
#define FUZZ_FAILURE_RECORDER_HPP

#include <cstdint>
#include <filesystem>
#include <fstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <tuple>
#include <utility>

#include "json.hpp"

#include "serialization/api.hpp"
#include "worker/specs.h"
#include "worker/utils.hpp"

namespace hotfuzz
{
    /**
     * @brief Writes reproducible artifacts for exceptions and crashes.
     */
    class failure_recorder
    {
    public:
        explicit failure_recorder(std::filesystem::path output_dir)
            : m_output_dir(std::move(output_dir)),
              m_bin_dir(m_output_dir / "bin"),
              m_json_path(m_output_dir / "errors_and_crashes.json")
        {
            std::filesystem::create_directories(m_bin_dir);
            m_entries = nlohmann::json::array();
            flush();
        }

        template <typename... Ts>
        void record_exception(
            std::uint64_t task_id,
            const std::tuple<Ts...>& args,
            const std::string& text
        )
        {
            record("exception", task_id, args, text);
        }

        template <typename... Ts>
        void record_crash(
            std::uint64_t task_id,
            const std::tuple<Ts...>& args,
            const std::string& text
        )
        {
            record("crash", task_id, args, text);
        }

        template <typename... Ts>
        void record_result(const isolated_result<Ts...>& result)
        {
            if (result.status == isolated_status::exception)
                record_exception(result.task_id, result.args, result.message);
            else if (result.status == isolated_status::crash)
                record_crash(result.task_id, result.args, signal_name(result.signal_number));
        }

    private:
        template <typename... Ts>
        void record(
            std::string_view kind,
            std::uint64_t task_id,
            const std::tuple<Ts...>& args,
            const std::string& text
        )
        {
            const std::uint64_t record_id = m_next_record_id++;
            const std::string file_name =
                std::string(kind) + "_" + std::to_string(record_id) + ".args";
            const std::filesystem::path relative_path = std::filesystem::path("bin") / file_name;
            const std::filesystem::path full_path = m_output_dir / relative_path;

            auto bytes = to_bytes(args);

            std::ofstream out(full_path, std::ios::binary);

            if (!out)
                throw std::runtime_error("failed to write fuzz args file: " + full_path.string());

            out.write(
                reinterpret_cast<const char*>(bytes.data()),
                static_cast<std::streamsize>(bytes.size())
            );

            if (!out)
                throw std::runtime_error("failed to finish fuzz args file: " + full_path.string());

            m_entries.push_back(
                {
                    { "record_id", record_id },
                    { "task_id", task_id },
                    { "result", std::string(kind) },
                    { "text", text },
                    { "path", relative_path.generic_string() }
                }
            );

            flush();
        }

        void flush() const
        {
            std::ofstream out(m_json_path);

            if (!out)
                throw std::runtime_error("failed to write fuzz result json: " + m_json_path.string());

            out << m_entries.dump(2);
        }

    private:
        std::filesystem::path m_output_dir;
        std::filesystem::path m_bin_dir;
        std::filesystem::path m_json_path;
        nlohmann::json m_entries;
        std::uint64_t m_next_record_id { 1 };
    };
}

#endif // FUZZ_FAILURE_RECORDER_HPP
