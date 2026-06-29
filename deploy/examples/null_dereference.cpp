/*
 * hotfuzz example: null pointer dereference in a session state machine.
 *
 * Bug class
 * ---------
 * This file models a request handler that processes a compact stream of
 * commands. One command creates an authenticated session. Another command
 * assumes the session exists and reads session fields through a raw pointer.
 *
 * This is a realistic server-side bug shape: authorization, handshake, or
 * connection setup code often creates per-client state, while later handlers
 * accidentally assume that state is already initialized.
 *
 * How the failure happens
 * -----------------------
 * The command byte values are reduced to opcodes:
 *
 *   1 => login
 *   2 => data
 *   3 => logout
 *   0 => ping/no-op
 *
 * A sequence starting with opcode 2 reaches the data handler before login.
 * The vulnerable code dereferences session_ptr while it is still null. In an
 * isolated worker this becomes SIGSEGV and hotfuzz records the input.
 *
 * How hotfuzz helps
 * -----------------
 * The provider below emits command streams that cover ordinary flows and bad
 * ordering:
 *
 *   data before login
 *   login then data
 *   logout then data
 *   ping then data
 *
 * hotfuzz runs each stream in isolation. A null dereference kills only the
 * worker process, not the parent fuzzing process. The recorder writes:
 *
 *   HOTFUZZ_OUTPUT_DIR/null_dereference/errors_and_crashes.json
 *   HOTFUZZ_OUTPUT_DIR/null_dereference/bin/crash_*.args
 *
 * How to analyze a result
 * -----------------------
 * Open the JSON file first. It contains the result kind, task id, signal text,
 * and relative .args path. Then replay the exact input:
 *
 *   HOTFUZZ_INPUT_BIN=/workspace/hotfuzz_output/null_dereference/bin/crash_1.args
 *
 * Replay uses run_mode::bin, so the same target runs against the recorded
 * command stream. This is useful after adding logging, assertions, or a fix.
 */

#include "hotfuzz.hpp"

#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <iostream>
#include <optional>
#include <vector>

namespace
{
    struct session
    {
        std::uint32_t account_id {};
        bool admin {};
    };

    std::filesystem::path recorder_dir()
    {
        if (const char* root = std::getenv("HOTFUZZ_OUTPUT_DIR"); root != nullptr && *root != '\0')
            return std::filesystem::path(root) / "null_dereference";

        return std::filesystem::path("hotfuzz_output") / "null_dereference";
    }

    std::vector<std::vector<std::uint8_t>> corpus()
    {
        return {
            {},
            { 1, 2 },
            { 2 },
            { 0, 2 },
            { 1, 3, 2 },
            { 3, 2 },
            { 0, 1, 2, 3 }
        };
    }

    void process_commands(const std::vector<std::uint8_t>& commands)
    {
        std::optional<session> current_session;
        session* session_ptr = nullptr;

        for (std::uint8_t raw_command : commands)
        {
            const std::uint8_t opcode = raw_command % 4;

            if (opcode == 0)
                continue;

            if (opcode == 1)
            {
                current_session.emplace(session { .account_id = 42, .admin = false });
                session_ptr = &*current_session;
                continue;
            }

            if (opcode == 3)
            {
                current_session.reset();
                session_ptr = nullptr;
                continue;
            }

            volatile std::uint32_t account_id = session_ptr->account_id;
            (void)account_id;
        }
    }

    hotfuzz::fuzz_options options()
    {
        hotfuzz::fuzz_options opts;
        opts.isolation_mode = true;
        opts.use_recorder = true;
        opts.output_dir = recorder_dir();
        opts.num_workers = 5;
        opts.timeouts.task_timeout = std::chrono::milliseconds { 1000 };
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
    auto command_streams = corpus();
    hotfuzz::iterable_provider provider(command_streams.size(), command_streams);

    auto opts = options();

    if (const char* replay = std::getenv("HOTFUZZ_INPUT_BIN"); replay != nullptr && *replay != '\0')
    {
        opts.input_bin = replay;
        std::cout << "Replaying " << replay << '\n';
        hotfuzz::fuzz(process_commands, hotfuzz::run_mode::bin, opts, provider);
        return 0;
    }

    std::cout << "Recorder output: " << opts.output_dir << '\n';
    hotfuzz::fuzz(process_commands, hotfuzz::run_mode::zip, opts, provider);
    return 0;
}
