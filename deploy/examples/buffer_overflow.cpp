/*
 * hotfuzz example: stack buffer overflow in a length-prefixed packet decoder.
 *
 * Bug class
 * ---------
 * This file models a common protocol parsing bug. A packet starts with one
 * length byte followed by payload bytes. The vulnerable decoder trusts the
 * length field and copies that many bytes into a fixed 16-byte stack buffer.
 *
 * The bug is not that the packet is malformed. The packet can be internally
 * consistent: "length == available payload bytes". The bug is that the parser
 * validates the packet length against the input size, but never validates it
 * against the destination buffer capacity.
 *
 * How the failure happens
 * -----------------------
 * A packet like this is enough:
 *
 *   [ 32, 'A', 'A', ... 32 payload bytes ... ]
 *
 * The decoder sees that 32 payload bytes are available, then calls memcpy()
 * into a 16-byte local array. In a plain build this is undefined behavior: it may corrupt stack memory, abort,
 * or appear to continue depending on compiler, optimization level, and platform.
 *
 * How hotfuzz helps
 * -----------------
 * The provider below emits realistic packet shapes: empty packets, short
 * packets, exact-boundary packets, and oversized-but-well-formed packets.
 * hotfuzz runs each packet in an isolated worker process. When the worker
 * crashes, the parent process stays alive and the recorder stores:
 *
 *   HOTFUZZ_OUTPUT_DIR/buffer_overflow/errors_and_crashes.json
 *   HOTFUZZ_OUTPUT_DIR/buffer_overflow/bin/crash_*.args
 *
 * The JSON file tells you which task crashed and where the serialized input is.
 * The .args file is a reproducible copy of the input tuple.
 *
 * How to analyze a result
 * -----------------------
 * Run this example, then inspect:
 *
 *   deploy/output/buffer_overflow/errors_and_crashes.json
 *
 * To replay one artifact through the same target, run the container with:
 *
 *   HOTFUZZ_INPUT_BIN=/workspace/hotfuzz_output/buffer_overflow/bin/crash_1.args
 *
 * The replay path uses hotfuzz run_mode::bin, so the providers are only used
 * for type deduction; the actual packet comes from the .args file.
 */

#include "hotfuzz.hpp"

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <iostream>
#include <vector>

namespace
{
    std::filesystem::path recorder_dir()
    {
        if (const char* root = std::getenv("HOTFUZZ_OUTPUT_DIR"); root != nullptr && *root != '\0')
            return std::filesystem::path(root) / "buffer_overflow";

        return std::filesystem::path("hotfuzz_output") / "buffer_overflow";
    }

    std::vector<std::uint8_t> packet(std::uint8_t claimed_size, std::uint8_t fill)
    {
        std::vector<std::uint8_t> bytes;
        bytes.reserve(static_cast<std::size_t>(claimed_size) + 1);
        bytes.push_back(claimed_size);

        for (std::uint8_t i = 0; i < claimed_size; ++i)
            bytes.push_back(static_cast<std::uint8_t>(fill + i));

        return bytes;
    }

    std::vector<std::vector<std::uint8_t>> corpus()
    {
        return {
            {},
            packet(0, 0x10),
            packet(4, 0x20),
            packet(15, 0x30),
            packet(16, 0x40),
            packet(17, 0x50),
            packet(32, 0x60),
            packet(64, 0x70)
        };
    }

    void decode_length_prefixed_packet(const std::vector<std::uint8_t>& frame)
    {
        if (frame.empty())
            return;

        const std::size_t claimed_size = frame[0];
        const std::size_t available = frame.size() - 1;

        if (available < claimed_size)
            return;

        char payload[16] {};

        std::memcpy(payload, frame.data() + 1, claimed_size);

        volatile unsigned checksum = 0;

        for (char byte : payload)
            checksum += static_cast<unsigned char>(byte);

        (void)checksum;
    }

    hotfuzz::fuzz_options options()
    {
        hotfuzz::fuzz_options opts;
        opts.isolation_mode = true;
        opts.use_recorder = true;
        opts.output_dir = recorder_dir();
        opts.num_workers = 1;
        opts.timeouts.task_timeout = std::chrono::milliseconds { 5000 };
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
    auto frames = corpus();
    hotfuzz::iterable_provider provider(frames.size(), frames);

    auto opts = options();

    if (const char* replay = std::getenv("HOTFUZZ_INPUT_BIN"); replay != nullptr && *replay != '\0')
    {
        opts.input_bin = replay;
        std::cout << "Replaying " << replay << '\n';
        hotfuzz::fuzz(decode_length_prefixed_packet, hotfuzz::run_mode::bin, opts, provider);
        return 0;
    }

    std::cout << "Recorder output: " << opts.output_dir << '\n';
    hotfuzz::fuzz(decode_length_prefixed_packet, hotfuzz::run_mode::zip, opts, provider);
    return 0;
}
