#ifndef PROTOCOL_SPECS_H
#define PROTOCOL_SPECS_H

#include <cstdint>
#include <stdexcept>

namespace hotfuzz
{
    /**
     * @brief Protocol identity and version used by every packet header.
     */
    inline constexpr std::uint32_t packet_magic = 0x48505a5a; // "HPZZ"
    inline constexpr std::uint16_t packet_version = 1;

    /**
     * @brief High-level message type exchanged between pool and workers.
     */
    enum class packet_kind : std::uint8_t
    {
        run = 1,
        ok = 2,
        exception = 3,
        stop = 4,
        protocol_error = 5
    };

    /**
     * @brief Describes how packet_manager should decode the payload bytes.
     */
    enum class payload_kind : std::uint8_t
    {
        none = 0,
        tuple = 1,
        text = 2
    };

    /**
     * @brief Fixed packet frame prefix.
     *
     * The header identifies the protocol version, logical packet kind, payload
     * kind, task id, optional flags, and payload byte size. Payload bytes follow
     * the header directly.
     */
    struct packet_header
    {
        std::uint32_t magic { packet_magic };
        std::uint16_t version { packet_version };
        std::uint16_t header_size { sizeof(packet_header) };

        std::uint8_t kind {};
        std::uint8_t payload_kind {};
        std::uint16_t flags {};

        std::uint64_t task_id {};
        std::uint32_t payload_size {};
    };

    /**
     * @brief Thrown when packet framing, header validation, or payload decoding fails.
     */
    class protocol_error : public std::runtime_error
    {
    public:
        using std::runtime_error::runtime_error;
    };
}

#endif // PROTOCOL_SPECS_H
