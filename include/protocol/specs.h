#ifndef PROTOCOL_SPECS_H
#define PROTOCOL_SPECS_H

#include <cstdint>
#include <stdexcept>

namespace hotfuzz
{
    // ---------------------------------------------------------------------
    // IO specs
    // ---------------------------------------------------------------------


    
    /**
     * @brief Result category for low-level descriptor IO utils.
     *
     * `ok` means the requested byte count was transferred. 
     * `timeout` is produced only by *_for utils. 
     * `eof` means read returned 0 or write made no progress. 
     * `disconnected` covers broken peer errors such as EPIPE and ECONNRESET. 
     * `system_error` carries any other errno value.
     */
    enum class io_status
    {
        ok,
        timeout,
        eof,
        disconnected,
        system_error
    };

    struct io_result
    {
        io_status status { io_status::ok };
        int error_number { 0 };

        const bool ok() const { return status == io_status::ok; };
    };



    // ---------------------------------------------------------------------
    // Packet specs
    // ---------------------------------------------------------------------



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



    // ---------------------------------------------------------------------
    // Errors specs
    // ---------------------------------------------------------------------



    /**
     * @brief Thrown when packet framing, header validation, or payload decoding fails.
     */
    class protocol_error : public std::runtime_error
    {
    public:
        using std::runtime_error::runtime_error;
    };

    
    /**
     * @brief Base class for transport-level packet IO failures.
     */
    class ipc_error : public std::runtime_error
    {
    public:
        using std::runtime_error::runtime_error;
    };


    /**
     * @brief Thrown when a bounded protocol operation reaches its deadline.
     */
    class timeout_error : public ipc_error
    {
    public:
        using ipc_error::ipc_error;
    };


    /**
     * @brief Thrown when the peer closes or breaks the protocol transport.
     */
    class disconnected_error : public ipc_error
    {
    public:
        using ipc_error::ipc_error;
    };
}

#endif // PROTOCOL_SPECS_H
