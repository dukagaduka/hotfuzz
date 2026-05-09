#ifndef PROTOCOL_PACKET_MANAGER_HPP
#define PROTOCOL_PACKET_MANAGER_HPP

#include <chrono>
#include <cstdint>
#include <limits>
#include <stdexcept>
#include <string>
#include <string_view>
#include <tuple>
#include <utility>
#include <variant>
#include <vector>

#include "serialization/api.hpp"
#include "protocol/io_utils.hpp"
#include "protocol/packet.hpp"
#include "protocol/specs.h"

namespace hotfuzz
{
    /**
     * @brief High-level packet protocol API over read/write file descriptors.
     *
     * It owns framing, header validation, payload serialization, and payload
     * decoding. Transport failures are reported as ipc_error subclasses, while
     * malformed frames and decode failures are protocol_error.
     */
    template <typename... Ts>
    class packet_manager
    {
    public:
        using args_tuple = std::tuple<Ts...>;
        using packet_type = packet<Ts...>;

        explicit packet_manager(int fd);
        packet_manager(int read_fd, int write_fd);


        void send_run(
            std::uint64_t task_id,
            const args_tuple& args,
            std::chrono::milliseconds timeout = std::chrono::milliseconds::zero(),
            std::uint16_t flags = 0
        );

        void send_ok(
            std::uint64_t task_id,
            std::chrono::milliseconds timeout = std::chrono::milliseconds::zero(),
            std::uint16_t flags = 0
        );

        void send_stop(
            std::chrono::milliseconds timeout = std::chrono::milliseconds::zero(),
            std::uint16_t flags = 0
        );

        void send_exception(
            std::uint64_t task_id,
            std::string_view text,
            std::chrono::milliseconds timeout = std::chrono::milliseconds::zero(),
            std::uint16_t flags = 0
        );

        void send_protocol_error(
            std::uint64_t task_id,
            std::string_view text,
            std::chrono::milliseconds timeout = std::chrono::milliseconds::zero(),
            std::uint16_t flags = 0
        );

        void send_text(
            packet_kind kind,
            std::uint64_t task_id,
            std::string_view text,
            std::chrono::milliseconds timeout = std::chrono::milliseconds::zero(),
            std::uint16_t flags = 0
        );

        [[nodiscard]] packet_type receive(
            std::chrono::milliseconds timeout = std::chrono::milliseconds::zero()
        );

    private:
        void send_packet(
            packet_kind kind,
            payload_kind payload_type,
            std::uint64_t task_id,
            std::uint16_t flags,
            const std::vector<std::uint8_t>& payload,
            std::chrono::milliseconds timeout = std::chrono::milliseconds::zero()
        );

        [[nodiscard]] static packet_header make_header(
            packet_kind kind,
            payload_kind payload_type,
            std::uint64_t task_id,
            std::uint16_t flags,
            std::size_t payload_size
        );

        static void validate_header(const packet_header& header);
        static void throw_io_failure(const io_result& result, std::string_view operation);
        static void throw_protocol_decode(std::string_view message, const std::exception& e);

        [[nodiscard]] packet_type decode_packet(
            const packet_header& header,
            const std::vector<std::uint8_t>& payload_bytes
        ) const;

    private:
        int m_read_fd {};
        int m_write_fd {};

    };


    template <typename... Ts>
    packet_manager<Ts...>::packet_manager(int fd)
        : m_read_fd(fd),
          m_write_fd(fd)
    {}


    template <typename... Ts>
    packet_manager<Ts...>::packet_manager(int read_fd, int write_fd)
        : m_read_fd(read_fd),
          m_write_fd(write_fd)
    {}


    template <typename... Ts>
    inline void packet_manager<Ts...>::send_run(
        std::uint64_t task_id,
        const args_tuple& args,
        std::chrono::milliseconds timeout,
        std::uint16_t flags
    )
    {
        send_packet(
            packet_kind::run,
            payload_kind::tuple,
            task_id,
            flags,
            to_bytes(args),
            timeout
        );
    }


    template <typename... Ts>
    inline void packet_manager<Ts...>::send_ok(
        std::uint64_t task_id,
        std::chrono::milliseconds timeout,
        std::uint16_t flags
    )
    {
        send_packet(packet_kind::ok, payload_kind::none, task_id, flags, {}, timeout);
    }

    
    template <typename... Ts>
    inline void packet_manager<Ts...>::send_stop(
        std::chrono::milliseconds timeout,
        std::uint16_t flags
    )
    {
        send_packet(packet_kind::stop, payload_kind::none, 0, flags, {}, timeout);
    }


    template <typename... Ts>
    inline void packet_manager<Ts...>::send_exception(
        std::uint64_t task_id,
        std::string_view text,
        std::chrono::milliseconds timeout,
        std::uint16_t flags
    )
    {
        send_text(packet_kind::exception, task_id, text, timeout, flags);
    }


    template <typename... Ts>
    inline void packet_manager<Ts...>::send_protocol_error(
        std::uint64_t task_id,
        std::string_view text,
        std::chrono::milliseconds timeout,
        std::uint16_t flags
    )
    {
        send_text(packet_kind::protocol_error, task_id, text, timeout, flags);
    }


    template <typename... Ts>
    inline void packet_manager<Ts...>::send_text(
        packet_kind kind,
        std::uint64_t task_id,
        std::string_view text,
        std::chrono::milliseconds timeout,
        std::uint16_t flags
    )
    {
        send_packet(
            kind,
            payload_kind::text,
            task_id,
            flags,
            to_bytes(std::string{text}),
            timeout
        );
    }


    template <typename... Ts>
    inline typename packet_manager<Ts...>::packet_type packet_manager<Ts...>::receive(std::chrono::milliseconds timeout)
    {
        io_result result {};
        packet_header header {};
        const auto deadline = std::chrono::steady_clock::now() + timeout;

        if (timeout != std::chrono::milliseconds::zero())
        {
            result = read_all_for(m_read_fd, &header, sizeof(header), utils::timeout_ms_until_chrono(deadline));
        }
        else
        {
            result = read_all(m_read_fd, &header, sizeof(header));
        }

        if (!result.ok())
            throw_io_failure(result, "read packet header");

        validate_header(header);

        std::vector<std::uint8_t> payload_bytes(header.payload_size);

        if (!payload_bytes.empty())
        {
            if (timeout != std::chrono::milliseconds::zero())
            {
                result = read_all_for(m_read_fd, payload_bytes.data(), payload_bytes.size(), utils::timeout_ms_until_chrono(deadline));
            }
            else
            {
                result = read_all(m_read_fd, payload_bytes.data(), payload_bytes.size());
            }

            if (!result.ok())
                throw_io_failure(result, "read packet payload");
        }

        return decode_packet(header, payload_bytes);
    }


    template <typename... Ts>
    inline void packet_manager<Ts...>::send_packet(
        packet_kind kind,
        payload_kind payload_type,
        std::uint64_t task_id,
        std::uint16_t flags,
        const std::vector<std::uint8_t>& payload,
        std::chrono::milliseconds timeout
    )
    {
        io_result result {};
        const auto header = make_header(kind, payload_type, task_id, flags, payload.size());
        const auto deadline = std::chrono::steady_clock::now() + timeout;

        if (timeout != std::chrono::milliseconds::zero())
        {
            result = write_all_for(m_write_fd, &header, sizeof(header), utils::timeout_ms_until_chrono(deadline));
        }
        else
        {
            result = write_all(m_write_fd, &header, sizeof(header));
        }

        if (!result.ok())
            throw_io_failure(result, "write packet header");

        if (!payload.empty())
        {
            if (timeout != std::chrono::milliseconds::zero())
            {
                result = write_all_for(m_write_fd, payload.data(), payload.size(), utils::timeout_ms_until_chrono(deadline));
            }
            else
            {
                result = write_all(m_write_fd, payload.data(), payload.size());
            }

            if (!result.ok())
                throw_io_failure(result, "write packet payload");
        }
    }


    template <typename... Ts>
    inline packet_header packet_manager<Ts...>::make_header(
        packet_kind kind,
        payload_kind payload_type,
        std::uint64_t task_id,
        std::uint16_t flags,
        std::size_t payload_size)
    {
        if (payload_size > std::numeric_limits<std::uint32_t>::max())
            throw protocol_error("packet payload is too large");

        packet_header header {};

        header.kind = static_cast<std::uint8_t>(kind);
        header.payload_kind = static_cast<std::uint8_t>(payload_type);
        header.flags = flags;
        header.task_id = task_id;
        header.payload_size = static_cast<std::uint32_t>(payload_size);

        validate_header(header);

        return header;
    }


    template <typename... Ts>
    inline void packet_manager<Ts...>::validate_header(const packet_header& header)
    {
        if (header.magic != packet_magic)
            throw protocol_error("bad packet magic");

        if (header.version != packet_version)
            throw protocol_error("unsupported packet version");

        if (header.header_size != sizeof(packet_header))
            throw protocol_error("unsupported packet header size");

        const auto kind = static_cast<packet_kind>(header.kind);
        const auto payload_type = static_cast<payload_kind>(header.payload_kind);

        switch (payload_type)
        {
            case payload_kind::none:
            case payload_kind::tuple:
            case payload_kind::text:
                break;

            default:
                throw protocol_error("unknown packet payload kind");
        }

        switch (kind)
        {
            case packet_kind::run:
                if (payload_type != payload_kind::tuple)
                    throw protocol_error("run packet must carry tuple payload");
                break;

            case packet_kind::ok:
                break;

            case packet_kind::stop:
                if (payload_type != payload_kind::none)
                    throw protocol_error("empty packet kind must not carry payload");
                break;

            case packet_kind::exception:
                if (payload_type != payload_kind::text)
                    throw protocol_error("text packet kind must carry text payload");
                break;

            case packet_kind::protocol_error:
                if (payload_type != payload_kind::text)
                    throw protocol_error("text packet kind must carry text payload");
                break;

            default:
                throw protocol_error("unknown packet kind");
        }

        if (payload_type == payload_kind::none && header.payload_size != 0)
            throw protocol_error("none packet payload must be empty");
    }


    template <typename... Ts>
    inline void packet_manager<Ts...>::throw_io_failure(const io_result& result, std::string_view operation)
    {
        std::string message(operation);

        switch (result.status)
        {
            case io_status::timeout:
                throw timeout_error(message + " timed out");

            case io_status::eof:
                throw disconnected_error(message + " reached EOF");

            case io_status::disconnected:
                throw disconnected_error(message + " disconnected");

            case io_status::system_error:
                throw ipc_error(message + " failed with errno " + std::to_string(result.error_number));

            case io_status::ok:
                return;
        }
    }


    template <typename... Ts>
    inline void packet_manager<Ts...>::throw_protocol_decode(
        std::string_view message,
        const std::exception& e
    )
    {
        throw protocol_error(std::string(message) + ": " + e.what());
    }


    template <typename... Ts>
    inline typename packet_manager<Ts...>::packet_type packet_manager<Ts...>::decode_packet(
        const packet_header& header,
        const std::vector<std::uint8_t>& payload_bytes
    ) const
    {
        packet_type packet {};
        packet.header = header;

        try
        {
            switch (static_cast<payload_kind>(header.payload_kind))
            {
                case payload_kind::none:
                    packet.payload = std::monostate {};
                    break;

                case payload_kind::tuple:
                    packet.payload = from_bytes<args_tuple>(payload_bytes);
                    break;

                case payload_kind::text:
                    packet.payload = from_bytes<std::string>(payload_bytes);
                    break;
            }
        }
        catch (const protocol_error&)
        {
            throw;
        }
        catch (const std::exception& e)
        {
            throw_protocol_decode("failed to decode packet payload", e);
        }

        return packet;
    }
}

#endif // PROTOCOL_PACKET_MANAGER_HPP
