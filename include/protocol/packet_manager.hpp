#ifndef PROTOCOL_PACKET_MANAGER_HPP
#define PROTOCOL_PACKET_MANAGER_HPP

#include <chrono>
#include <cstdint>
#include <limits>
#include <string>
#include <string_view>
#include <tuple>
#include <utility>
#include <variant>
#include <vector>

#include "protocol/helpers.hpp"
#include "protocol/specs.h"
#include "serialization/serialization.hpp"

namespace hotfuzz
{
    /**
     * @brief Decoded protocol packet for the tuple type handled by packet_manager.
     *
     * The payload is either empty, std::tuple<Ts...>, or std::string depending
     * on payload_kind.
     */
    template <typename... Ts>
    struct packet
    {
        using args_tuple = std::tuple<Ts...>;
        using payload_variant = std::variant<std::monostate, args_tuple, std::string>;

        packet_header header {};
        payload_variant payload {};

        /**
         * @brief Returns the logical packet kind stored in the header.
         */
        [[nodiscard]] packet_kind kind() const noexcept
        {
            return static_cast<packet_kind>(header.kind);
        }

        /**
         * @brief Returns the payload kind stored in the header.
         */
        [[nodiscard]] payload_kind payload_type() const noexcept
        {
            return static_cast<payload_kind>(header.payload_kind);
        }

        /**
         * @brief Returns the task id associated with this packet.
         */
        [[nodiscard]] std::uint64_t task_id() const noexcept
        {
            return header.task_id;
        }

        /**
         * @brief Returns header flags carried by this packet.
         */
        [[nodiscard]] std::uint16_t flags() const noexcept
        {
            return header.flags;
        }

        /**
         * @brief Returns tuple payload or throws when this packet does not carry one.
         */
        [[nodiscard]] const args_tuple& as_tuple() const
        {
            if (!std::holds_alternative<args_tuple>(payload))
                throw protocol_error("packet payload is not a tuple");

            return std::get<args_tuple>(payload);
        }

        /**
         * @brief Returns text payload or throws when this packet does not carry one.
         */
        [[nodiscard]] const std::string& as_text() const
        {
            if (!std::holds_alternative<std::string>(payload))
                throw protocol_error("packet payload is not text");

            return std::get<std::string>(payload);
        }
    };

    /**
     * @brief High-level packet protocol API over read/write file descriptors.
     *
     * It owns framing, header validation, payload serialization, and payload
     * decoding. Worker code should deal with decoded packets, not raw bytes.
     */
    template <typename... Ts>
    class packet_manager
    {
    public:
        using args_tuple = std::tuple<Ts...>;
        using packet_type = packet<Ts...>;

        /**
         * @brief Uses the same fd for reads and writes.
         */
        explicit packet_manager(int fd);

        /**
         * @brief Uses separate read and write descriptors.
         */
        packet_manager(int read_fd, int write_fd);

        /**
         * @brief Sends a run packet with a tuple payload.
         */
        [[nodiscard]] bool send_run(
            std::uint64_t task_id,
            const args_tuple& args,
            std::uint16_t flags = 0
        );

        /**
         * @brief Sends an ok packet without payload.
         */
        [[nodiscard]] bool send_ok(std::uint64_t task_id, std::uint16_t flags = 0);

        /**
         * @brief Sends a stop packet without payload.
         */
        [[nodiscard]] bool send_stop(std::uint16_t flags = 0);

        /**
         * @brief Sends an exception packet with text payload.
         */
        [[nodiscard]] bool send_exception(
            std::uint64_t task_id,
            std::string_view text,
            std::uint16_t flags = 0
        );

        /**
         * @brief Sends a protocol_error packet with text payload.
         */
        [[nodiscard]] bool send_protocol_error(
            std::uint64_t task_id,
            std::string_view text,
            std::uint16_t flags = 0
        );

        /**
         * @brief Sends an arbitrary text-carrying packet kind.
         */
        [[nodiscard]] bool send_text(
            packet_kind kind,
            std::uint64_t task_id,
            std::string_view text,
            std::uint16_t flags = 0
        );

        /**
         * @brief Sends a run packet with a tuple payload before timeout expires.
         */
        [[nodiscard]] bool send_run_for(
            std::uint64_t task_id,
            const args_tuple& args,
            std::chrono::milliseconds timeout,
            std::uint16_t flags = 0
        );

        /**
         * @brief Sends an ok packet before timeout expires.
         */
        [[nodiscard]] bool send_ok_for(
            std::uint64_t task_id,
            std::chrono::milliseconds timeout,
            std::uint16_t flags = 0
        );

        /**
         * @brief Sends a stop packet before timeout expires.
         */
        [[nodiscard]] bool send_stop_for(
            std::chrono::milliseconds timeout,
            std::uint16_t flags = 0
        );

        /**
         * @brief Sends an exception packet with text payload before timeout expires.
         */
        [[nodiscard]] bool send_exception_for(
            std::uint64_t task_id,
            std::string_view text,
            std::chrono::milliseconds timeout,
            std::uint16_t flags = 0
        );

        /**
         * @brief Sends a protocol_error packet with text payload before timeout expires.
         */
        [[nodiscard]] bool send_protocol_error_for(
            std::uint64_t task_id,
            std::string_view text,
            std::chrono::milliseconds timeout,
            std::uint16_t flags = 0
        );

        /**
         * @brief Sends an arbitrary text-carrying packet before timeout expires.
         */
        [[nodiscard]] bool send_text_for(
            packet_kind kind,
            std::uint64_t task_id,
            std::string_view text,
            std::chrono::milliseconds timeout,
            std::uint16_t flags = 0
        );

        /**
         * @brief Reads, validates, and decodes one packet.
         */
        [[nodiscard]] packet_type receive();

        /**
         * @brief Reads, validates, and decodes one packet before timeout expires.
         */
        [[nodiscard]] packet_type receive_for(std::chrono::milliseconds timeout);

    private:
        /**
         * @brief Writes a complete header + payload frame.
         */
        [[nodiscard]] bool send_packet(
            packet_kind kind,
            payload_kind payload_type,
            std::uint64_t task_id,
            std::uint16_t flags,
            const std::vector<std::uint8_t>& payload
        );

        /**
         * @brief Writes a complete header + payload frame before timeout expires.
         */
        [[nodiscard]] bool send_packet_for(
            packet_kind kind,
            payload_kind payload_type,
            std::uint64_t task_id,
            std::uint16_t flags,
            const std::vector<std::uint8_t>& payload,
            std::chrono::milliseconds timeout
        );

        /**
         * @brief Builds a checked packet header.
         */
        [[nodiscard]] static packet_header make_header(
            packet_kind kind,
            payload_kind payload_type,
            std::uint64_t task_id,
            std::uint16_t flags,
            std::size_t payload_size
        );

        /**
         * @brief Validates protocol identity and payload shape constraints.
         */
        static void validate_header(const packet_header& header);

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
    bool packet_manager<Ts...>::send_run(
        std::uint64_t task_id,
        const args_tuple& args,
        std::uint16_t flags
    )
    {
        return send_packet(
            packet_kind::run,
            payload_kind::tuple,
            task_id,
            flags,
            to_bytes(args)
        );
    }

    template <typename... Ts>
    bool packet_manager<Ts...>::send_run_for(
        std::uint64_t task_id,
        const args_tuple& args,
        std::chrono::milliseconds timeout,
        std::uint16_t flags
    )
    {
        return send_packet_for(
            packet_kind::run,
            payload_kind::tuple,
            task_id,
            flags,
            to_bytes(args),
            timeout
        );
    }

    template <typename... Ts>
    bool packet_manager<Ts...>::send_ok(std::uint64_t task_id, std::uint16_t flags)
    {
        return send_packet(packet_kind::ok, payload_kind::none, task_id, flags, {});
    }

    template <typename... Ts>
    bool packet_manager<Ts...>::send_ok_for(
        std::uint64_t task_id,
        std::chrono::milliseconds timeout,
        std::uint16_t flags
    )
    {
        return send_packet_for(packet_kind::ok, payload_kind::none, task_id, flags, {}, timeout);
    }

    template <typename... Ts>
    bool packet_manager<Ts...>::send_stop(std::uint16_t flags)
    {
        return send_packet(packet_kind::stop, payload_kind::none, 0, flags, {});
    }

    template <typename... Ts>
    bool packet_manager<Ts...>::send_stop_for(
        std::chrono::milliseconds timeout,
        std::uint16_t flags
    )
    {
        return send_packet_for(packet_kind::stop, payload_kind::none, 0, flags, {}, timeout);
    }

    template <typename... Ts>
    bool packet_manager<Ts...>::send_exception(
        std::uint64_t task_id,
        std::string_view text,
        std::uint16_t flags
    )
    {
        return send_text(packet_kind::exception, task_id, text, flags);
    }

    template <typename... Ts>
    bool packet_manager<Ts...>::send_exception_for(
        std::uint64_t task_id,
        std::string_view text,
        std::chrono::milliseconds timeout,
        std::uint16_t flags
    )
    {
        return send_text_for(packet_kind::exception, task_id, text, timeout, flags);
    }

    template <typename... Ts>
    bool packet_manager<Ts...>::send_protocol_error(
        std::uint64_t task_id,
        std::string_view text,
        std::uint16_t flags
    )
    {
        return send_text(packet_kind::protocol_error, task_id, text, flags);
    }

    template <typename... Ts>
    bool packet_manager<Ts...>::send_protocol_error_for(
        std::uint64_t task_id,
        std::string_view text,
        std::chrono::milliseconds timeout,
        std::uint16_t flags
    )
    {
        return send_text_for(packet_kind::protocol_error, task_id, text, timeout, flags);
    }

    template <typename... Ts>
    bool packet_manager<Ts...>::send_text(
        packet_kind kind,
        std::uint64_t task_id,
        std::string_view text,
        std::uint16_t flags
    )
    {
        return send_packet(
            kind,
            payload_kind::text,
            task_id,
            flags,
            to_bytes(std::string{text})
        );
    }

    template <typename... Ts>
    bool packet_manager<Ts...>::send_text_for(
        packet_kind kind,
        std::uint64_t task_id,
        std::string_view text,
        std::chrono::milliseconds timeout,
        std::uint16_t flags
    )
    {
        return send_packet_for(
            kind,
            payload_kind::text,
            task_id,
            flags,
            to_bytes(std::string{text}),
            timeout
        );
    }

    template <typename... Ts>
    packet<Ts...> packet_manager<Ts...>::receive()
    {
        packet_header header {};

        if (!read_all(m_read_fd, &header, sizeof(header)))
            throw protocol_error("failed to read packet header");

        validate_header(header);

        std::vector<std::uint8_t> payload_bytes(header.payload_size);

        if (!payload_bytes.empty())
        {
            if (!read_all(m_read_fd, payload_bytes.data(), payload_bytes.size()))
                throw protocol_error("failed to read packet payload");
        }

        packet_type packet {};
        packet.header = header;

        switch (static_cast<payload_kind>(header.payload_kind))
        {
            case payload_kind::none:
                if (header.payload_size != 0)
                    throw protocol_error("none packet payload must be empty");
                    
                packet.payload = std::monostate {};
                break;

            case payload_kind::tuple:
                packet.payload = from_bytes<args_tuple>(payload_bytes);
                break;

            case payload_kind::text:
                packet.payload = from_bytes<std::string>(payload_bytes);
                break;

            default:
                throw protocol_error("unknown packet payload kind");
        }

        return packet;
    }

    template <typename... Ts>
    packet<Ts...> packet_manager<Ts...>::receive_for(std::chrono::milliseconds timeout)
    {
        const auto deadline = std::chrono::steady_clock::now() + timeout;

        auto remaining_timeout = [&deadline]() -> std::chrono::milliseconds
        {
            const auto now = std::chrono::steady_clock::now();

            if (now >= deadline)
                throw protocol_error("packet receive timed out");

            return std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now);
        };

        packet_header header {};

        if (!read_all_for(m_read_fd, &header, sizeof(header), remaining_timeout()))
            throw protocol_error("failed to read packet header before timeout");

        validate_header(header);

        std::vector<std::uint8_t> payload_bytes(header.payload_size);

        if (!payload_bytes.empty())
        {
            if (!read_all_for(m_read_fd, payload_bytes.data(), payload_bytes.size(), remaining_timeout()))
                throw protocol_error("failed to read packet payload before timeout");
        }

        packet_type packet {};
        packet.header = header;

        switch (static_cast<payload_kind>(header.payload_kind))
        {
            case payload_kind::none:
                if (header.payload_size != 0)
                    throw protocol_error("none packet payload must be empty");

                packet.payload = std::monostate {};
                break;

            case payload_kind::tuple:
                packet.payload = from_bytes<args_tuple>(payload_bytes);
                break;

            case payload_kind::text:
                packet.payload = from_bytes<std::string>(payload_bytes);
                break;

            default:
                throw protocol_error("unknown packet payload kind");
        }

        return packet;
    }

    template <typename... Ts>
    bool packet_manager<Ts...>::send_packet(
        packet_kind kind,
        payload_kind payload_type,
        std::uint64_t task_id,
        std::uint16_t flags,
        const std::vector<std::uint8_t>& payload
    )
    {
        const auto header = make_header(kind, payload_type, task_id, flags, payload.size());

        if (!write_all(m_write_fd, &header, sizeof(header)))
            return false;

        if (!payload.empty())
        {
            if (!write_all(m_write_fd, payload.data(), payload.size()))
                return false;
        }

        return true;
    }

    template <typename... Ts>
    bool packet_manager<Ts...>::send_packet_for(
        packet_kind kind,
        payload_kind payload_type,
        std::uint64_t task_id,
        std::uint16_t flags,
        const std::vector<std::uint8_t>& payload,
        std::chrono::milliseconds timeout
    )
    {
        const auto deadline = std::chrono::steady_clock::now() + timeout;

        auto remaining_timeout = [&deadline]() -> std::chrono::milliseconds
        {
            const auto now = std::chrono::steady_clock::now();

            if (now >= deadline)
                return std::chrono::milliseconds { 0 };

            return std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now);
        };

        const auto header = make_header(kind, payload_type, task_id, flags, payload.size());

        if (!write_all_for(m_write_fd, &header, sizeof(header), remaining_timeout()))
            return false;

        if (!payload.empty())
        {
            if (!write_all_for(m_write_fd, payload.data(), payload.size(), remaining_timeout()))
                return false;
        }

        return true;
    }

    template <typename... Ts>
    packet_header packet_manager<Ts...>::make_header(
        packet_kind kind,
        payload_kind payload_type,
        std::uint64_t task_id,
        std::uint16_t flags,
        std::size_t payload_size
    )
    {
        if (payload_size > std::numeric_limits<std::uint32_t>::max())
            throw protocol_error("packet payload is too large");

        packet_header header {};

        header.kind = static_cast<std::uint8_t>(kind);
        header.payload_kind = static_cast<std::uint8_t>(payload_type);
        header.flags = flags;
        header.task_id = task_id;
        header.payload_size = static_cast<std::uint32_t>(payload_size);

        return header;
    }

    template <typename... Ts>
    void packet_manager<Ts...>::validate_header(const packet_header& header)
    {
        if (header.magic != packet_magic)
            throw protocol_error("bad packet magic");

        if (header.version != packet_version)
            throw protocol_error("unsupported packet version");

        if (header.header_size != sizeof(packet_header))
            throw protocol_error("unsupported packet header size");

        const auto payload_type = static_cast<payload_kind>(header.payload_kind);

        if (payload_type == payload_kind::none && header.payload_size != 0)
            throw protocol_error("none packet payload must be empty");

        if (
            payload_type != payload_kind::none &&
            payload_type != payload_kind::tuple &&
            payload_type != payload_kind::text
        )
        {
            throw protocol_error("unknown packet payload kind");
        }
    }
}

#endif // PROTOCOL_PACKET_MANAGER_HPP
