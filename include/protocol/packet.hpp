#ifndef PROTOCOL_PACKET_HPP
#define PROTOCOL_PACKET_HPP

#include <variant>
#include <stdexcept>
#include <string>
#include <tuple>

#include "serialization/api.hpp"
#include "protocol/io_utils.hpp"
#include "protocol/specs.h"

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

        [[nodiscard]] packet_kind kind() const noexcept
        {
            return static_cast<packet_kind>(header.kind);
        }

        [[nodiscard]] payload_kind payload_type() const noexcept
        {
            return static_cast<payload_kind>(header.payload_kind);
        }

        [[nodiscard]] std::uint64_t task_id() const noexcept
        {
            return header.task_id;
        }

        [[nodiscard]] std::uint16_t flags() const noexcept
        {
            return header.flags;
        }

        [[nodiscard]] const args_tuple& as_tuple() const
        {
            if (!std::holds_alternative<args_tuple>(payload))
                throw protocol_error("packet payload is not a tuple");

            return std::get<args_tuple>(payload);
        }

        [[nodiscard]] const std::string& as_text() const
        {
            if (!std::holds_alternative<std::string>(payload))
                throw protocol_error("packet payload is not text");

            return std::get<std::string>(payload);
        }
    };

}

#endif // PROTOCOL_PACKET_HPP
