#ifndef SERIALIZATION_SERIALIZERS_OPTIONAL_HPP
#define SERIALIZATION_SERIALIZERS_OPTIONAL_HPP

#include <cstdint>
#include <optional>
#include <type_traits>
#include <utility>
#include <vector>

#include "serialization/api.hpp"

namespace hotfuzz
{
    /**
     * @brief Opaque serializer for std::optional.
     *
     * Stores an engagement flag followed by the value when present.
     */
    template <typename T>
    requires (!std::is_reference_v<T> && serializable_v<std::remove_cv_t<T>>)
    struct serializer<std::optional<T>>
    {
        static std::vector<std::uint8_t> to_bytes(const std::optional<T>& value)
        {
            std::vector<std::uint8_t> bytes;
            utils::write_value(bytes, value.has_value());

            if (value.has_value())
                utils::write_value(bytes, *value);

            return bytes;
        }

        static std::optional<T> from_bytes(const std::vector<std::uint8_t>& bytes)
        {
            using value_type = std::remove_cv_t<T>;

            utils::byte_reader reader(bytes);
            const bool has_value = utils::read_value<bool>(reader);

            if (!has_value)
            {
                if (!reader.empty())
                    throw std::runtime_error("trailing bytes after empty std::optional blob");

                return std::optional<T>{};
            }

            auto value = utils::read_value<value_type>(reader);

            if (!reader.empty())
                throw std::runtime_error("trailing bytes after std::optional blob");

            return std::optional<T>{std::in_place, std::move(value)};
        }
    };
}

#endif // SERIALIZATION_SERIALIZERS_OPTIONAL_HPP
