#ifndef SERIALIZATION_SERIALIZERS_TUPLE_HPP
#define SERIALIZATION_SERIALIZERS_TUPLE_HPP

#include <cstddef>
#include <cstdint>
#include <tuple>
#include <type_traits>
#include <utility>
#include <vector>

#include "serialization/serialization.hpp"

namespace hotfuzz
{
    /**
     * @brief Opaque serializer for std::tuple.
     *
     * Stores tuple elements in declaration order using the hotfuzz internal value codec.
     */
    template <typename... Ts>
    requires (
        ... &&
        (!std::is_reference_v<Ts> && serializable_v<std::remove_cv_t<Ts>>)
    )
    struct serializer<std::tuple<Ts...>>
    {
        static std::vector<std::uint8_t> to_bytes(const std::tuple<Ts...>& value)
        {
            std::vector<std::uint8_t> bytes;

            std::apply(
                [&bytes](const auto&... elements)
                {
                    (detail::write_value(bytes, elements), ...);
                },
                value
            );

            return bytes;
        }

        static std::tuple<Ts...> from_bytes(const std::vector<std::uint8_t>& bytes)
        {
            byte_reader reader(bytes);

            auto result = []<std::size_t... I>(
                byte_reader& current_reader,
                std::index_sequence<I...>
            ) -> std::tuple<Ts...>
            {
                return std::tuple<Ts...>{
                    detail::read_value<std::remove_cv_t<std::tuple_element_t<I, std::tuple<Ts...>>>>(current_reader)...
                };
            }(reader, std::index_sequence_for<Ts...>{});

            if (!reader.empty())
                throw std::runtime_error("trailing bytes after std::tuple blob");

            return result;
        }
    };
}

#endif // SERIALIZATION_SERIALIZERS_TUPLE_HPP
