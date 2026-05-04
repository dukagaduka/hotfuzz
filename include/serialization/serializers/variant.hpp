#ifndef SERIALIZATION_SERIALIZERS_VARIANT_HPP
#define SERIALIZATION_SERIALIZERS_VARIANT_HPP

#include <cstddef>
#include <cstdint>
#include <stdexcept>
#include <type_traits>
#include <utility>
#include <variant>
#include <vector>

#include "serialization/serialization.hpp"

namespace hotfuzz
{
    /**
     * @brief Opaque serializer for std::variant.
     *
     * Stores the active alternative index followed by that alternative value.
     */
    template <typename... Ts>
    requires (
        ... &&
        (!std::is_reference_v<Ts> && serializable_v<std::remove_cv_t<Ts>>)
    )
    struct serializer<std::variant<Ts...>>
    {
        static std::vector<std::uint8_t> to_bytes(const std::variant<Ts...>& value)
        {
            if (value.valueless_by_exception())
                throw std::runtime_error("cannot serialize valueless std::variant");

            std::vector<std::uint8_t> bytes;
            detail::write_value(bytes, value.index());

            std::visit(
                [&bytes](const auto& active_value)
                {
                    detail::write_value(bytes, active_value);
                },
                value
            );

            return bytes;
        }

        static std::variant<Ts...> from_bytes(const std::vector<std::uint8_t>& bytes)
        {
            using variant_type = std::variant<Ts...>;

            byte_reader reader(bytes);
            const std::size_t index = detail::read_value<std::size_t>(reader);

            auto result = []<std::size_t... I>(
                byte_reader& current_reader,
                std::size_t active_index,
                std::index_sequence<I...>
            ) -> variant_type
            {
                using maker_type = variant_type (*)(byte_reader&);

                // Runtime variant index is resolved through one reader function per alternative.
                static constexpr maker_type makers[] = {
                    +[](byte_reader& reader_for_value) -> variant_type
                    {
                        using alternative_type = std::remove_cv_t<std::variant_alternative_t<I, variant_type>>;
                        return variant_type{
                            std::in_place_index<I>,
                            detail::read_value<alternative_type>(reader_for_value)
                        };
                    }...
                };

                if (active_index >= sizeof...(I))
                    throw std::runtime_error("std::variant index out of range in serialized blob");

                return makers[active_index](current_reader);
            }(reader, index, std::index_sequence_for<Ts...>{});

            if (!reader.empty())
                throw std::runtime_error("trailing bytes after std::variant blob");

            return result;
        }
    };
}

#endif // SERIALIZATION_SERIALIZERS_VARIANT_HPP
