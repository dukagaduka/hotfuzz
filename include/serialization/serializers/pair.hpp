#ifndef SERIALIZATION_SERIALIZERS_PAIR_HPP
#define SERIALIZATION_SERIALIZERS_PAIR_HPP

#include <cstdint>
#include <type_traits>
#include <utility>
#include <vector>

#include "serialization/serialization.hpp"

namespace hotfuzz
{
    /**
     * @brief Opaque serializer for std::pair.
     *
     * Stores first and second consecutively using the hotfuzz internal value codec.
     */
    template <typename A, typename B>
    requires (
        !std::is_reference_v<A> &&
        !std::is_reference_v<B> &&
        serializable_v<std::remove_cv_t<A>> &&
        serializable_v<std::remove_cv_t<B>>
    )
    struct serializer<std::pair<A, B>>
    {
        static std::vector<std::uint8_t> to_bytes(const std::pair<A, B>& value)
        {
            std::vector<std::uint8_t> bytes;
            detail::write_value(bytes, value.first);
            detail::write_value(bytes, value.second);
            return bytes;
        }

        static std::pair<A, B> from_bytes(const std::vector<std::uint8_t>& bytes)
        {
            using first_type = std::remove_cv_t<A>;
            using second_type = std::remove_cv_t<B>;

            byte_reader reader(bytes);
            auto first = detail::read_value<first_type>(reader);
            auto second = detail::read_value<second_type>(reader);

            if (!reader.empty())
                throw std::runtime_error("trailing bytes after std::pair blob");

            return std::pair<A, B>{std::move(first), std::move(second)};
        }
    };
}

#endif // SERIALIZATION_SERIALIZERS_PAIR_HPP
