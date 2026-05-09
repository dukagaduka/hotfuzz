#ifndef SERIALIZATION_SERIALIZERS_MAP_HPP
#define SERIALIZATION_SERIALIZERS_MAP_HPP

#include <cstddef>
#include <cstdint>
#include <map>
#include <type_traits>
#include <utility>
#include <vector>

#include "serialization/api.hpp"

namespace hotfuzz
{
    /**
     * @brief Opaque serializer for std::map.
     *
     * Stores size followed by ordered key/value pairs.
     */
    template <typename Key, typename T, typename Compare, typename Allocator>
    requires (
        std::default_initializable<std::map<Key, T, Compare, Allocator>> &&
        serializable_v<std::remove_cv_t<Key>> &&
        serializable_v<std::remove_cv_t<T>>
    )
    struct serializer<std::map<Key, T, Compare, Allocator>>
    {
        using map_type = std::map<Key, T, Compare, Allocator>;

        static std::vector<std::uint8_t> to_bytes(const map_type& value)
        {
            std::vector<std::uint8_t> bytes;
            utils::write_value(bytes, value.size());

            for (const auto& [key, mapped] : value)
            {
                utils::write_value(bytes, key);
                utils::write_value(bytes, mapped);
            }

            return bytes;
        }

        static map_type from_bytes(const std::vector<std::uint8_t>& bytes)
        {
            using key_type = std::remove_cv_t<Key>;
            using mapped_type = std::remove_cv_t<T>;

            utils::byte_reader reader(bytes);
            const std::size_t size = utils::read_value<std::size_t>(reader);

            map_type result;

            for (std::size_t i = 0; i < size; ++i)
            {
                auto key = utils::read_value<key_type>(reader);
                auto mapped = utils::read_value<mapped_type>(reader);
                result.emplace(std::move(key), std::move(mapped));
            }

            if (!reader.empty())
                throw std::runtime_error("trailing bytes after std::map blob");

            return result;
        }
    };
}

#endif // SERIALIZATION_SERIALIZERS_MAP_HPP
