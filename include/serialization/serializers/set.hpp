#ifndef SERIALIZATION_SERIALIZERS_SET_HPP
#define SERIALIZATION_SERIALIZERS_SET_HPP

#include <cstddef>
#include <cstdint>
#include <set>
#include <type_traits>
#include <utility>
#include <vector>

#include "serialization/api.hpp"

namespace hotfuzz
{
    /**
     * @brief Opaque serializer for std::set.
     *
     * Stores size followed by ordered keys.
     */
    template <typename Key, typename Compare, typename Allocator>
    requires (
        std::default_initializable<std::set<Key, Compare, Allocator>> &&
        serializable_v<std::remove_cv_t<Key>>
    )
    struct serializer<std::set<Key, Compare, Allocator>>
    {
        using set_type = std::set<Key, Compare, Allocator>;

        static std::vector<std::uint8_t> to_bytes(const set_type& value)
        {
            std::vector<std::uint8_t> bytes;
            utils::write_value(bytes, value.size());

            for (const auto& key : value)
                utils::write_value(bytes, key);

            return bytes;
        }

        static set_type from_bytes(const std::vector<std::uint8_t>& bytes)
        {
            using key_type = std::remove_cv_t<Key>;

            utils::byte_reader reader(bytes);
            const std::size_t size = utils::read_value<std::size_t>(reader);

            set_type result;

            for (std::size_t i = 0; i < size; ++i)
                result.emplace(utils::read_value<key_type>(reader));

            if (!reader.empty())
                throw std::runtime_error("trailing bytes after std::set blob");

            return result;
        }
    };
}

#endif // SERIALIZATION_SERIALIZERS_SET_HPP
