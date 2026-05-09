#ifndef SERIALIZATION_API_HPP
#define SERIALIZATION_API_HPP

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <memory>
#include <span>
#include <stdexcept>
#include <string>
#include <type_traits>
#include <vector>

#include "serialization/byte_utils.hpp"
#include "serialization/rw_utils.hpp"
#include "serialization/specs.h"

namespace hotfuzz
{

    /**
     * @brief Serializes one supported value into a self-contained byte buffer.
     */
    template <serializable_v T>
    [[nodiscard]] std::vector<std::uint8_t> to_bytes(const T& value)
    {
        std::vector<std::uint8_t> bytes;
        utils::write_value(bytes, value);
        return bytes;
    }


    /**
     * @brief Deserializes one value from a bounded byte span.
     *
     * @throws std::runtime_error if the buffer is malformed or has trailing bytes.
     */
    template <serializable_v T>
    [[nodiscard]] std::remove_cvref_t<T> from_bytes(std::span<const std::uint8_t> bytes)
    {
        utils::byte_reader reader(bytes);
        auto value = utils::read_value<T>(reader);

        if (!reader.empty())
            throw std::runtime_error("trailing bytes after serialized object");

        return value;
    }


    /**
     * @brief Deserializes one value from a byte vector.
     *
     * @throws std::runtime_error if the buffer is malformed or has trailing bytes.
     */
    template <serializable_v T>
    [[nodiscard]] std::remove_cvref_t<T> from_bytes(const std::vector<std::uint8_t>& bytes)
    {
        return from_bytes<T>(std::span<const std::uint8_t>{bytes.data(), bytes.size()});
    }
    
}

#include "serialization/serializers/pair.hpp"
#include "serialization/serializers/tuple.hpp"
#include "serialization/serializers/optional.hpp"
#include "serialization/serializers/variant.hpp"
#include "serialization/serializers/map.hpp"
#include "serialization/serializers/set.hpp"

#endif // SERIALIZATION_API_HPP
