#ifndef SERIALIZATION_BYTE_UTILS_HPP
#define SERIALIZATION_BYTE_UTILS_HPP

#include <cstddef>
#include <cstdint>
#include <limits>
#include <span>
#include <stdexcept>
#include <vector>

#include "serialization/specs.h"

namespace hotfuzz
{
    namespace utils
    {
        /**
         * @brief Bounds-checked reader over a contiguous byte buffer.
         */
        class byte_reader
        {
        public:
            /**
             * @brief Creates a reader over byte storage owned by the caller.
             */
            explicit byte_reader(std::span<const std::uint8_t> bytes) noexcept
                : m_ptr(bytes.data()), m_remaining(bytes.size())
            {}

            explicit byte_reader(const std::vector<std::uint8_t>& bytes) noexcept
                : byte_reader(std::span<const std::uint8_t>{bytes.data(), bytes.size()})
            {}

            /**
             * @brief Returns the next count bytes and advances the cursor.
             */
            [[nodiscard]] const std::uint8_t* read_bytes(std::size_t count)
            {
                if (count > m_remaining)
                    throw std::runtime_error("not enough bytes in serialized buffer");

                const std::uint8_t* result = m_ptr;

                if (count != 0)
                    m_ptr += count;

                m_remaining -= count;

                return result;
            }

            /**
             * @brief Returns the number of unread bytes.
             */
            [[nodiscard]] std::size_t remaining() const noexcept
            {
                return m_remaining;
            }

            /**
             * @brief Returns true when the whole buffer has been consumed.
             */
            [[nodiscard]] bool empty() const noexcept
            {
                return m_remaining == 0;
            }

        private:
            const std::uint8_t* m_ptr {};
            std::size_t m_remaining {};
            
        };

        /**
         * @brief Appends raw bytes to a byte vector.
         */
        inline void append_bytes(
            std::vector<std::uint8_t>& out,
            const void* data,
            std::size_t count
        )
        {
            if (count == 0)
                return;

            const auto* ptr = static_cast<const std::uint8_t*>(data);
            out.insert(out.end(), ptr, ptr + count);
        }

        /**
         * @brief Calculates count * sizeof(T), throwing on size_t overflow.
         */
        template <typename T>
        [[nodiscard]] constexpr std::size_t checked_byte_size(std::size_t count)
        {
            if (count > std::numeric_limits<std::size_t>::max() / sizeof(T))
                throw std::runtime_error("serialized byte size overflow");

            return count * sizeof(T);
        }
    }
}

#endif // SERIALIZATION_BYTE_UTILS_HPP
