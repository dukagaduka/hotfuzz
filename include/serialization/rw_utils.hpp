#ifndef SERIALIZATION_RW_UTILS_HPP
#define SERIALIZATION_RW_UTILS_HPP

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <vector>
#include <type_traits>

#include "serialization/byte_utils.hpp"

namespace hotfuzz
{
    namespace utils
    {
        /**
         * @brief Internal value writer used by the core and bundled serializers.
         */
        template <serializable_v T>
        inline void write_value(std::vector<std::uint8_t>& out, const T& value);

        /**
         * @brief Internal value reader used by the core and bundled serializers.
         */
        template <serializable_v T>
        [[nodiscard]] std::remove_cvref_t<T> read_value(byte_reader& reader);

        

        /**
         * @brief Dedicated std::array path with serialized size validation.
         */
        template <std_array_serializable_v T>
        inline void write_array(std::vector<std::uint8_t>& out, const T& value)
        {
            using value_type = std::remove_cvref_t<T>;
            using element_type = std::remove_cv_t<std_array_value_t<value_type>>;

            constexpr std::size_t size = std_array_size_v<value_type>;

            write_value(out, size);

            if constexpr (raw_serializable_v<element_type>)
            {
                const std::size_t byte_size = checked_byte_size<element_type>(size);
                append_bytes(out, value.data(), byte_size);
            }
            else
            {
                for (const auto& element : value)
                    write_value(out, element);
            }
        }

        /**
         * @brief Reads a std::array and checks the encoded size against N.
         */
        template <std_array_serializable_v T>
        [[nodiscard]] std::remove_cvref_t<T> read_array(byte_reader& reader)
        {
            using value_type = std::remove_cvref_t<T>;
            using stored_element_type = std_array_value_t<value_type>;
            using read_element_type = std::remove_cv_t<stored_element_type>;

            constexpr std::size_t expected_size = std_array_size_v<value_type>;

            const std::size_t actual_size = read_value<std::size_t>(reader);

            if (actual_size != expected_size)
                throw std::runtime_error("std::array size mismatch in serialized buffer");

            if constexpr (raw_serializable_v<read_element_type> && !std::is_const_v<stored_element_type>)
            {
                value_type array {};
                const std::size_t byte_size = checked_byte_size<read_element_type>(expected_size);

                if (byte_size != 0)
                    std::memcpy(array.data(), reader.read_bytes(byte_size), byte_size);

                return array;
            }
            else
            {
                return []<std::size_t... I>(byte_reader& current_reader, std::index_sequence<I...>) -> value_type
                {
                    return value_type{((void)I, read_value<read_element_type>(current_reader))...};
                }(reader, std::make_index_sequence<expected_size>{});
            }
        }



        /**
         * @brief Dedicated std::vector path.
         */
        template <std_vector_serializable_v T>
        inline void write_vector(std::vector<std::uint8_t>& out, const T& value)
        {
            using value_type = std::remove_cvref_t<T>;
            using element_type = std_vector_value_t<value_type>;
            using write_element_type = std::remove_cv_t<element_type>;

            const std::size_t size = value.size();
            write_value(out, size);

            if constexpr (raw_serializable_v<write_element_type> && !is_std_vector_bool_v<value_type>)
            {
                const std::size_t byte_size = checked_byte_size<write_element_type>(size);
                append_bytes(out, value.data(), byte_size);
            }
            else
            {
                for (const auto& element : value)
                    write_value(out, static_cast<write_element_type>(element));
            }
        }

        /**
         * @brief Reads a std::vector using raw block copy when its elements allow it.
         */
        template <std_vector_serializable_v T>
        [[nodiscard]] std::remove_cvref_t<T> read_vector(byte_reader& reader)
        {
            using value_type = std::remove_cvref_t<T>;
            using element_type = std_vector_value_t<value_type>;
            using read_element_type = std::remove_cv_t<element_type>;

            const std::size_t size = read_value<std::size_t>(reader);
            value_type vector;

            if constexpr (raw_serializable_v<read_element_type> && !is_std_vector_bool_v<value_type>)
            {
                vector.resize(size);

                const std::size_t byte_size = checked_byte_size<read_element_type>(size);

                if (byte_size != 0)
                    std::memcpy(vector.data(), reader.read_bytes(byte_size), byte_size);
            }
            else
            {
                vector.reserve(size);

                for (std::size_t i = 0; i < size; ++i)
                    vector.push_back(read_value<read_element_type>(reader));
            }

            return vector;
        }



        /**
         * @brief Dedicated std::basic_string path using raw character bytes.
         */
        template <std_basic_string_serializable_v T>
        inline void write_string(std::vector<std::uint8_t>& out, const T& value)
        {
            using value_type = std::remove_cvref_t<T>;
            using char_type = std_basic_string_char_t<value_type>;

            const std::size_t size = value.size();
            write_value(out, size);

            const std::size_t byte_size = checked_byte_size<char_type>(size);
            append_bytes(out, value.data(), byte_size);
        }

        /**
         * @brief Reads a std::basic_string from size-prefixed character bytes.
         */
        template <std_basic_string_serializable_v T>
        [[nodiscard]] std::remove_cvref_t<T> read_string(byte_reader& reader)
        {
            using value_type = std::remove_cvref_t<T>;
            using char_type = std_basic_string_char_t<value_type>;

            const std::size_t size = read_value<std::size_t>(reader);
            value_type string;
            string.resize(size);

            const std::size_t byte_size = checked_byte_size<char_type>(size);

            if (byte_size != 0)
                std::memcpy(string.data(), reader.read_bytes(byte_size), byte_size);

            return string;
        }


        
        /**
         * @brief Dispatches a supported value into the first matching serialization basket.
         */
        template <serializable_v T>
        inline void write_value(std::vector<std::uint8_t>& out, const T& value)
        {
            using value_type = std::remove_cvref_t<T>;

            // Keep custom first: user serializer<T> must override every automatic path.
            if constexpr (custom_serializable_v<value_type>)
            {
                auto bytes = serializer<value_type>::to_bytes(value);
                write_value(out, bytes.size());
                append_bytes(out, bytes.data(), bytes.size());
            }
            else if constexpr (std_array_serializable_v<value_type>)
            {
                write_array(out, value);
            }
            else if constexpr (std_vector_serializable_v<value_type>)
            {
                write_vector(out, value);
            }
            else if constexpr (std_basic_string_serializable_v<value_type>)
            {
                write_string(out, value);
            }
            else if constexpr (raw_serializable_v<value_type>)
            {
                append_bytes(out, std::addressof(value), sizeof(value_type));
            }
            else
            {
                static_assert(always_false_v<value_type>, "type is not serializable");
            }
        }

        /**
         * @brief Dispatches bytes from the first matching serialization basket.
         */
        template <serializable_v T>
        [[nodiscard]] std::remove_cvref_t<T> read_value(byte_reader& reader)
        {
            using value_type = std::remove_cvref_t<T>;

            // Keep this order in sync with write_value().
            if constexpr (custom_serializable_v<value_type>)
            {
                const std::size_t size = read_value<std::size_t>(reader);
                std::vector<std::uint8_t> bytes(size);

                if (size != 0)
                    std::memcpy(bytes.data(), reader.read_bytes(size), size);

                return serializer<value_type>::from_bytes(bytes);
            }
            else if constexpr (std_array_serializable_v<value_type>)
            {
                return read_array<value_type>(reader);
            }
            else if constexpr (std_vector_serializable_v<value_type>)
            {
                return read_vector<value_type>(reader);
            }
            else if constexpr (std_basic_string_serializable_v<value_type>)
            {
                return read_string<value_type>(reader);
            }
            else if constexpr (raw_serializable_v<value_type>)
            {
                value_type value {};
                const auto* bytes = reader.read_bytes(sizeof(value_type));
                std::memcpy(std::addressof(value), bytes, sizeof(value_type));
                
                return value;
            }
            else
            {
                static_assert(always_false_v<value_type>, "type is not serializable");
            }
        }
    }
}

#endif // SERIALIZATION_RW_UTILS_HPP