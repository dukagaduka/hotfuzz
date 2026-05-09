#ifndef SERIALIZATION_SPECS_H
#define SERIALIZATION_SPECS_H

#include <array>
#include <concepts>
#include <cstddef>
#include <cstdint>
#include <string>
#include <type_traits>
#include <vector>

namespace hotfuzz
{
    /**
     * @brief User-specializable opaque byte codec.
     *
     * A specialization makes T a custom serializable type. Hotfuzz only stores
     * the returned byte blob and delegates reconstruction back to the same
     * specialization.
     */
    template <typename T>
    struct serializer;

    template <typename>
    inline constexpr bool always_false_v = false;



    /**
     * @brief std::array detection and compile-time metadata.
     */
    template <typename T>
    struct is_std_array : std::false_type {};

    template <typename T, std::size_t N>
    struct is_std_array<std::array<T, N>> : std::true_type {};

    template <typename T>
    inline constexpr bool is_std_array_v = is_std_array<std::remove_cvref_t<T>>::value;


    template <typename T>
    struct std_array_traits;

    template <typename T, std::size_t N>
    struct std_array_traits<std::array<T, N>>
    {
        using value_type = T;
        static constexpr std::size_t size = N;
    };

    template <typename T>
    using std_array_value_t = typename std_array_traits<std::remove_cvref_t<T>>::value_type;

    template <typename T>
    inline constexpr std::size_t std_array_size_v = std_array_traits<std::remove_cvref_t<T>>::size;



    /**
     * @brief std::vector detection and element metadata.
     */
    template <typename T>
    struct is_std_vector : std::false_type {};

    template <typename T, typename Allocator>
    struct is_std_vector<std::vector<T, Allocator>> : std::true_type {};

    template <typename T>
    inline constexpr bool is_std_vector_v = is_std_vector<std::remove_cvref_t<T>>::value;


    template <typename T>
    struct std_vector_traits;

    template <typename T, typename Allocator>
    struct std_vector_traits<std::vector<T, Allocator>>
    {
        using value_type = T;
    };

    template <typename T>
    using std_vector_value_t = typename std_vector_traits<std::remove_cvref_t<T>>::value_type;

    template <typename T>
    struct is_std_vector_bool : std::false_type {};

    template <typename Allocator>
    struct is_std_vector_bool<std::vector<bool, Allocator>> : std::true_type {};

    template <typename T>
    inline constexpr bool is_std_vector_bool_v = is_std_vector_bool<std::remove_cvref_t<T>>::value;



    /**
     * @brief std::basic_string detection and character metadata.
     */
    template <typename T>
    struct is_std_basic_string : std::false_type {};

    template <typename CharT, typename Traits, typename Allocator>
    struct is_std_basic_string<std::basic_string<CharT, Traits, Allocator>> : std::true_type {};

    template <typename T>
    inline constexpr bool is_std_basic_string_v = is_std_basic_string<std::remove_cvref_t<T>>::value;


    template <typename T>
    struct std_basic_string_traits;

    template <typename CharT, typename Traits, typename Allocator>
    struct std_basic_string_traits<std::basic_string<CharT, Traits, Allocator>>
    {
        using char_type = CharT;
    };

    template <typename T>
    using std_basic_string_char_t = typename std_basic_string_traits<std::remove_cvref_t<T>>::char_type;



    /**
     * @brief Public serialization baskets supported by the core serializer.
     *
     * Dispatch order is enforced in serialization.hpp: custom serializer first,
     * then dedicated std::array/std::vector/std::basic_string paths, then raw
     * trivially-copyable values.
     */
    template <typename T>
    concept custom_serializable_v =
        requires (const std::remove_cvref_t<T>& value, const std::vector<std::uint8_t>& bytes)
        {
            { serializer<std::remove_cvref_t<T>>::to_bytes(value) } -> std::same_as<std::vector<std::uint8_t>>;
            { serializer<std::remove_cvref_t<T>>::from_bytes(bytes) } -> std::same_as<std::remove_cvref_t<T>>;
        };


    template <typename T>
    concept raw_serializable_v =
        !custom_serializable_v<T> &&
        !is_std_array_v<T> &&
        !is_std_vector_v<T> &&
        !is_std_basic_string_v<T> &&
        !std::is_void_v<std::remove_cvref_t<T>> &&
        !std::is_function_v<std::remove_cvref_t<T>> &&
        !std::is_pointer_v<std::remove_cvref_t<T>> &&
        !std::is_member_pointer_v<std::remove_cvref_t<T>> &&
        !std::is_array_v<std::remove_cvref_t<T>> &&
        std::default_initializable<std::remove_cvref_t<T>> &&
        std::is_trivially_copyable_v<std::remove_cvref_t<T>>;


    /**
     * @brief Recursive support check used by serializable_v.
     *
     * The core only recurses through array/vector/string. Other standard
     * compound types are supported by serializer<T> specializations in
     * serialization/serializers.
     */
    template <typename T>
    struct is_serializable_type;

    template <typename T>
    struct is_serializable_type_impl
        : std::bool_constant<custom_serializable_v<T> || raw_serializable_v<T>> {};

    template <typename T>
    struct is_serializable_type : is_serializable_type_impl<std::remove_cvref_t<T>> {};

    
    template <typename T, std::size_t N>
    struct is_serializable_type_impl<std::array<T, N>>
        : std::bool_constant<
            custom_serializable_v<std::array<T, N>> ||
            is_serializable_type<std::remove_cv_t<T>>::value
        > {};

    template <typename T, typename Allocator>
    struct is_serializable_type_impl<std::vector<T, Allocator>>
        : std::bool_constant<
            custom_serializable_v<std::vector<T, Allocator>> ||
            is_serializable_type<T>::value
        > {};

    template <typename CharT, typename Traits, typename Allocator>
    struct is_serializable_type_impl<std::basic_string<CharT, Traits, Allocator>>
        : std::bool_constant<
            custom_serializable_v<std::basic_string<CharT, Traits, Allocator>> ||
            (
                std::default_initializable<CharT> &&
                std::is_trivially_copyable_v<CharT>
            )
        > {};


    template <typename T>
    concept serializable_v = is_serializable_type<T>::value;

    template <typename T>
    concept std_array_serializable_v =
        !custom_serializable_v<T> &&
        is_std_array_v<T> &&
        serializable_v<T>;

    template <typename T>
    concept std_vector_serializable_v =
        !custom_serializable_v<T> &&
        is_std_vector_v<T> &&
        serializable_v<T>;

    template <typename T>
    concept std_basic_string_serializable_v =
        !custom_serializable_v<T> &&
        is_std_basic_string_v<T> &&
        serializable_v<T>;
}

#endif // SERIALIZATION_SPECS_H
