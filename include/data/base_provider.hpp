#ifndef BASE_PROVIDER_HPP
#define BASE_PROVIDER_HPP

#include <cstdint>
#include <iostream>
#include <stdexcept>
#include <string>

namespace hotfuzz
{
    class exhaustion_signal : public std::exception
    {
    public:
        explicit exhaustion_signal(const std::string& msg) : message(msg) {}

        const char* what() const noexcept override
        {
            return message.c_str();
        }

    private:
        std::string message;
    };

    template <typename T>
    class base_provider
    {
    public:
        base_provider(std::size_t max_idx) : m_idx(0), m_max_idx(max_idx) {}
        virtual ~base_provider() = default; 

        std::size_t idx() const { return m_idx; }
        std::size_t max() const { return m_max_idx; }

        T iter()
        {
            if (m_idx >= m_max_idx)
                throw exhaustion_signal("Provider is exhausted");

            T val = this->next(); 
            ++m_idx; 

            return val;
        }

        virtual void reset()
        {
            m_idx = 0;
        }

    protected:
        virtual T next() = 0;
        std::size_t m_idx;
        std::size_t m_max_idx;

    };
}

#endif // BASE_PROVIDER_HPP
