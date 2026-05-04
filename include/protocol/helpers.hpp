#ifndef PROTOCOL_HELPERS_HPP
#define PROTOCOL_HELPERS_HPP

#include <cerrno>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <poll.h>
#include <unistd.h>

namespace hotfuzz
{
    /**
     * @brief Writes exactly size bytes to fd unless an unrecoverable IO error occurs.
     *
     * Retries interrupted system calls and returns false on EOF-like writes or
     * non-EINTR errors.
     */
    inline bool write_all(int fd, const void* data, std::size_t size)
    {
        const auto* ptr = static_cast<const std::uint8_t*>(data);
        std::size_t written = 0;

        while (written < size)
        {
            ssize_t rc = ::write(fd, ptr + written, size - written);

            if (rc < 0)
            {
                if (errno == EINTR)
                    continue;

                return false;
            }

            if (rc == 0)
                return false;

            written += static_cast<std::size_t>(rc);
        }

        return true;
    }

    /**
     * @brief Reads exactly size bytes from fd unless an unrecoverable IO error occurs.
     *
     * Retries interrupted system calls and returns false on EOF or non-EINTR errors.
     */
    inline bool read_all(int fd, void* data, std::size_t size)
    {
        auto* ptr = static_cast<std::uint8_t*>(data);
        std::size_t read_bytes = 0;

        while (read_bytes < size)
        {
            ssize_t rc = ::read(fd, ptr + read_bytes, size - read_bytes);

            if (rc < 0)
            {
                if (errno == EINTR)
                    continue;

                return false;
            }

            if (rc == 0)
                return false;

            read_bytes += static_cast<std::size_t>(rc);
        }

        return true;
    }

    /**
     * @brief Writes exactly size bytes to fd before timeout expires.
     */
    inline bool write_all_for(
        int fd,
        const void* data,
        std::size_t size,
        std::chrono::milliseconds timeout
    )
    {
        const auto deadline = std::chrono::steady_clock::now() + timeout;
        const auto* ptr = static_cast<const std::uint8_t*>(data);
        std::size_t written = 0;

        while (written < size)
        {
            const auto now = std::chrono::steady_clock::now();

            if (now >= deadline)
                return false;

            const auto wait_time = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now);
            
            pollfd pfd {};
            pfd.fd = fd;
            pfd.events = POLLOUT;

            int rc = ::poll(&pfd, 1, static_cast<int>(wait_time.count()));

            if (rc < 0)
            {
                if (errno == EINTR)
                    continue;

                return false;
            }

            if (rc == 0)
                return false;

            if (!(pfd.revents & POLLOUT) || (pfd.revents & (POLLERR | POLLHUP | POLLNVAL)))
                return false;

            ssize_t bytes = ::write(fd, ptr + written, size - written);

            if (bytes < 0)
            {
                if (errno == EINTR)
                    continue;

                return false;
            }

            if (bytes == 0)
                return false;

            written += static_cast<std::size_t>(bytes);
        }

        return true;
    }

    /**
     * @brief Reads exactly size bytes from fd before timeout expires.
     */
    inline bool read_all_for(
        int fd,
        void* data,
        std::size_t size,
        std::chrono::milliseconds timeout
    )
    {
        const auto deadline = std::chrono::steady_clock::now() + timeout;
        auto* ptr = static_cast<std::uint8_t*>(data);
        std::size_t read_bytes = 0;

        while (read_bytes < size)
        {
            const auto now = std::chrono::steady_clock::now();

            if (now >= deadline)
                return false;

            const auto wait_time = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now);
            pollfd pfd {};
            pfd.fd = fd;
            pfd.events = POLLIN;

            int rc = ::poll(&pfd, 1, static_cast<int>(wait_time.count()));

            if (rc < 0)
            {
                if (errno == EINTR)
                    continue;

                return false;
            }

            if (rc == 0)
                return false;

            if (!(pfd.revents & POLLIN))
                return false;

            if (pfd.revents & (POLLERR | POLLNVAL))
                return false;

            ssize_t bytes = ::read(fd, ptr + read_bytes, size - read_bytes);

            if (bytes < 0)
            {
                if (errno == EINTR)
                    continue;

                return false;
            }

            if (bytes == 0)
                return false;

            read_bytes += static_cast<std::size_t>(bytes);
        }

        return true;
    }
}

#endif // PROTOCOL_HELPERS_HPP
