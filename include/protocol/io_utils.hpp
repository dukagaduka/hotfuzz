#ifndef PROTOCOL_IO_UTILS_HPP
#define PROTOCOL_IO_UTILS_HPP

#include <cerrno>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include "protocol/specs.h"


namespace hotfuzz
{
    namespace utils
    {

        inline bool is_disconnected_errno(int value) noexcept
        {
            return value == EPIPE ||
                   value == ECONNRESET ||
                   value == ECONNABORTED ||
                   value == ENOTCONN;
        }


        inline io_result result_from_errno(int value) noexcept
        {
            if (is_disconnected_errno(value))
                return { io_status::disconnected, value };

            return { io_status::system_error, value };
        }


        inline ssize_t write_no_sigpipe(int fd, const void* data, std::size_t size)
        {

#ifdef MSG_NOSIGNAL
            ssize_t rc = ::send(fd, data, size, MSG_NOSIGNAL);

            // packet_manager is socket-oriented in worker mode, but keeping
            // this fallback makes the helper usable with plain descriptors too.
            if (rc < 0 && (errno == ENOTSOCK || errno == EPERM))
                rc = ::write(fd, data, size);

            return rc;
#else
            return ::write(fd, data, size);
#endif

        }


        inline int timeout_ms_until_int(std::chrono::steady_clock::time_point deadline)
        {
            const auto now = std::chrono::steady_clock::now();

            if (now >= deadline)
                return 0;

            return static_cast<int>(
                std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now).count()
            );
        }


        inline std::chrono::milliseconds timeout_ms_until_chrono(std::chrono::steady_clock::time_point deadline)
        {
            const auto now = std::chrono::steady_clock::now();

            if (now >= deadline)
                return std::chrono::milliseconds::zero();

            return std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now);
        }


        /**
         * @brief Writes exactly size bytes to fd.
         */
        inline io_result write_all(int fd, const void* data, std::size_t size)
        {
            const auto* ptr = static_cast<const std::uint8_t*>(data);
            std::size_t written = 0;

            while (written < size)
            {
                ssize_t rc = write_no_sigpipe(fd, ptr + written, size - written);

                if (rc < 0)
                {
                    if (errno == EINTR)
                        continue;

                    return result_from_errno(errno);
                }

                if (rc == 0)
                    return { io_status::eof, 0 };

                written += static_cast<std::size_t>(rc);
            }

            return { io_status::ok, 0 };
        }

        /**
         * @brief Reads exactly size bytes from fd.
         */
        inline io_result read_all(int fd, void* data, std::size_t size)
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

                    return result_from_errno(errno);
                }

                if (rc == 0)
                    return { io_status::eof, 0 };

                read_bytes += static_cast<std::size_t>(rc);
            }

            return { io_status::ok, 0 };
        }


        /**
         * @brief Writes exactly size bytes to fd before timeout expires.
         */
        inline io_result write_all_for(
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
                if (std::chrono::steady_clock::now() >= deadline)
                    return { io_status::timeout, 0 };

                pollfd pfd {};
                pfd.fd = fd;
                pfd.events = POLLOUT;

                int rc = ::poll(&pfd, 1, timeout_ms_until_int(deadline));

                if (rc < 0)
                {
                    if (errno == EINTR)
                        continue;

                    return result_from_errno(errno);
                }

                if (rc == 0)
                    return { io_status::timeout, 0 };

                if (pfd.revents & POLLNVAL)
                    return { io_status::system_error, EBADF };

                if (pfd.revents & (POLLERR | POLLHUP))
                    return { io_status::disconnected, EPIPE };

                if (!(pfd.revents & POLLOUT))
                    continue;

                ssize_t bytes = write_no_sigpipe(fd, ptr + written, size - written);

                if (bytes < 0)
                {
                    if (errno == EINTR)
                        continue;

                    if (errno == EAGAIN || errno == EWOULDBLOCK)
                        continue;

                    return result_from_errno(errno);
                }

                if (bytes == 0)
                    return { io_status::eof, 0 };

                written += static_cast<std::size_t>(bytes);
            }

            return { io_status::ok, 0 };
        }

        /**
         * @brief Reads exactly size bytes from fd before timeout expires.
         */
        inline io_result read_all_for(
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
                if (std::chrono::steady_clock::now() >= deadline)
                    return { io_status::timeout, 0 };

                pollfd pfd {};
                pfd.fd = fd;
                pfd.events = POLLIN;

                int rc = ::poll(&pfd, 1, timeout_ms_until_int(deadline));

                if (rc < 0)
                {
                    if (errno == EINTR)
                        continue;

                    return result_from_errno(errno);
                }

                if (rc == 0)
                    return { io_status::timeout, 0 };

                if (pfd.revents & POLLNVAL)
                    return { io_status::system_error, EBADF };

                if (!(pfd.revents & POLLIN))
                {
                    if (pfd.revents & POLLHUP)
                        return { io_status::eof, 0 };

                    if (pfd.revents & POLLERR)
                        return { io_status::disconnected, ECONNRESET };

                    continue;
                }

                ssize_t bytes = ::read(fd, ptr + read_bytes, size - read_bytes);

                if (bytes < 0)
                {
                    if (errno == EINTR)
                        continue;

                    if (errno == EAGAIN || errno == EWOULDBLOCK)
                        continue;

                    return result_from_errno(errno);
                }

                if (bytes == 0)
                    return { io_status::eof, 0 };

                read_bytes += static_cast<std::size_t>(bytes);
            }

            return { io_status::ok, 0 };
        }
    }
}

#endif // PROTOCOL_IO_UTILS_HPP
