#ifndef WORKER_HPP
#define WORKER_HPP

#ifndef _WIN32

#include <chrono>
#include <concepts>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <optional>
#include <signal.h>
#include <string>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <tuple>
#include <unistd.h>
#include <utility>

#include "hotfuzz.hpp"
#include "protocol/packet_manager.hpp"
#include "worker/specs.h"

namespace hotfuzz 
{
    /**
     * @brief Fork-backed worker process for executing one callable with tuple arguments.
     *
     * The worker owns process lifecycle and delegates packet framing/serialization
     * to packet_manager. Parent-side run/receive methods return isolated_result,
     * not raw protocol packets.
     */
    template <typename F, typename... Ts>
    class worker
    {
        static_assert(std::invocable<F&, Ts...>, "worker function must be invocable with Ts...");

    public:
        using args_tuple = std::tuple<Ts...>;
        using result_type = isolated_result<Ts...>;

        /**
         * @brief Creates an inactive worker bound to fn and parent-side timeout/retry policy.
         */
        explicit worker(
            F& fn,
            std::chrono::milliseconds read_timeout = std::chrono::milliseconds { 1000 },
            std::chrono::milliseconds write_timeout = std::chrono::milliseconds { 1000 },
            std::size_t protocol_retry_count = 3
        );

        ~worker();

        worker() = delete;
        worker(const worker&) = delete;
        worker& operator=(const worker&) = delete;

        /**
         * @brief Spawns the child process. Returns false when already active.
         */
        [[nodiscard]] bool spawn();

        /**
         * @brief Stops any current child, cleans it up, and starts a new one.
         */
        [[nodiscard]] bool respawn();

        /**
         * @brief Definitively stops the child, killing it when graceful stop fails.
         */
        void stop();

        [[nodiscard]] bool alive() const noexcept;
        [[nodiscard]] bool busy() const noexcept;
        [[nodiscard]] pid_t pid() const noexcept;
        [[nodiscard]] int fd() const noexcept;

        /**
         * @brief Sends a run packet and records the in-flight task context.
         */
        [[nodiscard]] bool send_run(
            std::uint64_t task_id,
            const args_tuple& args,
            std::uint16_t flags = 0
        );

        /**
         * @brief Receives one response and converts it to isolated_result.
         */
        [[nodiscard]] result_type receive();

        /**
         * @brief Runs one task, retrying protocol_error responses up to protocol_retry_count.
         */
        [[nodiscard]] result_type run(
            std::uint64_t task_id,
            const args_tuple& args,
            std::uint16_t flags = 0
        );

    private:
        struct current_task
        {
            std::uint64_t task_id {};
            args_tuple args {};
        };

        [[noreturn]] void child_loop(int fd);

        [[nodiscard]] result_type make_result(
            std::uint64_t task_id,
            const args_tuple& args,
            isolated_status status,
            std::string message = {}
        ) const;

        [[nodiscard]] result_type result_from_packet(const packet<Ts...>& response);
        [[nodiscard]] result_type unsuccessful_trial_result(
            std::uint64_t task_id,
            const args_tuple& args,
            std::string message
        ) const;

        void close_fd() noexcept;
        void reap_child() noexcept;
        void terminate_child() noexcept;
        void reset_parent_state() noexcept;

    private:
        F& m_fn;

        std::chrono::milliseconds m_read_timeout;
        std::chrono::milliseconds m_write_timeout;
        std::size_t m_protocol_retry_count {};

        pid_t m_pid { -1 };
        int m_fd { -1 };

        bool m_busy { false };
        std::optional<current_task> m_current_task;
    };

    template <typename F, typename... Ts>
    worker<F, Ts...>::worker(
        F& fn,
        std::chrono::milliseconds read_timeout,
        std::chrono::milliseconds write_timeout,
        std::size_t protocol_retry_count
    )
        : m_fn(fn),
          m_read_timeout(read_timeout),
          m_write_timeout(write_timeout),
          m_protocol_retry_count(protocol_retry_count)
    {}

    template <typename F, typename... Ts>
    worker<F, Ts...>::~worker()
    {
        stop();
    }

    template <typename F, typename... Ts>
    bool worker<F, Ts...>::spawn()
    {
        if (m_pid > 0 || m_fd >= 0)
            return false;

        int sv[2] {};

        if (::socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0)
            return false;

        pid_t child_pid = ::fork();

        if (child_pid < 0)
        {
            ::close(sv[0]);
            ::close(sv[1]);
            return false;
        }

        if (child_pid == 0)
        {
            ::close(sv[0]);
            child_loop(sv[1]);
        }

        ::close(sv[1]);

        m_pid = child_pid;
        m_fd = sv[0];
        m_busy = false;
        m_current_task.reset();

        return true;
    }

    template <typename F, typename... Ts>
    bool worker<F, Ts...>::respawn()
    {
        stop();
        return spawn();
    }

    template <typename F, typename... Ts>
    void worker<F, Ts...>::stop()
    {
        if (m_fd < 0)
        {
            terminate_child();
            reset_parent_state();
            return;
        }

        packet_manager<Ts...> packets(m_fd);

        if (packets.send_stop_for(m_write_timeout))
        {
            try
            {
                auto response = packets.receive_for(m_read_timeout);

                if (response.kind() == packet_kind::ok)
                {
                    close_fd();
                    reap_child();
                    reset_parent_state();

                    return;
                }
            }
            catch (...)
            {}
        }

        terminate_child();
        reset_parent_state();
    }

    template <typename F, typename... Ts>
    bool worker<F, Ts...>::alive() const noexcept
    {
        return m_pid > 0 && m_fd >= 0;
    }

    template <typename F, typename... Ts>
    bool worker<F, Ts...>::busy() const noexcept
    {
        return m_busy;
    }

    template <typename F, typename... Ts>
    pid_t worker<F, Ts...>::pid() const noexcept
    {
        return m_pid;
    }

    template <typename F, typename... Ts>
    int worker<F, Ts...>::fd() const noexcept
    {
        return m_fd;
    }

    template <typename F, typename... Ts>
    bool worker<F, Ts...>::send_run(
        std::uint64_t task_id,
        const args_tuple& args,
        std::uint16_t flags
    )
    {
        if (!alive())
            return false;

        packet_manager<Ts...> packets(m_fd);
        const bool sent = packets.send_run_for(task_id, args, m_write_timeout, flags);

        if (sent)
        {
            m_busy = true;
            m_current_task = current_task {
                .task_id = task_id,
                .args = args
            };
        }

        return sent;
    }

    template <typename F, typename... Ts>
    typename worker<F, Ts...>::result_type worker<F, Ts...>::receive()
    {
        if (!alive())
            throw protocol_error("cannot receive from inactive worker");

        if (!m_current_task.has_value())
            throw protocol_error("cannot receive without an in-flight worker task");

        packet_manager<Ts...> packets(m_fd);

        try
        {
            auto response = packets.receive_for(m_read_timeout);
            m_busy = false;
            return result_from_packet(response);
        }
        catch (const std::exception& e)
        {
            const auto task = *m_current_task;

            m_busy = false;
            terminate_child();
            reset_parent_state();

            return make_result(task.task_id, task.args, isolated_status::timeout, e.what());
        }
        catch (...)
        {
            const auto task = *m_current_task;

            m_busy = false;
            terminate_child();
            reset_parent_state();

            return make_result(
                task.task_id,
                task.args,
                isolated_status::timeout,
                "Unknown worker receive failure"
            );
        }
    }

    template <typename F, typename... Ts>
    typename worker<F, Ts...>::result_type worker<F, Ts...>::run(
        std::uint64_t task_id,
        const args_tuple& args,
        std::uint16_t flags
    )
    {
        std::string last_protocol_error;

        for (std::size_t attempt = 0; attempt <= m_protocol_retry_count; ++attempt)
        {
            if (!alive() && !spawn())
            {
                return unsuccessful_trial_result(
                    task_id,
                    args,
                    "failed to spawn worker for task"
                );
            }

            if (!send_run(task_id, args, flags))
            {
                terminate_child();
                reset_parent_state();

                last_protocol_error = "failed to send run packet to worker";
                continue;
            }

            auto result = receive();

            if (result.status != isolated_status::protocol_error)
                return result;

            last_protocol_error = result.message;
        }

        return unsuccessful_trial_result(task_id, args, last_protocol_error);
    }

    template <typename F, typename... Ts>
    [[noreturn]] void worker<F, Ts...>::child_loop(int fd)
    {
        packet_manager<Ts...> packets(fd);

        while (true)
        {
            try
            {
                auto request = packets.receive();

                if (request.kind() == packet_kind::stop)
                {
                    (void)packets.send_ok_for(request.task_id(), m_write_timeout);
                    ::close(fd);
                    _exit(0);
                }

                if (request.kind() != packet_kind::run)
                {
                    (void)packets.send_protocol_error_for(
                        request.task_id(),
                        "worker received unexpected packet kind",
                        m_write_timeout
                    );
                    
                    continue;
                }

                try
                {
                    call_with_tuple(m_fn, request.as_tuple());
                    (void)packets.send_ok_for(request.task_id(), m_write_timeout);
                }
                catch (const std::exception& e)
                {
                    (void)packets.send_exception_for(request.task_id(), e.what(), m_write_timeout);
                }
                catch (...)
                {
                    (void)packets.send_exception_for(
                        request.task_id(),
                        "Unknown non-std exception",
                        m_write_timeout
                    );
                }
            }
            catch (const std::exception& e)
            {
                (void)packets.send_protocol_error_for(0, e.what(), m_write_timeout);
            }
            catch (...)
            {
                (void)packets.send_protocol_error_for(
                    0,
                    "Unknown worker protocol failure",
                    m_write_timeout
                );
            }
        }
    }

    template <typename F, typename... Ts>
    typename worker<F, Ts...>::result_type worker<F, Ts...>::make_result(
        std::uint64_t task_id,
        const args_tuple& args,
        isolated_status status,
        std::string message
    ) const
    {
        result_type result {};
        result.task_id = task_id;
        result.status = status;
        result.message = std::move(message);
        result.args = args;
        return result;
    }

    template <typename F, typename... Ts>
    typename worker<F, Ts...>::result_type worker<F, Ts...>::result_from_packet(
        const packet<Ts...>& response
    )
    {
        if (!m_current_task.has_value())
            throw protocol_error("worker response received without an in-flight task");

        const auto task = *m_current_task;
        m_current_task.reset();

        if (response.kind() == packet_kind::ok)
            return make_result(task.task_id, task.args, isolated_status::ok);

        if (response.kind() == packet_kind::exception)
            return make_result(task.task_id, task.args, isolated_status::exception, response.as_text());

        if (response.kind() == packet_kind::protocol_error)
            return make_result(task.task_id, task.args, isolated_status::protocol_error, response.as_text());

        return make_result(
            task.task_id,
            task.args,
            isolated_status::protocol_error,
            "worker returned unexpected packet kind"
        );
    }

    template <typename F, typename... Ts>
    typename worker<F, Ts...>::result_type worker<F, Ts...>::unsuccessful_trial_result(
        std::uint64_t task_id,
        const args_tuple& args,
        std::string message
    ) const
    {
        return make_result(task_id, args, isolated_status::unsuccessful_trial, std::move(message));
    }

    template <typename F, typename... Ts>
    void worker<F, Ts...>::close_fd() noexcept
    {
        if (m_fd >= 0)
        {
            ::close(m_fd);
            m_fd = -1;
        }
    }

    template <typename F, typename... Ts>
    void worker<F, Ts...>::reap_child() noexcept
    {
        if (m_pid > 0)
        {
            int status {};
            ::waitpid(m_pid, &status, 0);
            m_pid = -1;
        }
    }

    template <typename F, typename... Ts>
    void worker<F, Ts...>::terminate_child() noexcept
    {
        close_fd();

        if (m_pid > 0)
        {
            ::kill(m_pid, SIGKILL);
            reap_child();
        }
    }

    template <typename F, typename... Ts>
    void worker<F, Ts...>::reset_parent_state() noexcept
    {
        m_pid = -1;
        m_fd = -1;
        m_busy = false;
        m_current_task.reset();
    }
}

#endif
#endif // WORKER_HPP
