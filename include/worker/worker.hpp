#ifndef WORKER_WORKER_HPP
#define WORKER_WORKER_HPP

#ifndef _WIN32

#include <chrono>
#include <concepts>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <optional>
#include <string>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <thread>
#include <tuple>
#include <unistd.h>
#include <utility>

#include "utils.hpp"
#include "protocol/packet_manager.hpp"
#include "worker/specs.h"

namespace hotfuzz
{
    /**
     * @brief Fork-backed state machine for one child process and one in-flight task.
     *
     * worker owns process lifecycle and request/result exchange only. It does
     * not queue tasks, retry sends, schedule work, or call result handlers.
     */
    template <typename F, typename... Ts>
    class worker
    {
        static_assert(std::invocable<F&, Ts...>, "worker function must be invocable with Ts...");

    public:
        using args_tuple = std::tuple<Ts...>;
        using result_type = isolated_result<Ts...>;

        /**
         * @brief Creates a stopped worker bound to fn.
         *
         * The constructor does not fork. Call spawn() before send().
         */
        explicit worker(F& fn, worker_timeouts timeouts = {});
        ~worker();

        worker() = delete;
        worker(const worker&) = delete;
        worker& operator=(const worker&) = delete;

        /**
         * @brief Starts the child process and moves the worker to idle.
         *
         * Returns false if a child already exists or fork/socketpair fails.
         */
        [[nodiscard]] bool spawn();

        /**
         * @brief Definitively stops the current child process, if any.
         *
         * Idle workers get a graceful stop packet first. Busy or broken workers
         * are killed because their protocol stream is not trusted anymore.
         */
        void stop();

        /**
         * @brief Stops the current child process and starts a fresh one.
         */
        [[nodiscard]] bool respawn();

        /**
         * @brief Delivers one task request to an idle worker.
         *
         * This is a delivery operation only. On accepted the worker becomes
         * busy and receive() must be used to get the execution result. On any
         * other status the task was not accepted by this worker.
         */
        [[nodiscard]] worker_send_result send(
            std::uint64_t task_id,
            const args_tuple& args,
            std::uint16_t flags = 0
        );

        /**
         * @brief Reads the result for the current in-flight task.
         *
         * Usually called after pollable() fd reports readiness. Protocol, IPC,
         * crash, and timeout failures are converted to isolated_result and the
         * child is stopped when the worker becomes broken.
         */
        [[nodiscard]] result_type receive();

        /**
         * @brief Returns timeout result and stops the child if task deadline expired.
         */
        [[nodiscard]] std::optional<result_type> expire_if_timed_out(
            std::chrono::steady_clock::time_point now
        );

        /**
         * @brief Returns true while a child process/fd is owned by this worker.
         */
        [[nodiscard]] bool alive() const noexcept;

        /**
         * @brief Returns true when the child is running and no task is in flight.
         */
        [[nodiscard]] bool idle() const noexcept;

        /**
         * @brief Returns true after accepted send() and before receive()/timeout finishes.
         */
        [[nodiscard]] bool busy() const noexcept;

        /**
         * @brief Returns true while the process/channel is known to be poisoned.
         */
        [[nodiscard]] bool broken() const noexcept;

        /**
         * @brief Returns true when fd() should be included into pool poll set.
         */
        [[nodiscard]] bool pollable() const noexcept;

        /**
         * @brief Returns current parent-side state.
         */
        [[nodiscard]] worker_state state() const noexcept;

        /**
         * @brief Returns child pid or -1 when no child is owned.
         */
        [[nodiscard]] pid_t pid() const noexcept;

        /**
         * @brief Returns parent-side socket fd or -1 when no child is owned.
         */
        [[nodiscard]] int fd() const noexcept;

    private:
        struct current_task
        {
            std::uint64_t task_id {};
            args_tuple args {};
            std::optional<std::chrono::steady_clock::time_point> deadline;
        };

        [[noreturn]] void child_loop(int fd);

        [[nodiscard]] result_type make_result(
            const current_task& task,
            isolated_status status,
            std::string message = {}
        ) const;

        [[nodiscard]] result_type make_exit_result(
            const current_task& task,
            int wait_status,
            isolated_status fallback_status,
            std::string fallback_message
        ) const;

        [[nodiscard]] std::optional<result_type> child_exit_result(
            const current_task& task,
            isolated_status fallback_status,
            std::string fallback_message
        );

        [[nodiscard]] result_type result_from_packet(const packet<Ts...>& response);

        void shutdown_child() noexcept;
        void close_fd() noexcept;
        void reset_parent_state() noexcept;

    private:
        F& m_fn;
        worker_timeouts m_timeouts;

        pid_t m_pid { -1 };
        int m_fd { -1 };

        worker_state m_state { worker_state::stopped };
        std::optional<current_task> m_current_task;

    };


    template <typename F, typename... Ts>
    worker<F, Ts...>::worker(F& fn, worker_timeouts timeouts)
        : m_fn(fn),
          m_timeouts(std::move(timeouts))
    {}


    template <typename F, typename... Ts>
    worker<F, Ts...>::~worker()
    {
        stop();
    }


    template <typename F, typename... Ts>
    inline bool worker<F, Ts...>::spawn()
    {
        if (m_state != worker_state::stopped || m_pid > 0 || m_fd >= 0)
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
        m_current_task.reset();
        m_state = worker_state::idle;

        return true;
    }


    template <typename F, typename... Ts>
    inline void worker<F, Ts...>::stop()
    {
        shutdown_child();
    }


    template <typename F, typename... Ts>
    inline bool worker<F, Ts...>::respawn()
    {
        stop();
        return spawn();
    }


    template <typename F, typename... Ts>
    inline worker_send_result worker<F, Ts...>::send(
        std::uint64_t task_id,
        const args_tuple& args,
        std::uint16_t flags
    )
    {
        if (m_state == worker_state::stopped || m_pid <= 0 || m_fd < 0)
        {
            return {
                .status = worker_send_status::stopped,
                .task_id = task_id,
                .message = "worker is stopped"
            };
        }

        if (m_state != worker_state::idle)
        {
            return {
                .status = worker_send_status::busy,
                .task_id = task_id,
                .message = "worker is busy"
            };
        }

        try
        {
            packet_manager<Ts...> packets(m_fd);
            packets.send_run(task_id, args, m_timeouts.send_timeout, flags);
        }
        catch (const timeout_error& e)
        {
            m_state = worker_state::broken;
            shutdown_child();

            return {
                .status = worker_send_status::timeout,
                .task_id = task_id,
                .message = e.what()
            };
        }
        catch (const disconnected_error& e)
        {
            m_state = worker_state::broken;
            shutdown_child();

            return {
                .status = worker_send_status::disconnected,
                .task_id = task_id,
                .message = e.what()
            };
        }
        catch (const ipc_error& e)
        {
            m_state = worker_state::broken;
            shutdown_child();

            return {
                .status = worker_send_status::io_error,
                .task_id = task_id,
                .message = e.what()
            };
        }
        // Transport errors above mean the stream may be corrupted, so the
        // child is stopped. Everything below happens while building the request
        // frame locally, before send() can mark the task as accepted.
        catch (const std::exception& e)
        {
            return {
                .status = worker_send_status::serialize_error,
                .task_id = task_id,
                .message = e.what()
            };
        }
        catch (...)
        {
            return {
                .status = worker_send_status::serialize_error,
                .task_id = task_id,
                .message = "unknown worker request serialization failure"
            };
        }

        current_task task {};
        task.task_id = task_id;
        task.args = args;

        if (m_timeouts.task_timeout.has_value())
            task.deadline = std::chrono::steady_clock::now() + *m_timeouts.task_timeout;

        m_current_task = std::move(task);
        m_state = worker_state::busy;

        return {
            .status = worker_send_status::accepted,
            .task_id = task_id,
            .message = {}
        };
    }


    template <typename F, typename... Ts>
    inline typename worker<F, Ts...>::result_type worker<F, Ts...>::receive()
    {
        if (m_state != worker_state::busy || !m_current_task.has_value())
            throw protocol_error("cannot receive without an in-flight worker task");

        if (auto expired_result = expire_if_timed_out(std::chrono::steady_clock::now()))
            return *expired_result;

        const auto task = *m_current_task;

        if (auto exited_result = child_exit_result(
                task,
                isolated_status::ipc_error,
                "worker exited before sending response"
            ))
        {
            m_state = worker_state::broken;
            shutdown_child();

            return *exited_result;
        }

        try
        {
            packet_manager<Ts...> packets(m_fd);
            auto response = packets.receive(m_timeouts.frame_timeout);

            return result_from_packet(response);
        }
        catch (const timeout_error& e)
        {
            // frame_timeout means we failed to read an already expected
            // response frame; task_timeout is handled by expire_if_timed_out().
            m_state = worker_state::broken;
            auto result = make_result(task, isolated_status::ipc_error, e.what());
            shutdown_child();

            return result;
        }
        catch (const disconnected_error& e)
        {
            if (auto exited = child_exit_result(task, isolated_status::ipc_error, e.what()))
            {
                m_state = worker_state::broken;
                shutdown_child();

                return *exited;
            }

            m_state = worker_state::broken;
            auto result = make_result(task, isolated_status::ipc_error, e.what());
            shutdown_child();

            return result;
        }
        catch (const ipc_error& e)
        {
            if (auto exited = child_exit_result(task, isolated_status::ipc_error, e.what()))
            {
                m_state = worker_state::broken;
                shutdown_child();

                return *exited;
            }

            m_state = worker_state::broken;
            auto result = make_result(task, isolated_status::ipc_error, e.what());
            shutdown_child();

            return result;
        }
        catch (const protocol_error& e)
        {
            if (auto exited = child_exit_result(task, isolated_status::protocol_error, e.what()))
            {
                m_state = worker_state::broken;
                shutdown_child();

                return *exited;
            }

            m_state = worker_state::broken;
            auto result = make_result(task, isolated_status::protocol_error, e.what());
            shutdown_child();

            return result;
        }
        catch (const std::exception& e)
        {
            m_state = worker_state::broken;
            auto result = make_result(task, isolated_status::internal_error, e.what());
            shutdown_child();

            return result;
        }
        catch (...)
        {
            m_state = worker_state::broken;
            auto result = make_result(task, isolated_status::internal_error, "unknown worker receive failure");
            shutdown_child();

            return result;
        }
    }


    template <typename F, typename... Ts>
    inline std::optional<typename worker<F, Ts...>::result_type> worker<F, Ts...>::expire_if_timed_out(
        std::chrono::steady_clock::time_point now
    )
    {
        if (m_state != worker_state::busy || !m_current_task.has_value())
            return std::nullopt;

        const auto task = *m_current_task;

        if (!task.deadline.has_value() || now < *task.deadline)
            return std::nullopt;

        m_state = worker_state::broken;
        auto result = make_result(task, isolated_status::timeout, "worker task timed out");
        shutdown_child();

        return result;
    }


    template <typename F, typename... Ts>
    inline bool worker<F, Ts...>::alive() const noexcept
    {
        return m_pid > 0 && m_fd >= 0 && m_state != worker_state::stopped;
    }


    template <typename F, typename... Ts>
    inline bool worker<F, Ts...>::idle() const noexcept
    {
        return m_state == worker_state::idle;
    }


    template <typename F, typename... Ts>
    inline bool worker<F, Ts...>::busy() const noexcept
    {
        return m_state == worker_state::busy;
    }


    template <typename F, typename... Ts>
    inline bool worker<F, Ts...>::broken() const noexcept
    {
        return m_state == worker_state::broken;
    }


    template <typename F, typename... Ts>
    inline bool worker<F, Ts...>::pollable() const noexcept
    {
        return m_state == worker_state::busy && m_pid > 0 && m_fd >= 0;
    }


    template <typename F, typename... Ts>
    inline worker_state worker<F, Ts...>::state() const noexcept
    {
        return m_state;
    }


    template <typename F, typename... Ts>
    inline pid_t worker<F, Ts...>::pid() const noexcept
    {
        return m_pid;
    }


    template <typename F, typename... Ts>
    inline int worker<F, Ts...>::fd() const noexcept
    {
        return m_fd;
    }


    template <typename F, typename... Ts>
    [[noreturn]] void worker<F, Ts...>::child_loop(int fd)
    {
        packet_manager<Ts...> packets(fd);

        while (true)
        {
            packet<Ts...> request {};

            try
            {
                request = packets.receive();
            }
            catch (const protocol_error&)
            {
                // A malformed request means the stream may be desynchronized.
                // The child exits and lets the parent classify by exit code.
                ::close(fd);
                _exit(worker_exit_protocol_error);
            }
            catch (const ipc_error&)
            {
                ::close(fd);
                _exit(worker_exit_ipc_error);
            }
            catch (...)
            {
                ::close(fd);
                _exit(worker_exit_internal_error);
            }

            if (request.kind() == packet_kind::stop)
            {
                ::close(fd);
                _exit(worker_exit_ok);
            }

            if (request.kind() != packet_kind::run)
            {
                ::close(fd);
                _exit(worker_exit_protocol_error);
            }

            try
            {
                call_with_tuple(m_fn, request.as_tuple());

                try
                {
                    packets.send_ok(request.task_id(), m_timeouts.send_timeout);
                }
                catch (...)
                {
                    ::close(fd);
                    _exit(worker_exit_ipc_error);
                }
            }
            catch (const std::exception& e)
            {
                try
                {
                    packets.send_exception(request.task_id(), e.what(), m_timeouts.send_timeout);
                }
                catch (...)
                {
                    ::close(fd);
                    _exit(worker_exit_ipc_error);
                }
            }
            catch (...)
            {
                try
                {
                    packets.send_exception(
                        request.task_id(),
                        "Unknown non-std exception",
                        m_timeouts.send_timeout
                    );
                }
                catch (...)
                {
                    ::close(fd);
                    _exit(worker_exit_ipc_error);
                }
            }
        }
    }


    template <typename F, typename... Ts>
    inline typename worker<F, Ts...>::result_type worker<F, Ts...>::make_result(
        const current_task& task,
        isolated_status status,
        std::string message
    ) const
    {
        result_type result {};
        result.task_id = task.task_id;
        result.status = status;
        result.message = std::move(message);
        result.args = task.args;
        return result;
    }
    

    template <typename F, typename... Ts>
    inline typename worker<F, Ts...>::result_type worker<F, Ts...>::make_exit_result(
        const current_task& task,
        int wait_status,
        isolated_status fallback_status,
        std::string fallback_message
    ) const
    {
        if (WIFSIGNALED(wait_status))
        {
            const int sig = WTERMSIG(wait_status);
            auto result = make_result(
                task,
                isolated_status::crash,
                "worker crashed with " + signal_name(sig)
            );
            result.signal_number = sig;
            return result;
        }

        if (WIFEXITED(wait_status))
        {
            const int code = WEXITSTATUS(wait_status);
            isolated_status status = fallback_status;
            std::string message = std::move(fallback_message);

            switch (code)
            {
                case worker_exit_ok:
                    status = isolated_status::ipc_error;
                    message = "worker exited normally before sending response";
                    break;

                case worker_exit_protocol_error:
                    status = isolated_status::protocol_error;
                    message = "worker exited after request protocol error";
                    break;

                case worker_exit_ipc_error:
                    status = isolated_status::ipc_error;
                    message = "worker exited after IPC error";
                    break;

                case worker_exit_internal_error:
                    status = isolated_status::internal_error;
                    message = "worker exited after internal error";
                    break;

                default:
                    status = isolated_status::internal_error;
                    message = "worker exited with code " + std::to_string(code);
                    break;
            }

            auto result = make_result(task, status, std::move(message));
            result.exit_code = code;
            return result;
        }

        return make_result(task, fallback_status, std::move(fallback_message));
    }


    template <typename F, typename... Ts>
    inline std::optional<typename worker<F, Ts...>::result_type> worker<F, Ts...>::child_exit_result(
        const current_task& task,
        isolated_status fallback_status,
        std::string fallback_message
    )
    {
        if (m_pid <= 0)
            return std::nullopt;

        int status {};
        const pid_t rc = ::waitpid(m_pid, &status, WNOHANG);

        if (rc == 0)
            return std::nullopt;

        if (rc == m_pid)
        {
            m_pid = -1;
            return make_exit_result(task, status, fallback_status, std::move(fallback_message));
        }

        return std::nullopt;
    }


    template <typename F, typename... Ts>
    inline typename worker<F, Ts...>::result_type worker<F, Ts...>::result_from_packet(
        const packet<Ts...>& response
    )
    {
        if (!m_current_task.has_value())
            throw protocol_error("worker response received without an in-flight task");

        const auto task = *m_current_task;

        if (response.task_id() != task.task_id)
        {
            m_state = worker_state::broken;
            auto result = make_result(
                task,
                isolated_status::protocol_error,
                "worker response task_id mismatch"
            );
            shutdown_child();

            return result;
        }

        if (response.kind() == packet_kind::ok)
        {
            m_current_task.reset();
            m_state = worker_state::idle;

            return make_result(task, isolated_status::ok);
        }

        if (response.kind() == packet_kind::exception)
        {
            m_current_task.reset();
            m_state = worker_state::idle;

            return make_result(task, isolated_status::exception, response.as_text());
        }

        if (response.kind() == packet_kind::protocol_error)
        {
            m_state = worker_state::broken;
            auto result = make_result(task, isolated_status::protocol_error, response.as_text());
            shutdown_child();

            return result;
        }

        m_state = worker_state::broken;
        auto result = make_result(
            task,
            isolated_status::protocol_error,
            "worker returned unexpected packet kind"
        );
        shutdown_child();

        return result;
    }


    template <typename F, typename... Ts>
    inline void worker<F, Ts...>::shutdown_child() noexcept
    {
        const bool try_graceful = m_state == worker_state::idle && m_pid > 0 && m_fd >= 0;

        if (try_graceful)
        {
            try
            {
                packet_manager<Ts...> packets(m_fd);
                (void)packets.send_stop(m_timeouts.send_timeout);
            }
            catch (...)
            {}

            // stop has no response packet: successful acknowledgement is the
            // child exiting with worker_exit_ok.
            const auto deadline = std::chrono::steady_clock::now() + m_timeouts.frame_timeout;

            while (m_pid > 0 && std::chrono::steady_clock::now() < deadline)
            {
                int status {};
                const pid_t rc = ::waitpid(m_pid, &status, WNOHANG);

                if (rc == m_pid)
                {
                    m_pid = -1;
                    break;
                }

                if (rc < 0)
                    break;

                std::this_thread::sleep_for(std::chrono::milliseconds { 1 });
            }
        }

        close_fd();

        if (m_pid > 0)
        {
            ::kill(m_pid, SIGKILL);

            int status {};
            (void)::waitpid(m_pid, &status, 0);
        }

        reset_parent_state();
    }


    template <typename F, typename... Ts>
    inline void worker<F, Ts...>::close_fd() noexcept
    {
        if (m_fd >= 0)
        {
            ::close(m_fd);
            m_fd = -1;
        }
    }


    template <typename F, typename... Ts>
    inline void worker<F, Ts...>::reset_parent_state() noexcept
    {
        m_pid = -1;
        m_fd = -1;
        m_current_task.reset();
        m_state = worker_state::stopped;
    }
}

#endif
#endif // WORKER_WORKER_HPP
