#ifndef FORK_WORKER_H
#define FORK_WORKER_H

#ifndef _WIN32

#include <cerrno>
#include <csignal>
#include <cstdint>
#include <cstring>

#include <chrono>
#include <exception>
#include <functional>
#include <optional>
#include <poll.h>
#include <queue>
#include <stdexcept>
#include <string>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <tuple>
#include <type_traits>
#include <unistd.h>
#include <utility>
#include <vector>

#include "worker/specs.h"

namespace hotfuzz
{
    template <typename F, typename... Ts>
    class fork_worker_pool
    {
    public:
        using args_tuple     = std::tuple<Ts...>;
        using result_type    = isolated_result<Ts...>;
        using result_handler = std::function<void(const result_type&)>;

        fork_worker_pool(std::size_t worker_count, F& fn);
        fork_worker_pool(const fork_worker_pool&) = delete;
        fork_worker_pool& operator=(const fork_worker_pool&) = delete;

        ~fork_worker_pool();

        // State

        std::size_t submitted() const noexcept;
        std::size_t finished() const noexcept;
        std::size_t pending() const noexcept;
        std::size_t inflight() const noexcept;
        bool done() const noexcept;

        // API

        void submit(args_tuple args);
        result_type wait_one();
        void drain(const result_handler& handler);

    private:
        struct task
        {
            std::uint64_t id {};
            args_tuple args {};
        };

        struct worker
        {
            pid_t pid { -1 };
            int fd { -1 };

            bool busy { false };
            std::optional<task> current_task;
        };

    private:
        F& m_fn;

        std::vector<worker> m_workers;
        std::queue<task> m_queue;
        std::queue<result_type> m_ready_results;

        std::uint64_t m_next_task_id { 1 };
        std::size_t m_submitted { 0 };
        std::size_t m_finished { 0 };

    private:
        void stop_all_workers()
        {
            for (auto& w : m_workers)
            {
                if (w.fd >= 0)
                {
                    detail::send_packet(w.fd, detail::packet_kind::stop, 0);
                    ::close(w.fd);
                    w.fd = -1;
                }

                if (w.pid > 0)
                {
                    int status {};
                    ::waitpid(w.pid, &status, 0);
                    w.pid = -1;
                }
            }
        }

        void dispatch_idle_workers()
        {
            for (std::size_t i = 0; i < m_workers.size(); ++i)
            {
                auto& w = m_workers[i];

                if (m_queue.empty())
                    return;

                if (w.busy)
                    continue;

                if (w.fd < 0 || w.pid <= 0)
                    continue;

                task t = std::move(m_queue.front());
                m_queue.pop();

                auto payload = detail::encode_tuple(t.args);

                w.busy = true;
                w.current_task = t;

                bool sent = detail::send_packet(
                    w.fd,
                    detail::packet_kind::run,
                    t.id,
                    payload
                );

                if (!sent)
                {
                    result_type result {};
                    result.task_id = t.id;
                    result.worker_index = i;
                    result.status = isolated_status::protocol_error;
                    result.message = "Failed to send task to worker";
                    result.args = t.args;

                    m_ready_results.push(std::move(result));
                    ++m_finished;

                    cleanup_worker(i);
                    spawn_worker(i);
                }
            }
        }

        std::optional<result_type> reap_dead_workers()
        {
            for (std::size_t i = 0; i < m_workers.size(); ++i)
            {
                auto& w = m_workers[i];

                if (w.pid <= 0)
                    continue;

                int status {};
                pid_t rc = ::waitpid(w.pid, &status, WNOHANG);

                if (rc == 0)
                    continue;

                if (rc < 0)
                    continue;

                bool had_task = w.busy && w.current_task.has_value();

                result_type result {};

                if (had_task)
                {
                    result.task_id = w.current_task->id;
                    result.args = w.current_task->args;
                    result.worker_index = i;

                    if (WIFSIGNALED(status))
                    {
                        int sig = WTERMSIG(status);

                        result.status = isolated_status::crash;
                        result.signal_number = sig;
                        result.message = "Worker crashed with " + signal_name(sig);
                    }
                    else if (WIFEXITED(status))
                    {
                        int code = WEXITSTATUS(status);

                        result.status = isolated_status::crash;
                        result.exit_code = code;
                        result.message = "Worker exited before sending result, exit_code=" + std::to_string(code);
                    }
                    else
                    {
                        result.status = isolated_status::protocol_error;
                        result.message = "Worker disappeared with unknown waitpid status";
                    }

                    ++m_finished;
                }

                cleanup_worker(i);
                spawn_worker(i);

                if (had_task)
                    return result;
            }

            return std::nullopt;
        }

        std::optional<result_type> handle_worker_disconnect(std::size_t index)
        {
            auto& w = m_workers[index];

            bool had_task = w.busy && w.current_task.has_value();

            result_type result {};

            if (had_task)
            {
                result.task_id = w.current_task->id;
                result.args = w.current_task->args;
                result.worker_index = index;
                result.status = isolated_status::crash;
                result.message = "Worker IPC disconnected before result";

                ++m_finished;
            }

            cleanup_worker(index);
            spawn_worker(index);

            if (had_task)
                return result;

            return std::nullopt;
        }

        result_type read_worker_result(std::size_t index)
        {
            auto& w = m_workers[index];

            if (!w.current_task.has_value())
                throw std::runtime_error("Worker result received without current task");

            detail::packet_header header {};

            if (!detail::read_all(w.fd, &header, sizeof(header)))
            {
                auto disconnected = handle_worker_disconnect(index);

                if (disconnected)
                    return *disconnected;

                throw std::runtime_error("Worker disconnected without task");
            }

            std::vector<std::uint8_t> payload(header.payload_size);

            if (header.payload_size > 0)
            {
                if (!detail::read_all(w.fd, payload.data(), payload.size()))
                {
                    auto disconnected = handle_worker_disconnect(index);

                    if (disconnected)
                        return *disconnected;

                    throw std::runtime_error("Worker disconnected while reading payload");
                }
            }

            result_type result {};
            result.task_id = w.current_task->id;
            result.args = w.current_task->args;
            result.worker_index = index;

            if (header.task_id != w.current_task->id)
            {
                result.status = isolated_status::protocol_error;
                result.message = "Task id mismatch in worker response";
            }
            else
            {
                auto kind = static_cast<detail::packet_kind>(header.kind);

                if (kind == detail::packet_kind::ok)
                {
                    result.status = isolated_status::ok;
                }
                else if (kind == detail::packet_kind::exception)
                {
                    result.status = isolated_status::exception;
                    result.message = detail::payload_to_string(payload);
                }
                else
                {
                    result.status = isolated_status::protocol_error;
                    result.message = "Unknown response packet kind";
                }
            }

            w.busy = false;
            w.current_task.reset();

            ++m_finished;

            dispatch_idle_workers();

            return result;
        }

        void cleanup_worker(std::size_t index)
        {
            auto& w = m_workers[index];

            if (w.fd >= 0)
            {
                ::close(w.fd);
                w.fd = -1;
            }

            if (w.pid > 0)
            {
                int status {};
                ::waitpid(w.pid, &status, WNOHANG);
                w.pid = -1;
            }

            w.busy = false;
            w.current_task.reset();
        }

        std::size_t find_worker_by_fd(int fd) const
        {
            for (std::size_t i = 0; i < m_workers.size(); ++i)
            {
                if (m_workers[i].fd == fd)
                    return i;
            }

            throw std::runtime_error("Unknown worker fd");
        }
    };

    /*
    * Pool Constructor/Destructor
    */

    template <typename F, typename... Ts>
    inline fork_worker_pool<F, Ts...>::fork_worker_pool(std::size_t worker_count, F& fn) : m_fn(fn)
    {
        static_assert(
            (... && std::is_trivially_copyable_v<Ts>),
            "fork_worker_pool currently supports only trivially copyable argument types"
        );

        if (worker_count == 0)
            throw std::invalid_argument("worker_count must be greater than zero");

        m_workers.resize(worker_count);

        for (std::size_t i = 0; i < worker_count; ++i)
            spawn_worker(i);
    }

    template <typename F, typename... Ts>
    inline fork_worker_pool<F, Ts...>::~fork_worker_pool()
    {
        stop_all_workers();
    }

    /*
    * Pool State getters
    */

    template <typename F, typename... Ts>
    inline std::size_t fork_worker_pool<F, Ts...>::submitted() const noexcept
    {
        return m_submitted;
    }

    template <typename F, typename... Ts>
    inline std::size_t fork_worker_pool<F, Ts...>::finished() const noexcept
    {
        return m_finished;
    }

    template <typename F, typename... Ts>
    inline std::size_t fork_worker_pool<F, Ts...>::pending() const noexcept
    {
        return m_queue.size();
    }

    template <typename F, typename... Ts>
    inline std::size_t fork_worker_pool<F, Ts...>::inflight() const noexcept
    {
        std::size_t count = 0;

        for (const auto& w : m_workers)
        {
            if (w.busy)
                ++count;
        }

        return count;
    }

    template <typename F, typename... Ts>
    inline bool fork_worker_pool<F, Ts...>::done() const noexcept
    {
        return m_finished >= m_submitted;
    }

    /*
    * Basic Pool API
    */

    template <typename F, typename... Ts>
    inline void fork_worker_pool<F, Ts...>::submit(args_tuple args)
    {
        task t {};
        t.id = m_next_task_id++;
        t.args = std::move(args);

        m_queue.push(std::move(t));
        ++m_submitted;

        dispatch_idle_workers();
    }

    template <typename F, typename... Ts>
    inline fork_worker_pool<F, Ts...>::result_type fork_worker_pool<F, Ts...>::wait_one()
    {
        while (true)
        {
            dispatch_idle_workers();

            if (!m_ready_results.empty())
            {
                auto result = std::move(m_ready_results.front());
                m_ready_results.pop();
                return result;
            }

            if (auto crash_result = reap_dead_workers())
                return *crash_result;

            std::vector<pollfd> fds;
            fds.reserve(m_workers.size());

            for (auto& w : m_workers)
            {
                if (w.fd >= 0 && w.busy)
                {
                    pollfd pfd {};
                    pfd.fd = w.fd;
                    pfd.events = POLLIN | POLLHUP | POLLERR;
                    pfd.revents = 0;
                    fds.push_back(pfd);
                }
            }

            if (fds.empty())
            {
                if (done())
                {
                    throw std::runtime_error("wait_one() called when pool is already done");
                }

                continue;
            }

            int rc = ::poll(fds.data(), fds.size(), 100);

            if (rc < 0)
            {
                if (errno == EINTR)
                    continue;

                throw std::runtime_error("poll() failed");
            }

            if (rc == 0)
                continue;

            for (const auto& pfd : fds)
            {
                if (pfd.revents == 0)
                    continue;

                std::size_t worker_index = find_worker_by_fd(pfd.fd);

                if (pfd.revents & POLLIN)
                {
                    return read_worker_result(worker_index);
                }

                if (pfd.revents & (POLLHUP | POLLERR))
                {
                    if (auto crash_result = handle_worker_disconnect(worker_index))
                        return *crash_result;
                }
            }
        }
    }

    void drain(const result_handler& handler)
    {
        while (!done())
        {
            auto result = wait_one();
            handler(result);
        }
    }
}

#endif 
#endif // FORK_WORKER_H
