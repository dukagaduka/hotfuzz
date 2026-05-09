#ifndef WORKER_POOL_HPP
#define WORKER_POOL_HPP

#ifndef _WIN32

#include <cerrno>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <optional>
#include <poll.h>
#include <queue>
#include <stdexcept>
#include <string>
#include <thread>
#include <tuple>
#include <utility>
#include <vector>

#include "worker/worker.hpp"
#include "worker/specs.h"

namespace hotfuzz
{
    /**
     * @brief Scheduler over a fixed set of isolated worker processes.
     *
     * The pool owns task queues, dispatch retry policy, poll(), and worker
     * respawn. It does not reinterpret execution results: accepted tasks return
     * isolated_result, while delivery failure after retries throws dispatch_error.
     */
    template <typename F, typename... Ts>
    class worker_pool
    {
    public:
        using args_tuple = std::tuple<Ts...>;
        using result_type = isolated_result<Ts...>;

        /**
         * @brief Creates and starts a fixed-size set of workers for fn.
         *
         * Construction fails with dispatch_error if any worker cannot be spawned
         * within max_dispatch_attempts.
         */
        worker_pool(F& fn, worker_pool_options options);

        /**
         * @brief Stops all workers immediately.
         */
        ~worker_pool();

        worker_pool() = delete;
        worker_pool(const worker_pool&) = delete;
        worker_pool& operator=(const worker_pool&) = delete;

        /**
         * @brief Adds one task to the pending queue and returns its task id.
         *
         * Throws std::runtime_error after close() or stop_now().
         */
        std::uint64_t submit(args_tuple args);

        /**
         * @brief Blocks until one accepted task produces an isolated_result.
         *
         * If a pending task cannot be delivered after the retry budget, this
         * throws dispatch_error instead of manufacturing an isolated_result.
         */
        [[nodiscard]] result_type wait_one();

        /**
         * @brief Stops accepting new tasks but lets pending/in-flight tasks finish.
         */
        void close() noexcept;

        /**
         * @brief Drops pending work and stops all child processes immediately.
         */
        void stop_now() noexcept;

        /**
         * @brief Number of tasks accepted by submit().
         */
        [[nodiscard]] std::size_t submitted() const noexcept;

        /**
         * @brief Number of execution results returned to the ready/result path.
         */
        [[nodiscard]] std::size_t finished() const noexcept;

        /**
         * @brief Number of tasks waiting for dispatch to a worker.
         */
        [[nodiscard]] std::size_t pending() const noexcept;

        /**
         * @brief Number of tasks accepted by workers and not answered yet.
         */
        [[nodiscard]] std::size_t inflight() const noexcept;

        /**
         * @brief Fixed number of worker slots owned by this pool.
         */
        [[nodiscard]] std::size_t worker_count() const noexcept;

        /**
         * @brief True while submit() is allowed.
         */
        [[nodiscard]] bool accepting() const noexcept;

        /**
         * @brief True after stop_now() or destructor shutdown started.
         */
        [[nodiscard]] bool stopped() const noexcept;

        /**
         * @brief True only after close() and after all accepted work is consumed.
         */
        [[nodiscard]] bool drained() const noexcept;

    private:
        using worker_type = worker<F, Ts...>;

        /**
         * @brief Pending unit of work tracked until a worker accepts it.
         *
         * dispatch_attempts counts delivery attempts only. It is not execution
         * retry and is not incremented after a worker accepted the task.
         */
        struct task
        {
            std::uint64_t id {};
            args_tuple args {};
            std::size_t dispatch_attempts {};
        };

        /**
         * @brief Returns true if the pool still has pending, ready, or in-flight work.
         */
        [[nodiscard]] bool has_work() const noexcept;

        /**
         * @brief Removes and returns the next already completed result, if any.
         */
        [[nodiscard]] std::optional<result_type> pop_ready();

        /**
         * @brief Checks in-flight task deadlines and returns a timeout result, if one expired.
         *
         * Timeout detection is separate from poll(), because a hung target may
         * never make its fd readable.
         */
        [[nodiscard]] std::optional<result_type> collect_expired_task();

        /**
         * @brief Converts one pollfd event into a worker receive() result.
         *
         * The worker owns crash/protocol/ipc classification. The pool only adds
         * worker_index, queues the result, and respawns the worker if needed.
         */
        [[nodiscard]] std::optional<result_type> collect_worker_event(const pollfd& pfd);

        /**
         * @brief Starts worker at worker_index or throws dispatch_error after retry budget.
         *
         * Spawn failure is infrastructure failure. The pool should not silently
         * continue with a smaller worker set than requested.
         */
        void spawn_worker_or_throw(std::size_t worker_index);

        /**
         * @brief Moves pending tasks into currently idle workers.
         *
         * Successful send() makes the task in-flight. Failed send() remains a
         * delivery failure and goes through handle_send_failure().
         */
        void dispatch_idle_workers();

        /**
         * @brief Applies pool dispatch retry policy after worker.send() failed.
         *
         * If retries remain, the task is returned to pending. If not, this
         * throws dispatch_error. It never creates isolated_result.
         */
        void handle_send_failure(
            std::size_t worker_index,
            task item,
            const worker_send_result& send_result
        );

        /**
         * @brief Builds and throws a detailed dispatch_error.
         */
        void throw_dispatch_failure(
            const task& item,
            std::size_t worker_index,
            const worker_send_result& send_result
        ) const;

        /**
         * @brief Queues a completed execution result and advances finished count.
         */
        void finish_result(result_type result);

        /**
         * @brief Restarts a worker slot when the owned worker stopped or became broken.
         */
        void respawn_if_needed(std::size_t worker_index);

        /**
         * @brief Builds pollfd list for workers that currently wait for a response.
         */
        [[nodiscard]] std::vector<pollfd> pollable_fds() const;

        /**
         * @brief Resolves a pollfd descriptor back to its fixed worker slot.
         */
        [[nodiscard]] std::optional<std::size_t> find_worker_by_fd(int fd) const noexcept;

        /**
         * @brief Drops all pending tasks during immediate shutdown.
         */
        static void clear_pending(std::queue<task>& queue) noexcept;

        /**
         * @brief Drops all already completed but unconsumed results during immediate shutdown.
         */
        static void clear_ready(std::queue<result_type>& queue) noexcept;

    private:
        F& m_fn;
        worker_pool_options m_options;

        std::deque<worker_type> m_workers;
        std::queue<task> m_pending;
        std::queue<result_type> m_ready;

        std::uint64_t m_next_task_id { 1 };
        std::size_t m_submitted {};
        std::size_t m_finished {};

        bool m_accepting { true };
        bool m_stopped { false };
    };

    template <typename F, typename... Ts>
    worker_pool<F, Ts...>::worker_pool(F& fn, worker_pool_options options)
        : m_fn(fn),
          m_options(std::move(options))
    {
        if (m_options.worker_count == 0)
            throw std::invalid_argument("worker_pool worker_count must be greater than zero");

        if (m_options.max_dispatch_attempts == 0)
            m_options.max_dispatch_attempts = 1;

        // std::deque stores non-movable worker process handles without moving
        // existing elements. The count is still fixed: we emplace exactly once
        // here and never grow/shrink m_workers afterwards.
        for (std::size_t i = 0; i < m_options.worker_count; ++i)
            m_workers.emplace_back(m_fn, m_options.timeouts);

        for (std::size_t i = 0; i < m_workers.size(); ++i)
            spawn_worker_or_throw(i);
    }

    template <typename F, typename... Ts>
    worker_pool<F, Ts...>::~worker_pool()
    {
        stop_now();
    }

    template <typename F, typename... Ts>
    std::uint64_t worker_pool<F, Ts...>::submit(args_tuple args)
    {
        if (!m_accepting || m_stopped)
            throw std::runtime_error("cannot submit task to a closed worker_pool");

        task item {};
        item.id = m_next_task_id++;
        item.args = std::move(args);

        m_pending.push(std::move(item));
        ++m_submitted;

        dispatch_idle_workers();

        return m_next_task_id - 1;
    }

    template <typename F, typename... Ts>
    typename worker_pool<F, Ts...>::result_type worker_pool<F, Ts...>::wait_one()
    {
        while (true)
        {
            if (m_stopped)
                throw std::runtime_error("wait_one() called on a stopped worker_pool");

            // Always try dispatch first: a previous result/timeout may have
            // freed a worker, and pending work should move to child processes
            // before the pool starts waiting on fds.
            dispatch_idle_workers();

            if (auto ready = pop_ready())
                return *ready;

            // Task timeout is not tied to fd readiness. A stuck target may
            // never make the socket readable, so deadlines are checked before
            // poll() every loop iteration.
            if (auto timeout = collect_expired_task())
                return *timeout;

            if (!has_work())
            {
                if (!m_accepting)
                    throw std::runtime_error("wait_one() called on a drained worker_pool");

                std::this_thread::sleep_for(m_options.poll_timeout);
                continue;
            }

            auto fds = pollable_fds();

            if (fds.empty())
            {
                // This can happen while workers are being respawned or while
                // the pool is open but currently idle. The pool remains usable:
                // future submit() calls may add more work.
                std::this_thread::sleep_for(m_options.poll_timeout);
                continue;
            }

            const int rc = ::poll(fds.data(), fds.size(), static_cast<int>(m_options.poll_timeout.count()));

            if (rc < 0)
            {
                if (errno == EINTR)
                    continue;

                throw std::runtime_error("worker_pool poll() failed");
            }

            if (rc == 0)
                continue;

            for (const auto& pfd : fds)
            {
                if (pfd.revents == 0)
                    continue;

                if (auto result = collect_worker_event(pfd))
                    return *result;
            }
        }
    }

    template <typename F, typename... Ts>
    void worker_pool<F, Ts...>::close() noexcept
    {
        m_accepting = false;
    }

    template <typename F, typename... Ts>
    void worker_pool<F, Ts...>::stop_now() noexcept
    {
        m_accepting = false;
        m_stopped = true;

        clear_pending(m_pending);
        clear_ready(m_ready);

        for (auto& item : m_workers)
            item.stop();
    }

    template <typename F, typename... Ts>
    std::size_t worker_pool<F, Ts...>::submitted() const noexcept
    {
        return m_submitted;
    }

    template <typename F, typename... Ts>
    std::size_t worker_pool<F, Ts...>::finished() const noexcept
    {
        return m_finished;
    }

    template <typename F, typename... Ts>
    std::size_t worker_pool<F, Ts...>::pending() const noexcept
    {
        return m_pending.size();
    }

    template <typename F, typename... Ts>
    std::size_t worker_pool<F, Ts...>::inflight() const noexcept
    {
        std::size_t count = 0;

        for (const auto& item : m_workers)
        {
            if (item.busy())
                ++count;
        }

        return count;
    }

    template <typename F, typename... Ts>
    std::size_t worker_pool<F, Ts...>::worker_count() const noexcept
    {
        return m_workers.size();
    }

    template <typename F, typename... Ts>
    bool worker_pool<F, Ts...>::accepting() const noexcept
    {
        return m_accepting;
    }

    template <typename F, typename... Ts>
    bool worker_pool<F, Ts...>::stopped() const noexcept
    {
        return m_stopped;
    }

    template <typename F, typename... Ts>
    bool worker_pool<F, Ts...>::drained() const noexcept
    {
        return !m_accepting && !has_work();
    }

    template <typename F, typename... Ts>
    bool worker_pool<F, Ts...>::has_work() const noexcept
    {
        return !m_pending.empty() || !m_ready.empty() || inflight() != 0;
    }

    template <typename F, typename... Ts>
    std::optional<typename worker_pool<F, Ts...>::result_type> worker_pool<F, Ts...>::pop_ready()
    {
        if (m_ready.empty())
            return std::nullopt;

        auto result = std::move(m_ready.front());
        m_ready.pop();
        return result;
    }

    template <typename F, typename... Ts>
    std::optional<typename worker_pool<F, Ts...>::result_type> worker_pool<F, Ts...>::collect_expired_task()
    {
        const auto now = std::chrono::steady_clock::now();

        for (std::size_t i = 0; i < m_workers.size(); ++i)
        {
            auto result = m_workers[i].expire_if_timed_out(now);

            if (!result.has_value())
                continue;

            result->worker_index = i;
            finish_result(std::move(*result));
            respawn_if_needed(i);

            return pop_ready();
        }

        return std::nullopt;
    }

    template <typename F, typename... Ts>
    std::optional<typename worker_pool<F, Ts...>::result_type> worker_pool<F, Ts...>::collect_worker_event(
        const pollfd& pfd
    )
    {
        if (!(pfd.revents & (POLLIN | POLLHUP | POLLERR | POLLNVAL)))
            return std::nullopt;

        const auto worker_index = find_worker_by_fd(pfd.fd);

        if (!worker_index.has_value())
            return std::nullopt;

        auto result = m_workers[*worker_index].receive();
        result.worker_index = *worker_index;
        finish_result(std::move(result));
        respawn_if_needed(*worker_index);

        return pop_ready();
    }

    template <typename F, typename... Ts>
    void worker_pool<F, Ts...>::spawn_worker_or_throw(std::size_t worker_index)
    {
        auto& item = m_workers[worker_index];

        if (item.alive())
            return;

        for (std::size_t attempt = 0; attempt < m_options.max_dispatch_attempts; ++attempt)
        {
            if (item.spawn())
                return;
        }

        throw dispatch_error(
            "failed to spawn worker " +
            std::to_string(worker_index) +
            " after " +
            std::to_string(m_options.max_dispatch_attempts) +
            " attempt(s)"
        );
    }

    template <typename F, typename... Ts>
    void worker_pool<F, Ts...>::dispatch_idle_workers()
    {
        if (m_pending.empty())
            return;

        for (std::size_t i = 0; i < m_workers.size(); ++i)
        {
            if (m_pending.empty())
                return;

            auto& current_worker = m_workers[i];

            if (current_worker.busy())
                continue;

            if (!current_worker.alive())
                spawn_worker_or_throw(i);

            if (!current_worker.idle())
                continue;

            task item = std::move(m_pending.front());
            m_pending.pop();

            // send() is delivery only. Accepted means the worker owns the task
            // and receive()/timeout will later produce isolated_result. Anything
            // else means user code has not executed.
            const auto send_result = current_worker.send(item.id, item.args);

            if (send_result.accepted())
                continue;

            handle_send_failure(i, std::move(item), send_result);
        }
    }

    template <typename F, typename... Ts>
    void worker_pool<F, Ts...>::handle_send_failure(
        std::size_t worker_index,
        task item,
        const worker_send_result& send_result
    )
    {
        ++item.dispatch_attempts;

        // The task was not accepted by a worker, so this is still dispatch
        // policy. Execution retry is intentionally not mixed into this branch.
        if (send_result.worker_is_poisoned())
            respawn_if_needed(worker_index);

        if (
            send_result.status != worker_send_status::serialize_error &&
            item.dispatch_attempts < m_options.max_dispatch_attempts
        )
        {
            m_pending.push(std::move(item));
            return;
        }

        throw_dispatch_failure(item, worker_index, send_result);
    }

    template <typename F, typename... Ts>
    void worker_pool<F, Ts...>::throw_dispatch_failure(
        const task& item,
        std::size_t worker_index,
        const worker_send_result& send_result
    ) const
    {
        std::string message = "failed to dispatch task " +
            std::to_string(item.id) +
            " through worker " +
            std::to_string(worker_index) +
            " after " +
            std::to_string(item.dispatch_attempts) +
            " attempt(s): " +
            worker_send_status_name(send_result.status);

        if (!send_result.message.empty())
            message += ": " + send_result.message;

        throw dispatch_error(message);
    }

    template <typename F, typename... Ts>
    void worker_pool<F, Ts...>::finish_result(result_type result)
    {
        m_ready.push(std::move(result));
        ++m_finished;
    }

    template <typename F, typename... Ts>
    void worker_pool<F, Ts...>::respawn_if_needed(std::size_t worker_index)
    {
        auto& item = m_workers[worker_index];

        if (item.alive() && !item.broken())
            return;

        spawn_worker_or_throw(worker_index);
    }

    template <typename F, typename... Ts>
    std::vector<pollfd> worker_pool<F, Ts...>::pollable_fds() const
    {
        std::vector<pollfd> fds;
        fds.reserve(m_workers.size());

        for (const auto& item : m_workers)
        {
            if (!item.pollable())
                continue;

            pollfd pfd {};
            pfd.fd = item.fd();
            pfd.events = POLLIN | POLLHUP | POLLERR;
            pfd.revents = 0;
            fds.push_back(pfd);
        }

        return fds;
    }

    template <typename F, typename... Ts>
    std::optional<std::size_t> worker_pool<F, Ts...>::find_worker_by_fd(int fd) const noexcept
    {
        for (std::size_t i = 0; i < m_workers.size(); ++i)
        {
            if (m_workers[i].fd() == fd)
                return i;
        }

        return std::nullopt;
    }

    template <typename F, typename... Ts>
    void worker_pool<F, Ts...>::clear_pending(std::queue<task>& queue) noexcept
    {
        std::queue<task> empty;
        queue.swap(empty);
    }

    template <typename F, typename... Ts>
    void worker_pool<F, Ts...>::clear_ready(std::queue<result_type>& queue) noexcept
    {
        std::queue<result_type> empty;
        queue.swap(empty);
    }
}

#endif
#endif // WORKER_POOL_HPP
