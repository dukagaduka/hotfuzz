#ifndef WORKER_POOL_HPP
#define WORKER_POOL_HPP

#ifndef _WIN32

#include <atomic>
#include <cerrno>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <condition_variable>
#include <deque>
#include <mutex>
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
#include "worker/utils.hpp"

namespace hotfuzz
{
    /**
     * @brief Scheduler over a fixed set of isolated worker processes.
     *
     * The pool owns task queues, dispatch retry policy, poll(), and worker
     * respawn. It does not reinterpret execution results: accepted tasks return
     * isolated_result, while delivery failure after retries throws dispatch_error.
     * submit(), wait_one(), stop(), stop_immediately(), and state accessors are
     * synchronized for producer/consumer use from different threads.
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
         * Throws std::runtime_error after stop() or stop_immediately().
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
        void stop() noexcept;

        /**
         * @brief Drops pending work and stops all child processes immediately.
         */
        void stop_immediately() noexcept;

        /**
         * @brief Number of tasks accepted by submit().
         */
        [[nodiscard]] std::size_t submitted() const noexcept;

        /**
         * @brief Number of execution results returned by wait_one().
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
         * @brief True after stop_immediately() or destructor shutdown started.
         */
        [[nodiscard]] bool stopped() const noexcept;

        /**
         * @brief True only after stop() and after all accepted work is consumed.
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
         * @brief Returns true if the pool still has pending or in-flight work.
         *
         * @pre m_pending_mutex and m_workers_mutex are held by the caller.
         */
        [[nodiscard]] bool has_work() const noexcept;

        /**
         * @brief Checks in-flight task deadlines and returns a timeout result, if one expired.
         *
         * Timeout detection is separate from poll(), because a hung target may
         * never make its fd readable.
         *
         * @pre m_workers_mutex is held by the caller.
         */
        [[nodiscard]] std::optional<result_type> collect_expired_task();

        /**
         * @brief Converts one pollfd event into a worker receive() result.
         *
         * The worker owns crash/protocol/ipc classification. The pool only adds
         * worker_index, queues the result, and respawns the worker if needed.
         *
         * @pre m_workers_mutex is held by the caller.
         */
        [[nodiscard]] std::optional<result_type> collect_worker_event(const pollfd& pfd);

        /**
         * @brief Starts worker at worker_index or throws dispatch_error after retry budget.
         *
         * Spawn failure is infrastructure failure. The pool should not silently
         * continue with a smaller worker set than requested.
         *
         * @pre m_workers_mutex is held by the caller.
         */
        void spawn_worker_or_throw(std::size_t worker_index);

        /**
         * @brief Moves pending tasks into currently idle workers.
         *
         * Successful send() makes the task in-flight. Failed send() is still
         * dispatch policy because user code has not executed yet.
         *
         * @pre m_pending_mutex and m_workers_mutex are held by the caller.
         */
        void dispatch_pending_tasks();

        /**
         * @brief Builds and throws a detailed dispatch_error.
         */
        void throw_dispatch_failure(
            const task& item,
            std::size_t worker_index,
            const worker_send_result& send_result
        ) const;

        /**
         * @brief Restarts a worker slot when the owned worker stopped or became broken.
         *
         * @pre m_workers_mutex is held by the caller.
         */
        void respawn_if_needed(std::size_t worker_index);

        /**
         * @brief Builds pollfd list for workers that currently wait for a response.
         *
         * @pre m_workers_mutex is held by the caller.
         */
        [[nodiscard]] std::vector<pollfd> pollable_fds() const;

        /**
         * @brief Resolves a pollfd descriptor back to its fixed worker slot.
         *
         * @pre m_workers_mutex is held by the caller.
         */
        [[nodiscard]] std::optional<std::size_t> find_worker_by_fd(int fd) const noexcept;

        /**
         * @brief Drops all pending tasks during immediate shutdown.
         */
        static void clear_pending(std::queue<task>& queue) noexcept;

    private:
        F& m_fn;
        worker_pool_options m_options;

        std::deque<worker_type> m_workers;
        std::queue<task> m_pending;

        std::uint64_t m_next_task_id { 1 };
        std::size_t m_submitted {};
        std::size_t m_finished {};

        std::atomic<pool_state> m_state { pool_state::accepting };

        mutable std::mutex m_pending_mutex;
        mutable std::mutex m_workers_mutex;
        std::condition_variable m_pending_cv;

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

        // worker owns a pid/fd pair and is intentionally non-copyable/non-movable.
        // std::deque lets us emplace these worker slots without relocating existing
        // elements as the container grows. The pool size is still fixed: all slots are
        // created here once, and later respawn() only replaces child processes inside
        // the same slots.
        for (std::size_t i = 0; i < m_options.worker_count; ++i)
            m_workers.emplace_back(m_fn, m_options.timeouts);

        {
            std::lock_guard lock(m_workers_mutex);

            for (std::size_t i = 0; i < m_workers.size(); ++i)
                spawn_worker_or_throw(i);
        }
    }


    template <typename F, typename... Ts>
    worker_pool<F, Ts...>::~worker_pool()
    {
        stop_immediately();
    }


    template <typename F, typename... Ts>
    std::uint64_t worker_pool<F, Ts...>::submit(args_tuple args)
    {
        std::uint64_t task_id {};

        {
            std::lock_guard lock(m_pending_mutex);

            if (m_state.load() != pool_state::accepting)
                throw std::runtime_error("cannot submit task to a non-accepting worker_pool");

            task item {};
            item.id = m_next_task_id++;
            item.args = std::move(args);

            task_id = item.id;

            m_pending.push(std::move(item));
            ++m_submitted;
        }

        m_pending_cv.notify_one();

        return task_id;
    }


    template <typename F, typename... Ts>
    typename worker_pool<F, Ts...>::result_type worker_pool<F, Ts...>::wait_one()
    {
        while (true)
        {
            if (m_state.load() == pool_state::stopped)
                throw std::runtime_error("wait_one() called on a stopped worker_pool");

            {
                // Always try dispatch first: a previous result/timeout may have
                // freed a worker, and pending work should move to child processes
                // before the pool starts waiting on fds.
                std::scoped_lock lock(m_pending_mutex, m_workers_mutex);

                if (m_state.load() == pool_state::stopped)
                    throw std::runtime_error("wait_one() called on a stopped worker_pool");

                dispatch_pending_tasks();
            }

            {
                std::unique_lock lock(m_workers_mutex);

                if (m_state.load() == pool_state::stopped)
                    throw std::runtime_error("wait_one() called on a stopped worker_pool");

                // Task timeout is not tied to fd readiness. A stuck target may
                // never make the socket readable, so deadlines are checked before
                // poll() every loop iteration.
                if (auto timeout = collect_expired_task())
                    return *timeout;
            }

            bool has_any_work {};

            {
                std::scoped_lock lock(m_pending_mutex, m_workers_mutex);
                has_any_work = has_work();

                if (!has_any_work && m_state.load() == pool_state::finishing)
                    throw std::runtime_error("wait_one() called on a drained worker_pool");
            }

            if (!has_any_work)
            {
                std::unique_lock lock(m_pending_mutex);

                m_pending_cv.wait(
                    lock,
                    [this]
                    {
                        return !m_pending.empty() ||
                               m_state.load() != pool_state::accepting;
                    }
                );

                continue;
            }

            {
                std::unique_lock lock(m_workers_mutex);

                if (m_state.load() == pool_state::stopped)
                    throw std::runtime_error("wait_one() called on a stopped worker_pool");

                auto fds = pollable_fds();

                if (fds.empty())
                {
                    // Work exists, but no worker is currently waiting on a
                    // response fd. Pending tasks may be waiting for busy slots
                    // to finish or for the next dispatch pass to accept them.
                    lock.unlock();
                    std::this_thread::sleep_for(m_options.poll_timeout);
                    continue;
                }

                const int rc = ::poll(
                    fds.data(),
                    fds.size(),
                    static_cast<int>(m_options.poll_timeout.count())
                );

                if (rc < 0)
                {
                    if (errno == EINTR)
                        continue;

                    throw std::runtime_error("worker_pool poll() failed");
                }

                // timeout
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
    }


    template <typename F, typename... Ts>
    void worker_pool<F, Ts...>::stop() noexcept
    {
        pool_state expected = pool_state::accepting;
        (void)m_state.compare_exchange_strong(expected, pool_state::finishing);
        m_pending_cv.notify_all();
    }


    template <typename F, typename... Ts>
    void worker_pool<F, Ts...>::stop_immediately() noexcept
    {
        m_state.store(pool_state::stopped);

        {
            std::scoped_lock lock(m_pending_mutex, m_workers_mutex);

            clear_pending(m_pending);

            for (auto& item : m_workers)
                item.stop();
        }

        m_pending_cv.notify_all();
    }


    template <typename F, typename... Ts>
    std::size_t worker_pool<F, Ts...>::submitted() const noexcept
    {
        std::lock_guard lock(m_pending_mutex);
        return m_submitted;
    }


    template <typename F, typename... Ts>
    std::size_t worker_pool<F, Ts...>::finished() const noexcept
    {
        std::lock_guard lock(m_workers_mutex);
        return m_finished;
    }


    template <typename F, typename... Ts>
    std::size_t worker_pool<F, Ts...>::pending() const noexcept
    {
        std::lock_guard lock(m_pending_mutex);
        return m_pending.size();
    }


    template <typename F, typename... Ts>
    std::size_t worker_pool<F, Ts...>::inflight() const noexcept
    {
        std::lock_guard lock(m_workers_mutex);
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
        std::lock_guard lock(m_workers_mutex);
        return m_workers.size();
    }


    template <typename F, typename... Ts>
    bool worker_pool<F, Ts...>::accepting() const noexcept
    {
        return m_state.load() == pool_state::accepting;
    }


    template <typename F, typename... Ts>
    bool worker_pool<F, Ts...>::stopped() const noexcept
    {
        return m_state.load() == pool_state::stopped;
    }


    template <typename F, typename... Ts>
    bool worker_pool<F, Ts...>::drained() const noexcept
    {
        std::scoped_lock lock(m_pending_mutex, m_workers_mutex);
        return m_state.load() == pool_state::finishing && !has_work();
    }


    template <typename F, typename... Ts>
    bool worker_pool<F, Ts...>::has_work() const noexcept
    {
        if (!m_pending.empty())
            return true;

        for (const auto& item : m_workers)
        {
            if (item.busy())
                return true;
        }

        return false;
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
            ++m_finished;
            respawn_if_needed(i);

            return result;
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
        ++m_finished;
        respawn_if_needed(*worker_index);

        return result;
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
    void worker_pool<F, Ts...>::dispatch_pending_tasks()
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

            ++item.dispatch_attempts;

            // The task was not accepted by a worker, so this is still dispatch
            // policy. Execution retry is intentionally not mixed into this branch.
            if (send_result.worker_is_poisoned())
                respawn_if_needed(i);

            if (
                send_result.status != worker_send_status::serialize_error &&
                item.dispatch_attempts < m_options.max_dispatch_attempts
            )
            {
                m_pending.push(std::move(item));
                continue;
            }

            throw_dispatch_failure(item, i, send_result);
        }
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
}

#endif
#endif // WORKER_POOL_HPP
