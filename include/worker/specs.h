#ifndef WORKER_SPECS_H
#define WORKER_SPECS_H

#include <chrono>
#include <cstdint>
#include <optional>
#include <stdexcept>
#include <string>
#include <tuple>

namespace hotfuzz
{
    /**
     * @brief Parent-side lifecycle state for one isolated child process.
     */
    enum class worker_state : std::uint8_t
    {
        stopped,
        idle,
        busy,
        broken
    };


    /**
     * @brief Lifecycle state for worker_pool scheduling.
     *
     * accepting allows submit(). finishing rejects new tasks but keeps pending
     * and in-flight work alive so wait_one() can drain results. stopped is the
     * immediate-shutdown state where pending/ready queues are discarded and
     * child processes are stopped.
     */
    enum class pool_state : std::uint8_t
    {
        accepting,
        finishing,
        stopped
    };


    /**
     * @brief Bounded operation deadlines used by worker.
     *
     * send_timeout bounds request delivery, frame_timeout bounds reading a
     * ready response frame, and task_timeout bounds target execution time.
     */
    struct worker_timeouts
    {
        std::chrono::milliseconds send_timeout { 100 };
        std::chrono::milliseconds frame_timeout { 100 };
        std::optional<std::chrono::milliseconds> task_timeout { std::chrono::milliseconds { 1000 } };
    };


    /**
     * @brief Child process exit codes used to distinguish worker infra from target crashes.
     */
    inline constexpr int worker_exit_ok = 0;
    inline constexpr int worker_exit_protocol_error = 70;
    inline constexpr int worker_exit_ipc_error = 71;
    inline constexpr int worker_exit_internal_error = 72;


    /**
     * @brief Thrown when worker_pool cannot deliver a task after its retry budget.
     */
    class dispatch_error : public std::runtime_error
    {
    public:
        using std::runtime_error::runtime_error;
    };


    /**
     * @brief Delivery result for sending a task to a worker.
     */
    enum class worker_send_status : std::uint8_t
    {
        accepted,
        busy,
        stopped,
        serialize_error,
        timeout,
        disconnected,
        io_error
    };


    struct worker_send_result
    {
        worker_send_status status { worker_send_status::stopped };
        std::uint64_t task_id {};
        std::string message;

        [[nodiscard]] bool accepted() const noexcept
        {
            return status == worker_send_status::accepted;
        }

        [[nodiscard]] bool task_was_not_executed() const noexcept
        {
            return status != worker_send_status::accepted;
        }

        [[nodiscard]] bool worker_is_poisoned() const noexcept
        {
            return status == worker_send_status::timeout ||
                   status == worker_send_status::disconnected ||
                   status == worker_send_status::io_error;
        }
    };

    /**
     * @brief Execution result for a task that was accepted by a worker.
     */
    enum class isolated_status : std::uint8_t
    {
        ok = 1,
        exception = 2,
        crash = 3,
        timeout = 4,
        protocol_error = 5,
        ipc_error = 6,
        internal_error = 7
    };

    template <typename... Ts>
    struct isolated_result
    {
        std::uint64_t task_id {};
        std::size_t worker_index {};

        isolated_status status { isolated_status::ok };

        int signal_number { 0 };
        int exit_code { 0 };

        std::string message;

        std::tuple<Ts...> args {};
    };

    /**
     * @brief Scheduling and delivery policy for worker_pool.
     *
     * worker_count is fixed for the lifetime of the pool. max_dispatch_attempts
     * limits delivery attempts before the pool throws dispatch_error.
     */
    struct worker_pool_options
    {
        std::size_t worker_count { 1 };
        std::size_t max_dispatch_attempts { 3 };
        std::chrono::milliseconds poll_timeout { 50 };
        worker_timeouts timeouts {};
    };
    
}

#endif // WORKER_SPECS_H
