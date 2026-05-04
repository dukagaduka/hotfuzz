#ifndef WORKER_SPECS_H
#define WORKER_SPECS_H

#include <csignal>
#include <cstdint>
#include <string>
#include <tuple>

namespace hotfuzz
{
    enum class isolated_status : std::uint8_t
    {
        ok = 1,
        exception = 2,
        crash = 3,
        protocol_error = 4,
        timeout = 5,
        unsuccessful_trial = 6
    };

    inline const char* isolated_status_name(isolated_status status)
    {
        switch (status)
        {
            case isolated_status::ok: return "ok";
            case isolated_status::exception: return "exception";
            case isolated_status::crash: return "crash";
            case isolated_status::protocol_error: return "protocol_error";
            case isolated_status::timeout: return "timeout";
            case isolated_status::unsuccessful_trial: return "unsuccessful_trial";
            default: return "unknown";
        }
    }

    inline std::string signal_name(int sig)
    {
        switch (sig)
        {
            case SIGSEGV: return "SIGSEGV";
            case SIGABRT: return "SIGABRT";
            case SIGFPE:  return "SIGFPE";
            case SIGILL:  return "SIGILL";
            case SIGBUS:  return "SIGBUS";
            case SIGKILL: return "SIGKILL";
            case SIGTERM: return "SIGTERM";
            
            default: return "signal(" + std::to_string(sig) + ")";
        }
    }

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

}

#endif // WORKER_SPECS_H
