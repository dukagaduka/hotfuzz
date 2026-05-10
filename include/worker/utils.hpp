#ifndef WORKER_UTILS_HPP
#define WORKER_UTILS_HPP

#include <csignal>
#include <string>

#include "worker/specs.h"

namespace hotfuzz
{
    /**
     * @brief Text name for worker_send_status diagnostics.
     */
    inline const char* worker_send_status_name(worker_send_status status)
    {
        switch (status)
        {
            case worker_send_status::accepted: return "accepted";
            case worker_send_status::busy: return "busy";
            case worker_send_status::stopped: return "stopped";
            case worker_send_status::serialize_error: return "serialize_error";
            case worker_send_status::timeout: return "timeout";
            case worker_send_status::disconnected: return "disconnected";
            case worker_send_status::io_error: return "io_error";
            default: return "unknown";
        }
    }


    /**
     * @brief Text name for isolated_status diagnostics.
     */
    inline const char* isolated_status_name(isolated_status status)
    {
        switch (status)
        {
            case isolated_status::ok: return "ok";
            case isolated_status::exception: return "exception";
            case isolated_status::crash: return "crash";
            case isolated_status::timeout: return "timeout";
            case isolated_status::protocol_error: return "protocol_error";
            case isolated_status::ipc_error: return "ipc_error";
            case isolated_status::internal_error: return "internal_error";
            default: return "unknown";
        }
    }


    /**
     * @brief Text name for common process termination signals.
     */
    inline std::string signal_name(int sig)
    {
        switch (sig)
        {
            case SIGSEGV: return "SIGSEGV";
            case SIGABRT: return "SIGABRT";
            case SIGFPE:  return "SIGFPE";
            case SIGILL:  return "SIGILL";
#ifdef SIGBUS
            case SIGBUS:  return "SIGBUS";
#endif
#ifdef SIGKILL
            case SIGKILL: return "SIGKILL";
#endif
#ifdef SIGTERM
            case SIGTERM: return "SIGTERM";
#endif

            default: return "signal(" + std::to_string(sig) + ")";
        }
    }
}

#endif // WORKER_UTILS_HPP
