#ifndef HOTFUZZ_HPP
#define HOTFUZZ_HPP

#include <concepts>
#include <optional>
#include <stdexcept>
#include <utility>

#include "data/providers.hpp"
#include "fuzz/failure_recorder.hpp"
#include "fuzz/specs.h"
#include "fuzz/utils.hpp"
#include "serialization/api.hpp"
#include "verbosity/scraper.hpp"

namespace hotfuzz
{
    /**
     * @brief Run fuzzing in selected mode.
     *
     * options.isolation_mode == false keeps in-process execution. In-process
     * mode can record exceptions, but crashes still terminate the current
     * process. options.isolation_mode == true runs each invocation through
     * worker_pool. Not supported on Windows.
     */
    template <typename F, typename... Ts>
    requires std::invocable<F&, Ts...>
    void fuzz(
        F&& f,
        run_mode mode,
        const fuzz_options& options,
        base_provider<Ts>&... providers
    )
    {
        static_assert(
            (serializable_v<Ts> && ...),
            "hotfuzz::fuzz requires all argument types to be serializable"
        );

        auto& fn = f;
        std::optional<failure_recorder> recorder;

        if (options.use_recorder)
            recorder.emplace(options.output_dir);

        failure_recorder* recorder_ptr = recorder ? &*recorder : nullptr;

        if (!options.isolation_mode)
        {
            utils::run_in_process_fuzz(fn, mode, options, recorder_ptr, providers...);
            return;
        }

#ifdef _WIN32
        throw std::runtime_error("hotfuzz isolation mode is not supported on WIN32");
#else
        utils::run_isolated_fuzz(fn, mode, options, recorder_ptr, providers...);
#endif
    }


    /**
     * @brief Run fuzzing with default fuzz_options.
     */
    template <typename F, typename... Ts>
    requires std::invocable<F&, Ts...>
    void fuzz(F&& f, run_mode mode, base_provider<Ts>&... providers)
    {
        fuzz(std::forward<F>(f), mode, fuzz_options {}, providers...);
    }
}

#endif // HOTFUZZ_HPP
