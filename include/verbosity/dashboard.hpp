#ifndef VERBOSITY_DASHBOARD_HPP
#define VERBOSITY_DASHBOARD_HPP

#include <condition_variable>
#include <cstdio>
#include <deque>
#include <iostream>
#include <mutex>
#include <thread>
#include <utility>
#include <vector>

#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <io.h>
#include <windows.h>
#else
#include <unistd.h>
#endif

#include "verbosity/console_formatter.hpp"
#include "verbosity/scraper.hpp"
#include "verbosity/specs.h"

namespace hotfuzz
{
    /**
     * @brief Background terminal dashboard for live metrics and recent failures.
     */
    class console_dashboard
    {
    public:
        explicit console_dashboard(const verbosity_options& options)
            : m_options(options),
              m_formatter(options.colors),
              m_active(terminal_supported())
        {
            if (!m_active)
                return;

            prepare_terminal();
            m_thread = std::thread([this] { run(); });
        }

        ~console_dashboard()
        {
            if (!m_active)
                return;

            {
                std::lock_guard lock(m_mutex);
                m_stopped = true;
            }

            m_cv.notify_all();

            if (m_thread.joinable())
                m_thread.join();

            render_current_frame();
            restore_terminal();
        }

        void publish(failure_event event)
        {
            if (!m_active)
                return;

            {
                std::lock_guard lock(m_mutex);
                m_failures.push_back(std::move(event));

                while (m_failures.size() > m_options.recent_failure_limit)
                    m_failures.pop_front();
            }

            m_cv.notify_all();
        }

    private:
        static bool terminal_supported()
        {
#ifdef _WIN32
            return _isatty(_fileno(stdout)) != 0;
#else
            return isatty(fileno(stdout)) != 0;
#endif
        }

        void prepare_terminal()
        {
#ifdef _WIN32
            HANDLE handle = GetStdHandle(STD_OUTPUT_HANDLE);

            if (handle != INVALID_HANDLE_VALUE && GetConsoleMode(handle, &m_original_console_mode) != 0)
            {
                DWORD requested_mode = m_original_console_mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING;

                if (SetConsoleMode(handle, requested_mode) != 0)
                    m_console_mode_saved = true;
            }
#endif

            std::cout << "\x1b[2J\x1b[H\x1b[?25l" << std::flush;
        }

        void restore_terminal()
        {
            std::cout << "\x1b[0m\x1b[?25h\n" << std::flush;

#ifdef _WIN32
            if (m_console_mode_saved)
            {
                HANDLE handle = GetStdHandle(STD_OUTPUT_HANDLE);

                if (handle != INVALID_HANDLE_VALUE)
                    (void)SetConsoleMode(handle, m_original_console_mode);
            }
#endif
        }

        void run()
        {
            while (true)
            {
                {
                    std::unique_lock lock(m_mutex);

                    if (m_stopped)
                        break;
                }

                render_current_frame();

                std::unique_lock lock(m_mutex);

                if (m_cv.wait_for(lock, m_options.refresh_interval, [this] { return m_stopped; }))
                    break;
            }
        }

        void render_current_frame()
        {
            std::vector<failure_event> failures;

            {
                std::lock_guard lock(m_mutex);
                failures.assign(m_failures.begin(), m_failures.end());
            }

            auto metrics = m_scraper.sample();
            auto frame = m_formatter.render(metrics, failures);

            std::cout << "\x1b[H" << frame << "\x1b[J" << std::flush;
        }

    private:
        verbosity_options m_options;
        console_formatter m_formatter;
        system_scraper m_scraper;
        bool m_active { false };
        bool m_stopped { false };
        std::mutex m_mutex;
        std::condition_variable m_cv;
        std::deque<failure_event> m_failures;
        std::thread m_thread;

#ifdef _WIN32
        DWORD m_original_console_mode {};
        bool m_console_mode_saved { false };
#endif
    };
}

#endif // VERBOSITY_DASHBOARD_HPP
