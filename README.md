# hotfuzz

`hotfuzz` - header-only C++23 библиотека для простого fuzzing'а функций.
Основная идея: пользователь задает функцию и набор providers, библиотека
перебирает аргументы, ловит исключения/краши, сохраняет воспроизводимые
артефакты и при необходимости показывает live-dashboard в терминале.

Публичная точка входа:

```cpp
#include "hotfuzz.hpp"
```

Все, что обычно нужно пользователю, подтягивается через этот include:

- `hotfuzz::fuzz`
- `hotfuzz::fuzz_options`
- `hotfuzz::run_mode`
- `hotfuzz::base_provider`
- `hotfuzz::std_random_provider`
- `hotfuzz::iterable_provider`
- `hotfuzz::std_random_generator`
- `hotfuzz::serializer<T>`
- `hotfuzz::to_bytes`
- `hotfuzz::from_bytes`
- `hotfuzz::load_fuzz_args`
- `hotfuzz::worker_timeouts`
- `hotfuzz::verbosity_options`


## Требования

- C++23
- CMake 3.16+
- Linux/macOS/Windows для in-process режима
- Linux для isolated worker режима
- Windows поддерживает сборку публичного API и system metrics scraper, но
  isolated mode сейчас недоступен

Проект подключает `nlohmann/json` из `third_party/nlohmann/include` через CMake.
На Windows дополнительно линкуется `psapi`, потому что dashboard собирает RSS
текущего процесса через WinAPI.

## Минимальное подключение через CMake

```cmake
add_subdirectory(hotfuzz)

add_executable(app main.cpp)
target_link_libraries(app PRIVATE hotfuzz)
```

Если библиотека лежит не как subdirectory, достаточно повторить интерфейсные
include paths:

```cmake
target_include_directories(app PRIVATE
    /path/to/hotfuzz/include
    /path/to/hotfuzz/third_party/nlohmann/include
)
```

## Главный flow

Пользовательский flow выглядит так:

1. Описать target-функцию.
2. Для нестандартных типов добавить `serializer<T>`.
3. Подготовить providers аргументов.
4. Вызвать `hotfuzz::fuzz(...)`.
5. Если включен recorder, изучать `errors_and_crashes.json` и файлы `.args`.
6. При необходимости воспроизвести конкретный `.args` через `run_mode::bin`
   или вручную через `load_fuzz_args`.

Пример:

```cpp
#include "hotfuzz.hpp"

#include <cstdint>
#include <filesystem>
#include <stdexcept>
#include <string>
#include <tuple>
#include <utility>
#include <vector>

class divider
{
public:
    divider() = default;
    divider(std::string name, int value)
        : m_name(std::move(name)), m_value(value)
    {}

    const std::string& name() const noexcept { return m_name; }
    int value() const noexcept { return m_value; }

    int divide(int dividend) const
    {
        if (m_value == 0)
            throw std::runtime_error("division by zero");

        return dividend / m_value;
    }

private:
    std::string m_name;
    int m_value {};
};

void target(int dividend, const divider& d)
{
    (void)d.divide(dividend);
}

namespace hotfuzz
{
    template <>
    struct serializer<divider>
    {
        static std::vector<std::uint8_t> to_bytes(const divider& value)
        {
            return hotfuzz::to_bytes(
                std::tuple<std::string, int>{ value.name(), value.value() }
            );
        }

        static divider from_bytes(const std::vector<std::uint8_t>& bytes)
        {
            auto [name, value] =
                hotfuzz::from_bytes<std::tuple<std::string, int>>(bytes);

            return divider(std::move(name), value);
        }
    };
}
```

## Providers

Provider - это источник значений для одного аргумента функции.

Базовый интерфейс:

```cpp
template <typename T>
class base_provider
{
public:
    explicit base_provider(std::size_t max_idx);

    std::size_t idx() const;
    std::size_t max() const;

    T iter();
    virtual void reset();

protected:
    virtual T next() = 0;
};
```

`iter()`:

- проверяет, не исчерпан ли provider
- вызывает `next()`
- увеличивает внутренний индекс
- при исчерпании бросает `hotfuzz::exhaustion_signal`

Обычно пользователь переопределяет только `next()`.

### std_random_provider

`std_random_provider<T>` генерирует значения для стандартных arithmetic типов:

```cpp
hotfuzz::std_random_provider<int> ints(1000, 42, -10, 10);
hotfuzz::std_random_provider<double> doubles(1000, 7, 0.0, 1.0);
hotfuzz::std_random_provider<bool> bools(1000, 11, 0.2);
```

Параметры:

- `max_idx` - сколько значений provider отдаст до exhaustion
- `seed` - seed генератора
- `low/high` - диапазон для чисел
- `true_probability` - вероятность `true` для `bool`

### iterable_provider

`iterable_provider` ходит по iterable-объекту:

```cpp
std::vector<int> values { 1, 2, 3 };
hotfuzz::iterable_provider provider(10, values);
```

Если `max_idx` больше размера контейнера, provider циклически возвращается к
началу контейнера.

### Custom provider

```cpp
class divider_provider : public hotfuzz::base_provider<divider>
{
public:
    explicit divider_provider(std::size_t count)
        : hotfuzz::base_provider<divider>(count)
    {
        m_values.reserve(count);

        for (std::size_t i = 0; i < count; ++i)
            m_values.emplace_back("divider_" + std::to_string(i), 1 + static_cast<int>(i % 40));

        if (!m_values.empty())
            m_values[count / 2] = divider("zero", 0);
    }

protected:
    divider next() override
    {
        return m_values[this->idx()];
    }

private:
    std::vector<divider> m_values;
};
```

Важно: `zip` mode идет от текущего состояния providers. Если один и тот же
provider переиспользуется в нескольких `fuzz(...)` вызовах, его нужно сбросить
через `reset()` или создать заново.

## Serialization

`hotfuzz::fuzz` запрещает запуск на несериализуемых типах. Это нужно, чтобы:

- отправлять аргументы в worker process в isolated mode
- сохранять `.args` артефакты
- восстанавливать аргументы из `.args`
- запускать `run_mode::bin`

Поддерживается:

- trivially copyable default-initializable types
- `std::array`
- `std::vector`
- `std::basic_string`
- `std::pair`
- `std::tuple`
- `std::optional`
- `std::variant`
- `std::map`
- `std::set`
- пользовательские типы через `hotfuzz::serializer<T>`

Для пользовательского типа нужно специализировать `serializer<T>` в namespace
`hotfuzz`:

```cpp
namespace hotfuzz
{
    template <>
    struct serializer<my_type>
    {
        static std::vector<std::uint8_t> to_bytes(const my_type& value);
        static my_type from_bytes(const std::vector<std::uint8_t>& bytes);
    };
}
```

Внутри пользовательского serializer лучше использовать публичные
`hotfuzz::to_bytes(...)` и `hotfuzz::from_bytes<T>(...)`, а не `hotfuzz::utils`.

## Run modes

### `run_mode::zip`

`zip` берет по одному значению из каждого provider и вызывает target на этих
парах/кортежах.

```text
ints:     i0 i1 i2 i3
dividers: d0 d1

zip calls:
    target(i0, d0)
    target(i1, d1)
```

Остановка происходит, когда первый provider исчерпан.

### `run_mode::grid`

`grid` строит Cartesian product:

```text
ints:     i0 i1
dividers: d0 d1 d2

grid calls:
    target(i0, d0)
    target(i0, d1)
    target(i0, d2)
    target(i1, d0)
    target(i1, d1)
    target(i1, d2)
```

Это удобно, когда нужно проверить все сочетания значений. Но число вызовов
растет как произведение размеров providers.

### `run_mode::bin`

`bin` запускает target на аргументах, сохраненных в `.args` файле.

```cpp
hotfuzz::fuzz(
    target,
    hotfuzz::run_mode::bin,
    hotfuzz::fuzz_options {
        .input_bin = "hotfuzz_output/bin/exception_1.args"
    },
    dividends,
    dividers
);
```

В `bin` mode providers нужны для вывода типов `Ts...` у шаблонной функции,
но значения берутся из `input_bin`.

Для ручного просмотра аргументов можно использовать:

```cpp
auto [dividend, d] =
    hotfuzz::load_fuzz_args<int, divider>("hotfuzz_output/bin/exception_1.args");
```

## In-process mode

`fuzz_options::isolation_mode = false` - режим по умолчанию.

В этом режиме target вызывается в текущем процессе:

- быстро
- работает на Linux/macOS/Windows
- exceptions перехватываются и могут быть записаны recorder'ом
- crash убьет текущий процесс

Это хороший режим для обычных exception-based проверок.

```cpp
hotfuzz::fuzz(
    target,
    hotfuzz::run_mode::zip,
    hotfuzz::fuzz_options {
        .isolation_mode = false,
        .use_recorder = true,
        .output_dir = "output"
    },
    ints,
    dividers
);
```

Важно: in-process target exceptions не пробрасываются наружу. Hotfuzz считает
их fuzzing results, записывает/показывает и продолжает выполнение.

## Isolated mode

`fuzz_options::isolation_mode = true` запускает target через worker pool.
Каждая задача отправляется в child process по IPC. Если target падает по
сигналу, падает только child, а parent получает `CRASH`.

```cpp
hotfuzz::fuzz(
    target,
    hotfuzz::run_mode::zip,
    hotfuzz::fuzz_options {
        .isolation_mode = true,
        .num_workers = 10,
        .output_dir = "output"
    },
    ints,
    dividers
);
```

Текущий isolated mode не доступен на Windows, будет брошено
исключение:

```text
hotfuzz isolation mode is not supported on WIN32
```

### Worker pool flow

Упрощенно:

```text
fuzz(...)
  -> creates worker_pool
  -> starts consumer thread with pool.wait_one()
  -> producer submits tasks from providers
  -> pool.stop()
  -> consumer drains accepted work
  -> recorder/dashboard consume results
```

`pool.stop()` не убивает текущие задачи. Он только запрещает новые submit'ы и
дает pending/in-flight задачам завершиться.

`pool.stop_immediately()` используется для аварийного пути: pending work
выбрасывается, child processes останавливаются сразу.

## Timeouts

Настройки:

```cpp
hotfuzz::worker_timeouts {
    .send_timeout = std::chrono::milliseconds { 100 },
    .frame_timeout = std::chrono::milliseconds { 100 },
    .task_timeout = std::chrono::milliseconds { 1000 }
}
```

Смысл:

- `send_timeout` - сколько можно ждать отправку request frame в worker
- `frame_timeout` - сколько можно ждать чтение уже ожидаемого response frame
- `task_timeout` - deadline для accepted task

`task_timeout` измеряет не одну инструкцию внутри target, а весь интервал:

```text
parent accepted send_run
  -> child received task
  -> child executed user code
  -> child sent response or crashed
  -> parent observed result
```

### Почему timeout может пересекаться с crash

На границе deadline возможна гонка:

```text
t0: task deadline expired
t1: parent checks timeout
t2: child crashes
t3: fd becomes POLLHUP / waitpid sees SIGABRT
```

Чтобы не превращать такой case в ложный `TIMEOUT`, worker делает:

```text
expired
  -> poll(fd, 0)
  -> waitpid(WNOHANG)
  -> short 10ms terminal-event grace
  -> waitpid(WNOHANG)
  -> only then TIMEOUT
```

То есть `task_timeout` остается обязательным, но уже готовый или почти готовый
`CRASH/EXCEPTION/OK` получает шанс быть классифицированным точно.

## Recorder

Recorder включен по умолчанию:

```cpp
hotfuzz::fuzz_options {
    .use_recorder = true,
    .output_dir = "hotfuzz_output"
}
```

Он пишет:

```text
hotfuzz_output/
  errors_and_crashes.json
  bin/
    exception_1.args
    crash_2.args
```

JSON entry:

```json
{
  "record_id": 1,
  "task_id": 66687,
  "result": "exception",
  "text": "division by zero",
  "path": "bin/exception_1.args"
}
```

Разница между `task_id` и `record_id`:

- `task_id` - внутренний id задачи в конкретном execution flow
- `record_id` - монотонный id recorder'а для файлов артефактов

Файлы называются по `record_id`, а не по `task_id`, чтобы не зависеть от
динамики worker pool и возможного переиспользования task ids в будущих схемах.

Recorder сохраняет только:

- `exception`
- `crash`

Crash artifact появляется только в isolated mode. В in-process mode crash
завершит текущий процесс раньше, чем recorder сможет что-либо записать.

`timeout`, `protocol_error`, `ipc_error`, `internal_error` показываются в
dashboard, но сейчас не пишутся как `.args` recorder'ом.

Важный практический момент: recorder создает/перезаписывает
`errors_and_crashes.json`, но не чистит старые файлы в `bin`. Для чистых
прогонов используйте свежий `output_dir` или очищайте его перед запуском.

## Live dashboard

Dashboard включается отдельно:

```cpp
hotfuzz::fuzz_options {
    .verbosity = hotfuzz::verbosity_options {
        .enabled = true,
        .recent_failure_limit = 10,
        .refresh_interval = std::chrono::milliseconds { 250 },
        .colors = hotfuzz::color_mode::auto_detect
    }
}
```

Он показывает:

```text
hotfuzz live
+---------------+---------------+---------------+---------------+---------------+
| CPU total     | CPU process   | RAM used      | RAM total     | RSS           |
+---------------+---------------+---------------+---------------+---------------+
| 13.9%         | 13.9%         | 2.0 GiB       | 13.7 GiB      | 233.6 MiB     |
+---------------+---------------+---------------+---------------+---------------+
Recent failures (5)
  [EXCEPTION] task=66687 record=1 division by zero -> bin/exception_1.args
  [CRASH] task=35288 record=2 SIGABRT -> bin/crash_2.args
```

Метрики собирает `system_scraper`:

- Linux:
  - CPU: `/proc/stat` + `/proc/self/stat`
  - RAM: `/proc/meminfo`
  - RSS: `/proc/self/status`
- Windows:
  - CPU: `GetSystemTimes` + `GetProcessTimes`
  - RAM: `GlobalMemoryStatusEx`
  - RSS: `GetProcessMemoryInfo`
- macOS/другие платформы:
  - пока заглушка

CPU проценты считаются по delta между двумя samples, поэтому первый кадр может
показывать `n/a`.

Dashboard активируется только если stdout похож на terminal. Если вывод
перенаправлен в файл или pipe, `color_mode::auto_detect` и сам dashboard не
будут ломать вывод ANSI escape sequences.

Цвета:

- `[CRASH]` - красный
- `[EXCEPTION]` - оранжевый
- `[TIMEOUT]` - magenta
- `[PROTOCOL]` - cyan
- `[IPC]` - blue
- `[INTERNAL]` - yellow

## Полный demo

`main.cpp` содержит демонстрационный сценарий:

- класс `demo::divider`
- `serializer<demo::divider>`
- `divider_provider`
- `std_random_provider<int>`
- `zip` exception flow
- isolated `zip` crash flow
- recorder artifacts
- dashboard
- ручная загрузка `.args`

Запуск:

```bash
cmake --build build --target app -j 2
./build/app
```

Демонстрация intentionally narrow: один пользовательский класс, один serializer,
один custom provider и два понятных target'а.

## Частые ошибки

### Пользовательский тип не сериализуется

Добавьте специализацию:

```cpp
namespace hotfuzz
{
    template <>
    struct serializer<my_type>
    {
        static std::vector<std::uint8_t> to_bytes(const my_type& value);
        static my_type from_bytes(const std::vector<std::uint8_t>& bytes);
    };
}
```

### In-process crash убил приложение

Это ожидаемо. In-process режим не изолирует process-level crash. Для crash
fuzzing нужен:

```cpp
.isolation_mode = true
```

### На Windows не работает isolated mode

Сейчас это ограничение проекта. Windows scraper и dashboard собираются, но
fork-backed worker pool реализован только для POSIX.

### Dashboard не появляется

Проверьте:

- `.verbosity.enabled = true`
- stdout является TTY
- вывод не перенаправлен в файл/pipe

### В `bin` остались старые `.args`

Recorder не чистит `bin`, чтобы не удалять пользовательские данные молча.
Используйте свежий `output_dir` или очищайте directory в demo/application code.

## Текущие ограничения

- Isolated worker pool сейчас не поддерживает Windows.
- macOS metrics scraper пока не реализован.
- Recorder пишет `.args` только для `exception` и `crash`.
- Dashboard рассчитан на live terminal output, а не на лог-файл.
- `task_timeout` относится ко всему accepted task lifecycle, а не только к
  времени выполнения одной строки пользовательского кода.
