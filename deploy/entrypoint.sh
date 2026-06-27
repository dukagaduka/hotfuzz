#!/usr/bin/env bash
set -euo pipefail

main_cpp="${HOTFUZZ_MAIN_CPP:-/workspace/main.cpp}"
build_dir="${HOTFUZZ_BUILD_DIR:-/workspace/.hotfuzz-build}"
output_dir="${HOTFUZZ_OUTPUT_DIR:-/workspace/hotfuzz_output}"
build_type="${HOTFUZZ_BUILD_TYPE:-Release}"
generator="${HOTFUZZ_CMAKE_GENERATOR:-Ninja}"
run_user="${HOTFUZZ_RUN_USER:-hotfuzz}"
run_uid="${HOTFUZZ_RUN_UID:-1000}"
run_gid="${HOTFUZZ_RUN_GID:-1000}"
run_umask="${HOTFUZZ_UMASK:-000}"

project_dir="${build_dir}/project"
cmake_dir="${build_dir}/cmake"
bin_dir="${build_dir}/bin"
binary="${bin_dir}/hotfuzz-user-app"
hash_file="${build_dir}/.build-key"
source_hash_file="/opt/hotfuzz/.hotfuzz-source.sha256"

if [[ "${EUID}" -eq 0 && "${HOTFUZZ_ALREADY_DROPPED:-0}" != "1" ]]; then
    existing_group="$(getent group "${run_gid}" | cut -d ':' -f 1 || true)"

    if [[ -n "${existing_group}" && "${existing_group}" != "${run_user}" ]]; then
        run_group="${existing_group}"
    else
        run_group="${run_user}"

        if getent group "${run_group}" >/dev/null; then
            groupmod --gid "${run_gid}" "${run_group}"
        else
            groupadd --gid "${run_gid}" "${run_group}"
        fi
    fi

    if id "${run_user}" >/dev/null 2>&1; then
        usermod --uid "${run_uid}" --gid "${run_group}" "${run_user}"
    else
        useradd --uid "${run_uid}" --gid "${run_group}" --create-home --shell /bin/bash "${run_user}"
    fi

    mkdir -p "${build_dir}" "${output_dir}"
    chown -R "${run_uid}:${run_gid}" "${build_dir}" "${output_dir}" /home/"${run_user}" 2>/dev/null || true
    chmod -R a+rwx "${build_dir}" "${output_dir}" /home/"${run_user}" 2>/dev/null || true

    export HOTFUZZ_ALREADY_DROPPED=1
    exec gosu "${run_uid}:${run_gid}" "$0" "$@"
fi

umask "${run_umask}"
mkdir -p "${build_dir}" "${output_dir}"
chmod a+rwx "${build_dir}" "${output_dir}" 2>/dev/null || true

if [[ ! -f "${main_cpp}" ]]; then
    echo "hotfuzz-run: main.cpp not found: ${main_cpp}" >&2
    echo "hotfuzz-run: mount a file to /workspace/main.cpp or set HOTFUZZ_MAIN_CPP." >&2
    exit 2
fi

read -r main_hash _ < <(sha256sum "${main_cpp}")
source_hash="unknown"

if [[ -f "${source_hash_file}" ]]; then
    source_hash="$(<"${source_hash_file}")"
fi

build_key="$(printf '%s\n%s\n%s\n%s\n%s\n%s\n%s\n' \
    "${main_hash}" \
    "${source_hash}" \
    "${build_type}" \
    "${generator}" \
    "${HOTFUZZ_ENABLE_SANITIZERS:-0}" \
    "${HOTFUZZ_CXX_FLAGS:-}" \
    "${HOTFUZZ_EXE_LINKER_FLAGS:-}" \
    | sha256sum \
    | cut -d ' ' -f 1)"
previous_key=""

if [[ -f "${hash_file}" ]]; then
    previous_key="$(<"${hash_file}")"
fi

needs_build=0

if [[ ! -x "${binary}" || "${previous_key}" != "${build_key}" ]]; then
    needs_build=1
fi

if [[ "${needs_build}" -eq 1 ]]; then
    mkdir -p "${project_dir}" "${cmake_dir}" "${bin_dir}"

    cat > "${project_dir}/CMakeLists.txt" <<'CMAKE'
cmake_minimum_required(VERSION 3.16)
project(hotfuzz_user_main LANGUAGES CXX)

set(HOTFUZZ_MAIN_CPP "" CACHE FILEPATH "Path to the user-provided main.cpp")
set(HOTFUZZ_RUNTIME_OUTPUT_DIR "" CACHE PATH "Directory for the compiled binary")

if(NOT HOTFUZZ_MAIN_CPP)
    message(FATAL_ERROR "HOTFUZZ_MAIN_CPP is required")
endif()

if(NOT EXISTS "${HOTFUZZ_MAIN_CPP}")
    message(FATAL_ERROR "HOTFUZZ_MAIN_CPP does not exist: ${HOTFUZZ_MAIN_CPP}")
endif()

if(HOTFUZZ_RUNTIME_OUTPUT_DIR)
    set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${HOTFUZZ_RUNTIME_OUTPUT_DIR}")
endif()

find_package(Threads REQUIRED)

add_executable(hotfuzz_user_app "${HOTFUZZ_MAIN_CPP}")
target_compile_features(hotfuzz_user_app PRIVATE cxx_std_23)
target_include_directories(hotfuzz_user_app PRIVATE
    /opt/hotfuzz/include
    /opt/hotfuzz/third_party/nlohmann/include
)
target_link_libraries(hotfuzz_user_app PRIVATE Threads::Threads)

if("$ENV{HOTFUZZ_ENABLE_SANITIZERS}" STREQUAL "1")
    if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
        target_compile_options(hotfuzz_user_app PRIVATE
            -fsanitize=address,undefined
            -fno-omit-frame-pointer
        )
        target_link_options(hotfuzz_user_app PRIVATE
            -fsanitize=address,undefined
        )
    endif()
endif()

if(DEFINED ENV{HOTFUZZ_CXX_FLAGS} AND NOT "$ENV{HOTFUZZ_CXX_FLAGS}" STREQUAL "")
    separate_arguments(HOTFUZZ_EXTRA_CXX_FLAGS UNIX_COMMAND "$ENV{HOTFUZZ_CXX_FLAGS}")
    target_compile_options(hotfuzz_user_app PRIVATE ${HOTFUZZ_EXTRA_CXX_FLAGS})
endif()

if(DEFINED ENV{HOTFUZZ_EXE_LINKER_FLAGS} AND NOT "$ENV{HOTFUZZ_EXE_LINKER_FLAGS}" STREQUAL "")
    separate_arguments(HOTFUZZ_EXTRA_LINKER_FLAGS UNIX_COMMAND "$ENV{HOTFUZZ_EXE_LINKER_FLAGS}")
    target_link_options(hotfuzz_user_app PRIVATE ${HOTFUZZ_EXTRA_LINKER_FLAGS})
endif()
CMAKE

    cmake \
        -S "${project_dir}" \
        -B "${cmake_dir}" \
        -G "${generator}" \
        -DCMAKE_BUILD_TYPE="${build_type}" \
        -DHOTFUZZ_MAIN_CPP="${main_cpp}" \
        -DHOTFUZZ_RUNTIME_OUTPUT_DIR="${bin_dir}"

    cmake --build "${cmake_dir}" --target hotfuzz_user_app --parallel "${HOTFUZZ_BUILD_JOBS:-$(nproc)}"
    printf '%s\n' "${build_key}" > "${hash_file}"
else
    echo "hotfuzz-run: reusing cached binary for ${main_cpp}"
fi

exec "${binary}" "$@"
