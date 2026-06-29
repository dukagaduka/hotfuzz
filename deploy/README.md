# hotfuzz Docker runner

This directory contains a self-contained Docker runner for user-provided
`main.cpp` files.

The image includes the hotfuzz sources and a preconfigured Ubuntu C++23
toolchain. At container start, the entrypoint compiles the mounted `main.cpp`
and runs the resulting binary.

## Usage

Create a local env file:

```bash
cp deploy/.env.example deploy/.env
```

PowerShell:

```powershell
Copy-Item deploy/.env.example deploy/.env
```

Set `HOTFUZZ_MAIN_CPP` in `deploy/.env` to the host path of the `main.cpp` you
want to run. Set `HOTFUZZ_RECORDER_DIR` to the host directory where recorder
artifacts should be written.

Build and run:

```bash
docker compose --env-file deploy/.env -f deploy/docker-compose.yml up --build
```

Run again after editing `main.cpp`:

```bash
docker compose --env-file deploy/.env -f deploy/docker-compose.yml up
```

The runner stores build output and the last input hash in the
`hotfuzz-build-cache` Docker volume. If `main.cpp` and the hotfuzz source
fingerprint did not change, the existing binary is reused.

Recorder output is mounted from `HOTFUZZ_RECORDER_DIR` to
`/workspace/hotfuzz_output`. The entrypoint drops from root to the `hotfuzz`
user before compiling and running the binary, and uses `umask 000`, so files
created in the mounted recorder directory are not root-owned and are writable by
other users.

To pass arguments to the compiled binary:

```bash
docker compose --env-file deploy/.env -f deploy/docker-compose.yml run --rm hotfuzz --arg value
```

## Examples

Three practical examples are included:

```text
deploy/examples/buffer_overflow.cpp
deploy/examples/null_dereference.cpp
deploy/examples/integer_overflow_allocation.cpp
```

Each example writes recorder artifacts under a separate subdirectory of
`HOTFUZZ_OUTPUT_DIR`, which maps to `HOTFUZZ_RECORDER_DIR` on the host.

The Docker runner builds examples as plain C++ programs. The terminal output is
produced by the example and by hotfuzz itself.

To run a different example, edit `HOTFUZZ_MAIN_CPP` in `deploy/.env`:

```env
HOTFUZZ_MAIN_CPP=./examples/buffer_overflow.cpp
```

To replay a recorded artifact:

```bash
docker compose --env-file deploy/.env -f deploy/docker-compose.yml run --rm \
  -e HOTFUZZ_INPUT_BIN=/workspace/hotfuzz_output/null_dereference/bin/crash_1.args \
  hotfuzz
```

## Sharing the image

After building the image, it can be exported and imported without the source
checkout:

```bash
docker save hotfuzz-runner:local -o hotfuzz-runner.tar
docker load -i hotfuzz-runner.tar
```

The receiving side only needs Docker and a `main.cpp` mounted through
`HOTFUZZ_MAIN_CPP`, plus a recorder directory mounted through
`HOTFUZZ_RECORDER_DIR`.
