#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
TEST_DIR="$ROOT_DIR/tests/function_relocation"
INCLUDE_DIR="$ROOT_DIR/src/FunctionRelocation"
EVIDENCE_DIR="$ROOT_DIR/.omo/evidence/function-relocation-match-v2"
LOG_FILE="$EVIDENCE_DIR/task-6-ctest.log"
BUILD_DIR="$(mktemp -d /tmp/function-relocation-match-v2.XXXXXX)"

trap 'rm -rf "$BUILD_DIR"' EXIT
mkdir -p "$EVIDENCE_DIR"

: >"$LOG_FILE"

compile_and_run() {
    local name="$1"
    local src="$TEST_DIR/$name.cpp"
    local exe="$BUILD_DIR/$name"

    printf '[g++] %s\n' "$name" | tee -a "$LOG_FILE"
    g++ -std=c++23 -O0 -g -I"$INCLUDE_DIR" -I"$TEST_DIR" "$src" -o "$exe" 2>&1 | tee -a "$LOG_FILE"
    printf '[run] %s\n' "$name" | tee -a "$LOG_FILE"
    "$exe" 2>&1 | tee -a "$LOG_FILE"
}

tests=(
    test_match_accept_policy
    test_micro_windows
    test_soft_score
    test_virtual_flatten
    test_orchestration
    test_schema_freeze
)

printf 'Standalone g++ match suite\n' | tee -a "$LOG_FILE"
for test_name in "${tests[@]}"; do
    compile_and_run "$test_name"
done

if command -v cmake >/dev/null 2>&1; then
    printf 'Temp CMake/CTest match suite\n' | tee -a "$LOG_FILE"
    CMAKE_DIR="$BUILD_DIR/cmake"
    mkdir -p "$CMAKE_DIR"
    cat >"$CMAKE_DIR/CMakeLists.txt" <<EOF
cmake_minimum_required(VERSION 3.20)
project(match_v2_fixture LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

enable_testing()

set(TEST_DIR "$TEST_DIR")
set(INCLUDE_DIR "$INCLUDE_DIR")

    foreach(test_name IN ITEMS test_match_accept_policy test_micro_windows test_soft_score test_virtual_flatten test_orchestration test_schema_freeze)
        add_executable(
            \${test_name}
            "\${TEST_DIR}/\${test_name}.cpp")
        target_include_directories(\${test_name} PRIVATE "\${INCLUDE_DIR}" "\${TEST_DIR}")
        add_test(NAME \${test_name} COMMAND \${test_name})
    set_tests_properties(\${test_name} PROPERTIES LABELS match_v2)
endforeach()
EOF
    cmake -S "$CMAKE_DIR" -B "$CMAKE_DIR/build" 2>&1 | tee -a "$LOG_FILE"
    cmake --build "$CMAKE_DIR/build" 2>&1 | tee -a "$LOG_FILE"
    ctest --test-dir "$CMAKE_DIR/build" -L match_v2 --output-on-failure 2>&1 | tee -a "$LOG_FILE"
fi

printf 'Log written to %s\n' "$LOG_FILE" | tee -a "$LOG_FILE"
