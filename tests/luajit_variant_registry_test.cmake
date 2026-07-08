# tests/luajit_variant_registry_test.cmake
#
# Characterization test for the LuaJIT variant registry contract.
#
# Reads the generated variant contract file (produced by
# luajit_generate_variant_contract at configure time) and asserts:
#   1. The registry contains exactly two variants: "default;gengc".
#   2. The default variant preserves its original contract.
#   3. The gengc variant resolves to its own target/output/executable names.
#
# This test will FAIL until the registry is wired into the top-level
# CMakeLists.txt (task 4) and the contract file is generated.  Once wiring
# is complete it should go green and stay green.
#
# Invocation (via ctest):
#   ctest -R luajit_variant_registry
#
# The path to the contract file is passed via -DLUAJIT_VARIANT_CONTRACT_FILE.

if(NOT DEFINED LUAJIT_VARIANT_CONTRACT_FILE)
    message(FATAL_ERROR "FAIL: LUAJIT_VARIANT_CONTRACT_FILE is not set")
endif()

if(NOT EXISTS "${LUAJIT_VARIANT_CONTRACT_FILE}")
    message(FATAL_ERROR "FAIL: Variant contract file not found: ${LUAJIT_VARIANT_CONTRACT_FILE}")
endif()

# Read and parse the contract file (key=value lines)
file(STRINGS "${LUAJIT_VARIANT_CONTRACT_FILE}" _lines)
set(_contract_keys)
foreach(_line ${_lines})
    # Skip comments
    if(_line MATCHES "^#")
        continue()
    endif()
    string(STRIP "${_line}" _line)
    if(_line)
        if(_line MATCHES "^([^=]+)=(.*)$")
            set(_key "${CMAKE_MATCH_1}")
            set(_val "${CMAKE_MATCH_2}")
            set("_ct_${_key}" "${_val}")
            list(APPEND _contract_keys "${_key}")
        endif()
    endif()
endforeach()

# --- Assertion 1: exactly two variants named "default;gengc" ---
if(NOT DEFINED _ct_VARIANTS)
    message(FATAL_ERROR "FAIL: VARIANTS key missing from contract file")
endif()

if(NOT "${_ct_VARIANTS}" STREQUAL "default;gengc")
    message(FATAL_ERROR
        "FAIL: expected exactly two variants 'default;gengc', got '${_ct_VARIANTS}'")
endif()

# --- Assertion 2: default OUTPUT_NAME is lua51DS ---
if(NOT DEFINED _ct_VARIANT_default_OUTPUT_NAME)
    message(FATAL_ERROR "FAIL: VARIANT_default_OUTPUT_NAME key missing from contract file")
endif()
if(NOT "${_ct_VARIANT_default_OUTPUT_NAME}" STREQUAL "lua51DS")
    message(FATAL_ERROR
        "FAIL: expected default OUTPUT_NAME='lua51DS', "
        "got '${_ct_VARIANT_default_OUTPUT_NAME}'")
endif()

# --- Assertion 3: default TARGET is luajit-5.1 ---
if(NOT DEFINED _ct_VARIANT_default_TARGET)
    message(FATAL_ERROR "FAIL: VARIANT_default_TARGET key missing from contract file")
endif()
if(NOT "${_ct_VARIANT_default_TARGET}" STREQUAL "luajit-5.1")
    message(FATAL_ERROR
        "FAIL: expected default TARGET='luajit-5.1', "
        "got '${_ct_VARIANT_default_TARGET}'")
endif()

# --- Assertion 4: default EXECUTABLE is luajit ---
if(NOT DEFINED _ct_VARIANT_default_EXECUTABLE)
    message(FATAL_ERROR "FAIL: VARIANT_default_EXECUTABLE key missing from contract file")
endif()
if(NOT "${_ct_VARIANT_default_EXECUTABLE}" STREQUAL "luajit")
    message(FATAL_ERROR
        "FAIL: expected default EXECUTABLE='luajit', "
        "got '${_ct_VARIANT_default_EXECUTABLE}'")
endif()

# --- Assertion 5: gengc OUTPUT_NAME is lua51DS_gengc ---
if(NOT DEFINED _ct_VARIANT_gengc_OUTPUT_NAME)
    message(FATAL_ERROR "FAIL: VARIANT_gengc_OUTPUT_NAME key missing from contract file")
endif()
if(NOT "${_ct_VARIANT_gengc_OUTPUT_NAME}" STREQUAL "lua51DS_gengc")
    message(FATAL_ERROR
        "FAIL: expected gengc OUTPUT_NAME='lua51DS_gengc', "
        "got '${_ct_VARIANT_gengc_OUTPUT_NAME}'")
endif()

# --- Assertion 6: gengc TARGET is luajit-5.1-gengc ---
if(NOT DEFINED _ct_VARIANT_gengc_TARGET)
    message(FATAL_ERROR "FAIL: VARIANT_gengc_TARGET key missing from contract file")
endif()
if(NOT "${_ct_VARIANT_gengc_TARGET}" STREQUAL "luajit-5.1-gengc")
    message(FATAL_ERROR
        "FAIL: expected gengc TARGET='luajit-5.1-gengc', "
        "got '${_ct_VARIANT_gengc_TARGET}'")
endif()

# --- Assertion 7: gengc EXECUTABLE is luajit-gengc ---
if(NOT DEFINED _ct_VARIANT_gengc_EXECUTABLE)
    message(FATAL_ERROR "FAIL: VARIANT_gengc_EXECUTABLE key missing from contract file")
endif()
if(NOT "${_ct_VARIANT_gengc_EXECUTABLE}" STREQUAL "luajit-gengc")
    message(FATAL_ERROR
        "FAIL: expected gengc EXECUTABLE='luajit-gengc', "
        "got '${_ct_VARIANT_gengc_EXECUTABLE}'")
endif()

message(STATUS "PASS: luajit_variant_registry contract verified "
    "(2 variants: default -> target=luajit-5.1, output=lua51DS, exe=luajit; "
    "gengc -> target=luajit-5.1-gengc, output=lua51DS_gengc, exe=luajit-gengc)")
