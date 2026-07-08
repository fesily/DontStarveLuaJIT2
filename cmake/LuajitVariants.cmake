# cmake/LuajitVariants.cmake
#
# LuaJIT variant registry / descriptor layer.
#
# This module provides a minimal registry for LuaJIT build variants.  Each
# variant is described by a small set of fields (library target, executable
# target, include directory, output library name) that decouple downstream
# consumers from raw target-name literals.
#
# The registry started with one variant ("default") and now supports multiple
# descriptors. The default variant still anchors downstream compatibility
# variables, while additional variants can be registered without forcing
# consumers to know raw target names.
#
# Design constraints:
#   * Registration must NOT require the targets to exist yet — it only records
#     descriptor strings.  This allows the module to be included and the
#     variant to be registered before add_subdirectory(luajit) runs.
#   * The registry is build-artifact metadata only; it does not build anything.
#   * Compatibility variables (LUAJIT_INCLUDE_DIR, LUAJIT_LIBRARIES) are
#     derived from the registry by the caller, not by this module.

# ---------------------------------------------------------------------------
# Internal global state
# ---------------------------------------------------------------------------
set(LUAJIT_VARIANTS "" CACHE INTERNAL "Registered LuaJIT variant names (ordered)")

# ---------------------------------------------------------------------------
# luajit_register_variant
#
# Registers one LuaJIT variant descriptor.
#
# Required arguments:
#   NAME        <id>      - variant identifier (e.g. "default")
#   TARGET      <target>  - CMake shared-library target name (e.g. "luajit-5.1")
#   EXECUTABLE  <target>  - CMake executable target name (e.g. "luajit")
#   INCLUDE_DIR <dir...>  - path(s) to the LuaJIT headers
#   OUTPUT_NAME <name>    - output library base name (e.g. "lua51DS")
# ---------------------------------------------------------------------------
function(luajit_register_variant)
    set(options)
    set(oneValueArgs NAME TARGET EXECUTABLE OUTPUT_NAME)
    set(multiValueArgs INCLUDE_DIR)
    cmake_parse_arguments(VAR "${options}" "${oneValueArgs}" "${multiValueArgs}" ${ARGN})

    foreach(req NAME TARGET EXECUTABLE INCLUDE_DIR OUTPUT_NAME)
        if(NOT DEFINED VAR_${req} OR VAR_${req} STREQUAL "")
            message(FATAL_ERROR
                "luajit_register_variant: missing required argument '${req}'\n"
                "Usage: luajit_register_variant(\n"
                "    NAME <id> TARGET <lib-target> EXECUTABLE <exe-target>\n"
                "    INCLUDE_DIR <dir...> OUTPUT_NAME <output-name>)")
        endif()
    endforeach()

    # Store descriptor fields as internal cache variables.
    # Using CACHE INTERNAL keeps them across reconfigures while avoiding
    # pollution of the user-visible cache.
    set(LUAJIT_VARIANT_${VAR_NAME}_TARGET      "${VAR_TARGET}"      CACHE INTERNAL "LuaJIT variant '${VAR_NAME}' library target")
    set(LUAJIT_VARIANT_${VAR_NAME}_EXECUTABLE  "${VAR_EXECUTABLE}"  CACHE INTERNAL "LuaJIT variant '${VAR_NAME}' executable target")
    set(LUAJIT_VARIANT_${VAR_NAME}_INCLUDE_DIR "${VAR_INCLUDE_DIR}" CACHE INTERNAL "LuaJIT variant '${VAR_NAME}' include directory")
    set(LUAJIT_VARIANT_${VAR_NAME}_OUTPUT_NAME "${VAR_OUTPUT_NAME}" CACHE INTERNAL "LuaJIT variant '${VAR_NAME}' output library name")

    # Append to the ordered global variant list (no duplicates).
    list(FIND LUAJIT_VARIANTS "${VAR_NAME}" _found)
    if(_found EQUAL -1)
        list(APPEND LUAJIT_VARIANTS "${VAR_NAME}")
        set(LUAJIT_VARIANTS "${LUAJIT_VARIANTS}" CACHE INTERNAL "Registered LuaJIT variant names (ordered)")
    else()
        message(WARNING "luajit_register_variant: variant '${VAR_NAME}' already registered — updating descriptor")
    endif()

    message(STATUS "LuaJIT variant registered: ${VAR_NAME} "
        "(target=${VAR_TARGET}, exe=${VAR_EXECUTABLE}, output=${VAR_OUTPUT_NAME})")
endfunction()

# ---------------------------------------------------------------------------
# luajit_get_variant_property
#
# Retrieves a single property of a registered variant.
#   result_var  - name of the variable to set in the caller's scope
#   variant_name - registered variant identifier
#   property     - one of: TARGET, EXECUTABLE, INCLUDE_DIR, OUTPUT_NAME
# ---------------------------------------------------------------------------
function(luajit_get_variant_property result_var variant_name property)
    if(NOT DEFINED LUAJIT_VARIANT_${variant_name}_${property})
        message(FATAL_ERROR
            "luajit_get_variant_property: variant '${variant_name}' "
            "has no property '${property}' (is the variant registered?)")
    endif()
    set(${result_var} "${LUAJIT_VARIANT_${variant_name}_${property}}" PARENT_SCOPE)
endfunction()

# ---------------------------------------------------------------------------
# luajit_get_variants
#
# Returns the list of all registered variant names in registration order.
#   result_var - name of the variable to set in the caller's scope
# ---------------------------------------------------------------------------
function(luajit_get_variants result_var)
    set(${result_var} "${LUAJIT_VARIANTS}" PARENT_SCOPE)
endfunction()

# ---------------------------------------------------------------------------
# luajit_get_variant
#
# Retrieves the full descriptor for a variant into the caller's scope as
# individual variables prefixed with the given prefix.
#   prefix       - prefix for the output variables (e.g. "DEFAULT")
#   variant_name - registered variant identifier
#
# Sets: ${prefix}_NAME, ${prefix}_TARGET, ${prefix}_EXECUTABLE,
#       ${prefix}_INCLUDE_DIR, ${prefix}_OUTPUT_NAME
# ---------------------------------------------------------------------------
function(luajit_get_variant prefix variant_name)
    if(NOT DEFINED LUAJIT_VARIANT_${variant_name}_TARGET)
        message(FATAL_ERROR "luajit_get_variant: variant '${variant_name}' is not registered")
    endif()
    set(${prefix}_NAME        "${variant_name}"                          PARENT_SCOPE)
    set(${prefix}_TARGET      "${LUAJIT_VARIANT_${variant_name}_TARGET}"      PARENT_SCOPE)
    set(${prefix}_EXECUTABLE  "${LUAJIT_VARIANT_${variant_name}_EXECUTABLE}"  PARENT_SCOPE)
    set(${prefix}_INCLUDE_DIR "${LUAJIT_VARIANT_${variant_name}_INCLUDE_DIR}" PARENT_SCOPE)
    set(${prefix}_OUTPUT_NAME "${LUAJIT_VARIANT_${variant_name}_OUTPUT_NAME}" PARENT_SCOPE)
endfunction()

# ---------------------------------------------------------------------------
# luajit_generate_variant_contract
#
# Writes a simple key=value contract file describing all registered variants.
# Tests consume this file to verify the variant contract without inspecting
# unresolved CMake targets directly.
#
#   output_file - absolute path to the contract file to generate
# ---------------------------------------------------------------------------
function(luajit_generate_variant_contract output_file)
    file(WRITE "${output_file}" "# LuaJIT variant registry contract (generated)\n")
    file(APPEND "${output_file}" "# Generated by cmake/LuajitVariants.cmake\n")
    file(APPEND "${output_file}" "VARIANTS=${LUAJIT_VARIANTS}\n")
    foreach(variant ${LUAJIT_VARIANTS})
        file(APPEND "${output_file}" "VARIANT_${variant}_TARGET=${LUAJIT_VARIANT_${variant}_TARGET}\n")
        file(APPEND "${output_file}" "VARIANT_${variant}_EXECUTABLE=${LUAJIT_VARIANT_${variant}_EXECUTABLE}\n")
        file(APPEND "${output_file}" "VARIANT_${variant}_INCLUDE_DIR=${LUAJIT_VARIANT_${variant}_INCLUDE_DIR}\n")
        file(APPEND "${output_file}" "VARIANT_${variant}_OUTPUT_NAME=${LUAJIT_VARIANT_${variant}_OUTPUT_NAME}\n")
    endforeach()
    message(STATUS "LuaJIT variant contract written to: ${output_file}")
endfunction()
