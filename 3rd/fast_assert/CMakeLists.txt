# fast_assert (vendored): C++23 FAST_ASSERT / FAST_DEBUG_ASSERT / FAST_ASSUME /
# FAST_PANIC / FAST_UNREACHABLE helpers.
#
# One implementation, one owner. Every entry point the macros can reach —
# ignore/log/abort_handler, detail::fail, detail::fail_unconditional, and the
# set/get_handler slot — is compiled exactly once, into `fast_assert_owner`, and
# exported from the module that links it. In this product that module is the
# Injector; consumers link the header-only `fast_assert` view and import the code
# through it (import library on Windows, DT_NEEDED on ELF), so the process holds
# a single copy of the reporting path and a single handler slot.
#
# OBJECT, not STATIC: a static archive member is dropped when the owning module
# has no TU that references it, which is exactly the Injector's situation (it
# only exports these symbols). A standalone tool/test owns its own copy the same
# way — link `fast_assert_owner` there.
#
# PIC + hidden visibility are mandatory: the objects are linked into shared
# libraries (PIC) and must not leak their mangled symbols into every DSO's
# .dynsym, where an RTLD_GLOBAL module could preempt them (hidden). The exported
# entry points opt back in through FAST_ASSERT_API.

cmake_minimum_required(VERSION 3.15)

# Header-only view: the macros, the types and the declarations.
add_library(fast_assert INTERFACE)
add_library(fast_assert::fast_assert ALIAS fast_assert)
target_compile_features(fast_assert INTERFACE cxx_std_23)
target_include_directories(fast_assert
    INTERFACE
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
)
# The macros in fast_assert.hpp forward their optional message with __VA_OPT__;
# cl.exe only understands it with the conforming preprocessor, which /std:c++latest
# does not imply on its own. Enabling it here keeps every consumer (Tests, the
# Injector, tools) compiling the header without per-target flags.
target_compile_options(fast_assert INTERFACE $<$<COMPILE_LANG_AND_ID:CXX,MSVC>:/Zc:preprocessor>)

# The implementation. Link this into exactly one module per process.
add_library(fast_assert_owner OBJECT
    src/fast_assert.cpp
    src/fast_assert_state.cpp
)
add_library(fast_assert::owner ALIAS fast_assert_owner)
target_link_libraries(fast_assert_owner PRIVATE fast_assert)
target_compile_definitions(fast_assert_owner PRIVATE FAST_ASSERT_BUILD)
set_target_properties(fast_assert_owner PROPERTIES
    POSITION_INDEPENDENT_CODE ON
    CXX_VISIBILITY_PRESET hidden
    VISIBILITY_INLINES_HIDDEN ON
)
