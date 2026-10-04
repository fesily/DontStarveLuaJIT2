#pragma once

#include "MemorySignature.hpp"

extern function_relocation::MemorySignature luaModuleSignature;
extern function_relocation::MemorySignature luaRegisterDebugGetsizeSignature;
extern function_relocation::MemorySignature luaSetExecutionErrorSignature;

namespace ds::core_vm::detail {
// Decode the engine's execution-error storage from the window matched by
// luaSetExecutionErrorSignature: the `cmp [flag], 0` slot (cross-checked by the
// `mov [flag], …` store to the same address) and the `lea` destination of the
// 0x1000-byte copy. Zero fields mean "not recognized" (fail closed).
struct ExecutionErrorStorage {
    uintptr_t flag = 0;
    uintptr_t buffer = 0;
    explicit operator bool() const { return flag != 0 && buffer != 0; }
};
ExecutionErrorStorage decode_execution_error_storage(uintptr_t helper);
} // namespace ds::core_vm::detail
