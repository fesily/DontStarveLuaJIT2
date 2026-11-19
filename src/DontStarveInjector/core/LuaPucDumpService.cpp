// PUC Lua 5.1 bytecode dump service. See core/LuaPucDumpService.hpp.
//
// One private PUC 5.1 state per call: no standard library, no execution of the
// supplied source, and no state shared with the L0 config cascade. The source is
// compiled once and the root closure stays on the PUC stack, anchoring the whole
// prototype tree while one of its descendants is serialized.

#include "core/LuaPucDumpService.hpp"

#include "lua_ds_pucdump.h"  /* completes the ABI structs declared in the header */

#include <cstdio>
#include <cstring>
#include <new>
#include <vector>

extern "C" {
#include "lua.h"
#include "lauxlib.h"
#include "lobject.h"
#include "lstate.h"
#include "lundump.h"
}

namespace {

constexpr char kOutOfMemory[] = "out of memory";

// Owns the dumped bytes. Heap-allocated so the release callback is a single
// delete expression in this CRT, exactly as the ABI header requires.
struct DumpBuffer {
    std::vector<char> bytes;
};

struct WriterCtx {
    DumpBuffer *buffer = nullptr;
    bool failed = false;
};

// C++ exceptions must not cross a PUC C frame: a growth failure is reported as a
// writer error (non-zero), which luaU_dump turns into a failed dump.
int write_buffer(lua_State *L, const void *p, size_t size, void *ud) noexcept {
    auto *ctx = static_cast<WriterCtx *>(ud);
    (void) L;
    try {
        const auto *first = static_cast<const char *>(p);
        ctx->buffer->bytes.insert(ctx->buffer->bytes.end(), first, first + size);
    } catch (...) {
        ctx->failed = true;
        return 1;
    }
    return 0;
}

void release_buffer(void *owner) noexcept {
    delete static_cast<DumpBuffer *>(owner);
}

void set_error(lua_DsPucDumpResult *result, const char *text) noexcept {
    if (text == nullptr) {
        text = "";
    }
    size_t n = std::strlen(text);
    if (n >= sizeof(result->error)) {
        n = sizeof(result->error) - 1;
    }
    std::memcpy(result->error, text, n);
    result->error[n] = '\0';
}

void set_error_prefixed(lua_DsPucDumpResult *result, const char *prefix, const char *text) noexcept {
    if (text == nullptr) {
        text = "";
    }
    char joined[sizeof(result->error)];
    const int written = std::snprintf(joined, sizeof(joined), "%s%s", prefix, text);
    (void) written;
    set_error(result, joined);
}

int count_nodes(const Proto *proto) {
    int total = 1;
    for (int i = 0; i < proto->sizep; ++i) {
        total += count_nodes(proto->p[i]);
    }
    return total;
}

// Pre-order walk in the same shape the VM assigns node indices to prototypes, so
// a mismatch is a hard error rather than a nearest-match guess.
const Proto *nth_node(const Proto *proto, uint32_t index, uint32_t *cursor) {
    if (*cursor == index) {
        return proto;
    }
    ++*cursor;
    for (int i = 0; i < proto->sizep; ++i) {
        const Proto *found = nth_node(proto->p[i], index, cursor);
        if (found != nullptr) {
            return found;
        }
    }
    return nullptr;
}

struct DumpCall {
    const Proto *target = nullptr;
    WriterCtx *writer = nullptr;
    int strip = 0;
    int status = 0;
};

// Runs inside lua_cpcall: luaU_dump may raise a memory error from inside its
// allocator, and an unprotected raise would reach the PUC panic handler.
int dump_protected(lua_State *L) {
    auto *call = static_cast<DumpCall *>(lua_touserdata(L, 1));
    call->status = luaU_dump(L, call->target, write_buffer, call->writer, call->strip);
    return 0;
}

} // namespace

namespace ds::puc51 {

int Dump(const lua_DsPucDumpRequest *request, lua_DsPucDumpResult *result) noexcept try {
    if (result == nullptr) {
        return 0;
    }
    result->data = nullptr;
    result->size = 0;
    result->owner = nullptr;
    result->release = nullptr;
    result->error[0] = '\0';

    if (request == nullptr) {
        set_error(result, "invalid request");
        return 0;
    }
    if (request->source == nullptr) {
        set_error(result, "source unavailable");
        return 0;
    }
    // A private PUC state must never become an untrusted bytecode loader.
    if (request->source_len > 0 && static_cast<unsigned char>(request->source[0]) == 0x1b) {
        set_error(result, "bytecode source rejected");
        return 0;
    }

    const char *chunkname = request->chunkname != nullptr ? request->chunkname : "?";

    lua_State *L = luaL_newstate();
    if (L == nullptr) {
        set_error(result, kOutOfMemory);
        return 0;
    }

    // Compile only. The chunk is never called: the source is untrusted mod text.
    const int load_status = luaL_loadbuffer(L, request->source, request->source_len, chunkname);
    if (load_status != 0) {
        const char *message = lua_tostring(L, -1);
        set_error_prefixed(result, "PUC compilation failed: ", message);
        lua_close(L);
        return 0;
    }

    const void *closure = lua_topointer(L, -1);
    if (closure == nullptr) {
        set_error(result, "PUC compilation failed: no root prototype");
        lua_close(L);
        return 0;
    }
    const Proto *root = static_cast<const Closure *>(closure)->l.p;
    if (root == nullptr) {
        set_error(result, "PUC compilation failed: no root prototype");
        lua_close(L);
        return 0;
    }

    if (request->node_count != static_cast<uint32_t>(count_nodes(root))) {
        set_error(result, "prototype mismatch: node count");
        lua_close(L);
        return 0;
    }
    uint32_t cursor = 0;
    const Proto *target = nth_node(root, request->node_index, &cursor);
    if (target == nullptr) {
        set_error(result, "prototype mismatch: node index");
        lua_close(L);
        return 0;
    }
    if (target->linedefined != static_cast<int>(request->firstline) ||
        target->numparams != static_cast<int>(request->numparams) ||
        target->nups != static_cast<int>(request->nups) ||
        ((target->is_vararg & VARARG_ISVARARG) ? 1u : 0u) != (request->is_vararg ? 1u : 0u) ||
        target->sizep != static_cast<int>(request->child_count)) {
        set_error(result, "prototype mismatch: shape");
        lua_close(L);
        return 0;
    }

    auto *buffer = new (std::nothrow) DumpBuffer();
    if (buffer == nullptr) {
        set_error(result, kOutOfMemory);
        lua_close(L);
        return 0;
    }

    WriterCtx writer;
    writer.buffer = buffer;
    DumpCall call;
    call.target = target;
    call.writer = &writer;
    call.strip = request->strip != 0 ? 1 : 0;
    // Protect the dump: luaU_dump allocates, and an unprotected OOM would abort
    // the process through the PUC panic handler instead of failing this call.
    const int call_status = lua_cpcall(L, dump_protected, &call);
    lua_close(L);

    if (writer.failed || call.status != 0) {
        delete buffer;
        set_error(result, "dump writer failed");
        return 0;
    }
    if (call_status != 0) {
        delete buffer;
        set_error(result, kOutOfMemory);
        return 0;
    }

    result->data = buffer->bytes.data();
    result->size = buffer->bytes.size();
    result->owner = buffer;
    result->release = &release_buffer;
    return 1;
} catch (...) {
    if (result != nullptr) {
        result->data = nullptr;
        result->size = 0;
        result->owner = nullptr;
        result->release = nullptr;
        set_error(result, kOutOfMemory);
    }
    return 0;
}

} // namespace ds::puc51
