// fast_assert handler-slot ownership across dynamically loaded modules.
//
// Models the production layout: the owner (Injector) is loaded first with
// RTLD_LOCAL / LoadLibrary, then a consumer (plugin) that links only the
// stateless archive and imports set_handler/get_handler from the owner.
// The third module is the negative control: it links the state archive itself
// and must therefore keep an independent slot.

#include <doctest/doctest.h>

#include <fast_assert/fast_assert.hpp>

#include <cstdlib>
#include <string_view>

#if defined(_WIN32)
#  include <windows.h>
namespace {
void* open_module(const char* path) {
    return reinterpret_cast<void*>(::LoadLibraryA(path));
}
void* find_symbol(void* module, const char* name) {
    return reinterpret_cast<void*>(
        ::GetProcAddress(static_cast<HMODULE>(module), name));
}
const char* last_error() {
    return "LoadLibrary failed";
}
} // namespace
#else
#  include <dlfcn.h>
namespace {
void* open_module(const char* path) {
    return ::dlopen(path, RTLD_NOW | RTLD_LOCAL);
}
void* find_symbol(void* module, const char* name) {
    return ::dlsym(module, name);
}
const char* last_error() {
    const char* err = ::dlerror();
    return err ? err : "dlopen failed";
}
} // namespace
#endif

namespace {
struct Recorder {
    int calls = 0;
    const char* last_message = nullptr;
};

Recorder g_host;

void host_handler(const fast_assert::Failure& f) noexcept {
    ++g_host.calls;
    g_host.last_message = f.message;
}

template <typename Fn>
Fn sym(void* module, const char* name) {
    return reinterpret_cast<Fn>(find_symbol(module, name));
}

void* as_ptr(fast_assert::Handler h) {
    return reinterpret_cast<void*>(h);
}
} // namespace

TEST_CASE("fast_assert/cross_dso_shared_slot") {
    const char* owner_path    = std::getenv("DS_FA_OWNER");
    const char* consumer_path = std::getenv("DS_FA_CONSUMER");
    const char* own_path      = std::getenv("DS_FA_CONSUMER_OWN");
    REQUIRE(owner_path != nullptr);
    REQUIRE(consumer_path != nullptr);
    REQUIRE(own_path != nullptr);

    // 1. Owner module first, exactly like the Injector in a game process.
    void* owner = open_module(owner_path);
    REQUIRE_MESSAGE(owner != nullptr, "owner module failed to load: " << last_error());
    auto owner_set = sym<void (*)(fast_assert::Handler)>(owner, "ds_fa_owner_set");
    auto owner_get = sym<void* (*)()>(owner, "ds_fa_owner_get");
    REQUIRE(owner_set != nullptr);
    REQUIRE(owner_get != nullptr);

    // 2. Consumer imports the slot from the owner.
    void* consumer = open_module(consumer_path);
    REQUIRE_MESSAGE(consumer != nullptr, "consumer module failed to load: " << last_error());
    auto consumer_get   = sym<void* (*)()>(consumer, "ds_fa_consumer_get");
    auto consumer_fail  = sym<void (*)()>(consumer, "ds_fa_consumer_fail");
    auto consumer_local = sym<int (*)()>(consumer, "ds_fa_consumer_local_calls");
    REQUIRE(consumer_get != nullptr);
    REQUIRE(consumer_fail != nullptr);
    REQUIRE(consumer_local != nullptr);

    owner_set(&host_handler);
    REQUIRE(owner_get() == as_ptr(&host_handler));
    REQUIRE(consumer_get() == as_ptr(&host_handler)); // same slot, not a local copy

    consumer_fail();
    REQUIRE(g_host.calls == 1);
    REQUIRE(g_host.last_message != nullptr);
    REQUIRE(std::string_view(g_host.last_message) == "consumer-assert");
    REQUIRE(consumer_local() == 0); // the local handler never ran

    // 3. Negative control: a module that links the state archive keeps its own
    //    slot. If this ever starts sharing, the ownership split has regressed.
    void* own = open_module(own_path);
    REQUIRE_MESSAGE(own != nullptr, "own-state module failed to load: " << last_error());
    auto own_set_self = sym<void (*)()>(own, "ds_fa_consumer_set_self");
    auto own_get      = sym<void* (*)()>(own, "ds_fa_consumer_get");
    auto own_fail     = sym<void (*)()>(own, "ds_fa_consumer_fail");
    auto own_local    = sym<int (*)()>(own, "ds_fa_consumer_local_calls");
    REQUIRE(own_set_self != nullptr);
    REQUIRE(own_get != nullptr);
    REQUIRE(own_fail != nullptr);
    REQUIRE(own_local != nullptr);

    own_set_self();
    REQUIRE(own_get() != as_ptr(&host_handler));
    own_fail();
    REQUIRE(own_local() == 1);      // its own handler ran
    REQUIRE(g_host.calls == 1);     // the owner's slot was untouched
    REQUIRE(owner_get() == as_ptr(&host_handler));
}
