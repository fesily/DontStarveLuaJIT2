// Process-wide service table: plugins register named C functions; core.vm looks up.
#include "core/PluginServices.hpp"

#include <cassert>
#include <cstdio>

namespace {

int add_one(int x) { return x + 1; }
const char *hello() { return "ok"; }

} // namespace

static void test_lookup_missing_is_null() {
    assert(ds::plugin::lookup_service("missing.service") == nullptr);
    assert(ds_host_lookup_service("missing.service") == nullptr);
    printf("PASS: lookup_missing_is_null\n");
}

static void test_register_and_lookup() {
    assert(ds::plugin::register_service("test.add_one", reinterpret_cast<void *>(&add_one)));
    auto *fn = reinterpret_cast<int (*)(int)>(ds::plugin::lookup_service("test.add_one"));
    assert(fn != nullptr);
    assert(fn(41) == 42);

    // C ABI path
    auto *fn2 = reinterpret_cast<int (*)(int)>(ds_host_lookup_service("test.add_one"));
    assert(fn2 == fn);
    printf("PASS: register_and_lookup\n");
}

static void test_duplicate_register_fails() {
    assert(!ds::plugin::register_service("test.add_one", reinterpret_cast<void *>(&hello)));
    // original kept
    auto *fn = reinterpret_cast<int (*)(int)>(ds::plugin::lookup_service("test.add_one"));
    assert(fn(1) == 2);
    printf("PASS: duplicate_register_fails\n");
}

static void test_second_service() {
    assert(ds_host_register_service("test.hello", reinterpret_cast<void *>(&hello)));
    auto *fn = reinterpret_cast<const char *(*)()>(ds_host_lookup_service("test.hello"));
    assert(fn != nullptr);
    assert(fn()[0] == 'o');
    printf("PASS: second_service\n");
}

int main() {
    test_lookup_missing_is_null();
    test_register_and_lookup();
    test_duplicate_register_fails();
    test_second_service();
    printf("ALL PASS: plugin_services\n");
    return 0;
}
