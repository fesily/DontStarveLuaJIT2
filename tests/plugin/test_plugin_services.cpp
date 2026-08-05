// Process-wide service table: Host registers during module window; lookup always.
#include "core/PluginHost.hpp"
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

static void test_host_register_and_lookup() {
    ds::plugin::PluginHost host;
    assert(host.register_service("test.add_one", reinterpret_cast<void *>(&add_one)));
    auto *fn = reinterpret_cast<int (*)(int)>(ds::plugin::lookup_service("test.add_one"));
    assert(fn != nullptr);
    assert(fn(41) == 42);
    auto *fn2 = reinterpret_cast<int (*)(int)>(ds_host_lookup_service("test.add_one"));
    assert(fn2 == fn);
    printf("PASS: host_register_and_lookup\n");
}

static void test_duplicate_register_fails() {
    ds::plugin::PluginHost host;
    assert(!host.register_service("test.add_one", reinterpret_cast<void *>(&hello)));
    auto *fn = reinterpret_cast<int (*)(int)>(ds::plugin::lookup_service("test.add_one"));
    assert(fn(1) == 2);
    printf("PASS: duplicate_register_fails\n");
}

static void test_window_closed_rejects_register() {
    ds::plugin::PluginHost host;
    host.end_module_registration();
    assert(!host.register_service("test.closed", reinterpret_cast<void *>(&hello)));
    assert(ds::plugin::lookup_service("test.closed") == nullptr);
    host.begin_module_registration();
    assert(host.register_service("test.hello", reinterpret_cast<void *>(&hello)));
    auto *fn = reinterpret_cast<const char *(*)()>(ds_host_lookup_service("test.hello"));
    assert(fn != nullptr);
    assert(fn()[0] == 'o');
    printf("PASS: window_closed_rejects_register\n");
}

int main() {
    test_lookup_missing_is_null();
    test_host_register_and_lookup();
    test_duplicate_register_fails();
    test_window_closed_rejects_register();
    printf("ALL PASS: plugin_services\n");
    return 0;
}
