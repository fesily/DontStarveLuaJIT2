// Typed service table: schema on register; request_service checks types.
#include "core/PluginHost.hpp"
#include "core/PluginServices.hpp"
#include "core/GameInjectorLuaRegistry.hpp"

#include <cassert>
#include <cstdio>

namespace {

using ds::plugin::GiType;

int add_one(int x) { return x + 1; }
const char *hello() { return "ok"; }

// Shared descriptors (register + request).
constexpr ds::plugin::ServiceDesc<int (*)(int), GiType::I32, GiType::I32> kAddOne{"test.add_one"};
constexpr ds::plugin::ServiceDesc<const char *(*)(), GiType::CString> kHello{"test.hello"};

} // namespace

static void test_lookup_missing_is_null() {
    assert(ds::plugin::lookup_service("missing.service") == nullptr);
    assert(ds_host_lookup_service("missing.service") == nullptr);
    assert(kAddOne.request() == nullptr);
    printf("PASS: lookup_missing_is_null\n");
}

static void test_host_register_and_request() {
    ds::plugin::PluginHost host;
    assert(host.register_service(kAddOne.name, kAddOne.types, reinterpret_cast<void *>(&add_one)));
    auto *fn = kAddOne.request();
    assert(fn != nullptr);
    assert(fn(41) == 42);
    // Untyped presence still works
    assert(ds::plugin::lookup_service("test.add_one") != nullptr);
    printf("PASS: host_register_and_request\n");
}

static void test_type_mismatch_returns_null() {
    // Registered as I32(I32); request as CString() must fail.
    auto *wrong = ds::plugin::request_service<const char *(*)()>(
        "test.add_one", {GiType::CString});
    assert(wrong == nullptr);
    // Correct schema still works
    assert(kAddOne.request() != nullptr);
    printf("PASS: type_mismatch_returns_null\n");
}

static void test_duplicate_register_fails() {
    ds::plugin::PluginHost host;
    assert(!host.register_service(kAddOne.name, kAddOne.types, reinterpret_cast<void *>(&hello)));
    assert(kAddOne.request()(1) == 2);
    printf("PASS: duplicate_register_fails\n");
}

static void test_window_closed_rejects_register() {
    ds::plugin::PluginHost host;
    host.end_module_registration();
    assert(!host.register_service(kHello.name, kHello.types, reinterpret_cast<void *>(&hello)));
    assert(kHello.request() == nullptr);
    host.begin_module_registration();
    assert(host.register_service(kHello.name, kHello.types, reinterpret_cast<void *>(&hello)));
    assert(kHello.request() != nullptr);
    assert(kHello.request()()[0] == 'o');
    printf("PASS: window_closed_rejects_register\n");
}

int main() {
    test_lookup_missing_is_null();
    test_host_register_and_request();
    test_type_mismatch_returns_null();
    test_duplicate_register_fails();
    test_window_closed_rejects_register();
    printf("ALL PASS: plugin_services\n");
    return 0;
}
