// Auto-deduced GiType[] from function pointer types.
#include "core/PluginHost.hpp"
#include "core/PluginServices.hpp"

#include <cassert>
#include <cstdio>

namespace {

int add_one(int x) { return x + 1; }
const char *hello() { return "ok"; }

constexpr ds::plugin::ServiceDesc<int (*)(int)> kAddOne{"test.add_one"};
constexpr ds::plugin::ServiceDesc<const char *(*)()> kHello{"test.hello"};

} // namespace

static void test_lookup_missing_is_null() {
    assert(ds::plugin::lookup_service("missing.service") == nullptr);
    assert(ds::plugin::request_service<int (*)(int)>("missing.service") == nullptr);
    assert(kAddOne.request() == nullptr);
    printf("PASS: lookup_missing_is_null\n");
}

static void test_host_register_and_request() {
    ds::plugin::PluginHost host;
    assert(host.register_service("test.add_one", &add_one));
    auto *fn = ds::plugin::request_service<int (*)(int)>("test.add_one");
    assert(fn != nullptr);
    assert(fn(41) == 42);
    assert(kAddOne.request() == fn);
    printf("PASS: host_register_and_request\n");
}

static void test_type_mismatch_returns_null() {
    // Registered as int(int); request as const char*(void) must fail.
    auto *wrong = ds::plugin::request_service<const char *(*)()>("test.add_one");
    assert(wrong == nullptr);
    assert(ds::plugin::request_service<int (*)(int)>("test.add_one") != nullptr);
    printf("PASS: type_mismatch_returns_null\n");
}

static void test_duplicate_register_fails() {
    ds::plugin::PluginHost host;
    assert(!host.register_service("test.add_one", &add_one));
    assert(kAddOne.request()(1) == 2);
    printf("PASS: duplicate_register_fails\n");
}

static void test_window_closed_rejects_register() {
    ds::plugin::PluginHost host;
    host.end_module_registration();
    assert(!host.register_service("test.hello", &hello));
    assert(kHello.request() == nullptr);
    host.begin_module_registration();
    assert(host.register_service("test.hello", &hello));
    assert(kHello.request() != nullptr);
    assert(kHello.request()()[0] == 'o');
    printf("PASS: window_closed_rejects_register\n");
}

static void test_gi_export_auto() {
    ds::plugin::PluginHost host;
    assert(host.register_game_injector_export("test.add_one_gi", &add_one));
    // presence in export table
    ds::plugin::GameInjectorExport buf[8];
    int n = ds::plugin::copy_game_injector_exports(buf, 8);
    bool found = false;
    for (int i = 0; i < n && i < 8; ++i) {
        if (buf[i].name && std::string_view(buf[i].name) == "test.add_one_gi") {
            found = true;
            // I32, I32
            assert(buf[i].ntypes == 2);
            assert(buf[i].types[0] == ds::plugin::GiType::I32);
            assert(buf[i].types[1] == ds::plugin::GiType::I32);
        }
    }
    assert(found);
    printf("PASS: gi_export_auto\n");
}

int main() {
    test_lookup_missing_is_null();
    test_host_register_and_request();
    test_type_mismatch_returns_null();
    test_duplicate_register_fails();
    test_window_closed_rejects_register();
    test_gi_export_auto();
    printf("ALL PASS: plugin_services\n");
    return 0;
}
