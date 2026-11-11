// Auto-deduced GiType[] from function pointer types.
#include "core/PluginHost.hpp"
#include "core/PluginServices.hpp"

#include <doctest/doctest.h>

namespace {

int add_one(int x) { return x + 1; }
const char *hello() { return "ok"; }

constexpr ds::plugin::ServiceDesc<int (*)(int)> kAddOne{"test.add_one"};
constexpr ds::plugin::ServiceDesc<const char *(*)()> kHello{"test.hello"};

} // namespace

// Lifecycle order matters: registration, duplicate rejection and the export
// table all build on state left by the earlier steps, and the services registry
// has no reset API. Each step keeps the PluginHost fixture it had as a separate
// scenario, so every host lifetime stays exactly what the original main() ran.
TEST_CASE("test_plugin_services/all") {
    REQUIRE_EQ(ds::plugin::lookup_service("missing.service"), nullptr);
    REQUIRE(ds::plugin::request_service<int (*)(int)>("missing.service") == nullptr);
    REQUIRE_EQ(kAddOne.request(), nullptr);

    {
        ds::plugin::PluginHost host;
        REQUIRE(host.register_service("test.add_one", &add_one));
        auto *fn = ds::plugin::request_service<int (*)(int)>("test.add_one");
        REQUIRE_NE(fn, nullptr);
        REQUIRE_EQ(fn(41), 42);
        REQUIRE_EQ(kAddOne.request(), fn);
    }

    {
        // Registered as int(int); request as const char*(void) must fail.
        auto *wrong = ds::plugin::request_service<const char *(*)()>("test.add_one");
        REQUIRE_EQ(wrong, nullptr);
        REQUIRE(ds::plugin::request_service<int (*)(int)>("test.add_one") != nullptr);
    }

    {
        ds::plugin::PluginHost host;
        REQUIRE_FALSE(host.register_service("test.add_one", &add_one));
        REQUIRE_EQ(kAddOne.request()(1), 2);
    }

    {
        ds::plugin::PluginHost host;
        host.end_module_registration();
        REQUIRE_FALSE(host.register_service("test.hello", &hello));
        REQUIRE_EQ(kHello.request(), nullptr);
        host.begin_module_registration();
        REQUIRE(host.register_service("test.hello", &hello));
        REQUIRE_NE(kHello.request(), nullptr);
        REQUIRE_EQ(kHello.request()()[0], 'o');
    }

    {
        ds::plugin::PluginHost host;
        REQUIRE(host.register_game_injector_export("test.add_one_gi", &add_one));
        // presence in export table
        ds::plugin::GameInjectorExport buf[8];
        int n = ds::plugin::copy_game_injector_exports(buf, 8);
        bool found = false;
        for (int i = 0; i < n && i < 8; ++i) {
            if (buf[i].name && std::string_view(buf[i].name) == "test.add_one_gi") {
                found = true;
                // I32, I32
                REQUIRE_EQ(buf[i].ntypes, 2);
                REQUIRE_EQ(buf[i].types[0], ds::plugin::GiType::I32);
                REQUIRE_EQ(buf[i].types[1], ds::plugin::GiType::I32);
            }
        }
        REQUIRE(found);
    }
}
