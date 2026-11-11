// Signature provider registration lifecycle (PluginHost staging/publish).
//
// Covers the boundaries that a failed registration must never cross:
//   * registration outside the module_init window is refused
//   * wrong struct_size / interface_version is refused
//   * an empty or duplicate name rejects the whole provider atomically
//   * a module whose init failed (or threw) publishes nothing
//   * the same name is allowed for disjoint platforms, rejected when they overlap
//
// The provider table is hand-built here on purpose: this test must not depend on
// frida-gum or the scan implementation, only on the POD contract.

#include "core/PluginHost.hpp"

#include <cstdio>
#include <cstring>
#include "support/test_assert.hpp"

using namespace ds::plugin;
using namespace ds::sig;

namespace {

struct FakeProvider {
    const char *owner = "fake.owner";
    const char *name = "fake.owner.entry";
    uint32_t platform_mask = kPlatformWindowsX64;
    uint32_t entry_count_value = 1;
    uint8_t client_only = 0;
};

uint32_t fake_entry_count(void *self) {
    return static_cast<FakeProvider *>(self)->entry_count_value;
}

bool fake_entry_at(void *self, uint32_t index, EntryView *out) {
    auto *fake = static_cast<FakeProvider *>(self);
    if (!out || index >= fake->entry_count_value) {
        return false;
    }
    *out = EntryView{};
    std::snprintf(out->owner, sizeof(out->owner), "%s", fake->owner);
    std::snprintf(out->name, sizeof(out->name), "%s", fake->name);
    out->platform_mask = fake->platform_mask;
    out->client_only = fake->client_only;
    out->definition_revision = 1;
    return true;
}

bool fake_get_cached(void *, const char *, const ContextView *, CacheRecord *) {
    return false;
}

bool fake_extract_from_file(void *, const char *, const char *, const ContextView *, CacheRecord *) {
    return false;
}

bool fake_resolve(void *, const char *, const ContextView *, ResolveReport *) {
    return false;
}

ProviderV1 make_fake(FakeProvider &fake) {
    ProviderV1 provider{};
    provider.self = &fake;
    provider.entry_count = &fake_entry_count;
    provider.entry_at = &fake_entry_at;
    provider.get_cached = &fake_get_cached;
    provider.extract_from_file = &fake_extract_from_file;
    provider.resolve = &fake_resolve;
    return provider;
}

// Mirrors DynamicPluginLoader: open, run init, end, then publish/discard.
bool run_module(PluginHost &host, const ProviderV1 &provider, bool init_result) {
    bool ok = false;
    host.begin_module_registration();
    ok = init_result ? host.register_signature_provider(&provider) : false;
    host.end_module_registration();
    if (ok && init_result) {
        host.publish_module_registration();
    } else {
        host.discard_module_registration();
    }
    return ok;
}

void test_window_and_versions() {
    PluginHost host; // DS_PLUGIN_HOST_STATIC: window starts open
    host.end_module_registration();
    FakeProvider fake;
    auto provider = make_fake(fake);
    DS_REQUIRE(!host.register_signature_provider(&provider));
    DS_REQUIRE(host.signature_provider_count() == 0);

    host.begin_module_registration();
    auto wrong_size = provider;
    wrong_size.struct_size = sizeof(ProviderV1) - 8;
    DS_REQUIRE(!host.register_signature_provider(&wrong_size));
    auto wrong_version = provider;
    wrong_version.interface_version = kProviderInterfaceVersion + 1;
    DS_REQUIRE(!host.register_signature_provider(&wrong_version));
    auto missing_fn = provider;
    missing_fn.resolve = nullptr;
    DS_REQUIRE(!host.register_signature_provider(&missing_fn));
    auto empty_count = provider;
    fake.entry_count_value = 0;
    DS_REQUIRE(!host.register_signature_provider(&empty_count));
    fake.entry_count_value = 1;
    DS_REQUIRE(host.register_signature_provider(&provider));
    host.end_module_registration();
    host.publish_module_registration();
    DS_REQUIRE(host.signature_provider_count() == 1);
    printf("PASS: window_and_versions\n");
}

void test_failed_init_publishes_nothing() {
    PluginHost host;
    FakeProvider fake;
    auto provider = make_fake(fake);
    DS_REQUIRE(!run_module(host, provider, /*init_result=*/false));
    DS_REQUIRE(host.signature_provider_count() == 0);

    // A staged provider from a failed module must not leak into the next one.
    host.begin_module_registration();
    DS_REQUIRE(host.register_signature_provider(&provider));
    host.end_module_registration();
    host.discard_module_registration();
    DS_REQUIRE(host.signature_provider_count() == 0);
    printf("PASS: failed_init_publishes_nothing\n");
}

void test_names() {
    PluginHost host;
    FakeProvider empty_name;
    empty_name.name = "";
    auto empty_provider = make_fake(empty_name);
    DS_REQUIRE(!run_module(host, empty_provider, true));
    DS_REQUIRE(host.signature_provider_count() == 0);

    FakeProvider first;
    auto first_provider = make_fake(first);
    DS_REQUIRE(run_module(host, first_provider, true));
    DS_REQUIRE(host.signature_provider_count() == 1);

    // Same name, overlapping platform: rejected.
    FakeProvider duplicate;
    duplicate.name = first.name;
    auto duplicate_provider = make_fake(duplicate);
    DS_REQUIRE(!run_module(host, duplicate_provider, true));
    DS_REQUIRE(host.signature_provider_count() == 1);

    // Same name, disjoint platform: a legitimate platform variant.
    FakeProvider variant;
    variant.name = first.name;
    variant.platform_mask = kPlatformLinuxX64;
    auto variant_provider = make_fake(variant);
    DS_REQUIRE(run_module(host, variant_provider, true));
    DS_REQUIRE(host.signature_provider_count() == 2);
    printf("PASS: names\n");
}

} // namespace

int main() {
    test_window_and_versions();
    test_failed_init_publishes_nothing();
    test_names();
    printf("all signature provider registration tests passed\n");
    return 0;
}
