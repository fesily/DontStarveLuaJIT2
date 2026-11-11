#include "util/FastHook.hpp"

#include <doctest/doctest.h>

#include <array>
#include <cstdint>
#include <cstring>
#include <limits>

namespace {

    struct Patch {
        const void *bytes;
        size_t size;
    };

    void apply_patch(void *writable, void *data) {
        const auto &patch = *static_cast<Patch *>(data);
        std::memcpy(writable, patch.bytes, patch.size);
    }

    void write(void *address, const void *bytes, size_t size) {
        Patch patch{bytes, size};
        REQUIRE_MESSAGE(gum_memory_patch_code(address, size, apply_patch, &patch), "write fixture code");
    }

    void jump(void *from, void *to) {
        std::array<uint8_t, 5> code{0xe9};
    const auto distance = reinterpret_cast<intptr_t>(to) -
                          (reinterpret_cast<intptr_t>(from) + static_cast<intptr_t>(code.size()));
        REQUIRE_MESSAGE(distance >= std::numeric_limits<int32_t>::min(), "fixture jump range");
        REQUIRE_MESSAGE(distance <= std::numeric_limits<int32_t>::max(), "fixture jump range");
        const auto offset = static_cast<int32_t>(distance);
        std::memcpy(code.data() + 1, &offset, sizeof(offset));
        write(from, code.data(), code.size());
    }

    void *jump_destination(void *entry) {
        const auto *bytes = static_cast<const uint8_t *>(entry);
        { INFO("entry is an E9 jump"); REQUIRE_EQ(bytes[0], 0xe9); }
        int32_t offset;
        std::memcpy(&offset, bytes + 1, sizeof(offset));
        return reinterpret_cast<void *>(reinterpret_cast<intptr_t>(entry) + 5 + offset);
    }

    using Function = int (*)();

    // Releases a gum mapping on scope exit, so an aborted assertion cannot leak
    // the fixture or the far replacement page.
    struct Mapping {
        uint8_t *bytes = nullptr;
        size_t size = 0;

        ~Mapping() {
            if (bytes != nullptr) gum_memory_free(bytes, size);
        }
    };

    // Ends the gum interceptor transaction even when an assertion unwinds.
    struct Transaction {
        explicit Transaction(GumInterceptor *interceptor) : interceptor_(interceptor) {
            gum_interceptor_begin_transaction(interceptor_);
        }

        ~Transaction() { gum_interceptor_end_transaction(interceptor_); }

        Transaction(const Transaction &) = delete;

        Transaction &operator=(const Transaction &) = delete;

    private:
        GumInterceptor *interceptor_;
    };

    struct Fixture {
        // The page is owned before the constructor body runs: a failed
        // allocation or write assertion then still frees it.
        struct Page {
            size_t size = gum_query_page_size();
            uint8_t *bytes = static_cast<uint8_t *>(gum_memory_allocate(nullptr, size, size, GUM_PAGE_RX));

            ~Page() {
                if (bytes != nullptr) gum_memory_free(bytes, size);
            }
        };

        Page owner;
        size_t page_size = owner.size;
        uint8_t *page = owner.bytes;
        std::array<uint8_t, 32> original{
                0x48, 0x83, 0xec, 0x28,// sub rsp, 40
                0xe8, 0xf7, 0x01, 0, 0,// call page + 0x200 (online relocatable span ends at 9)
                0x48, 0x83, 0xc4, 0x28, 0xc3};

        Fixture() {
            { INFO("allocate fixture"); REQUIRE_NE(page, nullptr); }
            write(page, original.data(), original.size());
            const uint8_t seven[]{0xb8, 7, 0, 0, 0, 0xc3};
            const uint8_t forty_two[]{0xb8, 42, 0, 0, 0, 0xc3};
            write(page + 0x200, seven, sizeof(seven));
            write(page + 0x100, forty_two, sizeof(forty_two));
        }

        int call() const { return reinterpret_cast<Function>(page)(); }

        void restored() const {
            { INFO("restore complete original bytes"); REQUIRE_EQ(std::memcmp(page, original.data(), original.size()), 0); }
            { INFO("restored original result"); REQUIRE_EQ(call(), 7); }
        }
    };

    void near_hooks(GumInterceptor *interceptor, Fixture &fixture) {
        { INFO("default fast hook rejects nine-byte online prologue");
            REQUIRE_EQ(gum_interceptor_replace_fast(interceptor, fixture.page, fixture.page + 0x100, nullptr, nullptr), GUM_REPLACE_WRONG_SIGNATURE); }
        fixture.restored();
        for (int iteration = 0; iteration != 32; ++iteration) {
            void *original = nullptr;
            { INFO("install near fast hook");
                REQUIRE_EQ(ds::FastHook::Install(interceptor, fixture.page, fixture.page + 0x100, &original), GUM_REPLACE_OK); }
            { INFO("jump directly to replacement"); REQUIRE_EQ(jump_destination(fixture.page), fixture.page + 0x100); }
            { INFO("near replacement result"); REQUIRE_EQ(fixture.call(), 42); }
            { INFO("original trampoline result"); REQUIRE_NE(original, nullptr); }
            REQUIRE_MESSAGE(reinterpret_cast<Function>(original)() == 7, "original trampoline result");
            REQUIRE_MESSAGE(!ds::FastHook::Revert(interceptor, original), "reject original trampoline as revert target");
            { INFO("reject duplicate installation");
                REQUIRE_EQ(ds::FastHook::Install(interceptor, fixture.page, fixture.page + 0x100), GUM_REPLACE_ALREADY_REPLACED); }
            REQUIRE_MESSAGE(ds::FastHook::Revert(interceptor, fixture.page), "revert near hook");
            REQUIRE_MESSAGE(ds::FastHook::Revert(interceptor, fixture.page), "revert is idempotent");
            fixture.restored();
        }
    }

    void far_hooks(GumInterceptor *interceptor, Fixture &fixture) {
        // `far` is freed by `far_mapping` even when a later assertion aborts.
        Mapping far_mapping{nullptr, fixture.page_size};
        uint8_t *&far = far_mapping.bytes;
        for (const uintptr_t candidate: {0x700000000000ull, 0x600000000000ull, 0x500000000000ull}) {
            auto *memory = static_cast<uint8_t *>(
                    gum_memory_allocate(reinterpret_cast<void *>(candidate), fixture.page_size, fixture.page_size, GUM_PAGE_RX));
            if (memory == nullptr) continue;
            const auto distance = reinterpret_cast<intptr_t>(memory) - reinterpret_cast<intptr_t>(fixture.page);
            if (distance > std::numeric_limits<int32_t>::max() || distance < std::numeric_limits<int32_t>::min()) {
                far = memory;
                break;
            }
            gum_memory_free(memory, fixture.page_size);
        }
        { INFO("allocate replacement outside rel32 range"); REQUIRE_NE(far, nullptr); }
        const uint8_t fifty_three[]{0xb8, 53, 0, 0, 0, 0xc3};
        write(far, fifty_three, sizeof(fifty_three));
        // Fill more than one relay page while exercising null original outputs.
        const auto iterations = fixture.page_size / 16 + 1;
        void *first_relay = nullptr;
        for (size_t iteration = 0; iteration != iterations; ++iteration) {
            { INFO("install far fast hook"); REQUIRE_EQ(ds::FastHook::Install(interceptor, fixture.page, far), GUM_REPLACE_OK); }
            auto *relay = static_cast<uint8_t *>(jump_destination(fixture.page));
            if (first_relay == nullptr) first_relay = relay;
            { INFO("relay uses register-preserving indirect jump"); REQUIRE_NE(relay, far); }
            { INFO("relay uses register-preserving indirect jump"); REQUIRE_EQ(relay[0], 0xff); }
            { INFO("relay uses register-preserving indirect jump"); REQUIRE_EQ(relay[1], 0x25); }
            uintptr_t relay_target;
            std::memcpy(&relay_target, relay + 6, sizeof(relay_target));
            REQUIRE_MESSAGE(relay_target == reinterpret_cast<uintptr_t>(far), "relay contains replacement address");
            { INFO("far replacement result"); REQUIRE_EQ(fixture.call(), 53); }
            REQUIRE_MESSAGE(ds::FastHook::Revert(interceptor, fixture.page), "revert far hook");
            fixture.restored();
        }
        REQUIRE_MESSAGE(reinterpret_cast<Function>(first_relay)() == 53, "retired relay remains executable");

        const uint8_t add_one[]{0x48, 0x83, 0xc0, 1, 0xc3};
        const uint8_t set_rax[]{0x48, 0xb8, 0x78, 0x56, 0x34, 0x12, 0, 0, 0, 0};
        write(far, add_one, sizeof(add_one));
        write(fixture.page + 0x400, set_rax, sizeof(set_rax));
        jump(fixture.page + 0x400 + sizeof(set_rax), fixture.page);
        { INFO("install register check"); REQUIRE_EQ(ds::FastHook::Install(interceptor, fixture.page, far), GUM_REPLACE_OK); }
        REQUIRE_MESSAGE(reinterpret_cast<Function>(fixture.page + 0x400)() == 0x12345679, "relay preserves RAX");
        REQUIRE_MESSAGE(ds::FastHook::Revert(interceptor, fixture.page), "revert register check");
        fixture.restored();
    }

    void thunk_and_transactions(GumInterceptor *interceptor, Fixture &fixture) {
        auto *thunk = fixture.page + 0x300;
        jump(thunk, fixture.page);
        std::array<uint8_t, 5> thunk_bytes;
        std::memcpy(thunk_bytes.data(), thunk, thunk_bytes.size());
        { INFO("reject self jump after resolving a native thunk");
            REQUIRE_EQ(ds::FastHook::Install(interceptor, thunk, fixture.page), GUM_REPLACE_WRONG_SIGNATURE); }
        fixture.restored();
        void *original = nullptr;
        { INFO("install through native thunk");
            REQUIRE_EQ(ds::FastHook::Install(interceptor, thunk, fixture.page + 0x100, &original), GUM_REPLACE_OK); }
        { INFO("thunk original and replacement"); REQUIRE_EQ(fixture.call(), 42); }
        REQUIRE_MESSAGE(reinterpret_cast<Function>(original)() == 7, "thunk original and replacement");
        REQUIRE_MESSAGE(ds::FastHook::Revert(interceptor, thunk), "revert using saved resolved address");
        { INFO("native thunk unchanged"); REQUIRE_EQ(std::memcmp(thunk, thunk_bytes.data(), thunk_bytes.size()), 0); }
        fixture.restored();

        {
            Transaction transaction(interceptor);
            { INFO("install within transaction");
                REQUIRE_EQ(ds::FastHook::Install(interceptor, fixture.page, fixture.page + 0x100), GUM_REPLACE_OK); }
            fixture.restored();
        }
        { INFO("transaction commits hook"); REQUIRE_EQ(fixture.call(), 42); }
        {
            Transaction transaction(interceptor);
            REQUIRE_MESSAGE(!ds::FastHook::Revert(interceptor, fixture.page), "deferred restore retains installation record");
        }
        REQUIRE_MESSAGE(ds::FastHook::Revert(interceptor, fixture.page), "retry deferred restore");
        fixture.restored();
    }

    void rejections_and_rip_relative(GumInterceptor *interceptor, Fixture &fixture) {
        { INFO("reject null interceptor");
            REQUIRE_EQ(ds::FastHook::Install(nullptr, fixture.page, fixture.page + 0x100), GUM_REPLACE_WRONG_SIGNATURE); }
        { INFO("reject self replacement");
            REQUIRE_EQ(ds::FastHook::Install(interceptor, fixture.page, fixture.page), GUM_REPLACE_WRONG_SIGNATURE); }
        const uint8_t tiny[]{0x31, 0xc0, 0xc3};
        write(fixture.page + 0x500, tiny, sizeof(tiny));
        { INFO("reject entry shorter than five bytes");
            REQUIRE_EQ(ds::FastHook::Install(interceptor, fixture.page + 0x500, fixture.page + 0x100), GUM_REPLACE_WRONG_SIGNATURE); }
        { INFO("failed install leaves tiny entry unchanged"); REQUIRE_EQ(std::memcmp(fixture.page + 0x500, tiny, sizeof(tiny)), 0); }

        { INFO("install ordinary hook for conflict check");
            REQUIRE_EQ(gum_interceptor_replace(interceptor, fixture.page, fixture.page + 0x100, nullptr, nullptr), GUM_REPLACE_OK); }
        std::array<uint8_t, 9> ordinary_entry;
        std::memcpy(ordinary_entry.data(), fixture.page, ordinary_entry.size());
        { INFO("reject ordinary interceptor context");
            REQUIRE_EQ(ds::FastHook::Install(interceptor, fixture.page, fixture.page + 0x100), GUM_REPLACE_WRONG_TYPE); }
        { INFO("conflict preserves existing hook"); REQUIRE_EQ(std::memcmp(ordinary_entry.data(), fixture.page, ordinary_entry.size()), 0); }
        gum_interceptor_revert(interceptor, fixture.page);
        fixture.restored();

        const uint8_t rip_load[]{0x8b, 0x05, 0xfa, 0, 0, 0, 0xc3};
        const int value = 19;
        write(fixture.page + 0x600, rip_load, sizeof(rip_load));
        write(fixture.page + 0x700, &value, sizeof(value));
        void *original = nullptr;
        { INFO("install over RIP-relative load");
            REQUIRE_EQ(ds::FastHook::Install(interceptor, fixture.page + 0x600, fixture.page + 0x100, &original), GUM_REPLACE_OK); }
        REQUIRE_MESSAGE(reinterpret_cast<Function>(original)() == value, "relocated RIP-relative original");
        REQUIRE_MESSAGE(ds::FastHook::Revert(interceptor, fixture.page + 0x600), "restore RIP-relative entry");
        { INFO("RIP-relative bytes restored"); REQUIRE_EQ(std::memcmp(fixture.page + 0x600, rip_load, sizeof(rip_load)), 0); }
    }

}// namespace

TEST_CASE("test_fast_hook/all") {
    // gum stays initialized for the rest of the process: this frida build has no
    // interceptor release, so tearing the engine down would leave the obtained
    // interceptor behind anyway.
    gum_init_embedded();
    auto *interceptor = gum_interceptor_obtain();
    Fixture fixture;
    fixture.restored();
    near_hooks(interceptor, fixture);
    far_hooks(interceptor, fixture);
    thunk_and_transactions(interceptor, fixture);
    rejections_and_rip_relative(interceptor, fixture);
}
