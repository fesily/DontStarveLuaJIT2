#include "util/FastHook.hpp"

#include <array>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <limits>

namespace {

    void require(bool condition, const char *message) {
        if (!condition) {
            std::fprintf(stderr, "FAIL: %s\n", message);
            std::exit(1);
        }
    }

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
        require(gum_memory_patch_code(address, size, apply_patch, &patch), "write fixture code");
    }

    void jump(void *from, void *to) {
        std::array<uint8_t, 5> code{0xe9};
    const auto distance = reinterpret_cast<intptr_t>(to) -
                          (reinterpret_cast<intptr_t>(from) + static_cast<intptr_t>(code.size()));
        require(distance >= std::numeric_limits<int32_t>::min() &&
                        distance <= std::numeric_limits<int32_t>::max(),
                "fixture jump range");
        const auto offset = static_cast<int32_t>(distance);
        std::memcpy(code.data() + 1, &offset, sizeof(offset));
        write(from, code.data(), code.size());
    }

    void *jump_destination(void *entry) {
        const auto *bytes = static_cast<const uint8_t *>(entry);
        require(bytes[0] == 0xe9, "entry is an E9 jump");
        int32_t offset;
        std::memcpy(&offset, bytes + 1, sizeof(offset));
        return reinterpret_cast<void *>(reinterpret_cast<intptr_t>(entry) + 5 + offset);
    }

    using Function = int (*)();

    struct Fixture {
        size_t page_size = gum_query_page_size();
        uint8_t *page = static_cast<uint8_t *>(gum_memory_allocate(nullptr, page_size, page_size, GUM_PAGE_RX));
        std::array<uint8_t, 32> original{
                0x48, 0x83, 0xec, 0x28,// sub rsp, 40
                0xe8, 0xf7, 0x01, 0, 0,// call page + 0x200 (online relocatable span ends at 9)
                0x48, 0x83, 0xc4, 0x28, 0xc3};

        Fixture() {
            require(page != nullptr, "allocate fixture");
            write(page, original.data(), original.size());
            const uint8_t seven[]{0xb8, 7, 0, 0, 0, 0xc3};
            const uint8_t forty_two[]{0xb8, 42, 0, 0, 0, 0xc3};
            write(page + 0x200, seven, sizeof(seven));
            write(page + 0x100, forty_two, sizeof(forty_two));
        }

        ~Fixture() { gum_memory_free(page, page_size); }

        int call() const { return reinterpret_cast<Function>(page)(); }

        void restored() const {
            require(std::memcmp(page, original.data(), original.size()) == 0, "restore complete original bytes");
            require(call() == 7, "restored original result");
        }
    };

    void near_hooks(GumInterceptor *interceptor, Fixture &fixture) {
        require(gum_interceptor_replace_fast(interceptor, fixture.page, fixture.page + 0x100, nullptr, nullptr) ==
                        GUM_REPLACE_WRONG_SIGNATURE,
                "default fast hook rejects nine-byte online prologue");
        fixture.restored();
        for (int iteration = 0; iteration != 32; ++iteration) {
            void *original = nullptr;
            require(ds::FastHook::Install(interceptor, fixture.page, fixture.page + 0x100, &original) == GUM_REPLACE_OK,
                    "install near fast hook");
            require(jump_destination(fixture.page) == fixture.page + 0x100, "jump directly to replacement");
            require(fixture.call() == 42, "near replacement result");
            require(original != nullptr && reinterpret_cast<Function>(original)() == 7, "original trampoline result");
            require(!ds::FastHook::Revert(interceptor, original), "reject original trampoline as revert target");
            require(ds::FastHook::Install(interceptor, fixture.page, fixture.page + 0x100) == GUM_REPLACE_ALREADY_REPLACED,
                    "reject duplicate installation");
            require(ds::FastHook::Revert(interceptor, fixture.page), "revert near hook");
            require(ds::FastHook::Revert(interceptor, fixture.page), "revert is idempotent");
            fixture.restored();
        }
    }

    void far_hooks(GumInterceptor *interceptor, Fixture &fixture) {
        uint8_t *far = nullptr;
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
        require(far != nullptr, "allocate replacement outside rel32 range");
        const uint8_t fifty_three[]{0xb8, 53, 0, 0, 0, 0xc3};
        write(far, fifty_three, sizeof(fifty_three));
        // Fill more than one relay page while exercising null original outputs.
        const auto iterations = fixture.page_size / 16 + 1;
        void *first_relay = nullptr;
        for (size_t iteration = 0; iteration != iterations; ++iteration) {
            require(ds::FastHook::Install(interceptor, fixture.page, far) == GUM_REPLACE_OK, "install far fast hook");
            auto *relay = static_cast<uint8_t *>(jump_destination(fixture.page));
            if (first_relay == nullptr) first_relay = relay;
            require(relay != far && relay[0] == 0xff && relay[1] == 0x25, "relay uses register-preserving indirect jump");
            uintptr_t relay_target;
            std::memcpy(&relay_target, relay + 6, sizeof(relay_target));
            require(relay_target == reinterpret_cast<uintptr_t>(far), "relay contains replacement address");
            require(fixture.call() == 53, "far replacement result");
            require(ds::FastHook::Revert(interceptor, fixture.page), "revert far hook");
            fixture.restored();
        }
        require(reinterpret_cast<Function>(first_relay)() == 53, "retired relay remains executable");

        const uint8_t add_one[]{0x48, 0x83, 0xc0, 1, 0xc3};
        const uint8_t set_rax[]{0x48, 0xb8, 0x78, 0x56, 0x34, 0x12, 0, 0, 0, 0};
        write(far, add_one, sizeof(add_one));
        write(fixture.page + 0x400, set_rax, sizeof(set_rax));
        jump(fixture.page + 0x400 + sizeof(set_rax), fixture.page);
        require(ds::FastHook::Install(interceptor, fixture.page, far) == GUM_REPLACE_OK, "install register check");
        require(reinterpret_cast<Function>(fixture.page + 0x400)() == 0x12345679, "relay preserves RAX");
        require(ds::FastHook::Revert(interceptor, fixture.page), "revert register check");
        fixture.restored();
        gum_memory_free(far, fixture.page_size);
    }

    void thunk_and_transactions(GumInterceptor *interceptor, Fixture &fixture) {
        auto *thunk = fixture.page + 0x300;
        jump(thunk, fixture.page);
        std::array<uint8_t, 5> thunk_bytes;
        std::memcpy(thunk_bytes.data(), thunk, thunk_bytes.size());
        require(ds::FastHook::Install(interceptor, thunk, fixture.page) == GUM_REPLACE_WRONG_SIGNATURE,
                "reject self jump after resolving a native thunk");
        fixture.restored();
        void *original = nullptr;
        require(ds::FastHook::Install(interceptor, thunk, fixture.page + 0x100, &original) == GUM_REPLACE_OK,
                "install through native thunk");
        require(fixture.call() == 42 && reinterpret_cast<Function>(original)() == 7, "thunk original and replacement");
        require(ds::FastHook::Revert(interceptor, thunk), "revert using saved resolved address");
        require(std::memcmp(thunk, thunk_bytes.data(), thunk_bytes.size()) == 0, "native thunk unchanged");
        fixture.restored();

        gum_interceptor_begin_transaction(interceptor);
        require(ds::FastHook::Install(interceptor, fixture.page, fixture.page + 0x100) == GUM_REPLACE_OK,
                "install within transaction");
        fixture.restored();
        gum_interceptor_end_transaction(interceptor);
        require(fixture.call() == 42, "transaction commits hook");
        gum_interceptor_begin_transaction(interceptor);
        require(!ds::FastHook::Revert(interceptor, fixture.page), "deferred restore retains installation record");
        gum_interceptor_end_transaction(interceptor);
        require(ds::FastHook::Revert(interceptor, fixture.page), "retry deferred restore");
        fixture.restored();
    }

    void rejections_and_rip_relative(GumInterceptor *interceptor, Fixture &fixture) {
        require(ds::FastHook::Install(nullptr, fixture.page, fixture.page + 0x100) == GUM_REPLACE_WRONG_SIGNATURE,
                "reject null interceptor");
        require(ds::FastHook::Install(interceptor, fixture.page, fixture.page) == GUM_REPLACE_WRONG_SIGNATURE,
                "reject self replacement");
        const uint8_t tiny[]{0x31, 0xc0, 0xc3};
        write(fixture.page + 0x500, tiny, sizeof(tiny));
        require(ds::FastHook::Install(interceptor, fixture.page + 0x500, fixture.page + 0x100) == GUM_REPLACE_WRONG_SIGNATURE,
                "reject entry shorter than five bytes");
        require(std::memcmp(fixture.page + 0x500, tiny, sizeof(tiny)) == 0, "failed install leaves tiny entry unchanged");

        require(gum_interceptor_replace(interceptor, fixture.page, fixture.page + 0x100, nullptr, nullptr) == GUM_REPLACE_OK,
                "install ordinary hook for conflict check");
        std::array<uint8_t, 9> ordinary_entry;
        std::memcpy(ordinary_entry.data(), fixture.page, ordinary_entry.size());
        require(ds::FastHook::Install(interceptor, fixture.page, fixture.page + 0x100) == GUM_REPLACE_WRONG_TYPE,
                "reject ordinary interceptor context");
        require(std::memcmp(ordinary_entry.data(), fixture.page, ordinary_entry.size()) == 0, "conflict preserves existing hook");
        gum_interceptor_revert(interceptor, fixture.page);
        fixture.restored();

        const uint8_t rip_load[]{0x8b, 0x05, 0xfa, 0, 0, 0, 0xc3};
        const int value = 19;
        write(fixture.page + 0x600, rip_load, sizeof(rip_load));
        write(fixture.page + 0x700, &value, sizeof(value));
        void *original = nullptr;
        require(ds::FastHook::Install(interceptor, fixture.page + 0x600, fixture.page + 0x100, &original) == GUM_REPLACE_OK,
                "install over RIP-relative load");
        require(reinterpret_cast<Function>(original)() == value, "relocated RIP-relative original");
        require(ds::FastHook::Revert(interceptor, fixture.page + 0x600), "restore RIP-relative entry");
        require(std::memcmp(fixture.page + 0x600, rip_load, sizeof(rip_load)) == 0, "RIP-relative bytes restored");
    }

}// namespace

int main() {
    gum_init_embedded();
    auto *interceptor = gum_interceptor_obtain();
    Fixture fixture;
    fixture.restored();
    near_hooks(interceptor, fixture);
    far_hooks(interceptor, fixture);
    thunk_and_transactions(interceptor, fixture);
    rejections_and_rip_relative(interceptor, fixture);
    std::puts("PASS: direct/relay jumps, original trampolines, restoration, transactions, rejection paths");
}
