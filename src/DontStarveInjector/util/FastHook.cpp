#include "FastHook.hpp"

#include <array>
#include <cstdint>
#include <cstring>
#include <limits>
#include <memory>
#include <mutex>
#include <vector>

namespace ds {

#if defined(_M_X64) || defined(__x86_64__)
    namespace {

        constexpr size_t entry_jump_size = 5;
        constexpr size_t relay_size = 16;

        struct HookRecord {
            GumInterceptor *interceptor;
            void *requested_target;
            void *replacement;
            void *installed_target = nullptr;
            std::array<uint8_t, entry_jump_size> original_entry{};
            bool active = false;
        };

        struct RelayPage {
            uint8_t *address;
            size_t used;
        };

        struct HookRegistry {
            std::mutex mutex;
            std::vector<std::unique_ptr<HookRecord>> records;
            std::vector<RelayPage> relay_pages;
        };

        HookRegistry &registry() {
            // Both relay code and callback data may outlive the plugin that installed them.
            static auto *instance = new HookRegistry;
            return *instance;
        }

        bool near_jump_offset(uintptr_t from, uintptr_t to, int32_t &offset) {
            const auto distance = static_cast<int64_t>(to) - static_cast<int64_t>(from + entry_jump_size);
            if (distance < std::numeric_limits<int32_t>::min() || distance > std::numeric_limits<int32_t>::max()) {
                return false;
            }
            offset = static_cast<int32_t>(distance);
            return true;
        }

        void write_relay(void *writable, void *data) {
            const auto *code = static_cast<const std::array<uint8_t, relay_size> *>(data);
            std::memcpy(writable, code->data(), code->size());
        }

        void *allocate_relay(uintptr_t entry, void *replacement) {
            auto &pages = registry().relay_pages;
            const auto page_size = gum_query_page_size();
            RelayPage *page = nullptr;
            int32_t ignored;
            for (auto &candidate: pages) {
                if (candidate.used + relay_size <= page_size &&
                    near_jump_offset(entry, reinterpret_cast<uintptr_t>(candidate.address + candidate.used), ignored)) {
                    page = &candidate;
                    break;
                }
            }
            if (page == nullptr) {
                GumAddressSpec spec{};
                spec.near_address = reinterpret_cast<void *>(entry);
                spec.max_distance = std::numeric_limits<int32_t>::max() - page_size;
                auto *address = static_cast<uint8_t *>(gum_memory_allocate_near(&spec, page_size, page_size, GUM_PAGE_RX));
                if (address == nullptr) {
                    return nullptr;
                }
                pages.push_back({address, 0});
                page = &pages.back();
            }

            auto *relay = page->address + page->used;
            page->used += relay_size;
            std::array<uint8_t, relay_size> code{0xff, 0x25, 0, 0, 0, 0};
            const auto destination = reinterpret_cast<uint64_t>(replacement);
            std::memcpy(code.data() + 6, &destination, sizeof(destination));
            return gum_memory_patch_code(relay, code.size(), write_relay, &code) ? relay : nullptr;
        }

        GumRedirectWriteResult write_redirect(const GumRedirectWriteDetails *details, void *data) {
            auto &record = *static_cast<HookRecord *>(data);
            auto *writer = static_cast<GumX86Writer *>(details->writer);
            if (details->capacity < entry_jump_size) {
                return GUM_REDIRECT_DECLINED;
            }

            // FAST invokes this callback before assigning details->target.
            const auto entry = static_cast<uintptr_t>(writer->pc);
            if (entry == reinterpret_cast<uintptr_t>(record.replacement)) {
                return GUM_REDIRECT_DECLINED;
            }
            record.installed_target = reinterpret_cast<void *>(entry);
            std::memcpy(record.original_entry.data(), record.installed_target, record.original_entry.size());
            int32_t offset;
            if (!near_jump_offset(entry, reinterpret_cast<uintptr_t>(record.replacement), offset)) {
                auto *relay = allocate_relay(entry, record.replacement);
                if (relay == nullptr || !near_jump_offset(entry, reinterpret_cast<uintptr_t>(relay), offset)) {
                    return GUM_REDIRECT_DECLINED;
                }
            }

            std::array<uint8_t, entry_jump_size> code{0xe9};
            std::memcpy(code.data() + 1, &offset, sizeof(offset));
            gum_x86_writer_put_bytes(writer, code.data(), code.size());
            return GUM_REDIRECT_WRITTEN;
        }

        HookRecord *find_record(HookRegistry &state, GumInterceptor *interceptor, void *target) {
            for (auto it = state.records.rbegin(); it != state.records.rend(); ++it) {
                auto &record = **it;
                if (record.interceptor == interceptor &&
                    (record.requested_target == target || record.installed_target == target)) {
                    return &record;
                }
            }
            return nullptr;
        }

    }// namespace
#endif

    GumReplaceReturn FastHook::Install(GumInterceptor *interceptor, void *target, void *replacement, void **original) {
        if (original != nullptr) {
            *original = nullptr;
        }
        if (interceptor == nullptr || target == nullptr || replacement == nullptr || target == replacement) {
            return GUM_REPLACE_WRONG_SIGNATURE;
        }
#if defined(_M_X64) || defined(__x86_64__)
        auto &state = registry();
        std::lock_guard lock(state.mutex);
        if (auto *record = find_record(state, interceptor, target); record != nullptr && record->active) {
            return GUM_REPLACE_ALREADY_REPLACED;
        }
        auto record = std::make_unique<HookRecord>();
        record->interceptor = interceptor;
        record->requested_target = target;
        record->replacement = replacement;
        auto *installed = record.get();
        state.records.push_back(std::move(record));

        GumInterceptorOptions options{};
        options.write_redirect = write_redirect;
        options.write_redirect_data = installed;
        options.redirect_space_hint = entry_jump_size;
        const auto result = gum_interceptor_replace_fast(interceptor, target, replacement, original, &options);
        installed->active = result == GUM_REPLACE_OK;
        return result;
#else
        return GUM_REPLACE_WRONG_SIGNATURE;
#endif
    }

    bool FastHook::Revert(GumInterceptor *interceptor, void *target) {
#if defined(_M_X64) || defined(__x86_64__)
        auto &state = registry();
        std::lock_guard lock(state.mutex);
        auto *record = find_record(state, interceptor, target);
        if (record == nullptr || record->installed_target == nullptr) {
            return false;
        }
        if (record->active) {
            gum_interceptor_revert(interceptor, record->installed_target);
        }
        if (std::memcmp(record->installed_target, record->original_entry.data(), record->original_entry.size()) != 0) {
            return false;
        }
        record->active = false;
        return true;
#else
        return false;
#endif
    }

}// namespace ds
