#include "InjectorSignatures.hpp"

#include "SignatureManager.hpp"

#include "ProviderDesc.hpp"

namespace ds::sig {

bool register_injector_provider(std::string *detail) {
    ProviderV1 table{};
    if (!make_provider(&injector_provider_desc(), &table)) {
        if (detail) {
            *detail = "injector provider descriptor is malformed";
        }
        return false;
    }
    // L0 provider: published directly (no plugin module owns it), and it must be
    // visible before LoadGameModConfig() installs the SetThreadName hook.
    return add_provider(&table, detail);
}

} // namespace ds::sig
