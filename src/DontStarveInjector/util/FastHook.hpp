#pragma once

#include "platform.hpp"
#include <frida-gum.h>

namespace ds {

    // Direct replacement hooks on x86-64. Gum owns relocation and entry restoration;
    // nearby jump relays remain executable for the lifetime of the process.
    class FastHook {
    public:
        static DS_PLATFORM_API GumReplaceReturn Install(GumInterceptor *interceptor, void *target,
                                                        void *replacement, void **original = nullptr);

        // Use the installation target, never the returned original trampoline.
        // Returns true only after the saved entry bytes are visible again.
        static DS_PLATFORM_API bool Revert(GumInterceptor *interceptor, void *target);
    };

}// namespace ds
