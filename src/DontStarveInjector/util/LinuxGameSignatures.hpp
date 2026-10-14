#pragma once

namespace ds::linux_signatures {
    inline constexpr char lua_module[] = "81 FE F1 D8 FF FF 7D ?? 81 FE EF D8 FF FF 74 ?? 81 FE F0 D8 FF FF";
    inline constexpr char register_debug_getsize[] = "48 8B 45 18 48 89 EF 48 8B 40 10 48 8B 70 20";
    inline constexpr char execution_error[] =
            "F3 0F 1E FA 48 83 3D ?? ?? ?? ?? 00 74 02 C3 90 48 83 EC 08 48 89 FE "
            "BA 00 10 00 00 48 8D 3D ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 8D 05 ?? ?? ?? ?? "
            "48 89 05 ?? ?? ?? ?? 48 83 C4 08 C3";
    inline constexpr char profiler_push[] = "F3 0F 1E FA 0F B6 47 20 84 C0 74 ?? E9";
    inline constexpr char profiler_push_singleton[] = "F3 0F 1E FA 48 8B 3D ?? ?? ?? ?? 0F B6 47 20 84 C0 74 ?? E9";
    inline constexpr char profiler_pop[] = "64 48 8B 1C 25 F8 FF FF FF";
}// namespace ds::linux_signatures
