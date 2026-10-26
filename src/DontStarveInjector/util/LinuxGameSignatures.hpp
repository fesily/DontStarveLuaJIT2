#pragma once

namespace ds::linux_signatures {
    inline constexpr char lua_module[] = "81 FE F1 D8 FF FF 7D ?? 81 FE EF D8 FF FF 74 ?? 81 FE F0 D8 FF FF";
    inline constexpr char register_debug_getsize[] = "48 8B 45 18 48 89 EF 48 8B 40 10 48 8B 70 20";
    // 759671 rewrote the helper body (strlen + __memcpy_chk into a static
    // 0x1000-byte block). Slots unchanged: flag = compared pointer,
    // buffer = the first lea destination; decode_execution_error_storage
    // still recovers both from this window.
    inline constexpr char execution_error[] =
            "F3 0F 1E FA 48 83 3D ?? ?? ?? ?? 00 74 02 C3 90 "
            "41 54 55 48 89 FD 53 48 85 FF 74 ?? "
            "4C 8D 25 ?? ?? ?? ?? 4C 39 E7 74 ?? "
            "E8 ?? ?? ?? ?? 48 89 C3 48 3D FF 0F 00 00 76 ?? "
            "BB FF 0F 00 00 EB ?? 90 48 83 EB 01 74 ?? "
            "0F B6 44 1D 00 83 E0 C0 3C 80 74 ?? "
            "B9 00 10 00 00 48 89 DA 48 89 EE 48 8D 3D ?? ?? ?? ?? "
            "E8 ?? ?? ?? ?? 41 C6 04 1C 00 5B 5D";
    inline constexpr char profiler_push[] = "F3 0F 1E FA 0F B6 47 20 84 C0 74 ?? E9";
    inline constexpr char profiler_push_singleton[] = "F3 0F 1E FA 48 8B 3D ?? ?? ?? ?? 0F B6 47 20 84 C0 74 ?? E9";
    inline constexpr char profiler_pop[] = "64 48 8B 1C 25 F8 FF FF FF";

}// namespace ds::linux_signatures
