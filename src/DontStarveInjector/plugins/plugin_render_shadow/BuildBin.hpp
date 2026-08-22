#pragma once

#include "SilhouetteMath.hpp"

#include <cstddef>
#include <cstdint>

namespace ds::shadow {

// Load anim/<name>.zip build.bin and parse 24B file verts (FUN_14016ec80 input).
// Cached by build name. Returns false if the zip/bin is missing or not BILD.
bool LoadBildVertsForName(const char *build_name, const BildVert **verts,
                          size_t *count) noexcept;

// MSVC x64 std::string at sBuild+off. Returns nullptr if not a name.
const char *ReadSBuildName(const uint8_t *sbuild) noexcept;

} // namespace ds::shadow
