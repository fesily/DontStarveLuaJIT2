// Unit tests for the Lua-visible game IO path mapping (da5b9f0 regression:
// "../mods/workshop-<id>/<file>" was resolved to "<root>/<id>/<id>/<file>").
#include <doctest/doctest.h>

#include "plugins/plugin_core_vm/io/workshop_path.hpp"

namespace {

using ds::injector::io::map_workshop_mod_path;
using ds::injector::io::split_workshop_mod_path;

const std::filesystem::path kWorkshopRoot = "D:/Steam/steamapps/workshop/content/322330";

}  // namespace

TEST_CASE("workshop mod path keeps a single mod id") {
    const auto mapped = map_workshop_mod_path("../mods/workshop-3435352667/main/ia_preparedfoods.lua", kWorkshopRoot);

    REQUIRE(mapped.has_value());
    CHECK(*mapped == kWorkshopRoot / "3435352667" / "main" / "ia_preparedfoods.lua");

    // The regression form: the id-carrying prefix appended under the mod dir.
    CHECK(*mapped != kWorkshopRoot / "3435352667" / "3435352667" / "main" / "ia_preparedfoods.lua");
    CHECK(mapped->lexically_relative(kWorkshopRoot) == std::filesystem::path{"3435352667/main/ia_preparedfoods.lua"});
}

TEST_CASE("workshop mod path accepts either separator and deep leftovers") {
    const auto mapped = map_workshop_mod_path("../mods/workshop-1991746508\\scripts\\components\\xd_dtlevel.lua",
                                                kWorkshopRoot);

    REQUIRE(mapped.has_value());
    CHECK(*mapped == kWorkshopRoot / "1991746508" / "scripts" / "components" / "xd_dtlevel.lua");
    CHECK(*mapped != kWorkshopRoot / "1991746508" / "1991746508" / "scripts" / "components" / "xd_dtlevel.lua");
}

TEST_CASE("split exposes the id and the remainder") {
    const auto split = split_workshop_mod_path("../mods/workshop-3435352667/main/cooking.lua");
    REQUIRE(split.has_value());
    CHECK(split->mod_id == "3435352667");
    CHECK(split->relative == "main/cooking.lua");

    // A bare mod root has no file part: lj_fpath_format answered {} for it.
    CHECK_FALSE(split_workshop_mod_path("../mods/workshop-3435352667").has_value());
    // Trailing separator names the mod directory itself.
    const auto root_only = map_workshop_mod_path("../mods/workshop-3435352667/", kWorkshopRoot);
    REQUIRE(root_only.has_value());
    CHECK(*root_only == kWorkshopRoot / "3435352667");
    CHECK(*root_only != kWorkshopRoot / "3435352667" / "3435352667");
}

TEST_CASE("non-workshop paths are left to the caller") {
    CHECK_FALSE(split_workshop_mod_path("../mods/ds_dump_plain/modmain.lua").has_value());
    CHECK_FALSE(split_workshop_mod_path("scripts/util.lua").has_value());
    CHECK_FALSE(split_workshop_mod_path("databundles/scripts.zip").has_value());
    CHECK_FALSE(split_workshop_mod_path("").has_value());
    CHECK_FALSE(map_workshop_mod_path("../mods/workshop-", kWorkshopRoot).has_value());
}
