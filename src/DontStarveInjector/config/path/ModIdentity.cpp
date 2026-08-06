#include "ModIdentity.hpp"

#include "config/path/ModFolderAliases.hpp"
#include "config/sources/LuajitConfigFile.hpp"

#include <algorithm>
#include <cctype>
#include <filesystem>
#include <string_view>

namespace ds::config::path {
namespace {

using namespace std::string_view_literals;


void add_alias(std::vector<std::string> &aliases, std::string_view alias) {
    if (alias.empty()) {
        return;
    }
    const auto value = std::string{alias};
    if (std::find(aliases.begin(), aliases.end(), value) == aliases.end()) {
        aliases.push_back(value);
    }
}

bool is_digits(std::string_view value) {
    return !value.empty() &&
           std::all_of(value.begin(), value.end(),
                       [](unsigned char ch) { return std::isdigit(ch) != 0; });
}

void add_alias_variants(std::vector<std::string> &aliases, std::string_view alias) {
    add_alias(aliases, alias);
    if (alias.starts_with("workshop-"sv)) {
        add_alias(aliases, alias.substr(sizeof("workshop-") - 1));
    } else if (is_digits(alias)) {
        add_alias(aliases, std::string{"workshop-"}.append(alias));
    }
}

std::string resolve_canonical_modname_from_modmain_path(std::string_view modmain_path) {
    if (modmain_path.empty()) {
        return {};
    }
    const auto folder = std::filesystem::path(modmain_path).parent_path().filename().string();
    if (folder.empty()) {
        return {};
    }
    if (!is_digits(folder)) {
        return folder;
    }
    return std::string{"workshop-"}.append(folder);
}

std::string resolve_modid_from_modname(std::string_view modname) {
    if (modname.starts_with("workshop-"sv)) {
        return std::string{modname.substr(sizeof("workshop-") - 1)};
    }
    return std::string{modname};
}

} // namespace

ResolvedModIdentity build_mod_identity() {
    ResolvedModIdentity identity;
    identity.canonical_modname = std::string{kPrimaryWorkshopModName};
    identity.modname = identity.canonical_modname;
    identity.modid = resolve_modid_from_modname(identity.modname);

    if (auto config = luajit_config::read_from_file(); config) {
        if (!config->modmain_path.empty()) {
            const auto canonical_from_modmain_path =
                resolve_canonical_modname_from_modmain_path(config->modmain_path);
            if (!canonical_from_modmain_path.empty()) {
                identity.canonical_modname = canonical_from_modmain_path;
                identity.modname = canonical_from_modmain_path;
                identity.modid = resolve_modid_from_modname(identity.modname);
                add_alias_variants(identity.aliases, canonical_from_modmain_path);
            }
        }
        add_alias_variants(identity.aliases, identity.modname);
        add_alias_variants(identity.aliases, identity.modid);
    }

    for (auto alias : kModFolderAliases) {
        add_alias_variants(identity.aliases, alias);
    }
    add_alias_variants(identity.aliases, identity.canonical_modname);
    return identity;
}

} // namespace ds::config::path
