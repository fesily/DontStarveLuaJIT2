#pragma once

#include <string>
#include <string_view>

namespace ds::plugin_manager {

inline std::string_view trim_trailing_slashes(std::string_view s) {
    while (!s.empty() && s.back() == '/') {
        s.remove_suffix(1);
    }
    return s;
}

// {github_base}/{repo}/releases/download/{tag}/{asset}
// Trailing slashes on bases are trimmed to avoid // in the path.
inline std::string release_asset_url(std::string_view github_base,
                                     std::string_view repo,
                                     std::string_view tag,
                                     std::string_view asset) {
    github_base = trim_trailing_slashes(github_base);
    repo = trim_trailing_slashes(repo);
    tag = trim_trailing_slashes(tag);

    std::string out;
    out.reserve(github_base.size() + repo.size() + tag.size() + asset.size() + 32);
    out.append(github_base);
    out.push_back('/');
    out.append(repo);
    out.append("/releases/download/");
    out.append(tag);
    out.push_back('/');
    out.append(asset);
    return out;
}

// prefer_proxy: "always" | "never" | "auto"
// auto_use_proxy only matters when prefer_proxy == "auto".
// Wrap form: {gh_proxy_base}/{direct_url}
// No double-wrap when direct_url already starts with gh_proxy_base.
inline std::string maybe_proxy_url(std::string_view direct_url,
                                   std::string_view gh_proxy_base,
                                   std::string_view prefer_proxy,
                                   bool auto_use_proxy) {
    const std::string_view base = trim_trailing_slashes(gh_proxy_base);

    // Already proxied — never double-wrap.
    if (!base.empty() && direct_url.size() >= base.size() &&
        direct_url.substr(0, base.size()) == base) {
        // Require boundary: exact match, or next char is '/' (proxy base prefix).
        if (direct_url.size() == base.size() || direct_url[base.size()] == '/') {
            return std::string(direct_url);
        }
    }

    bool use_proxy = false;
    if (prefer_proxy == "always") {
        use_proxy = true;
    } else if (prefer_proxy == "never") {
        use_proxy = false;
    } else if (prefer_proxy == "auto") {
        use_proxy = auto_use_proxy;
    } else {
        // Unknown prefer_proxy → treat as never (safe default).
        use_proxy = false;
    }

    if (!use_proxy || base.empty()) {
        return std::string(direct_url);
    }

    std::string out;
    out.reserve(base.size() + 1 + direct_url.size());
    out.append(base);
    out.push_back('/');
    out.append(direct_url);
    return out;
}

} // namespace ds::plugin_manager
