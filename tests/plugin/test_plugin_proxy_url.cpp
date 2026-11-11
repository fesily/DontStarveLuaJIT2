#include "plugins/plugin_manager/PluginDownloadUrl.hpp"

#include <string>
#include <string_view>
#include <doctest/doctest.h>

using namespace ds::plugin_manager;

TEST_CASE("test_plugin_proxy_url/release_asset_url_basic") {
    const std::string url = release_asset_url(
        "https://github.com",
        "fesily/DontStarveLuaJIT2",
        "v2.9.1",
        "plugin_manager-1.0.0-windows.zip");
    REQUIRE_EQ(url, "https://github.com/fesily/DontStarveLuaJIT2/releases/download/"
           "v2.9.1/plugin_manager-1.0.0-windows.zip");
}

TEST_CASE("test_plugin_proxy_url/release_asset_url_trims_trailing_slash") {
    const std::string url = release_asset_url(
        "https://github.com/",
        "owner/repo",
        "tag",
        "asset.zip");
    REQUIRE_EQ(url, "https://github.com/owner/repo/releases/download/tag/asset.zip");
}

TEST_CASE("test_plugin_proxy_url/always_wraps") {
    const std::string direct =
        "https://github.com/fesily/DontStarveLuaJIT2/releases/download/v1/a.zip";
    const std::string out = maybe_proxy_url(direct, "https://gh-proxy.com", "always", false);
    REQUIRE_EQ(out, "https://gh-proxy.com/" + direct);
}

TEST_CASE("test_plugin_proxy_url/never_keeps_direct_even_if_auto_true") {
    const std::string direct =
        "https://github.com/fesily/DontStarveLuaJIT2/releases/download/v1/a.zip";
    const std::string out = maybe_proxy_url(direct, "https://gh-proxy.com", "never", true);
    REQUIRE_EQ(out, direct);
}

TEST_CASE("test_plugin_proxy_url/auto_true_wraps") {
    const std::string direct =
        "https://github.com/fesily/DontStarveLuaJIT2/releases/download/v1/a.zip";
    const std::string out = maybe_proxy_url(direct, "https://gh-proxy.com", "auto", true);
    REQUIRE_EQ(out, "https://gh-proxy.com/" + direct);
}

TEST_CASE("test_plugin_proxy_url/auto_false_keeps_direct") {
    const std::string direct =
        "https://github.com/fesily/DontStarveLuaJIT2/releases/download/v1/a.zip";
    const std::string out = maybe_proxy_url(direct, "https://gh-proxy.com", "auto", false);
    REQUIRE_EQ(out, direct);
}

TEST_CASE("test_plugin_proxy_url/no_double_wrap") {
    const std::string direct =
        "https://github.com/fesily/DontStarveLuaJIT2/releases/download/v1/a.zip";
    const std::string already = "https://gh-proxy.com/" + direct;
    const std::string out = maybe_proxy_url(already, "https://gh-proxy.com", "always", true);
    REQUIRE_EQ(out, already);
}

TEST_CASE("test_plugin_proxy_url/proxy_base_trailing_slash_no_double_slash") {
    const std::string direct =
        "https://github.com/fesily/DontStarveLuaJIT2/releases/download/v1/a.zip";
    const std::string out = maybe_proxy_url(direct, "https://gh-proxy.com/", "always", false);
    REQUIRE_EQ(out, "https://gh-proxy.com/" + direct);
}
