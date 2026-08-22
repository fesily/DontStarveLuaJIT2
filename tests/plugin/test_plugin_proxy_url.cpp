#include "plugins/plugin_manager/PluginDownloadUrl.hpp"

#include <cassert>
#include <cstdio>
#include <string>
#include <string_view>

using namespace ds::plugin_manager;

static void test_release_asset_url_basic() {
    const std::string url = release_asset_url(
        "https://github.com",
        "fesily/DontStarveLuaJIT2",
        "v2.9.1",
        "plugin_manager-1.0.0-windows.zip");
    assert(url ==
           "https://github.com/fesily/DontStarveLuaJIT2/releases/download/"
           "v2.9.1/plugin_manager-1.0.0-windows.zip");
    printf("PASS: release_asset_url_basic\n");
}

static void test_release_asset_url_trims_trailing_slash() {
    const std::string url = release_asset_url(
        "https://github.com/",
        "owner/repo",
        "tag",
        "asset.zip");
    assert(url == "https://github.com/owner/repo/releases/download/tag/asset.zip");
    printf("PASS: release_asset_url_trims_trailing_slash\n");
}

static void test_always_wraps() {
    const std::string direct =
        "https://github.com/fesily/DontStarveLuaJIT2/releases/download/v1/a.zip";
    const std::string out = maybe_proxy_url(direct, "https://gh-proxy.com", "always", false);
    assert(out == "https://gh-proxy.com/" + direct);
    printf("PASS: always_wraps\n");
}

static void test_never_keeps_direct_even_if_auto_true() {
    const std::string direct =
        "https://github.com/fesily/DontStarveLuaJIT2/releases/download/v1/a.zip";
    const std::string out = maybe_proxy_url(direct, "https://gh-proxy.com", "never", true);
    assert(out == direct);
    printf("PASS: never_keeps_direct_even_if_auto_true\n");
}

static void test_auto_true_wraps() {
    const std::string direct =
        "https://github.com/fesily/DontStarveLuaJIT2/releases/download/v1/a.zip";
    const std::string out = maybe_proxy_url(direct, "https://gh-proxy.com", "auto", true);
    assert(out == "https://gh-proxy.com/" + direct);
    printf("PASS: auto_true_wraps\n");
}

static void test_auto_false_keeps_direct() {
    const std::string direct =
        "https://github.com/fesily/DontStarveLuaJIT2/releases/download/v1/a.zip";
    const std::string out = maybe_proxy_url(direct, "https://gh-proxy.com", "auto", false);
    assert(out == direct);
    printf("PASS: auto_false_keeps_direct\n");
}

static void test_no_double_wrap() {
    const std::string direct =
        "https://github.com/fesily/DontStarveLuaJIT2/releases/download/v1/a.zip";
    const std::string already = "https://gh-proxy.com/" + direct;
    const std::string out = maybe_proxy_url(already, "https://gh-proxy.com", "always", true);
    assert(out == already);
    printf("PASS: no_double_wrap\n");
}

static void test_proxy_base_trailing_slash_no_double_slash() {
    const std::string direct =
        "https://github.com/fesily/DontStarveLuaJIT2/releases/download/v1/a.zip";
    const std::string out = maybe_proxy_url(direct, "https://gh-proxy.com/", "always", false);
    assert(out == "https://gh-proxy.com/" + direct);
    printf("PASS: proxy_base_trailing_slash_no_double_slash\n");
}

int main() {
    test_release_asset_url_basic();
    test_release_asset_url_trims_trailing_slash();
    test_always_wraps();
    test_never_keeps_direct_even_if_auto_true();
    test_auto_true_wraps();
    test_auto_false_keeps_direct();
    test_no_double_wrap();
    test_proxy_base_trailing_slash_no_double_slash();
    printf("ALL PASS plugin_proxy_url\n");
    return 0;
}
