#pragma once
// Minimal HTTP GET for plugin.manager (WinHTTP on Windows; libcurl optional elsewhere).
// Fail-soft: returns false with err set; never throws.

#include <cstddef>
#include <string>
#include <string_view>

namespace ds::plugin_manager {

// Maximum accepted HTTP response body size (64 MiB). Exceeding fails soft with an error.
inline constexpr size_t kMaxHttpBodyBytes = 64ull * 1024ull * 1024ull;

// GET `url` into *body (if non-null). timeout_ms bounds the whole request.
// Returns true only on HTTP 2xx with body captured (empty body is still success).
// On failure: returns false and writes a short message to *err when non-null.
bool http_get(std::string_view url, int timeout_ms, std::string *body, std::string *err);


// Injectable transport for offline unit tests. nullptr restores the platform default.
using HttpGetFn = bool (*)(std::string_view url, int timeout_ms, std::string *body, std::string *err);
void set_http_get_override(HttpGetFn fn);
HttpGetFn http_get_override();

// Probe policy for prefer_proxy:
//  - always: only proxied URL
//  - never: only direct URL
//  - auto: short direct timeout first, then proxy
// Uses maybe_proxy_url + http_get. Returns true on first successful GET.
bool http_get_with_proxy(std::string_view direct_url, std::string_view gh_proxy_base,
                         std::string_view prefer_proxy, int timeout_ms, std::string *body,
                         std::string *err, int auto_direct_timeout_ms = 3000);

} // namespace ds::plugin_manager
