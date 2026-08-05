#include "PluginHttp.hpp"
#include "PluginDownloadUrl.hpp"

#include <string>

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <winhttp.h>
#pragma comment(lib, "winhttp.lib")
#endif

namespace ds::plugin_manager {
namespace {

HttpGetFn g_http_override = nullptr;

#if defined(_WIN32)

std::wstring utf8_to_wide(std::string_view s) {
    if (s.empty()) {
        return {};
    }
    const int n = MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), nullptr, 0);
    if (n <= 0) {
        return {};
    }
    std::wstring out(static_cast<size_t>(n), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), out.data(), n);
    return out;
}

bool http_get_winhttp(std::string_view url, int timeout_ms, std::string *body, std::string *err) {
    if (timeout_ms <= 0) {
        timeout_ms = 15000;
    }
    const std::wstring wurl = utf8_to_wide(url);
    if (wurl.empty()) {
        if (err) {
            *err = "http_get: empty or invalid url";
        }
        return false;
    }

    URL_COMPONENTS uc{};
    uc.dwStructSize = sizeof(uc);
    uc.dwSchemeLength = static_cast<DWORD>(-1);
    uc.dwHostNameLength = static_cast<DWORD>(-1);
    uc.dwUrlPathLength = static_cast<DWORD>(-1);
    uc.dwExtraInfoLength = static_cast<DWORD>(-1);
    if (!WinHttpCrackUrl(wurl.c_str(), static_cast<DWORD>(wurl.size()), 0, &uc)) {
        if (err) {
            *err = "http_get: WinHttpCrackUrl failed";
        }
        return false;
    }

    const std::wstring host(uc.lpszHostName, uc.dwHostNameLength);
    std::wstring path(uc.lpszUrlPath, uc.dwUrlPathLength);
    if (uc.dwExtraInfoLength > 0 && uc.lpszExtraInfo) {
        path.append(uc.lpszExtraInfo, uc.dwExtraInfoLength);
    }
    if (path.empty()) {
        path = L"/";
    }

    const bool https = uc.nScheme == INTERNET_SCHEME_HTTPS;
    HINTERNET session = WinHttpOpen(L"DontStarveLuaJIT2-plugin-manager/1.0",
                                    WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME,
                                    WINHTTP_NO_PROXY_BYPASS, 0);
    if (!session) {
        if (err) {
            *err = "http_get: WinHttpOpen failed";
        }
        return false;
    }

    // Whole-request budget shared across resolve/connect/send/receive.
    WinHttpSetTimeouts(session, timeout_ms, timeout_ms, timeout_ms, timeout_ms);

    HINTERNET conn =
        WinHttpConnect(session, host.c_str(), uc.nPort ? uc.nPort : (https ? 443 : 80), 0);
    if (!conn) {
        WinHttpCloseHandle(session);
        if (err) {
            *err = "http_get: WinHttpConnect failed";
        }
        return false;
    }

    DWORD flags = https ? WINHTTP_FLAG_SECURE : 0;
    HINTERNET req = WinHttpOpenRequest(conn, L"GET", path.c_str(), nullptr, WINHTTP_NO_REFERER,
                                       WINHTTP_DEFAULT_ACCEPT_TYPES, flags);
    if (!req) {
        WinHttpCloseHandle(conn);
        WinHttpCloseHandle(session);
        if (err) {
            *err = "http_get: WinHttpOpenRequest failed";
        }
        return false;
    }

    // Follow redirects (GitHub release assets / proxy).
    DWORD redir = WINHTTP_OPTION_REDIRECT_POLICY_ALWAYS;
    WinHttpSetOption(req, WINHTTP_OPTION_REDIRECT_POLICY, &redir, sizeof(redir));

    bool ok = false;
    do {
        if (!WinHttpSendRequest(req, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0,
                                0)) {
            if (err) {
                *err = "http_get: WinHttpSendRequest failed";
            }
            break;
        }
        if (!WinHttpReceiveResponse(req, nullptr)) {
            if (err) {
                *err = "http_get: WinHttpReceiveResponse failed";
            }
            break;
        }

        DWORD status = 0;
        DWORD status_size = sizeof(status);
        if (!WinHttpQueryHeaders(req, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                                 WINHTTP_HEADER_NAME_BY_INDEX, &status, &status_size,
                                 WINHTTP_NO_HEADER_INDEX)) {
            if (err) {
                *err = "http_get: status query failed";
            }
            break;
        }
        if (status < 200 || status >= 300) {
            if (err) {
                *err = "http_get: HTTP status " + std::to_string(status);
            }
            break;
        }

        std::string data;
        for (;;) {
            DWORD avail = 0;
            if (!WinHttpQueryDataAvailable(req, &avail)) {
                if (err) {
                    *err = "http_get: QueryDataAvailable failed";
                }
                data.clear();
                break;
            }
            if (avail == 0) {
                ok = true;
                break;
            }
            const size_t off = data.size();
            data.resize(off + avail);
            DWORD read = 0;
            if (!WinHttpReadData(req, data.data() + off, avail, &read)) {
                if (err) {
                    *err = "http_get: ReadData failed";
                }
                data.clear();
                break;
            }
            data.resize(off + read);
            if (read == 0) {
                ok = true;
                break;
            }
        }
        if (ok && body) {
            *body = std::move(data);
        }
    } while (false);

    WinHttpCloseHandle(req);
    WinHttpCloseHandle(conn);
    WinHttpCloseHandle(session);
    return ok;
}

#else // !_WIN32

// Optional libcurl. When not linked, fail-soft with a clear error (Task 8 YAGNI).
#if defined(DS_PLUGIN_MANAGER_HAS_CURL)
#include <curl/curl.h>

size_t curl_write_cb(char *ptr, size_t size, size_t nmemb, void *userdata) {
    auto *out = static_cast<std::string *>(userdata);
    const size_t n = size * nmemb;
    out->append(ptr, n);
    return n;
}

bool http_get_curl(std::string_view url, int timeout_ms, std::string *body, std::string *err) {
    if (timeout_ms <= 0) {
        timeout_ms = 15000;
    }
    CURL *curl = curl_easy_init();
    if (!curl) {
        if (err) {
            *err = "http_get: curl_easy_init failed";
        }
        return false;
    }
    std::string data;
    std::string url_copy(url);
    curl_easy_setopt(curl, CURLOPT_URL, url_copy.c_str());
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curl_write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &data);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "DontStarveLuaJIT2-plugin-manager/1.0");
    curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, static_cast<long>(timeout_ms));
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT_MS, static_cast<long>(timeout_ms));
    const CURLcode rc = curl_easy_perform(curl);
    long status = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &status);
    curl_easy_cleanup(curl);
    if (rc != CURLE_OK) {
        if (err) {
            *err = std::string("http_get: curl ") + curl_easy_strerror(rc);
        }
        return false;
    }
    if (status < 200 || status >= 300) {
        if (err) {
            *err = "http_get: HTTP status " + std::to_string(status);
        }
        return false;
    }
    if (body) {
        *body = std::move(data);
    }
    return true;
}
#else
bool http_get_curl(std::string_view, int, std::string *, std::string *err) {
    if (err) {
        *err = "http unsupported";
    }
    return false;
}
#endif

#endif // _WIN32

bool http_get_platform(std::string_view url, int timeout_ms, std::string *body, std::string *err) {
#if defined(_WIN32)
    return http_get_winhttp(url, timeout_ms, body, err);
#else
    return http_get_curl(url, timeout_ms, body, err);
#endif
}

} // namespace

bool http_get(std::string_view url, int timeout_ms, std::string *body, std::string *err) {
    if (g_http_override) {
        return g_http_override(url, timeout_ms, body, err);
    }
    return http_get_platform(url, timeout_ms, body, err);
}

void set_http_get_override(HttpGetFn fn) { g_http_override = fn; }

HttpGetFn http_get_override() { return g_http_override; }

bool http_get_with_proxy(std::string_view direct_url, std::string_view gh_proxy_base,
                         std::string_view prefer_proxy, int timeout_ms, std::string *body,
                         std::string *err, int auto_direct_timeout_ms) {
    if (timeout_ms <= 0) {
        timeout_ms = 30000;
    }
    if (auto_direct_timeout_ms <= 0) {
        auto_direct_timeout_ms = 3000;
    }

    auto try_url = [&](std::string_view u, int tmo, std::string *e) {
        return http_get(u, tmo, body, e);
    };

    if (prefer_proxy == "always") {
        const std::string proxied =
            maybe_proxy_url(direct_url, gh_proxy_base, "always", /*auto_use_proxy=*/true);
        return try_url(proxied, timeout_ms, err);
    }
    if (prefer_proxy == "never") {
        return try_url(direct_url, timeout_ms, err);
    }

    // auto (and unknown → treated as auto probe for better reachability)
    std::string direct_err;
    if (try_url(direct_url, auto_direct_timeout_ms, &direct_err)) {
        if (err) {
            err->clear();
        }
        return true;
    }
    const std::string proxied =
        maybe_proxy_url(direct_url, gh_proxy_base, "always", /*auto_use_proxy=*/true);
    if (proxied == direct_url) {
        // No proxy base — surface the direct failure.
        if (err) {
            *err = direct_err.empty() ? std::string("http_get: auto probe failed") : direct_err;
        }
        return false;
    }
    std::string proxy_err;
    if (try_url(proxied, timeout_ms, &proxy_err)) {
        if (err) {
            err->clear();
        }
        return true;
    }
    if (err) {
        *err = "http_get: auto failed direct (" + direct_err + ") and proxy (" + proxy_err + ")";
    }
    return false;
}

} // namespace ds::plugin_manager
