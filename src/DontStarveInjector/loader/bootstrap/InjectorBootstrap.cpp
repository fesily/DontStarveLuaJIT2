#include "InjectorBootstrap.hpp"

#include "config/path/ModFolderAliases.hpp"

#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <mutex>
#include <string>
#include <string_view>
#include <unordered_set>
#include <utility>
#include <vector>

#if defined(_WIN32)
#  ifndef NOMINMAX
#    define NOMINMAX
#  endif
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  include <Windows.h>
#  include <shellapi.h>
#else
#  include <limits.h>
#  include <unistd.h>
#endif

namespace ds::bootstrap {
namespace {

namespace fs = std::filesystem;

std::mutex g_state_mu;
fs::path g_cached_module;
std::string g_last_source;
fs::path g_marker_game_root_override;
fs::path g_exe_dir_override;
std::vector<std::string> g_cmdline_override;
bool g_has_cmdline_override = false;
bool g_logged_legacy = false;
bool g_logged_failure = false;

void log_once_tag(const char *msg) {
    static std::mutex mu;
    static std::unordered_set<std::string> seen;
    std::lock_guard lock(mu);
    if (!seen.insert(msg).second) {
        return;
    }
    std::fprintf(stderr, "[ds-bootstrap] %s\n", msg);
    std::fflush(stderr);
}

std::string trim_copy(std::string s) {
    auto is_space = [](unsigned char c) { return std::isspace(c) != 0; };
    while (!s.empty() && is_space(static_cast<unsigned char>(s.front()))) {
        s.erase(s.begin());
    }
    while (!s.empty() && is_space(static_cast<unsigned char>(s.back()))) {
        s.pop_back();
    }
    return s;
}

const char *env_or_null(const char *key) {
#if defined(_WIN32)
    char *buf = nullptr;
    size_t len = 0;
    if (_dupenv_s(&buf, &len, key) != 0 || buf == nullptr || len == 0 || buf[0] == '\0') {
        free(buf);
        return nullptr;
    }
    thread_local std::string storage;
    storage.assign(buf);
    free(buf);
    return storage.c_str();
#else
    const char *v = std::getenv(key);
    if (!v || !*v) {
        return nullptr;
    }
    return v;
#endif
}

fs::path production_exe_directory() {
#if defined(_WIN32)
    wchar_t buf[MAX_PATH];
    const DWORD n = GetModuleFileNameW(nullptr, buf, MAX_PATH);
    if (n == 0 || n >= MAX_PATH) {
        return {};
    }
    return fs::path(buf).parent_path();
#else
    char buf[PATH_MAX];
    const ssize_t n = readlink("/proc/self/exe", buf, sizeof(buf) - 1);
    if (n <= 0) {
        return {};
    }
    buf[n] = '\0';
    return fs::path(buf).parent_path();
#endif
}

std::vector<std::string> production_cmdline_tokens() {
    std::vector<std::string> cmds;
#if defined(_WIN32)
    int n = 0;
    LPWSTR *argv = CommandLineToArgvW(GetCommandLineW(), &n);
    if (!argv) {
        return cmds;
    }
    cmds.reserve(static_cast<size_t>(n));
    for (int i = 0; i < n; ++i) {
        cmds.push_back(fs::path(argv[i]).string());
    }
    LocalFree(argv);
#else
    std::ifstream file("/proc/self/cmdline");
    std::string token;
    while (std::getline(file, token, '\0')) {
        if (!token.empty()) {
            cmds.push_back(std::move(token));
        }
    }
#endif
    return cmds;
}

fs::path current_exe_dir() {
    if (!g_exe_dir_override.empty()) {
        return g_exe_dir_override;
    }
    return production_exe_directory();
}

fs::path current_game_root() {
    if (!g_marker_game_root_override.empty()) {
        return g_marker_game_root_override;
    }
    const auto exe = current_exe_dir();
    if (exe.empty()) {
        return {};
    }
    return exe.parent_path();
}

std::vector<std::string> current_cmdline() {
    if (g_has_cmdline_override) {
        return g_cmdline_override;
    }
    return production_cmdline_tokens();
}

fs::path marker_path() {
    const auto root = current_game_root();
    if (root.empty()) {
        return {};
    }
    return root / "data" / "unsafedata" / kMarkerFileName;
}

fs::path absolute_if_possible(const fs::path &p) {
    std::error_code ec;
    auto abs = fs::absolute(p, ec);
    if (ec) {
        abs = p;
    }
    auto canon = fs::weakly_canonical(abs, ec);
    return ec ? abs : canon;
}

bool is_regular_existing(const fs::path &p) {
    std::error_code ec;
    return !p.empty() && fs::is_regular_file(p, ec);
}

std::vector<fs::path> module_candidates_under_dir(const fs::path &dir) {
    std::vector<fs::path> out;
    if (dir.empty()) {
        return out;
    }
    const char *name = injector_module_filename();
    out.push_back(dir / name);
#if !defined(_WIN32) && !defined(__APPLE__)
    out.push_back(dir / "lib64" / name);
#endif
    return out;
}

std::vector<fs::path> module_candidates_under_mod_root(const fs::path &mod_root) {
    return module_candidates_under_dir(mod_root / "bin64");
}

bool looks_like_mod_root(const fs::path &mod_root) {
    std::error_code ec;
    return fs::is_regular_file(mod_root / "modmain.lua", ec) ||
           fs::is_regular_file(mod_root / "modinfo.lua", ec) ||
           fs::is_regular_file(mod_root / "install.bat", ec) ||
           fs::is_regular_file(mod_root / "install_linux.sh", ec);
}

bool find_module_in_dir(const fs::path &dir, fs::path &out) {
    for (const auto &cand : module_candidates_under_dir(dir)) {
        if (is_regular_existing(cand)) {
            out = absolute_if_possible(cand);
            return true;
        }
    }
    return false;
}

bool find_module_in_mod_root(const fs::path &mod_root, fs::path &out) {
    for (const auto &cand : module_candidates_under_mod_root(mod_root)) {
        if (is_regular_existing(cand)) {
            out = absolute_if_possible(cand);
            return true;
        }
    }
    return false;
}

void collect_scan_bases(std::vector<fs::path> &bases) {
    auto push_unique = [&](const fs::path &p) {
        if (p.empty()) {
            return;
        }
        for (const auto &existing : bases) {
            if (existing == p) {
                return;
            }
        }
        bases.push_back(p);
    };

    const auto exe = current_exe_dir();
    if (!exe.empty()) {
        push_unique(exe.parent_path() / "mods");
        push_unique(exe / "mods");
        const auto steamapps = exe.parent_path().parent_path().parent_path();
        if (!steamapps.empty()) {
            push_unique(steamapps / "workshop" / "content" / "322330");
        }
    }

    const auto cmds = current_cmdline();
    for (size_t i = 0; i < cmds.size(); ++i) {
        if (cmds[i] == "-ugc_directory" && i + 1 < cmds.size() && !cmds[i + 1].empty()) {
            push_unique(fs::path(cmds[i + 1]));
        }
    }
}

bool scan_mod_injector(fs::path &out) {
    std::vector<fs::path> bases;
    collect_scan_bases(bases);

    // Prefer roots that look real first, then any root with a module.
    for (const auto &base : bases) {
        std::error_code ec;
        if (base.empty() || !fs::is_directory(base, ec)) {
            continue;
        }
        for (const auto alias : ds::config::path::kModFolderAliases) {
            const auto mod_root = base / std::string{alias};
            if (!looks_like_mod_root(mod_root)) {
                continue;
            }
            if (find_module_in_mod_root(mod_root, out)) {
                return true;
            }
        }
    }
    for (const auto &base : bases) {
        std::error_code ec;
        if (base.empty() || !fs::is_directory(base, ec)) {
            continue;
        }
        for (const auto alias : ds::config::path::kModFolderAliases) {
            const auto mod_root = base / std::string{alias};
            if (find_module_in_mod_root(mod_root, out)) {
                return true;
            }
        }
    }
    return false;
}

bool pin_success(const fs::path &module_abs, const char *source, bool write_marker) {
    g_cached_module = module_abs;
    g_last_source = source;
    if (write_marker) {
        (void)write_injector_marker(module_abs);
    }
    return true;
}

} // namespace

const char *injector_module_filename() {
#if defined(_WIN32)
    return "Injector.dll";
#elif defined(__APPLE__)
    return "libInjector.dylib";
#else
    return "libInjector.so";
#endif
}

bool write_injector_marker(const fs::path &abs_module) {
    const auto path = marker_path();
    if (path.empty() || abs_module.empty()) {
        return false;
    }
    std::error_code ec;
    fs::create_directories(path.parent_path(), ec);
    if (ec) {
        return false;
    }

    const auto abs = absolute_if_possible(abs_module);
    const auto tmp = path.string() + ".tmp";
    {
        std::ofstream out(tmp, std::ios::binary | std::ios::trunc);
        if (!out) {
            return false;
        }
        out << abs.string() << "\n";
        if (!out.good()) {
            return false;
        }
    }
    fs::rename(tmp, path, ec);
    if (ec) {
        // Windows: replace existing target.
        fs::remove(path, ec);
        fs::rename(tmp, path, ec);
        if (ec) {
            fs::remove(tmp, ec);
            return false;
        }
    }
    return true;
}

bool read_injector_marker(fs::path &out_abs) {
    const auto path = marker_path();
    if (path.empty()) {
        return false;
    }
    std::error_code ec;
    if (!fs::is_regular_file(path, ec)) {
        return false;
    }
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        return false;
    }
    std::string line;
    if (!std::getline(in, line)) {
        return false;
    }
    line = trim_copy(std::move(line));
    if (line.empty()) {
        return false;
    }
    fs::path candidate = line;
    if (!is_regular_existing(candidate)) {
        return false;
    }
    out_abs = absolute_if_possible(candidate);
    return true;
}

bool resolve_injector_module(std::filesystem::path &out_abs) {
    std::lock_guard lock(g_state_mu);

    if (!g_cached_module.empty() && is_regular_existing(g_cached_module)) {
        out_abs = g_cached_module;
        return true;
    }

    // 1) DS_LUAJIT_INJECTOR file
    if (const char *file_env = env_or_null(kInjectorFileEnv)) {
        fs::path cand = file_env;
        if (is_regular_existing(cand)) {
            const auto abs = absolute_if_possible(cand);
            out_abs = abs;
            return pin_success(abs, "env_file", /*write_marker=*/true);
        }
    }

    // 2) DS_LUAJIT_INJECTOR_DIR directory
    if (const char *dir_env = env_or_null(kInjectorDirEnv)) {
        fs::path found;
        if (find_module_in_dir(fs::path(dir_env), found)) {
            out_abs = found;
            return pin_success(found, "env_dir", /*write_marker=*/true);
        }
    }

    // 3) Marker
    {
        fs::path marked;
        if (read_injector_marker(marked)) {
            g_cached_module = marked;
            g_last_source = "marker";
            out_abs = marked;
            return true;
        }
    }

    // 4) Mod alias scan
    {
        fs::path found;
        if (scan_mod_injector(found)) {
            out_abs = found;
            return pin_success(found, "scan", /*write_marker=*/true);
        }
    }

    // 5) Legacy next to exe
    {
        fs::path found;
        const auto exe = current_exe_dir();
        if (find_module_in_dir(exe, found)) {
            if (!g_logged_legacy) {
                log_once_tag("using legacy Injector next to game exe (no marker pin)");
                g_logged_legacy = true;
            }
            g_cached_module = found;
            g_last_source = "legacy";
            out_abs = found;
            return true;
        }
    }

    g_last_source = "none";
    g_cached_module.clear();
    if (!g_logged_failure) {
        log_once_tag("failed to resolve real Injector module (env/marker/scan/legacy)");
        g_logged_failure = true;
    }
    return false;
}

void reset_for_test() {
    std::lock_guard lock(g_state_mu);
    g_cached_module.clear();
    g_last_source.clear();
    g_marker_game_root_override.clear();
    g_exe_dir_override.clear();
    g_cmdline_override.clear();
    g_has_cmdline_override = false;
    g_logged_legacy = false;
    g_logged_failure = false;
}

void set_marker_game_root_for_test(const std::filesystem::path &game_root_or_empty) {
    std::lock_guard lock(g_state_mu);
    g_marker_game_root_override = game_root_or_empty;
}

void set_exe_dir_for_test(const std::filesystem::path &exe_dir_or_empty) {
    std::lock_guard lock(g_state_mu);
    g_exe_dir_override = exe_dir_or_empty;
}

void set_cmdline_for_test(std::vector<std::string> args_or_empty) {
    std::lock_guard lock(g_state_mu);
    g_cmdline_override = std::move(args_or_empty);
    g_has_cmdline_override = true;
}

std::string last_resolve_source_for_test() {
    std::lock_guard lock(g_state_mu);
    return g_last_source;
}

} // namespace ds::bootstrap
