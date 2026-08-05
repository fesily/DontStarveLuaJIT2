#pragma once

#include "config/ConfigSchema.hpp"
#include "PluginTypes.hpp"

#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

// C++ export for PluginHost methods used across the Injector <-> plugin DLL boundary.
// Not covered by DONTSTARVEINJECTOR_API (which is always extern "C").
#if defined(_WIN32)
#  if defined(DONTSTARVEINJECTOR_BUILD)
#    define DS_PLUGIN_HOST_API __declspec(dllexport)
#  elif defined(DS_PLUGIN_HOST_STATIC)
// Standalone unit tests compile PluginHost.cpp into the test binary (no DLL).
#    define DS_PLUGIN_HOST_API
#  else
#    define DS_PLUGIN_HOST_API __declspec(dllimport)
#  endif
#else
#  define DS_PLUGIN_HOST_API __attribute__((visibility("default")))
#endif

namespace ds::plugin {

struct ResolveResult {
    std::vector<std::string> enabled; // option+gate candidates before conflict/dep fail
    std::vector<std::string> failed;
    std::vector<std::string> disabled;
};

struct LoadResult {
    std::vector<std::string> loaded_order;
    bool ok = true;
};

class PluginHost {
public:
    DS_PLUGIN_HOST_API void register_plugin(IPlugin *plugin); // non-owning; caller keeps lifetime
    DS_PLUGIN_HOST_API bool register_option_schema(OptionSchemaEntry e);
    // Service registration — only while registration window is open (module_init).
    DS_PLUGIN_HOST_API bool register_service(std::string_view name, void *fn);
    DS_PLUGIN_HOST_API void begin_module_registration();
    DS_PLUGIN_HOST_API void end_module_registration();
    DS_PLUGIN_HOST_API ConfigSchemaRegistry &option_schema();
    DS_PLUGIN_HOST_API const ConfigSchemaRegistry &option_schema() const;

    ResolveResult resolve(const ConfigView &config, const PluginContext &gate_ctx);
    LoadResult load_phase(PluginPhase phase);
    // Only if support_reload; returns false if sticky or not loaded.
    bool unload_plugin(std::string_view id, PluginContext &ctx);

    const std::vector<PluginEvent> &events() const { return events_; }
    void clear_events() { events_.clear(); }

    PluginStatus status(std::string_view id) const;
    PluginFailReason fail_reason(std::string_view id) const;
    std::vector<std::string> loaded_order(PluginPhase phase) const;

private:
    struct Entry {
        IPlugin *plugin = nullptr;
        PluginStatus status = PluginStatus::Registered;
        PluginFailReason reason = PluginFailReason::None;
        std::string fail_detail;
        bool option_enabled = false;
        bool gate_ok = false;
        bool resolved = false;
        std::vector<PluginPhase> loaded_phases;
    };

    void push_event(std::string_view id, PluginPhase phase, PluginStatus st, PluginFailReason reason,
                    std::string_view detail = {});
    Entry *find(std::string_view id);
    const Entry *find(std::string_view id) const;
    std::vector<std::string> topo_order_for_phase(PluginPhase phase) const;

    std::vector<Entry> entries_;
    std::unordered_map<std::string, size_t> index_;
    std::vector<PluginEvent> events_;
    ConfigView last_config_;
    PluginContext last_ctx_{};
    bool resolved_ = false;
    ConfigSchemaRegistry option_schema_;
    // Production: closed until DynamicPluginLoader opens around module_init.
    // DS_PLUGIN_HOST_STATIC tests: open by default so graph tests stay simple.
#if defined(DS_PLUGIN_HOST_STATIC)
    bool registration_open_ = true;
#else
    bool registration_open_ = false;
#endif
};

} // namespace ds::plugin
