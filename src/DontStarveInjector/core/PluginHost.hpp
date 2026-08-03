#pragma once

#include "PluginTypes.hpp"

#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>
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
    void register_plugin(IPlugin *plugin); // non-owning; caller keeps lifetime

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
};

} // namespace ds::plugin
