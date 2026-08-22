#include "PluginConfigBridge.hpp"

namespace ds::plugin {

ConfigView BuildConfigView(const ConfigSchemaRegistry &schema,
                           const ConfigView &resolved) {
    ConfigView view = resolved;

    // Fill schema defaults only for keys not already present (late plugin keys).
    // Cascade-resolved values always win — no second disk re-read.
    for (auto *e : schema.all()) {
        if (view.find(e->key) == view.end()) {
            view[e->key] = e->default_value;
        }
    }

    return view;
}

} // namespace ds::plugin
