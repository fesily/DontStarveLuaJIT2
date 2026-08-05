#include "PluginHost.hpp"
#include "PluginOptionRules.hpp"
#include "PluginServices.hpp"

#include <algorithm>
#include <functional>
#include <queue>
#include <stdexcept>
#include <string_view>
#include <unordered_set>
namespace ds::plugin {
namespace {

std::string join_cycle(const std::vector<std::string> &nodes) {
    std::string out;
    for (size_t i = 0; i < nodes.size(); ++i) {
        if (i) {
            out += " -> ";
        }
        out += nodes[i];
    }
    if (!nodes.empty()) {
        out += " -> ";
        out += nodes.front();
    }
    return out;
}

} // namespace

void PluginHost::register_plugin(IPlugin *plugin) {
    if (!registration_open_) {
        return;
    }
    if (!plugin) {
        return;
    }
    const auto &id = plugin->manifest().id;
    if (id.empty() || index_.count(id)) {
        return;
    }
    index_[id] = entries_.size();
    Entry e;
    e.plugin = plugin;
    e.status = PluginStatus::Registered;
    entries_.push_back(std::move(e));
}

bool PluginHost::register_option_schema(OptionSchemaEntry e) {
    if (!registration_open_) {
        return false;
    }
    return option_schema_.add(std::move(e));
}

bool PluginHost::register_service(std::string_view name, void *fn) {
    if (!registration_open_) {
        return false;
    }
    return ds::plugin::register_service(name, fn);
}

void PluginHost::begin_module_registration() {
    registration_open_ = true;
}

void PluginHost::end_module_registration() {
    registration_open_ = false;
}

ConfigSchemaRegistry &PluginHost::option_schema() {
    return option_schema_;
}

const ConfigSchemaRegistry &PluginHost::option_schema() const {
    return option_schema_;
}

PluginHost::Entry *PluginHost::find(std::string_view id) {
    auto it = index_.find(std::string(id));
    if (it == index_.end()) {
        return nullptr;
    }
    return &entries_[it->second];
}

const PluginHost::Entry *PluginHost::find(std::string_view id) const {
    auto it = index_.find(std::string(id));
    if (it == index_.end()) {
        return nullptr;
    }
    return &entries_[it->second];
}

void PluginHost::push_event(std::string_view id, PluginPhase phase, PluginStatus st, PluginFailReason reason,
                            std::string_view detail) {
    PluginEvent ev;
    ev.plugin_id = std::string(id);
    ev.phase = phase;
    ev.status = st;
    ev.reason = reason;
    ev.detail = std::string(detail);
    events_.push_back(std::move(ev));
}

PluginStatus PluginHost::status(std::string_view id) const {
    const Entry *e = find(id);
    return e ? e->status : PluginStatus::Registered;
}

PluginFailReason PluginHost::fail_reason(std::string_view id) const {
    const Entry *e = find(id);
    return e ? e->reason : PluginFailReason::None;
}

std::vector<std::string> PluginHost::loaded_order(PluginPhase phase) const {
    std::vector<std::string> out;
    // Preserve registration-relative order among loaded for this phase by scanning load events.
    for (const auto &ev : events_) {
        if (ev.phase == phase && ev.status == PluginStatus::Loaded) {
            out.push_back(ev.plugin_id);
        }
    }
    return out;
}

ResolveResult PluginHost::resolve(const ConfigView &config, const PluginContext &gate_ctx) {
    last_config_ = config;
    last_ctx_ = gate_ctx;
    last_ctx_.config = &last_config_;
    resolved_ = true;
    events_.clear();

    ResolveResult result;

    // Reset runtime state except registration.
    for (auto &e : entries_) {
        e.status = PluginStatus::Registered;
        e.reason = PluginFailReason::None;
        e.fail_detail.clear();
        e.option_enabled = false;
        e.gate_ok = false;
        e.resolved = false;
        e.loaded_phases.clear();
    }

    // Phase 1: options + can_load
    for (auto &e : entries_) {
        const auto &man = e.plugin->manifest();
        e.option_enabled = EvaluateOptionRule(man.options, last_config_);
        e.gate_ok = e.option_enabled && e.plugin->can_load(last_ctx_);
        if (!e.option_enabled || !e.gate_ok) {
            e.status = PluginStatus::Disabled;
            e.resolved = true;
            result.disabled.push_back(man.id);
            push_event(man.id, PluginPhase::None, PluginStatus::Disabled, PluginFailReason::None, "options_or_gate");
        } else {
            result.enabled.push_back(man.id);
        }
    }

    auto mark_failed = [&](Entry &e, PluginFailReason reason, std::string_view detail) {
        if (e.status == PluginStatus::Failed) {
            return;
        }
        e.status = PluginStatus::Failed;
        e.reason = reason;
        e.fail_detail = std::string(detail);
        e.resolved = true;
        result.failed.push_back(e.plugin->manifest().id);
        push_event(e.plugin->manifest().id, PluginPhase::None, PluginStatus::Failed, reason, detail);
    };

    // Phase 2: conflicts among still-candidate plugins
    std::unordered_set<std::string> candidates;
    for (const auto &e : entries_) {
        if (e.status == PluginStatus::Registered) {
            candidates.insert(e.plugin->manifest().id);
        }
    }

    std::unordered_set<std::string> conflict_dead;
    for (const auto &id : candidates) {
        Entry *e = find(id);
        if (!e || e->status != PluginStatus::Registered) {
            continue;
        }
        for (const auto &other : e->plugin->manifest().conflicts) {
            if (!candidates.count(other)) {
                continue;
            }
            Entry *o = find(other);
            if (!o || o->status != PluginStatus::Registered) {
                continue;
            }
            conflict_dead.insert(id);
            conflict_dead.insert(other);
        }
    }
    for (const auto &id : conflict_dead) {
        Entry *e = find(id);
        if (e && e->status == PluginStatus::Registered) {
            mark_failed(*e, PluginFailReason::Conflict, "conflict");
        }
    }

    // Refresh candidates after conflicts
    candidates.clear();
    for (const auto &e : entries_) {
        if (e.status == PluginStatus::Registered) {
            candidates.insert(e.plugin->manifest().id);
        }
    }

    // Phase 3: hard deps (iterate until fixpoint)
    bool changed = true;
    while (changed) {
        changed = false;
        for (const auto &id : std::vector<std::string>(candidates.begin(), candidates.end())) {
            Entry *e = find(id);
            if (!e || e->status != PluginStatus::Registered) {
                continue;
            }
            for (const auto &dep : e->plugin->manifest().depends) {
                Entry *d = find(dep);
                const bool dep_ok = d && d->status == PluginStatus::Registered;
                if (!dep_ok) {
                    mark_failed(*e, PluginFailReason::MissingHardDep, dep);
                    candidates.erase(id);
                    changed = true;
                    break;
                }
            }
        }
    }

    // Phase 3b: hard service requirements (registered during module_init)
    candidates.clear();
    for (const auto &e : entries_) {
        if (e.status == PluginStatus::Registered) {
            candidates.insert(e.plugin->manifest().id);
        }
    }
    for (const auto &id : std::vector<std::string>(candidates.begin(), candidates.end())) {
        Entry *e = find(id);
        if (!e || e->status != PluginStatus::Registered) {
            continue;
        }
        for (const auto &svc : e->plugin->manifest().requires_services) {
            if (lookup_service(svc) == nullptr) {
                mark_failed(*e, PluginFailReason::MissingService, svc);
                candidates.erase(id);
                break;
            }
        }
    }

    // Phase 3c: re-propagate plugin-id hard deps after service failures (fixpoint).
    // MissingService/Conflict/Failed providers must poison dependents.
    candidates.clear();
    for (const auto &e : entries_) {
        if (e.status == PluginStatus::Registered) {
            candidates.insert(e.plugin->manifest().id);
        }
    }
    changed = true;
    while (changed) {
        changed = false;
        for (const auto &id : std::vector<std::string>(candidates.begin(), candidates.end())) {
            Entry *e = find(id);
            if (!e || e->status != PluginStatus::Registered) {
                continue;
            }
            for (const auto &dep : e->plugin->manifest().depends) {
                Entry *d = find(dep);
                const bool dep_ok = d && d->status == PluginStatus::Registered;
                if (!dep_ok) {
                    mark_failed(*e, PluginFailReason::MissingHardDep, dep);
                    candidates.erase(id);
                    changed = true;
                    break;
                }
            }
        }
    }

    // Phase 4: cycle detection among remaining candidates (hard deps only)
    candidates.clear();
    for (const auto &e : entries_) {
        if (e.status == PluginStatus::Registered) {
            candidates.insert(e.plugin->manifest().id);
        }
    }

    enum class Color : uint8_t { White, Gray, Black };
    std::unordered_map<std::string, Color> color;
    for (const auto &id : candidates) {
        color[id] = Color::White;
    }
    std::vector<std::string> stack;
    std::vector<std::vector<std::string>> cycles;

    std::function<void(const std::string &)> dfs = [&](const std::string &u) {
        color[u] = Color::Gray;
        stack.push_back(u);
        Entry *e = find(u);
        if (e) {
            for (const auto &dep : e->plugin->manifest().depends) {
                if (!candidates.count(dep)) {
                    continue;
                }
                if (color[dep] == Color::Gray) {
                    auto it = std::find(stack.begin(), stack.end(), dep);
                    cycles.emplace_back(it, stack.end());
                } else if (color[dep] == Color::White) {
                    dfs(dep);
                }
            }
        }
        stack.pop_back();
        color[u] = Color::Black;
    };

    for (const auto &id : candidates) {
        if (color[id] == Color::White) {
            dfs(id);
        }
    }

    std::unordered_set<std::string> cycle_nodes;
    for (const auto &cyc : cycles) {
        for (const auto &n : cyc) {
            cycle_nodes.insert(n);
        }
    }
    for (const auto &id : cycle_nodes) {
        Entry *e = find(id);
        if (e && e->status == PluginStatus::Registered) {
            mark_failed(*e, PluginFailReason::Cycle, join_cycle(
                [&] {
                    for (const auto &c : cycles) {
                        if (std::find(c.begin(), c.end(), id) != c.end()) {
                            return c;
                        }
                    }
                    return std::vector<std::string>{id};
                }()));
        }
    }

    for (auto &e : entries_) {
        if (e.status == PluginStatus::Registered) {
            e.resolved = true;
            // still Registered means "ready to load"
        }
    }

    return result;
}

std::vector<std::string> PluginHost::topo_order_for_phase(PluginPhase phase) const {
    // Nodes: ready (Registered or already Loaded from prior phase) that declare this phase
    // and have not loaded this phase yet.
    std::vector<std::string> nodes;
    for (const auto &e : entries_) {
        if (!e.plugin) {
            continue;
        }
        const auto &man = e.plugin->manifest();
        if (!has_phase(man.phases, phase)) {
            continue;
        }
        if (e.status != PluginStatus::Registered && e.status != PluginStatus::Loaded) {
            continue;
        }
        if (std::find(e.loaded_phases.begin(), e.loaded_phases.end(), phase) != e.loaded_phases.end()) {
            continue;
        }
        nodes.push_back(man.id);
    }

    auto is_ready_provider = [&](const std::string &id) -> bool {
        const Entry *e = find(id);
        if (!e) {
            return false;
        }
        // Available as dep if loaded already OR will load in this phase (in nodes) OR
        // status Registered/Loaded and satisfied.
        if (e->status == PluginStatus::Failed || e->status == PluginStatus::Disabled) {
            return false;
        }
        return e->status == PluginStatus::Registered || e->status == PluginStatus::Loaded;
    };

    std::unordered_map<std::string, int> indeg;
    std::unordered_map<std::string, std::vector<std::string>> adj; // dep -> dependents
    std::unordered_set<std::string> node_set(nodes.begin(), nodes.end());

    for (const auto &id : nodes) {
        indeg[id] = 0;
    }

    auto add_edge = [&](const std::string &from_dep, const std::string &to) {
        // from_dep must be ordered before to when both in this phase set
        if (!node_set.count(from_dep) || !node_set.count(to)) {
            return;
        }
        adj[from_dep].push_back(to);
        indeg[to]++;
    };

    for (const auto &id : nodes) {
        const Entry *e = find(id);
        if (!e) {
            continue;
        }
        const auto &man = e->plugin->manifest();
        for (const auto &dep : man.depends) {
            if (!is_ready_provider(dep)) {
                // Should have been Failed at resolve; skip edge
                continue;
            }
            add_edge(dep, id);
        }
        for (const auto &dep : man.soft_depends) {
            if (node_set.count(dep) && is_ready_provider(dep)) {
                add_edge(dep, id);
            }
        }
    }

    auto priority_of = [&](const std::string &id) {
        const Entry *e = find(id);
        return e ? e->plugin->manifest().priority : 100;
    };

    // Min-heap by (priority, id)
    using QItem = std::pair<int, std::string>;
    std::priority_queue<QItem, std::vector<QItem>, std::greater<QItem>> q;
    for (const auto &id : nodes) {
        if (indeg[id] == 0) {
            q.push({priority_of(id), id});
        }
    }

    std::vector<std::string> order;
    while (!q.empty()) {
        auto [prio, u] = q.top();
        (void) prio;
        q.pop();
        order.push_back(u);
        for (const auto &v : adj[u]) {
            if (--indeg[v] == 0) {
                q.push({priority_of(v), v});
            }
        }
    }

    // If cycle within phase (shouldn't if resolve worked), append remaining by priority
    if (order.size() != nodes.size()) {
        std::vector<std::string> rest;
        std::unordered_set<std::string> seen(order.begin(), order.end());
        for (const auto &id : nodes) {
            if (!seen.count(id)) {
                rest.push_back(id);
            }
        }
        std::sort(rest.begin(), rest.end(), [&](const std::string &a, const std::string &b) {
            if (priority_of(a) != priority_of(b)) {
                return priority_of(a) < priority_of(b);
            }
            return a < b;
        });
        order.insert(order.end(), rest.begin(), rest.end());
    }

    return order;
}

LoadResult PluginHost::load_phase(PluginPhase phase) {
    LoadResult result;
    if (!resolved_) {
        result.ok = false;
        return result;
    }

    auto order = topo_order_for_phase(phase);
    for (const auto &id : order) {
        Entry *e = find(id);
        if (!e) {
            continue;
        }
        if (e->status == PluginStatus::Failed || e->status == PluginStatus::Disabled) {
            continue;
        }
        // Hard dep must be Loaded (or Registered only if not yet required — require Loaded if dep has any phase)
        bool dep_fail = false;
        for (const auto &dep : e->plugin->manifest().depends) {
            Entry *d = find(dep);
            if (!d || (d->status != PluginStatus::Loaded && d->status != PluginStatus::Registered)) {
                e->status = PluginStatus::Failed;
                e->reason = PluginFailReason::MissingHardDep;
                e->fail_detail = dep;
                push_event(id, phase, PluginStatus::Failed, PluginFailReason::MissingHardDep, dep);
                result.ok = false;
                dep_fail = true;
                break;
            }
            // If dep is only Registered and shares this phase later in order, topo ensures order.
            // If dep already Failed:
            if (d->status == PluginStatus::Failed) {
                e->status = PluginStatus::Failed;
                e->reason = PluginFailReason::MissingHardDep;
                e->fail_detail = dep;
                push_event(id, phase, PluginStatus::Failed, PluginFailReason::MissingHardDep, dep);
                result.ok = false;
                dep_fail = true;
                break;
            }
        }
        if (dep_fail) {
            continue;
        }

        try {
            PluginContext load_ctx = last_ctx_;
            load_ctx.config = &last_config_;
            load_ctx.services.clear();
            const auto &man = e->plugin->manifest();
            for (const auto &svc : man.requires_services) {
                if (void *fn = lookup_service(svc)) {
                    load_ctx.services.emplace(svc, fn);
                }
            }
            for (const auto &svc : man.soft_requires_services) {
                if (void *fn = lookup_service(svc)) {
                    load_ctx.services.emplace(svc, fn);
                }
            }
            e->plugin->load(load_ctx);
            e->status = PluginStatus::Loaded;
            e->loaded_phases.push_back(phase);
            result.loaded_order.push_back(id);
            push_event(id, phase, PluginStatus::Loaded, PluginFailReason::None, {});
        } catch (const std::exception &ex) {
            e->status = PluginStatus::Failed;
            e->reason = PluginFailReason::LoadThrew;
            e->fail_detail = ex.what();
            push_event(id, phase, PluginStatus::Failed, PluginFailReason::LoadThrew, ex.what());
            result.ok = false;
            // Fail dependents later in this phase that hard-depend on us
            for (auto &other : entries_) {
                if (other.status != PluginStatus::Registered && other.status != PluginStatus::Loaded) {
                    continue;
                }
                if (std::find(other.loaded_phases.begin(), other.loaded_phases.end(), phase) !=
                    other.loaded_phases.end()) {
                    continue;
                }
                for (const auto &dep : other.plugin->manifest().depends) {
                    if (dep == id) {
                        other.status = PluginStatus::Failed;
                        other.reason = PluginFailReason::MissingHardDep;
                        other.fail_detail = id;
                        push_event(other.plugin->manifest().id, phase, PluginStatus::Failed,
                                   PluginFailReason::MissingHardDep, id);
                    }
                }
            }
        } catch (...) {
            e->status = PluginStatus::Failed;
            e->reason = PluginFailReason::LoadThrew;
            e->fail_detail = "unknown";
            push_event(id, phase, PluginStatus::Failed, PluginFailReason::LoadThrew, "unknown");
            result.ok = false;
        }
    }

    return result;
}

bool PluginHost::unload_plugin(std::string_view id, PluginContext &ctx) {
    Entry *e = find(id);
    if (!e || e->status != PluginStatus::Loaded) {
        return false;
    }
    if (!e->plugin->manifest().support_reload) {
        return false;
    }
    e->plugin->unload(ctx);
    e->status = PluginStatus::Registered;
    e->loaded_phases.clear();
    push_event(id, PluginPhase::None, PluginStatus::Registered, PluginFailReason::None, "unloaded");
    return true;
}

} // namespace ds::plugin
