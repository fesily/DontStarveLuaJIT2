#include "signature_providers.hpp"

#include "NetworkRpcSignatures.hpp"
#include "NetworkSimSignatures.hpp"
#include "NetStatsSignatures.hpp"
#include "NetworkTickSignatures.hpp"
#include "FpsSignatures.hpp"
#include "ProfilerSignatures.hpp"
#include "ShadowSignatures.hpp"
#include "VbpoolSignatures.hpp"

#include "CoreVmSignatures.hpp"
#include "core/InjectorSignatures.hpp"

namespace ds::sig {

const std::vector<ProviderBinding> &repository_providers() {
    static const std::vector<ProviderBinding> providers = {
#if defined(DS_SIG_HAVE_INJECTOR)
            {"injector", &injector_provider_desc},
#endif
            {"core.vm", &core_vm::signature_provider},
#if defined(DS_SIG_HAVE_DEBUG_PROFILER)
            {"debug.profiler", &debug_profiler::signature_provider},
#endif
#if defined(DS_SIG_HAVE_FPS_RENDER)
            {"fps.render", &fps_render::signature_provider},
#endif
#if defined(DS_SIG_HAVE_NETWORK_RPC)
            {"network.rpc", &network_rpc::signature_provider},
#endif
#if defined(DS_SIG_HAVE_NETWORK_SIM)
            {"network.sim", &network_sim::signature_provider},
#endif
#if defined(DS_SIG_HAVE_NETWORK_STATS)
            {"network.stats", &net_stats::signature_provider},
#endif
#if defined(DS_SIG_HAVE_NETWORK_TICK)
            {"network.tick", &network_tick::signature_provider},
#endif
#if defined(DS_SIG_HAVE_RENDER_SHADOW)
            {"render.shadow", &shadow::signature_provider},
#endif
#if defined(DS_SIG_HAVE_RENDER_VBPOOL)
            {"render.vbpool", &render_vbpool::signature_provider},
#endif
    };
    return providers;
}

} // namespace ds::sig
