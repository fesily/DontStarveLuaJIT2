#include "GameNetwork.hpp"
#include "GameLua.hpp"
#include "frida-gum.h"
#include "config.hpp"
#include "MemorySignature.hpp"
#include "util/inlinehook.hpp"
#include <disasm.h>
#include <spdlog/spdlog.h>
#include <plf_hive.h>
#include <slikenet/RPC4Plugin.h>
#include <slikenet/ReplicaManager3.h>
#include <optional>
#include <mutex>
#include <memory_resource>
struct EntityNetWorkExtension {
    static constexpr auto vtb_length = 41;
    static constexpr auto vtb_guard = 8;
    int64_t hooked_vtb[vtb_length + vtb_guard];
    struct EntityNetWorkExtensionVal {
        char channel;
    } extension_val;
    static constexpr auto vtb_offset = 0x20;// offset of vtb in network object
    constexpr static auto LuaUdataTypeName = "Network";
    constexpr static auto RakNetChannelCount = 32 - 1;// 0 is reserved for default channel, so we use 1-32 for channels
    static void *get_vtb(void *network) {
#ifdef _WIN32
        // get vtb from network obj
        return *(void **) ((uintptr_t) network + vtb_offset);
#elif defined(__linux__)
        return nullptr;
#else
        return nullptr;
#endif
    }
    static void *get_vtb_replica3(void *replica3) {
#ifdef _WIN32
        // get vtb from network obj
        return *(void **) ((uintptr_t) replica3);
#elif defined(__linux__)
        return nullptr;
#else
        return nullptr;
#endif
    }
    static void set_vtb(void *network, void *vtb) {
#ifdef _WIN32
        // set vtb to network obj
        *(void **) ((uintptr_t) network + vtb_offset) = vtb;
#else
#endif
    }
    static void set_vtb_replica3(void *replica3, void *vtb) {
#ifdef _WIN32
        // set vtb to network obj
        *(void **) ((uintptr_t) replica3) = vtb;
#else
#endif
    }

    static void *original_network_vtb_ptr;

    static bool initialize_virtual_table(void *rip_insn_address) {
        auto insn = function_relocation::disasm::get_insn((void *) rip_insn_address, 32);

        auto vtb_ptr = (void *) function_relocation::read_operand_rip_mem(*insn, insn->detail->x86.operands[1]);
        if (!gum_memory_is_readable(vtb_ptr, vtb_length * sizeof(int64_t))) {
            spdlog::error("EntityNetWorkExtension: initialize_virtual_table failed, cNetworkVtb_ptr is not readable");
            return false;
        }

        auto ptr = (int64_t *) vtb_ptr;
        while (*ptr != 0) {
            GumPageProtection prot;
            gum_memory_query_protection((void *) *ptr, &prot);
            if (prot != GUM_PAGE_RX) {
                spdlog::error("EntityNetWorkExtension: initialize_virtual_table failed, function memory is not RX");
                return false;
            }
            ptr++;
        }
        if ((ptr - (int64_t *) vtb_ptr) != vtb_length) {
            spdlog::error("EntityNetWorkExtension: vtb length is not 24, got {}", ptr - (int64_t *) vtb_ptr);
            return false;
        }
        original_network_vtb_ptr = vtb_ptr;
        return true;
    }

    static EntityNetWorkExtension *getExtensionFromNetworkComponent(void *network) {
        auto network_vtb_ptr = (int64_t *) original_network_vtb_ptr;
        if (!network_vtb_ptr) {
            return nullptr;
        }
        auto current_vtb = (int64_t *) get_vtb(network);

        // check deconstructed ptr
        if (*network_vtb_ptr == *current_vtb) {
            return nullptr;
        }
        return reinterpret_cast<EntityNetWorkExtension *>(current_vtb);
    }
    static EntityNetWorkExtension *getExtensionFromReplica3(void *replica3) {
        auto network_vtb_ptr = (int64_t *) original_network_vtb_ptr;
        if (!network_vtb_ptr) {
            return nullptr;
        }
        auto current_vtb = (int64_t *) get_vtb_replica3(replica3);
        // check deconstructed ptr
        if (*network_vtb_ptr == *current_vtb) {
            return nullptr;
        }
        return reinterpret_cast<EntityNetWorkExtension *>(current_vtb);
    }
    //
    /* lua code
    function EntityNetWorkExtension.RegisterEntity(networkid, network)
        entity.networkentityexternsion = EntityNetWorkExtension.registerEntity(network, networkid)
    end
    */
    static EntityNetWorkExtensionVal *registerEntityNetworkComponent(void *networkcomponent, SLNet::NetworkID networkid) {
        auto replica3 = (SLNet::Replica3 *) ((uint64_t) networkcomponent + vtb_offset);
        return registerReplica3(replica3, networkid);
    }
    static EntityNetWorkExtensionVal *registerReplica3(SLNet::Replica3 *replica3, SLNet::NetworkID networkid = SLNet::UNASSIGNED_NETWORK_ID) {
        auto network_vtb_ptr = (int64_t *) original_network_vtb_ptr;
        if (!network_vtb_ptr) {
            spdlog::error("EntityNetWorkExtension: registerEntity failed, vtb failed");
            return 0;
        }
        auto current_vtb = (int64_t *) get_vtb_replica3(replica3);
        if (*network_vtb_ptr != *current_vtb) {
            return nullptr;
        }
        if (networkid != SLNet::UNASSIGNED_NETWORK_ID) {
            assert(replica3->GetNetworkID() == networkid);
        } else {
            networkid = replica3->GetNetworkID();
        }

        // hook network vtb

        auto userdata = getHive().emplace();

        memset(userdata->hooked_vtb, 0xCC, sizeof(userdata->hooked_vtb));
        memcpy(userdata->hooked_vtb, network_vtb_ptr, vtb_length * sizeof(int64_t));
        // replace vtb deconstructed ptr

        userdata->hooked_vtb[0] = (int64_t) +[](void *replica3, char a2) {
            auto vtb_ptr = (void **) original_network_vtb_ptr;
            auto userdata = EntityNetWorkExtension::getExtensionFromReplica3(replica3);
            getHive().erase(getHive().get_iterator(userdata));
            set_vtb_replica3(replica3, vtb_ptr);
            auto old_deconstructed_ptr = (void *(*) (void *, char) ) vtb_ptr[0];
            return old_deconstructed_ptr(replica3, a2);
        };

        // hash networkid to (1, RakNetChannelCount)
        userdata->extension_val.channel = (networkid % RakNetChannelCount) + 1;
        set_vtb_replica3(replica3, userdata->hooked_vtb);
        return &(userdata->extension_val);
    }

    static plf::hive<EntityNetWorkExtension> &getHive() {
        static plf::hive<EntityNetWorkExtension> entity_network_extension_hive;
        return entity_network_extension_hive;
    }
};

void *EntityNetWorkExtension::original_network_vtb_ptr = nullptr;

/*
export lua module EntityNetWorkExtension
*/
DONTSTARVEINJECTOR_API EntityNetWorkExtension::EntityNetWorkExtensionVal *DS_LUAJIT_EntityNetWorkExtension_Register(void *networkComponentLuaProxyPtr, int64_t networkid) {
    if (!networkComponentLuaProxyPtr) {
        spdlog::error("EntityNetWorkExtension: registerEntity failed, network is null");
        return 0;
    }
    auto networkComponentLuaProxy = *(int64_t ***) networkComponentLuaProxyPtr;
    if (!networkComponentLuaProxy) {
        spdlog::error("EntityNetWorkExtension: registerEntity failed, network is null");
        return 0;
    }
    return EntityNetWorkExtension::registerEntityNetworkComponent(*(networkComponentLuaProxy + 1), networkid);
}

static_assert(sizeof(SLNet::RPC4) == 392);

static std::optional<PacketPriority> next_packetPriority;
static std::optional<PacketReliability> next_reliability;
static std::optional<char> next_orderingChannel;

DONTSTARVEINJECTOR_API void DS_LUAJIT_SetNextRpcInfo(PacketPriority *packetPriority, PacketReliability *reliability, char *orderingChannel) {
    if (packetPriority)
        next_packetPriority = *packetPriority;
    else
        next_packetPriority.reset();
    if (reliability)
        next_reliability = *reliability;
    else
        next_reliability.reset();
    if (orderingChannel)
        next_orderingChannel = *orderingChannel;
    else
        next_orderingChannel.reset();
}

void ResetNextRpcInfo(GumInvocationContext *context) {
    if (next_packetPriority) {
        auto packetPriority = *next_packetPriority;
        gum_invocation_context_replace_nth_argument(context, 3, (gpointer) packetPriority);
        next_packetPriority.reset();
    }
    if (next_reliability) {
        auto reliability = *next_reliability;
        gum_invocation_context_replace_nth_argument(context, 4, (gpointer) reliability);
        next_reliability.reset();
    }
    if (next_orderingChannel) {
        auto orderingChannel = *next_orderingChannel;
        gum_invocation_context_replace_nth_argument(context, 5, (gpointer) orderingChannel);
        next_orderingChannel.reset();
    }
}

void SendUnified(SLNet::PluginInterface2 *plugin, const SLNet::BitStream *bitStream, PacketPriority priority, PacketReliability reliability, char orderingChannel, const SLNet::AddressOrGUID systemIdentifier, bool broadcast);
decltype(&SendUnified) original_SendUnified = nullptr;
void SendUnified(SLNet::PluginInterface2 *plugin, const SLNet::BitStream *bitStream, PacketPriority priority, PacketReliability reliability, char orderingChannel, const SLNet::AddressOrGUID systemIdentifier, bool broadcast) {
    spdlog::debug("SendUnified called, priority: {}, reliability: {}, orderingChannel: {}, systemIdentifier: {}, broadcast: {}", (int) priority, (int) reliability, (int) orderingChannel, systemIdentifier.ToString(), broadcast);
    original_SendUnified(plugin, bitStream, priority, reliability, orderingChannel, systemIdentifier, broadcast);
}


void GameWatcherEntityNetwork(GumInterceptor *interceptor) {
}

namespace SLNet {
    struct SerializeParameters1 {
        /// Write your output for serialization here
        /// If nothing is written, the serialization will not occur
        /// Write to any or all of the NUM_OUTPUT_BITSTREAM_CHANNELS channels available. Channels can hold independent data
        SLNet::BitStream outputBitstream[1];

        /// Last bitstream we sent for this replica to this system.
        /// Read, but DO NOT MODIFY
        SLNet::BitStream *lastSentBitstream[1];

        /// Set to non-zero to transmit a timestamp with this message.
        /// Defaults to 0
        /// Use SLNet::GetTime() for this
        SLNet::Time messageTimestamp;

        /// Passed to RakPeerInterface::Send(). Defaults to ReplicaManager3::SetDefaultPacketPriority().
        /// Passed to RakPeerInterface::Send(). Defaults to ReplicaManager3::SetDefaultPacketReliability().
        /// Passed to RakPeerInterface::Send(). Defaults to ReplicaManager3::SetDefaultOrderingChannel().
        PRO pro[1];

        /// Passed to RakPeerInterface::Send().
        SLNet::Connection_RM3 *destinationConnection;

        /// For prior serializations this tick, for the same connection, how many bits have we written so far?
        /// Use this to limit how many objects you send to update per-tick if desired
        BitSize_t bitsWrittenSoFar;

        /// When this object was last serialized to the connection
        /// 0 means never
        SLNet::Time whenLastSerialized;

        /// Current time, in milliseconds.
        /// curTime - whenLastSerialized is how long it has been since this object was last sent
        SLNet::Time curTime;
    };

    /// \ingroup REPLICA_MANAGER_GROUP3
    struct DeserializeParameters1 {
        SLNet::BitStream serializationBitstream[1];
        bool bitstreamWrittenTo[1];
        SLNet::Time timeStamp;
        SLNet::Connection_RM3 *sourceConnection;
    };
}// namespace SLNet

void GameNetWorkHookRpc4() {
    static auto interceptor = gum_interceptor_obtain();
    function_relocation::MemorySignature RakNet__RPC4__Signal{"48 81 EC 30 03 00 00 48 8B 05", -0x7};
    function_relocation::MemorySignature RakNet_Plugin2_SendUnified{"48 89 84 24 90 00 00 00 48 83 79 08 00", -0x18};
    // function_relocation::MemorySignature RakNet_ReplicaManager3_defaultparams{"C7 43 1C 03 00 00 00", 0x3};
    /*
C7 87 34 01 00 00 03 00 00 00
mov dword ptr [rdi+134], 3  // pro->reliability = PacketReliability::RELIABLE_ORDERED;
*/
    function_relocation::MemorySignature cNetWorkComponent_serialize{"C7 87 34 01 00 00 03 00 00 00"};
    // check channel size = 0x80/4 = 32
    function_relocation::MemorySignature RakNet_ReliabilityLayer_InitializeVariables_NUMBER_OF_ORDERED_STREAMS{"48 8D 8B 68 12 00 00 33 D2 41 B8 80"};
    // lea     rax, NetworkComponentReplica3_vtb
    function_relocation::MemorySignature cNetWorkComponent_cNetworkComponent{"48 8D 8B E8 01 00 00 48 89 43 20", -7};

    if (RakNet__RPC4__Signal.scan(nullptr)) {
        auto listener = gum_make_probe_listener(+[](GumInvocationContext *context, gpointer user_data) { ResetNextRpcInfo(context); }, nullptr, nullptr);
        gum_interceptor_attach(interceptor, (uint8_t *) RakNet__RPC4__Signal.target_address, listener, nullptr, GUM_ATTACH_FLAGS_NONE);
    }

    // if (RakNet_Plugin2_SendUnified.scan(nullptr)) {
    //     gum_interceptor_replace_fast(interceptor, (uint8_t *) RakNet_Plugin2_SendUnified.target_address, (uint8_t *) SendUnified, (gpointer *) &original_SendUnified);
    // }

    if (cNetWorkComponent_serialize.scan(nullptr) && RakNet_ReliabilityLayer_InitializeVariables_NUMBER_OF_ORDERED_STREAMS.scan(nullptr) && cNetWorkComponent_cNetworkComponent.scan(nullptr)) {
        if (EntityNetWorkExtension::initialize_virtual_table((void *) cNetWorkComponent_cNetworkComponent.target_address)) {
            auto listener = gum_make_probe_listener(+[](GumInvocationContext *context, gpointer user_data) {
            // TODO: check this entity is player entity 
            // rdi + 134 reliability
            // rdi + 135 channel
            auto sp = (SLNet::SerializeParameters1 *) context->cpu_context->rdi;

            // rsi -> cNetWorkComponent
            auto replica3 = (SLNet::Replica3 *) context->cpu_context->rsi;
            auto extension = EntityNetWorkExtension::getExtensionFromReplica3((void*)replica3);
            EntityNetWorkExtension::EntityNetWorkExtensionVal *entityNetworkExtensionVal;
            if (!extension) {
                entityNetworkExtensionVal = EntityNetWorkExtension::registerReplica3(replica3);
            } else {
                entityNetworkExtensionVal = &extension->extension_val;
            }
            if (entityNetworkExtensionVal) {
                assert(sp->pro->sendReceipt == 0);
                sp->pro->orderingChannel = entityNetworkExtensionVal->channel;
            } }, nullptr, nullptr);
            gum_interceptor_attach(interceptor, (uint8_t *) cNetWorkComponent_serialize.target_address, listener, nullptr, GUM_ATTACH_FLAGS_NONE);
        }
    }
}
