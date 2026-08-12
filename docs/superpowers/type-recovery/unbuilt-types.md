# 未创建核心类型恢复报告 (2026-08-08)

> 二进制:`dontstarve_steam`(macOS i386 32位, base 0x1000)
> 背景:review 后盘点「引擎使用但未创建」的类型,补齐 27 个核心类型。
> 方法:IDA/Ghidra ctor/dtor 反编译 → 字段定型 → 回写 Ghidra。

## 恢复清单(27 类型)

### Tier 0 级核心(被已建类型引用)

| 类型 | 大小 | 关键证据 |
|---|---|---|
| cSimTime | 12B | ctor 0xf5e26:vtable@0 + nTick@4 + fRemainder@8;cSimulation 子对象@0x48 吻合 |
| cBPWorld | 52B | ctor 0xc9fb2:vtable + 8 指针(broadphase/config/dispatcher/solver/world/groundShape/groundBody)+ pSimulation@0x30;new(0x34) |
| EnvelopeManager | 24B | ctor 0xde76:vtable + vec<Envelope*> + IndexManager;EnvelopeComponent dtor 引用 |
| cApplication | 16B | ctor 0x6d94 + dtor 0x6eca + Startup 0x872a:mSystemService@0/mGameService@4/mGame@8/mCommandLine@12 |
| cLogger | 4184B | singleton init 0xa9d0:new(0x1058),vtable + cLoggerImplementation@4 |
| cLoggerImplementation | 4180B | ctor 0x257a2c:vtable + string@8 + Mutex@0x10 + time@0x1050 |
| cInventoryManager | 1096B | ctor 0x1501d6:list/map 头 + 2 string@0x40/0x44 + UNKNOWN 尾 |
| cSoundSystem | 56B | ctor 0x124a1c:双 map 头 + vtable + byte@0x34;cGame+0x64 引用 |

### 网络层

| 类型 | 大小 | 关键证据 |
|---|---|---|
| cNetID2 | 44B | Clear 0x1623a2:11 dword 清零;cAccountCommunication m_netId 吻合 |
| cMasterServer | 145B | ctor 0x1583e6 + dtor 0x1585a2:list + Timer + deque + pRequest/pBroadcast + vector |

### 18 个 Component(基类 cEntityComponent 16B + 自有字段)

| 类型 | 大小 | 关键证据 |
|---|---|---|
| WaveComponent | 144B | ctor 0x8979c:31 字段,vec@0x64 |
| FollowerComponent | 66B | ctor 0x35ebc:vec×2 + string + 字段 |
| cLabelComponent | 20B | ctor 0x40cac:仅 vtable + 1 字段 |
| cLightEmitterComponent | 41B | ctor 0x41e5c:colour vec + 字段 |
| cLightWatcherComponent | 62B | ctor 0x43a2c:含 cSimTime@0x1C |
| MiniMapComponent | 96B | ctor 0x4fa9e:双 vtable + map 头 |
| MiniMapEntityComponent | 33B | ctor 0x4f59c:5 字段 |
| DebugRenderComponent | 232B | ctor 0x317dc:SceneGraphNode 子对象@0x10 |
| DynamicShadowComponent | 36B | AddComponentToEntity 0x723ca:new(0x24) |
| StaticShadowComponent | 36B | AddComponentToEntity 0x72c50:new(0x24) |
| ShadowManagerComponent | 32B | ctor 0x70df6:4 字段(-1 哨兵) |
| GraphicsOptionsComponent | 16B | ctor 0x385dc:仅基类 |
| PostProcessorComponent | 16B | ctor 0x6b7cc:仅基类 |
| RoadManagerComponent | 248B | ctor 0x6c896:SceneGraphNode + RoadBuilder@0xA4 |
| TwitchComponent | 48B | ctor 0x826bc:双 vtable + map 头 |
| cUITransformComponent | 388B | ctor 0x83b3e:4 vtable + 双 map + 字段 |
| cShardClientComponent | 30B | ctor 0x739dc:list 头 + 字段 |
| cShardNetworkComponent | 21B | ctor 0x753cc:2 字段 |
| cSerializableEntityComponent | 16B | 抽象标记类,仅基类 |

## 跳过/记录

- cNetworkConnection、cNetworkReplica:继承 RakNet 基类,ctor 内联,Tier 4 范围
- cNetworkReplicaManager:5048B 已存在(插件先验)
- cDontStarveSim(1148B)、cDontStarveGame(316B)、cNetworkManager(5048B)、GameRenderer(2024B)、SceneGraphNode(145B):插件先验已建

## 验证

- 全部 27 类型已回写 Ghidra 根路径
- 关键交叉验证:cSimTime/cBPWorld 与 cSimulation 布局互证;cNetID2 与 cAccountCommunication 互证;Component 均基于 cEntityComponent 基类
