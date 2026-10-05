# 更新日志

## 未发布

- 修复加密模组（风雪/daxsg 家族，如《神话书说》workshop-1991746508）导致的服务器世界生成卡死/崩溃：其加载器探测 `require("jit")` 后会在 LuaJIT 下走坏路径（字节码 VM 报 `K nil` 或死循环），污染 worldgen 状态。新增 `Mod/modworldgenmain.lua`：只在真正的世界生成状态（`WORLDGEN_MAIN`，`scripts/worldgen_main.lua` 设置；客户端前端/普通加载路径无此标记）里 `rawset` 掉 `_G.jit` 并清 `package.loaded.jit`（`jit.runtime` 的 HideGlobalJIT 只覆盖 modmain 阶段，worldgen 不跑 modmain），受 `HideGlobalJIT` 选项控制（默认开）。

- 修复 VBPool 与显式 ANGLE 后端（如 `AngleBackend=vulkan`）同时开启时的画面错乱：GL 入口点改为从引擎自身的 `libGLESv2.dll` IAT 槽解析（即 `render.angle` 重绑后的活动渲染器），并声明 soft dep 让 `render.angle` 先加载（priority 36）。
- `render.shadow` 剪影批的 GL 入口点同样改走引擎 IAT 槽确定活动渲染器模块（新增共享头 `util/engine_gles.hpp`）。
- 修复 `render.shadow` 剪影阴影完全失效（游戏 2026-10 更新后）：`LoadShader` 从硬编码 RVA(0x3e9f00) 改为签名定位（新 RVA 0x12170）；`shaders/sil.ksh` 的两段 GLSL 源码补上引擎要求的尾部 NUL（此前编译报 `0:18: '?' : syntax error`）；shader 资产纳入插件包（CMake install + 调试部署脚本）。
- `BufferNamePool` 单测期望改用类内上限常量（128/桶、1024、64MiB），跟上现容量设置。
- Steam 接入迁入宿主 `sdk/steam/`，客户端在配置解析前采集 AccountID，服务端创意工坊钩子不再依赖 VM 启用状态。
- 创意工坊目录缓存和查询接口统一由宿主管理，VM 文件读取复用该缓存；移除旧 Steam 工具层和测试库目标。

## 2.8.0

- LuaJIT Gen GC 支持（分代 GC、帧 GC，禁用 Full GC）
- 游戏存档 Fork Save 支持
- 新增顶点缓冲池（VB Pool）
- 缓冲池统计追踪（EMA 命中率）
- 更新 Linux 签名
- 修复 Linux 递归崩溃
- 修复 lua-debug 模式
- 重命名本地服务器配置目录
- 修复 profiler_push 签名

## 2.7.3

- SlowTaICall 检查器迁移到 C 端

## 2.7.2

- 修复网络模拟器（netsim）bug

## 2.7.1

- 修复 GameLuaModule 相关 bug

## 2.7.0

- 客户端渲染顶点缓存
- 服务器延迟补偿功能
- 网络丢包模拟器
- 压力测试机器人框架
- mod 配置选项可视化禁用
- modinfo 注入平台环境
- 修复网络优化 bug
- 修复读取错误配置文件