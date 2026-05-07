# GameRenderHook 设计文档

## 概述

GameRenderHook 是 Don't Starve 渲染管线的运行时优化系统。通过 DLL 注入 + 函数 hook，拦截游戏的 OpenGL 渲染调用，减少每帧 GPU 资源分配/释放的开销。

核心观察：Don't Starve 的短生命周期动态几何（尤其是 `Batcher::Flush` 生成的流式顶点数据）会频繁触发底层 `glGenBuffers` / `glDeleteBuffers`。这类对象通常只活一个很短的渲染周期，CPU 侧对象和资源管理器语义都很轻，但驱动层 buffer name 的反复创建/销毁存在额外开销。

当前结论：
- **旧方案（已否定）**：在 `CreateVB` / `ReleaseVB` 层复用 `cResourceManager` handle 与 `HWBuffer` 对象
- **新方案（采用）**：在 `HWBuffer::Init` / `HWBuffer::~HWBuffer` 层复用底层 GL buffer name，保留引擎原生 `cResourceManager` / `FrameDelayedResourceManager` 生命周期语义
- **Draw Call Batcher**：已评估，ROI 不足，继续放弃

> 本文档中的“语义基准”均以 **32-bit macOS 带符号二进制** 的 Ghidra 逆向结果为准；Windows x64 仅用于最终落地时验证字段偏移与 hook 点可实现性，不作为生命周期语义来源。

## 设计变更摘要

最初版本将问题建模为“`Batcher::Flush` 频繁创建/释放 VertexBuffer，因此应在 `CreateVB` / `ReleaseVB` 层做对象池”。

后续对 `FrameDelayedResourceManager<VertexBuffer>`、`cResourceManager<VertexBuffer>`、`HWBuffer`、`Renderer::CreateVB/CreateIB`、`HWRenderer::BindVertexState/BindIndexState` 的逆向表明：

1. `VertexBuffer` / `IndexBuffer` 并不是裸 GL 句柄，而是处于完整的 manager 生命周期之内
2. `Release(handle)` 并不等价于“立刻析构对象”，而是进入 **refcount -> delayed queue -> frame-over drain -> final DoUnload -> deleting destructor** 的正式死亡路径
3. 在 `ReleaseVB` 层吞掉原始释放、缓存旧 handle，再在下一次 `CreateVB` 中复用这个 handle，本质上是在 **绕过 manager 生命周期契约并复活已应进入死亡语义的资源记录**
4. 真正高频且昂贵的部分并不是 manager handle 本身，而是 `HWBuffer::Init()` 中的 `glGenBuffers` / `glBufferData` 与 `HWBuffer::~HWBuffer()` 中的 `glDeleteBuffers`

因此，优化层级必须下沉：

- **保留** `cResourceManager` / `FrameDelayedResourceManager` / `VertexBuffer` / `IndexBuffer` 对象语义
- **仅复用** 最底层的 GL buffer name

## 架构概览

```
游戏启动 → DLL 注入 (DontStarveInjector)
           → 通过 MemorySignature 扫描二进制特征码定位函数地址
           → 通过 Frida gum_interceptor_replace() 安装 hook
           → hook HWBuffer::Init / HWBuffer::~HWBuffer
```

技术栈：
- **Frida GumInterceptor** — 运行时函数替换（非 inline hook）
- **MemorySignature** — 字节特征码扫描，定位无符号二进制中的目标函数
- **spdlog** — 日志输出
- **Ghidra MCP** — 以带符号 macOS 二进制为基准确认结构体、vtable、生命周期和插入点

Hook 安装流程（目标形态）：

1. `gum_module_get_path(gum_process_get_main_module())` 获取主模块路径
2. 扫描 `HWBuffer::Init`、`HWBuffer::~HWBuffer`、必要的 GL 相关辅助点位
3. 用 hook 替换这两个底层对象生命周期函数
4. 签名扫描失败时自动禁用 buffer pool（回退为完全原生路径）

## 二进制依赖分析

## 语义基准与跨平台说明

- **语义来源**：32-bit macOS 符号二进制 `dontstarve_steam`
- **落地目标**：Windows x64 `dontstarve_steam_x64.exe`
- **使用原则**：
  - 生命周期、调用链、管理器语义，以 macOS 符号版为准
  - 字段偏移、vtable slot、renderer member offset，在 Windows 落地前单独交叉验证
  - 不以 Windows 无符号反编译去“推翻”macOS 已确认语义

### HWBuffer 结构体布局

#### 32-bit macOS（语义基准）

```cpp
struct HWBuffer {
    void*       vtable;      // +0x00
    uint32_t    stride;      // +0x04
    uint32_t    count;       // +0x08
    uint32_t    glBufferID;  // +0x0C
    eUsageType  usageType;   // +0x10
};
```

对象大小：`0x14`

#### Windows x64（落地验证）

```cpp
struct HWBuffer {
    void*       vtable;      // +0x00 (8 bytes)
    uint32_t    stride;      // +0x08
    uint32_t    count;       // +0x0C
    uint32_t    glBufferID;  // +0x10
    eUsageType  usageType;   // +0x14
    // +0x18 可能还有派生类自用字段 / 对齐空间
};
```

对象大小：`0x20`

**结论**：当前 `GameRenderHook.cpp` 中使用的 Windows x64 字段偏移是正确的；但旧文档把该布局误写成“通用布局”，不适合作为语义文档。今后必须区分 32-bit macOS 与 Windows x64。

### HWBuffer / VertexBuffer / IndexBuffer vtable 布局

#### HWBuffer 基类 vtable（32-bit macOS）

Ghidra 读取结果：`00457758`

| Slot | 偏移 | 函数 |
|------|------|------|
| 0 | +0x00 | `HWBuffer::~HWBuffer()` non-deleting |
| 1 | +0x04 | `HWBuffer::~HWBuffer()` deleting |
| 2 | +0x08 | `HWBuffer::Init(const void*)` |
| 3 | +0x0C | `HWBuffer::TargetType()` 虚函数槽位 |

#### VertexBuffer vtable（32-bit macOS）

`CreateVB` 中将 `HWBuffer*` 的 vtable 写为 `PTR_vtable_00450b8c + 8`，解析后实际起始地址为 `004578a8`：

| Slot | 偏移 | 地址 | 函数 |
|------|------|------|------|
| 0 | +0x00 | `001cf2bc` | `VertexBuffer::~VertexBuffer()` non-deleting |
| 1 | +0x04 | `001cf2c2` | `VertexBuffer::~VertexBuffer()` deleting |
| 2 | +0x08 | `001c6338` | `HWBuffer::Init(const void*)` |
| 3 | +0x0C | `001cf2b6` | `VertexBuffer::TargetType()` → `0x8892` (`GL_ARRAY_BUFFER`) |

#### IndexBuffer vtable（32-bit macOS）

`CreateIB` 中将 vtable 写为 `PTR_vtable_00450b84 + 8`，解析后实际起始地址为 `00457888`：

| Slot | 偏移 | 地址 | 函数 |
|------|------|------|------|
| 0 | +0x00 | `001cf284` | `IndexBuffer::~IndexBuffer()` non-deleting |
| 1 | +0x04 | `001cf28a` | `IndexBuffer::~IndexBuffer()` deleting |
| 2 | +0x08 | `001c6338` | `HWBuffer::Init(const void*)` |
| 3 | +0x0C | `001cf27e` | `IndexBuffer::TargetType()` → `0x8893` (`GL_ELEMENT_ARRAY_BUFFER`) |

**关键结论**：
- `VertexBuffer` 与 `IndexBuffer` 的差异主要是 `TargetType()` 返回值不同
- 两者共享同一个 `HWBuffer::Init()` 和 `HWBuffer::~HWBuffer()` 低层 GL 生命周期
- 因此新方案天然适合统一覆盖 VB 与 IB，而不是只特殊处理 VB

### eUsageType 枚举

macOS 与 Windows 已确认数值一致：

```cpp
enum class eUsageType : uint32_t {
    STATIC_DRAW  = 9,
    STREAM_DRAW  = 10,
    STATIC_COPY  = 0xC,
    STATIC_READ  = 0x11,
    STREAM_READ  = 0x12,
    STREAM_COPY  = 0x14,
    DYNAMIC_READ = 0x21,
    DYNAMIC_DRAW = 0x22,
    DYNAMIC_COPY = 0x24,
};
```

OpenGL usage 映射由引擎内部 `Rendering::GetGLUsage()` 负责。

### Renderer 相关偏移

#### 32-bit macOS

| 字段 | 偏移 | 说明 |
|------|------|------|
| render-thread flag | +0x0C | `CreateVB/CreateIB` 中用于决定直接 Init 还是入命令队列 |
| VertexBuffer manager | +0x194 | `cResourceManager<VertexBuffer>` / `FrameDelayedResourceManager<VertexBuffer>` |
| IndexBuffer manager | +0x198 | `cResourceManager<IndexBuffer>` / `FrameDelayedResourceManager<IndexBuffer>` |

#### Windows x64

| 字段 | 偏移 | 说明 |
|------|------|------|
| VertexBuffer manager | +0x1A8 | 已验证 |
| Index/other command queue | +0x200 | 非渲染线程路径使用 |

> 新方案主要 hook `HWBuffer` 自身，不再依赖 VB manager handle 复用逻辑，因此对 `renderer+managerOffset` 的运行时依赖显著降低。

## 原生资源生命周期分析

### CreateVB / CreateIB 真正做了什么

#### `Renderer::CreateVB`

macOS 符号版流程：

1. `operator_new(0x14)` 分配 `HWBuffer` 对象
2. `HWBuffer::HWBuffer(usageType, stride, count)` 初始化基础字段
3. 把 vtable 改成 `VertexBuffer` vtable
4. `cResourceManager<VertexBuffer>::Add(resource)` 把对象加入 manager 记录并返回 handle
5. 若当前在渲染线程：直接调用 vtable `slot[2]` → `HWBuffer::Init(data)`
6. 若不在渲染线程：复制数据并入 command queue，稍后在渲染线程执行

#### `Renderer::CreateIB`

流程与 `CreateVB` 完全对称，只是 manager 类型不同、`TargetType()` 返回 `GL_ELEMENT_ARRAY_BUFFER`。

### `HWBuffer::Init(const void*)` 的低层语义

`HWBuffer::Init()` 是真实的 GL buffer 创建/上传入口：

1. `glGenBuffers(1, &glBufferID)`
2. `target = this->vtable->TargetType()`
3. `glBindBuffer(target, glBufferID)`
4. `size = count * stride`
5. `usage = Rendering::GetGLUsage(usageType)`
6. `glBufferData(target, size, data, usage)`
7. `glGetError() == 0` 检查

也就是说：
- **对象语义创建点** 在 `CreateVB/CreateIB + cResourceManager::Add`
- **底层 GL name 创建点** 在 `HWBuffer::Init`

这两个层级必须严格区分。

### `HWBuffer::~HWBuffer()` 的低层语义

`HWBuffer::~HWBuffer()` 内部执行：

1. 重设为基类 vtable
2. `glDeleteBuffers(1, &glBufferID)`

派生类 `VertexBuffer::~VertexBuffer()` / `IndexBuffer::~IndexBuffer()` 只是薄包装，最终都落到这里。

因此：
- **对象死亡** 是 manager / dtor 语义
- **GL name 回收** 是 `HWBuffer::~HWBuffer()` 里的副作用

新方案应该只替换后者，不破坏前者。

### cResourceManager / FrameDelayedResourceManager 生命周期契约

逆向确认：`VertexBufferManager` 本质上就是 `FrameDelayedResourceManager<VertexBuffer, unsigned_int, FakeLock>` 的实例化，IndexBuffer 同理。

#### `cResourceManager::Release(handle)`

语义：

1. 校验 handle
2. 找到资源记录 `sResourceRecord`
3. `refcount > 1`：仅递减引用计数
4. `refcount == 1`：
   - 调用 `OnUnload(resource*)`
   - 若有命名资源则移除 name→handle 索引
   - 调用虚函数 `DoUnload(handle)`

#### `FrameDelayedResourceManager::DoUnload(handle)`

并不直接析构对象，而是：

1. 将 handle 放入当前 delayed-release list
2. 等待 frame-over callback 触发

#### `FrameDelayedResourceManager::FrameOver()`

在每帧结束回调中：

1. 加锁
2. 切换双缓冲 release list
3. 调用 `ReleaseList()`
4. 解锁

#### `ReleaseList()`

对排队 handle 逐个调用：

- `cResourceManager::DoUnload(handle)`

#### `cResourceManager::DoUnload(handle)`

这是最终死亡语义：

1. 断言 handle 不在 free list 中
2. 把 handle 放回 free list
3. 断言 `refcount == 1`
4. 断言 `resource != NULL`
5. `refcount = 0`
6. 调用资源 deleting destructor
7. `mResource = NULL`

最终 deleting destructor 再走到 `HWBuffer::~HWBuffer()`，执行 `glDeleteBuffers()`。

### 结论：原生完整链条

```
CreateVB/CreateIB
  → cResourceManager::Add(resource)
  → HWBuffer::Init(data)

Release(handle)
  → cResourceManager::Release(handle)
  → FrameDelayedResourceManager::DoUnload(handle)   // 仅排队
  → FrameOver()
  → ReleaseList()
  → cResourceManager::DoUnload(handle)              // 最终死亡
  → deleting destructor
  → HWBuffer::~HWBuffer()
  → glDeleteBuffers()
```

这条链是当前设计必须尊重的核心契约。

## 旧方案复盘：为何 `CreateVB/ReleaseVB` 对象池是错误层级

旧方案：

- 在 `ReleaseVB` 时截获 handle，按 `(stride, roundedCount)` 缓存
- 跳过原始 `ReleaseVB`
- 在下一次 `CreateVB` 命中时，重新取出这个旧 handle，解析成 `HWBuffer*`，改写 `count`，重新上传数据并返回

这个思路的问题不在“实现细节粗糙”，而在 **层级错误**：

### 1. 绕过 manager refcount / free-list / delayed-release 语义

hook 吞掉 `Release(handle)` 后：

- manager 记录的 `refcount` 不会进入正常归零路径
- handle 不会进入 delayed queue
- frame-over drain 不会发生
- handle 不会回到 manager free-list
- `mResource` 不会置空

### 2. 复活本应死亡的资源记录

后续命中池时，代码直接把旧 handle 重新当成“活资源”使用。对 manager 而言，这个 handle 不是“重新创建的新资源”，而是“未正式死亡、却被旁路保留下来的旧资源”。

### 3. 对 `HWBuffer` 对象状态做越权修改

旧实现会在复用路径中直接改写：

- `hwBuf->count = count`

这属于在 manager 生命周期之外修改对象内部状态。即使短期看似可用，也会让对象状态与原生创建流程脱节。

### 4. 无法解释长期运行后的闪屏/贴图错误

由于 manager 生命周期被破坏，长期运行后可能出现：

- 资源记录与真实 GL 对象状态分离
- handle 池与 manager 内部 bookkeeping 分离
- drain 时机缺失导致池中对象长期滞留
- 渲染路径拿到“逻辑上仍活着、但状态已偏离原生预期”的对象

这类问题正符合“本地短时间难复现，但长时间运行后出现闪屏/贴图错误”的反馈特征。

## 新方案：HWBuffer 级 GL Buffer Name Pool

## 设计目标

只优化下面这一层：

- `glGenBuffers`
- `glDeleteBuffers`

绝不改变下面这些语义：

- `cResourceManager::Add/Release/DoUnload`
- `FrameDelayedResourceManager::DoUnload/FrameOver/ReleaseList`
- `VertexBuffer` / `IndexBuffer` 对象的创建与析构
- manager handle 的分配、回收、free-list、record 生命周期

### 总体思路

将 hook 点改为：

- `HWBuffer::Init(const void*)`
- `HWBuffer::~HWBuffer()`

逻辑变为：

#### hooked_Init(this, data)

1. 读取 `target = this->TargetType()`
2. 读取 `usageType`
3. 读取 `size = stride * count`
4. 按 `(target, usageType, capacityBucket)` 查询底层 GL buffer name pool
5. 若命中：
   - 取出一个旧 `GLuint`
   - 写回 `this->glBufferID`
   - `glBindBuffer(target, glBufferID)`
   - `glBufferData(target, size, data, usage)` 重新初始化存储
   - 跳过 `glGenBuffers`
6. 若未命中：
   - 调用原始 `HWBuffer::Init`

#### hooked_~HWBuffer(this)

1. 读取 `target / usageType / current capacity class / glBufferID`
2. 判断该对象是否适合进入池
3. 若适合：
   - 不执行 `glDeleteBuffers`
   - 将 `glBufferID` 放回 pool
   - 把对象上的 `glBufferID` 清零，避免后续误删
4. 然后继续完成原始对象析构剩余语义（或在受控方式下复刻 dtor 中除 `glDeleteBuffers` 外的逻辑）

> 关键原则：**对象照常死亡，只有 GL name 不死**。

### 为什么这个层级是正确的

因为对引擎而言：

- 每次 `CreateVB` / `CreateIB` 仍然是新对象、新 handle、新 manager record
- 每次 `Release(handle)` 仍然走原生 refcount + delayed release 语义
- `HWRenderer::BindVertexState/BindIndexState` draw 时只依赖“当前对象上的 `glBufferID` 和 `TargetType/NumElements` 是正确的”

引擎不要求这个 `glBufferID` 必须是“从未被别的旧对象用过”的全新名字；只要求它在当前对象生命周期里是一个有效、已正确初始化的 buffer name。

这与低层 GL name 池化是兼容的。

## Pool Key 与复用策略

### Key 建议

```cpp
struct BufferPoolKey {
    uint32_t target;          // GL_ARRAY_BUFFER / GL_ELEMENT_ARRAY_BUFFER
    uint32_t usageType;       // eUsageType 原值
    uint32_t capacityBucket;  // roundUpPow2(byteSize) 或按区间分桶
};
```

### 为什么要包含这几个维度

- **target**：VB 与 IB 必须分桶，不能混用 `GL_ARRAY_BUFFER` / `GL_ELEMENT_ARRAY_BUFFER`
- **usageType**：避免不同 usage hint 之间复用过度混杂，便于保守控制
- **capacityBucket**：允许“大 buffer 复用给小请求”，避免严重碎片化

### bucket 建议

- 以 **字节大小** 分桶，而不是顶点数分桶
- 可使用 `roundUpPow2(byteSize)`
- 复用时要求 `pooledCapacity >= requestedSize`

原因：
- 对底层 GL name 来说，真正重要的是 buffer storage 容量，不是“顶点个数”
- VB/IB 的 `stride/count` 组合不同，但最终都会落成一个 byte size

## 适用范围

### 第一阶段建议

保守只处理：

- `GL_ARRAY_BUFFER`
- `GL_ELEMENT_ARRAY_BUFFER`
- `STREAM_DRAW`

原因：
- 这是最接近原始性能热点的子集
- 风险最小
- 与 `Batcher::Flush` / 动态几何路径高度重叠

### 后续可扩展

若验证稳定，可逐步评估是否纳入：

- `DYNAMIC_DRAW`
- 其他 usage 类型
- 非批处理但同样短生命周期的 debug/text/fog helper 路径

## 函数签名（已实现）

```cpp
using HWBufferInit_t = void (*)(void* hwBuffer, const void* data);
using HWBufferDtor_t = void (*)(void* hwBuffer);           // non-deleting dtor
```

实现决策：

- hook **non-deleting dtor**（Windows x64: `0x1403e68e0`）
- 抑制 `glDeleteBuffers` 的方式：清零 `hwBuffer->glBufferID` 后调用原始 dtor（`glDeleteBuffers(1, &0)` 按 OpenGL 规范 §4.4 为 no-op）
- TargetType() 调用：Windows x64 使用 vtable slot[2]（MSVC ABI），macOS 使用 slot[3]（Itanium ABI）

## 与 Draw 路径的兼容性

逆向确认：

- `Renderer::SetVertexBuffer(handle)` / `SetIndexBuffer(handle)` 只是把 handle 写入 render state
- 真正的 `glBindBuffer(...)` 发生在 `HWRenderer::BindVertexState()` / `BindIndexState()`
- 这两个函数会通过 manager record 把 handle 解析为对象，再读取对象上的 `glBufferID`

这说明 draw 路径关心的是：

1. handle 能正确解析到当前活对象
2. 当前活对象的 `glBufferID` 有效
3. `TargetType()` 正确
4. `count/NumElements` 与本对象状态一致

新方案不改变 1、3、4，只在对象自己的 Init/dtor 内替换 2 的底层来源，因此与 draw 路径兼容。

## Batcher / Render Helper 影响面

`HWBuffer::Init` 的直接调用者不只有 `CreateVB/CreateIB`，还包括：

- `DrawDebugLines`
- `DrawFogLayer`
- `DrawTriangles`
- `GenerateVB`
- `InitializeResources`
- `RenderCacheLines`
- `RenderDebugLines_Uncached`
- `RenderText`
- `UpdateFogLayer`

这意味着：

- 新方案不是“只优化 Batcher::Flush 的特判 hack”，而是统一优化共享的底层 buffer 创建路径
- 同时也意味着筛选条件必须保守，避免把长生命周期或初始化期资源误纳入池中

## 容量限制

| 参数 | 值 | 说明 |
|------|------|------|
| MAX_POOL_SIZE_PER_BUCKET | 32 | 单个 `(target, usageType, capacityBucket)` 最大缓存数 |
| MAX_TOTAL_POOLED | 256 | 全局池上限（name 个数） |
| MAX_TOTAL_BYTES | 16MB | 总显存预算 |

### 淘汰策略

池满时不拒绝入池，而是主动淘汰冷数据腾出空间：

| 触发条件 | 淘汰方式 | 复杂度 |
|---------|---------|--------|
| 同 bucket 满（≥32） | 同 bucket FIFO：pop front（最旧 name），glDeleteBuffers | O(1) |
| 全局总量/字节超限 | 全局 FIFO（`globalFifo_` deque）：取最旧入池 name，删除 | O(1) 摊销 |

热数据保护机制：高频复用的 name 被 acquire 取走后不在 bucket 中，全局 FIFO 遍历时自动跳过已不存在的 name。

### 统计指标

| 字段 | 含义 |
|------|------|
| `hits` | acquire() 命中池次数 |
| `misses` | acquire() 未命中次数（走原始 glGenBuffers） |
| `evictions` | 淘汰次数 |
| `reusedBytes` | 从池复用的累计字节数 |
| `genSaved` | 省掉的 glGenBuffers 调用次数（= hits） |
| `deleteSaved` | 省掉的 glDeleteBuffers 调用次数（成功入池次数） |

命中率计算：`hitRate = hits / (hits + misses)`

## 安全防护

| 防护 | 说明 |
|------|------|
| 签名扫描失败降级 | `HWBuffer::Init` / dtor 任一点扫描失败则禁用整个池 |
| 仅对白名单 target/usage 启用 | 第一阶段只处理 `ARRAY_BUFFER/ELEMENT_ARRAY_BUFFER + STREAM_DRAW` |
| bucket 容量检查 | 只允许 `pooledCapacity >= requestedSize` |
| pool 上限 | 同时限制 bucket 数量、对象数量、总字节数 |
| glBufferID 清零 | 对象析构后若 GL name 已回池，必须清零实例字段避免重复删除 |
| 明确的 drainAll() | 进程退出 / 渲染系统停机时可主动清空池并真正 `glDeleteBuffers` |
| 线程约束 | 若落地平台存在 render-thread 约束，pool 操作仅在 GL 上下文合法线程进行 |

## 已知开放问题

1. **容量元数据来源**：dtor 时若要按 bucket 回收 GL name，需要能拿到"该对象最后一次 Init 的实际 capacity class"；必要时需在旁路表中记录 `glBufferID -> bucket`（已实现 side-map）
2. **上下文丢失/销毁**：虽然目前没有证据表明运行时频繁重建主 GL context，但 disable 时会 drain 整个池
3. **Windows ANGLE 行为**：Windows 版通过 ANGLE/EGL 间接落到 GL buffer API；需要验证"保留 buffer name 不 delete、稍后重新 bind + bufferData"的行为在 ANGLE 上是否稳定
4. **过滤策略**：`HWBuffer::Init` 被多个 helper 调用，新方案不能默认所有 buffer 都值得池化（当前只处理 STREAM_DRAW）

## vtable ABI 差异（实现关键）

| 平台 | ABI | vtable 布局 | TargetType() 所在 slot |
|------|-----|-------------|----------------------|
| macOS x86 | Itanium | [non-deleting dtor, deleting dtor, Init, TargetType] | slot[3] |
| Windows x64 | MSVC | [deleting dtor, Init, TargetType] | slot[2] |

实现中必须按目标平台使用正确的 slot index，否则会跳转到无效地址导致崩溃。

## 运行时动态切换

当前设计 **支持运行时动态切换**，无需重启进程：

- `DS_LUAJIT_set_vbpool_enabled(true)`：解析 GL 函数 → 扫描签名 → 安装 Init/Dtor/BatcherFlush hooks → 启用池
- `DS_LUAJIT_set_vbpool_enabled(false)`：禁用池 → drain 所有 pooled GL names（调用 `glDeleteBuffers`）→ revert 所有 hooks

切换安全性保证：
- 启用：all-or-nothing，Init 和 Dtor hook 必须同时成功，否则 revert 已安装的部分
- 禁用：先设 `g_enableBufferPool = false`（hook 函数立即 passthrough），再 drain pool，最后 revert hooks
- `InstallRenderHooks()` 和 `ShutdownRenderHooks()` 为空函数（兼容旧调用点）

## Draw Call Batcher（已评估，继续放弃）

运行时诊断曾表明：

- 状态匹配时矩阵 100% 匹配，技术上可做 adjacent merge
- 但稳态仅约 12% 的 Flush 可合并
- 平均 run 很短，收益有限

在旧方案时代，这部分已被判定 ROI 不足。即使切换到新方案，这个结论仍然成立：

- 真正高频、通用、低风险的收益点仍是底层 buffer name 复用
- Draw call merge 的复杂度与渲染正确性风险不匹配当前收益

## 当前文档结论

1. **旧的 CreateVB/ReleaseVB handle pool 设计应视为错误方向，不应继续实现或扩展**
2. **新的正确层级是 HWBuffer::Init / HWBuffer::~HWBuffer**
3. **复用对象应是 GL buffer name，而不是 manager handle / VertexBuffer 对象本身**
4. **所有实现都必须以“保持原生 manager 生命周期不变”为硬约束**
5. **第一阶段建议只覆盖 STREAM_DRAW 的 VB/IB 低层 GL name 复用**

## 后续实现任务（文档层面）

1. ~~为 `HWBuffer::Init` / `HWBuffer::~HWBuffer` 补充 Windows x64 特征码与落地验证~~ ✓ 已完成
2. ~~设计 `BufferNamePool` 的元数据结构~~ ✓ 已完成（`BufferNamePool.hpp`）
3. ~~明确析构 hook 的最小侵入实现方式~~ ✓ 已完成（hook non-deleting dtor，清零 glBufferID）
4. ~~更新 `GameRenderHook.cpp`，移除旧的 `CreateVB/ReleaseVB` handle pool 逻辑~~ ✓ 已完成
5. 验证 ANGLE 上 buffer name 复用行为的长期稳定性（待运行时 QA）
5. 重新设计日志与统计项：命中率、复用字节数、真实 `glGenBuffers/glDeleteBuffers` 节省量
