---
name: cross-build-symbol-channel-calibration
description: "标定跨构建符号迁移通道(字符串/被调图/assert 文件行号),并记录被否证的近似通道"
---

# 跨构建(同版本,不同编译器/平台)符号迁移:先标定通道,再批量落地

## 适用

同一产品版本的两个构建(例:macOS x64 clang ↔ Windows x64 MSVC;或 clang ↔ GCC),
需要把一侧已有的函数符号名移到另一侧。也适用于同架构跨版本(需重新标定)。

## 铁律:没有目标端锚,就没有名字

符号名不随函数体携带。目标构建里必须存在可观察的锚:字符串、被调名集合、assert 的
`文件:行号:文本`、`luaL_Reg` 绑定表、RTTI 类型名、vtable 槽位。
**「同版本所以布局几乎一样」不能作为搬名依据** —— 必须先量化每个通道的精度。

## 步骤

### 1. 建立 ground truth

两侧已有同名的函数对 = 标定集。比较用「去 Ghidra 去重后缀 + 剥库命名空间 + 取末两段」:

```python
def key(n):
    p=re.sub(r"_[0-9a-f]{4,}$","",n).split("::")
    while len(p)>=2 and p[0] in LIBNS: p=p[1:]   # LIBNS=std,boost,RakNet,...
    return "::".join(p[-2:])
```

只取 tail 在两侧都唯一的对作为可靠标定集。

### 2. 逐通道标定(覆盖 + 精度),不要凭感觉

按性价比顺序试,每个通道都在 step 1 的集合上量:

| 通道 | 典型精度 | 说明 |
|---|---:|---|
| 字符串互唯一(两侧 freq==1) | ~95–100% | 最省事,先做 |
| 字符串 jaccard≥0.8 + 唯一最优 | ~100% | 加 margin 判据 |
| 被调名集合重叠(margin≥2) | ~94–95% | 需要目标端已有部分名字 |
| 调用图传播(≥3 共有被调,多轮) | ~100% | 反向也要做:填目标端缺口 |
| assert (文件,行号) 1:1 | ~100% | 同版本最强锚;文件名归一化到 `source/` 之后 |
| assert 断言文本 1:1 | 高但产出低 | 常已被占用 |

**先证伪再排除**,别把弱通道混进来:(指令数,块数) 精确桶真值常只有 ~10%;
同类别尺寸序位 ~25%;vtable 槽号跨编译器对齐往往 0%(两侧检出数量不对称);
MSVC 引擎构建常 `/GR-`(RTTI 只剩 std 异常),RTTI 定类不可用。

### 3. 双向跑,不要只跑一个方向

- 正向(源名 → 目标缺口):容易被「目标已有同名」挡掉。
- 反向(目标匿名 → 源最佳匹配):直接对着缺口做,产出更实。
- 落地前做 **1:1 约束**(目标地址唯一、源名唯一),同名多映射一律丢。

### 4. 落地与复核

- 单条可用 MCP `rename_function_by_address`(`function_address` + `new_name`)。
- 批量用 Ghidra 脚本(`DstApplyNames.java` 风格:`addr \t name \t tier \t evidence`,apply)。
- 复验:随机抽 6–10 条 `get_function_by_address`,名字 tail 必须出现在返回里。

## Ghidra MCP 操作要点(踩过的坑)

- `load_program_from_project` 的参数是 **`{
