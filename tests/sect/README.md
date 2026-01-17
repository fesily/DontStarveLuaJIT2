### 如何解密

## 虚拟机支持

1. 封装lua成C函数

## 解密核心步骤

1. 追踪核心执行步骤
2. 模拟执行的时候modmain环境变量设置成env


## workshop-2847908822

1. 常量计算式折叠
2. dump常量表
3. 折叠常量表
4. 折叠无效表达式
5. 折叠全卷函数访问
6. 折叠upvalues访问
7. 动态追踪派发thunk, 每个thunk写成opcode函数

### 具体加密方式解析

1. 字符串表区间反转三次
2. base64解码字符串表 变形编码表
3. 进入VM执行字节码

### VM解析

1. VM主要函数(OPCODE, fn_args, fn_upvalues, fn_env)
2. OPCODE = fenv.乱码 = nil = 退出函数
3. 模拟堆栈, 大部分操作都是在进出栈
