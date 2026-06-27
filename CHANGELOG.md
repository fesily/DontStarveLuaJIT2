# 更新日志

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