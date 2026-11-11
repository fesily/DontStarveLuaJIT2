---
name: wpr-etl-orphan-cleanup
description: TEMP 被巨型 ETL 占满、怀疑 WPR 采集残留时:用 logman(不是 wpr -cancel)停孤儿会话并删 WPR_initiated_*.etl
---

# WPR/ETL 孤儿会话清理(Windows)

用途:磁盘被 %TEMP% 里的巨型 `.etl` 吃光,且怀疑是 WPR(Windows Performance Recorder)采集没收尾所致。

## 判定
```powershell
# 1) 找大 ETL($env:TEMP 含递归,列 >1GB)
Get-ChildItem "$env:TEMP" -Filter *.etl -Force -Recurse | ? {$_.Length -gt 1GB} |
  % { '{0,9:N2} GB  {1}  {2}' -f ($_.Length/1GB), $_.LastWriteTime.ToString('HH:mm:ss'), $_.FullName }
# 2) 是否仍在采集(关键:ETL 存在 ≠ 会话活着,看 mtime 是否在变 + logman)
logman query -ets | Select-String 'WPR_initiated'
# 3) WPR 自身是否认账(孤儿会话它不认,所以不能靠 wpr -cancel)
& "C:\Program Files (x86)\Windows Kits\10\Windows Performance Toolkit\wpr.exe" -status
```
确认真占盘(排除稀疏):`fsutil sparse queryflag <file>`,或 P/Invoke `kernel32!GetCompressedFileSizeW` 对比 logical/on-disk。

## 清理(需管理员)
```powershell
logman stop "WPR_initiated_DsPerf-<32hex>_DS Performance Boundaries" -ets   # exit=0 即成功
logman stop "WPR_initiated_DsPerf-<32hex>_WPR System Collector" -ets       # 若存在
Remove-Item "$env:TEMP\WPR_initiated_DsPerf-*.etl" -Force                 # 未提权通常也能删
```
- 提权(本机已启用 sudo):`sudo.exe cmd.exe /c "powershell -File C:\path\kill.ps1 > C:\path\kill.log 2>&1"` —— **sudo 默认不回传 stdout**,必须重定向到文件再读。
- 会话名不要靠 `\s{2,}` 解析:`logman query -ets` 的名字列与类型列(中文 `跟踪`/英文 `Trace`)只隔一个空格,会把状态词并进名字导致 `找不到数据收集器集`。硬编码名字最稳;若解析用 `^\s*(WPR_initiated_DsPerf-.+?)\s+(跟踪|Trace)\s`,并注意提权进程下中文字面量可能失配(无 BOM 的 .ps1 在中文 Windows 上按 GBK 解码,写中文正则必挂)。
- **别用 `wpr -cancel -instancename`**:孤儿会话报 0xc5583000 "There are no trace profiles running"。

## 验证
```powershell
logman query -ets | Select-String 'WPR_initiated'    # 应为空
Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='C:'" | % { 'free={0:N2} GiB' -f ($_.FreeSpace/1GB) }
```
NTFS 释放有延迟:删完立刻读可能只涨一半,隔几秒采 2–3 次直到稳定。

## 防复发(DST 性能 harness)
`DontStarveLuaJIT2/tests/performance/etw_control.py` 的 `wpr -start ... -filemode` 天生把临时 ETL 写进 %TEMP%,一轮可达 135 GB。建议:采集前后检查 %TEMP% 余量;`finally` 里对失败的采集做 `-cancel` + 删 `WPR_initiated_*.etl`;或把 `TEMP` 指到专用目录;并检测孤儿会话。

## 证据(2026-10-16 实测)
两个孤儿会话各留 135.2/135.1 GiB `..._WPR System Collector.etl` + 各 1.05 GiB markers ETL,共 272.41 GiB;停会话+删除后可用 212.12 → 484.03 GiB。
