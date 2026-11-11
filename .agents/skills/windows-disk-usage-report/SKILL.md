---
name: windows-disk-usage-report
description: Windows 上生成可对账的项目级磁盘占用报告(robocopy 计量、GiB 口径、junction/硬链接残差、WSL+vhdx 一并统计)
---

# Windows 磁盘占用报告(项目级、可对账)

目标:给出**加得起来**的文件夹级/项目级占用报告,而不是一堆看起来远小于实际用量的数字。用户抱怨通常来自两处:容器级目录(如 AppData)整块未展开、以及单位混淆(GB vs GiB / 逻辑 vs 实占)。

## 粒度约定(先说清)
- 一个目录 = 一个项目,只报该目录总量,不向内展开;代码库群(如 `source\repos`)逐仓库一条。
- 报告必须能对账:C: 各顶层目录 + 根文件(pagefile/hiberfil/swapfile)相加 ≈ `(Size-FreeSpace)`。

## 工具(每次现写,放 %TEMP%)

`dusize.ps1`(**ASCII only**,中文正则会被 GBK 解码搞坏):
```powershell
param([string[]]$Paths)
$rows = foreach ($p in $Paths) {
  if (-not (Test-Path -LiteralPath $p)) { [pscustomobject]@{GB=$null; Path=$p; Note='MISSING'}; continue }
  $out = robocopy $p 'C:\__nul_dummy' /L /S /XJ /NJH /NC /NFL /NDL /BYTES /R:0 /W:0 /NP
  $bytes=$null; $fails=0
  foreach ($l in $out) {
    if ($l -match '^[^:]*:\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)') { $bytes=[int64]$Matches[1]; $fails=[int]$Matches[5] }
  }
  [pscustomobject]@{GB=[math]::Round($bytes/1GB,2); Path=$p; Note=$(if($fails -gt 0){"Fails=$fails"}else{''})}
}
$rows | Sort-Object GB -Descending | Format-Table -AutoSize | Out-String -Width 220
```
要点:6 组数字、取**最后**一条匹配(字节行在目录/文件行之后);写 `[^:]*:` 而不是中文字面量。

包装脚本(多路径必须硬编码进 .ps1 —— bash 会把逗号列表当一个参数):
```powershell
& "$env:TEMP\dusize.ps1" -Paths (Get-ChildItem 'C:\' -Directory -Force | ? { -not $_.LinkType } | % { $_.FullName })
```

会话注意:长扫描一律 `async: true` + `timeout: 0`(默认 300s 会砍掉);并发跑多个 robocopy 大扫描会互相拖慢,出结果后串行下一个。

## 计量口径
- **只报 GiB**(PowerShell `1GB` = 2^30);`Win32_LogicalDisk` 的 Size/FreeSpace ÷1GB 就是 GiB,别再乘 1.0737。
- 排除别名:`C:\Users\All Users`(→ProgramData 的 symlink)、`C:\Users\Default User`(junction)、用户配置目录里的 `Application Data`/`Local Settings`/`My Documents` 等 junction(robocopy /XJ 本来会跳,但逐目录循环时要靠 `-not $_.LinkType` 过滤)。
- robocopy 汇总比 NTFS 实占高 ~1%,原因=硬链接(WinSxS↔System32)+簇余量;要在报告里写明残差,别让用户再问一遍。
- 虚拟盘:列出所有 `*.vhdx`;`Attributes` 无 `SparseFile` 时逻辑长度≈真实占用。需要精确 on-disk 用 P/Invoke `kernel32!GetCompressedFileSizeW`(逐文件,慢,只对目标树跑)。
- 大 ETL/日志类文件要单独判定**是否仍在写入**(mtime 是否在变)和是否稀疏(`fsutil sparse queryflag`),否则会把活跃采集误当成可删垃圾。

## 扫描清单(缺一不可)
1. `C:\` 顶层目录 + 根文件(pagefile/hiberfil/swapfile/杂项 .tmp)
2. 用户配置目录一级
3. `AppData\{Local,Roaming,LocalLow}` 再展开**一层**(Local 是黑洞所在)
4. 代码库群逐仓库
5. WSL:`wsl -d <distro> -- bash /mnt/c/.../scan.sh`(脚本文件避免转义),`df -h /`、`du -x -h -d1 /home/<user>`、`du -x -sh /usr /var /opt`
6. 虚拟盘 + Docker(`docker system df`、`docker ps -a --size`、`docker volume ls`)
7. 系统树实占对照(`C:\Windows`、`Program Files*`、`ProgramData` 的 logical vs on-disk)

## 常见黑洞(本机实测,2026-09/10)
- `%TEMP%` 里的 WPR ETL(见 wpr-etl-orphan-cleanup 技能),单次 135 GB 级
- WSL/Docker 的 `ext4.vhdx`/`docker_data.vhdx`:删了文件不会还盘,要 `wsl --shutdown` 后 `Optimize-VHD -Mode Full`(管理员)
- pagefile 自动托管会涨到 RAM 以上;`hiberfil.sys` 关休眠即消失
- vcpkg `buildtrees`+`downloads`、`.vs`、`.next`、`target/`、`node_modules`、`.cache/huggingface`、`.bun/install`、`.android/avd`、各 `*-cache`

报告收尾:临时脚本从 %TEMP% 删掉,并把「可回收」按“不动个人数据 / 需用户拍板”分两栏,给出可执行的单行命令。
