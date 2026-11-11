---
name: vpn-host-accepts-then-silent-triage
description: "Diagnose host reachable only from its own LAN (TCP handshake succeeds over VPN/site-to-site but zero payload, no RST) and fix with SNAT on the OpenWrt/Kwrt gateway, incl. fw4_compatible requirement."
---

# 症状

经 VPN（n2n / WireGuard / 类似 10.0.0.0/24 overlay）访问某 LAN 主机：
- ping 通，`tracert` 正常（一跳网关 + 一跳目标）
- **TCP 握手成功**（`Test-NetConnection` True、`curl` 显示 `Established`），随后 **零字节**、无 RST、无 FIN
- 同一 VPN 下其它主机 HTTP 正常 → 排除隧道、NAT 路径、PMTU

→ 结论：目标设备实现“只服务本网段源”的 ACL——SYN 进得去，数据/应答被应用层丢弃，连接挂着不关。

# 判定步骤

1. 对照测试同网段健康主机：`curl -m 6 http://<gw>/`、`http://<other>/` 应为 200/302。
2. 端口扫描多端口（21/22/80/443）：**所有服务同样静默** = 主机级策略，不是单个应用。
3. 探测“数据是否到达对端”：连上后狂写数据
   ```powershell
   $t=New-Object Net.Sockets.TcpClient; $t.Connect('IP',80); $s=$t.GetStream(); $s.WriteTimeout=4000
   $b=New-Object byte[] 65536; $n=0; $sw=[Diagnostics.Stopwatch]::StartNew()
   while($n -lt 1000000){ $s.Write($b,0,$b.Length); $n+=65536; if($sw.ElapsedMilliseconds -gt 6000){break} }
   ```
   在 ~64KB（对端接收窗口）后阻塞 = 包到了对端内核、应用从不 read → 主机级 ACL/挂死，与路由无关。
4. 对照“不存在的 IP”（如 .111）: 若 TCP 被拒（`connected=False`）说明中间没有 SYN 代理，握手是真的目标回的。
5. MTU 排除：`ping -f -l 1250 / 1300` 对两个主机表现一致即可排除 PMTU 黑洞（本例 n2n0 MTU 1290 → PMTU ≈1278）。

# 修复（OpenWrt / Kwrt / fw4）

前提：目标只认 LAN 源 → 在网关对 overlay→LAN 做 **SNAT**，让目标看到网关 LAN 地址。

1. `n2n` zone 的 `option masq '1'` **不够**：它生成 `oifname "n2n0" masquerade`，只作用于出 overlay 方向。
2. 在 `/etc/firewall.user` 写幂等片段（**不要带 `comment "带 空格"`，nft CLI 会拆参数报 syntax error**）：
   ```sh
   nft list chain inet fw4 srcnat 2>/dev/null | grep -qF 'oifname "br-lan" masquerade' || \
       nft insert rule inet fw4 srcnat ip saddr 10.0.0.0/24 oifname "br-lan" masquerade
   ```
3. **关键**：fw4 默认忽略该 include，必须打兼容标志，否则静默失效（日志 `Section @include[N] is not marked as compatible with fw4, ignoring section`）：
   ```sh
   uci set firewall.@include[N].fw4_compatible='1'   # N 用 uci show firewall | grep firewall.user 查
   uci commit firewall
   ```
4. `/etc/init.d/firewall reload` 后确认规则仍在（证明可持久化）：
   `nft list chain inet fw4 srcnat` 首行应为 `ip saddr 10.0.0.0/24 oifname "br-lan" masquerade`；但注意 `srcnat` 里顺序：手工插入的规则在 `oifname "n2n0" jump` 之前。

# 验证

- 从 VPN 端 `curl` 目标 → 由超时变 200/302。
- 网关上 conntrack 证明 SNAT：`cat /proc/net/nf_conntrack | grep <target>` 应见 `reply src=<target> dst=<gw LAN IP>`，而非 dst=10.0.0.x。
- 回归：原正常主机（网关自身、其它 LAN 设备）仍 200/302。

# 陷阱

- Windows 无管理员时不能跑 `pktmon`，拿不到 SYN-ACK TTL；改用“写满窗口阻塞”判断数据面。
- `whoami` 在 Git Bash 下不是 Windows 版本，`net session` 判管理员更可靠。
- PowerShell 里 `$` 会被 bash 吃掉：探测脚本写成 `.ps1` 后用 `powershell -File`（路径需 Windows 形式）。
- `Socket.Poll` 不要用 6 参数重载（不存在），用它观察 RST/FIN 会刷屏。
