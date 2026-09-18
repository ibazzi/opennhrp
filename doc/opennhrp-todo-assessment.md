# OpenNHRP TODO 梳理、优先度及可行性评估报告
## 一、 背景与分析概述

本文档对 OpenNHRP 源码仓库根目录下的 [TODO](../TODO) 文件进行了全面审计，并结合当前代码库实现（包括网络协议栈、内核接口交互、事件循环及近期新增的 HA 模块）进行了逐项评估。

### 1. 梳理统计概况
原始 `TODO` 文件共记录 26 行事项，经代码交叉比对后归纳如下：
- **有效独立事项**：25 项。
- **完全重复项**：原第 6 行与第 60 行内容完全一致（*检测 map 指令中 NBMA 与公网 IP 颠倒*）。
- **已实现/部分实现项**：原第 63 行的 `支持配置重载 (SIGHUP 或 opennhrpctl reload)` 已在 `opennhrp.c` 及 `admin.c` 中实现。
- **架构局限项**：IPv6 支持受限于全局协议地址结构硬编码为 6 字节（`NHRP_MAX_ADDRESS_LEN 6`），涉及底层重构成本极高。

---

## 二、 分类评估与技术分析矩阵

### 1. 协议规范与核心逻辑 (Protocol Compliance & Core RFC Logic)

| 事项说明 | 代码现状与技术分析 | 优先度 | 可行性 / 复杂度 | 建议实施路径 |
| :--- | :--- | :---: | :---: | :--- |
| **正确处理 Unique Bit**<br>`Proper handling of unique bit` | RFC 2332 规定：当客户端携带 Unique 标志注册时，若 NHS 本地已存在该 IP 但 NBMA 地址不同，必须拒绝并报错。当前代码在 `nhrp_server.c` 中直接覆盖已有动态表项，存在 IP 冲突与仿冒安全隐患。 | **高** | **高**<br>(低难度) | 在 `nhrp_server_start_cie_reg` 中补充对比已有表项的 NBMA 地址，若设置 Unique 且 NBMA 不符，返回 `ADMINISTRATIVELY_PROHIBITED`。 |
| **优雅停机发送 Purge Request**<br>`Clean shutdown: send purge request` | 当前在 `opennhrp.c` 捕获到 `SIGINT`/`SIGTERM` 时直接退出事件循环并释放资源，不通知远端。NHS 和对端客户端必须等待 Holding Time 超时（数十分钟至数小时）才感知下线。 | **高** | **高**<br>(中难度) | 在进程退出清理前，遍历 peer 表向所有注册的 NHS 及活跃对端发送 Purge Request，设置短暂的等待/flush 超时后安全退出。 |
| **NHS 本地直答解析请求**<br>`NHS reply itself based on registered leases` | 当 NHS 收到针对其已注册 NHC 的解析请求时，目前仍倾向于将请求下发给下游 NHC。由 NHS 作为权威服务器直接根据本地注册的 Lease 回复，能显著缩短 Spoke-to-Spoke 协商时延。 | **高** | **高**<br>(中难度) | 优化 `nhrp_server.c` 中 `nhrp_handle_resolution_request` 分支，当目标属于本地有效动态注册表项时直接构建并返回 Resolution Reply。 |
| **消除 REPLACED 标志，重构状态机为 Renew 模型**<br>`get rid of replaced flag; convert state machine to renew` | 当前更新 peer 时通过创建新 entry 并将老 entry 打上 `NHRP_PEER_FLAG_REPLACED` 屏蔽脚本回调，导致生命周期混乱、容易在 IP/NBMA 频繁变更时引入竞态。 | **中** | **中**<br>(中难度) | 梳理状态机模型，改为原结构体原地 Refresh/Renew，清晰规范 route-up/down 脚本的触发条件。 |
| **直连不可达时回退到 Forward NHS 中继**<br>`closest known NHS from ResolutionReply Forward NHS list` | Spoke 间若存在对称 NAT 或防火墙阻断导致直连失败时，从 Forward Transit NHS 列表中选取最近的已知中继节点维持数据转发。 | **中** | **中**<br>(中偏高难度) | 结合现有 `NHRP_EXTENSION_FORWARD_TRANSIT_NHS` 扩展数据，在连接探测失败或超时时回退下一跳。 |
| **Core 节点链路未建全时避免 Negative 缓存**<br>`core links not up, avoid negative cache` | 多 Hub/Core 互联场景下，启动初期其他 Core 链路尚未就绪，过早生成的 Negative 缓存会导致后续恢复延迟。 | **中** | **高**<br>(低难度) | 判定当前 active core links 数量，为 0 时缩短或跳过 negative 缓存。 |
| **主网段 (/16) 与细分子网 (/24) 捷径冲突**<br>`shortcut-target /16 with subnet /24 delegation` | 已经存在主捷径网段时，细分子网委托的 Traffic Indication 会因大网段匹配而被忽略，无法建立更优的细分子网捷径。 | **中** | **中**<br>(中难度) | 引入最长前缀匹配（LPM）优先机制，允许细分前缀覆盖宽泛的前缀路由捷径。 |
| **BGP NextHop 变更时主动 Purge 捷径**<br>`send purge on bgp nexthop change` | 承载网络 BGP 下一跳发生变化时，旧的 NHRP 捷径已经失效，需主动清理并通知对端。 | **中** | **中**<br>(中难度) | 监听 Netlink 路由事件或 Quagga/Zebra 事件，捕获到下一跳变更时注销对应 NHRP 缓存。 |

---

### 2. 配置、运维与管理面 (Configuration & Administration)

| 事项说明 | 代码现状与技术分析 | 优先度 | 可行性 / 复杂度 | 建议实施路径 |
| :--- | :--- | :---: | :---: | :--- |
| **检测 map 指令中 NBMA 与协议 IP 颠倒**<br>*(原第 6、60 行重复)* | 用户配置 `map <proto-ip> <nbma-ip>` 时常将内网隧道 IP 与公网 IP 颠倒，目前解析逻辑无任何告警，排查排错难度高。 | **高** | **极高**<br>(极低难度) | 在 `opennhrp.c` 的 `map` 解析处增加校验：结合接口已配置的子网掩码或公私网段启发式规则，发现倒置时输出显著 Warning。 |
| **配置重载支持 (SIGHUP / opennhrpctl reload)**<br>*(原第 63 行)* | **代码已实现**：`opennhrp.c` 中已绑定 `SIGHUP -> nhrp_reload_config()`，`admin.c` 亦注册了 `reload` 与 `config reload`。 | **已完成** | - | 从 TODO 中移除，并补充相应回归测试脚本。 |
| **Admin 端口非阻塞写入与可断点枚举**<br>`non-blocking admin port writes` | 当前 `admin_raw_write` 采用阻塞同步写，失败直接忽略。在面对海量 peer 导出（dump）时极易阻塞主事件循环或因缓冲区满导致丢字。 | **中** | **中**<br>(中难度) | 将管理 socket 设置为非阻塞模式，建立环形/链表发送队列，peer 导出改为基于游标（cursor）的迭代分批发送。 |
| **非 root 降权运行 (libcap-ng)**<br>`opennhrp to drop capabilities, libcap-ng` | 安全合规加固需求。OpenNHRP 启动建立完 Raw/Netlink Socket 后，可丢弃除 `CAP_NET_ADMIN` 和 `CAP_NET_RAW` 以外的特权并切换非 root 运行。 | **低** | **高**<br>(低难度) | 引入 `libcap-ng` 依赖，在网络与接口初始化完成后调用降权接口。 |

---

### 3. 性能优化与数据面扩展 (Performance & Datapath)

| 事项说明 | 代码现状与技术分析 | 优先度 | 可行性 / 复杂度 | 建议实施路径 |
| :--- | :--- | :---: | :---: | :--- |
| **基于协议地址的 Hash 查找与路由缓存**<br>`hash lookup for peers based on protocol address` | 当前 NBMA 已使用 Hash 表，但协议地址查找依赖 `peer_list` 线性单链表扫描（$O(N)$）。在千级 Spoke 的大型 Hub 场景下 CPU 消耗巨大。 | **高** | **高**<br>(中难度) | 为协议地址引入 `proto_hash_entry`（哈希桶），使精确匹配降为 $O(1)$，对未决路由建立专用查找缓存。 |
| **组播转发卸载至内核**<br>`offload multicast packet forwarding to kernel` | 目前在用户态通过 `sysdep_pfpacket.c` 截获并逐个复制组播包，转发延迟高、性能瓶颈明显，且易发生丢包。 | **中** | **低**<br>(高难度) | 严重依赖 Linux 内核 GRE 实现；目前原生内核支持有限，通常需要修改内核 ip_gre 模块或借助 eBPF/XDP。 |
| **PF_PACKET 使用 PACKET_MMAP**<br>`use mmapped pf_packet interface` | 目前使用常规 `recvmsg`/`sendmsg`。使用 PACKET_RX_RING/TX_RING 环形共享内存可规避系统调用与用户-内核拷贝开销。 | **低** | **中**<br>(中难度) | 仅在流量重定向/组播包量非常大时有收益，控制面为主的场景收益有限。 |
| **IGMP Snooping 与组播中继优化**<br>`IGMP snooping and multicast relaying` | 在 Hub 端避免将组播流向未加入组播组的 Spoke 泛洪，节省 WAN 宽带。 | **低** | **中**<br>(偏高难度) | 维护 IGMP 加入/离开状态机，仅向加入特定组的 Spoke 复制多播报文。 |

---

### 4. 架构重构与代码清理 (Architecture & Refactoring)

| 事项说明 | 代码现状与技术分析 | 优先度 | 可行性 / 复杂度 | 建议实施路径 |
| :--- | :--- | :---: | :---: | :--- |
| **拆分臃肿的 `nhrp_peer.c`**<br>`nhrp_peer should be split to more files` | `nhrp_peer.c` 超过 2500 行，耦合了内存分配、哈希索引、定时器、状态机、路由查找及外部脚本执行。 | **中** | **高**<br>(低风险) | 拆分为子模块：`nhrp_peer_cache.c`（查找与哈希）、`nhrp_peer_fsm.c`（状态机与定时器）、`nhrp_peer_script.c`（外部调用）。 |
| **清理内部 `nhrp_packet_send_*` API**<br>`clean up internal nhrp_packet_send_* API` | 发送相关函数（`nhrp_packet_send`, `nhrp_packet_send_request`, `nhrp_packet_send_request_timed` 等）参数冗余，边界模糊。 | **低** | **高**<br>(低难度) | 统一报文路由判定与发送流水线，精简重叠接口。 |

---

### 5. 外部集成与高级网络特性 (External Ecosystem)

| 事项说明 | 代码现状与技术分析 | 优先度 | 可行性 / 复杂度 | 建议实施路径 |
| :--- | :--- | :---: | :---: | :--- |
| **脚本执行序列化 (面向 Quagga/FRR)**<br>`interface-up, nhs-up, nhs-down serialized` | 接口和邻居上下线脚本并发执行时，可能引起 Quagga vtysh 命令锁冲突或状态错乱。 | **中** | **高**<br>(中难度) | 在 OpenNHRP 内部维护 FIFO 脚本执行队列，保证事件按发生顺序串行执行。 |
| **脚本根据 RTT 设置 BGP 权重**<br>`opennhrp-script: setup bgp weight based on RTT` | 多 Hub 冗余场景下，Spoke 动态测量与各 Hub 的往返时延并调整 BGP 选路权重。 | **低** | **高**<br>(极低难度) | 纯外部脚本逻辑（`etc/opennhrp-script`），测量 RTT 并调用 `vtysh` 修改 route-map/local-pref，无需修改守护进程。 |
| **多 CIE 负载均衡与 ECMP 支持**<br>`Load balancing: return multiple CIE entries` | 解析应答携带多个下一跳 CIE，并在内核中创建多路径（Multipath/ECMP）路由。 | **低** | **中**<br>(较高难度) | 需调整 CIE 编解码解析、Netlink 路由多路径注入机制。 |
| **用内核路由查找替代本地路由表追踪**<br>`per-packet kernel lookup for off-nbma destinations` | 尝试简化对捷径路由的状态追踪。 | **低** | **中**<br>(中难度) | 收益不明显，且容易引入非预期的路由黑洞。 |
| **通过 Zserv 协议直连 Quagga**<br>`talk zserv to quagga for shortcut routes` | 绕过 shell 脚本，直接通过 Unix 域套接字与 Zebra 守护进程通信注入捷径路由。 | **低** | **低**<br>(高难度) | 现代方案普遍采用 FRR 内置的 `nhrpd`，在 OpenNHRP 中单独引入一套 Zebra 协议栈性价比过低。 |
| **IPv6 全面支持**<br>`IPv6-over-IPv4, IPv[46]-over-IPv6` | 当前 `nhrp_address.h` 中硬编码最大地址长度为 6 字节（仅适配 IPv4 4 字节及 MAC 6 字节）。支持 16 字节 IPv6 意味着全工程涉及数据结构、编解码、Netlink、PF_PACKET 几乎全部重写。 | **极低** | **极低**<br>(极高难度) | 历史包袱过重。若生产环境需要 IPv6 DMVPN，推荐直接选型 FRRouting (FRR) 原生 nhrpd。 |

---

## 三、 实施路线图建议 (Roadmap)

建议分三个阶段稳步推进改造：

### 阶段一：Quick Wins（高性价比、协议修复与安全稳定，1~2 周）
1. **规范 Unique Bit 校验**：杜绝动态注册中的非授权覆写与 IP 抢占漏洞。
2. **map 指令 IP 倒置检测**：启动与重载时对私网/公网 IP 倒置进行启发式 Warning 告警。
3. **优雅停机（Clean Shutdown）**：在接收到退出信号时向注册服务器与客户端广播 Purge Request，加速网络收敛。
4. **清理 TODO 与补充测试**：删除已实现的 SIGHUP/reload 描述与重复条目，补充相关配置重载的回归测试。

### 阶段二：Core Scaling & Architecture（核心扩展与架构治理，2~4 周）
1. **协议地址 Hash 查找**：解决单链表遍历在大规模 Spoke 拓扑下的 CPU 性能瓶颈。
2. **NHS 本地直接应答**：跳过下游 NHC 转发环节，降低 Spoke-to-Spoke 协商延迟。
3. **消除 REPLACED 标志**：重构 peer 状态机生命周期为 Renew 机制。
4. **Admin 端口非阻塞写入与游标遍历**：防止大规模 peer 查询导致守护进程挂起或丢字。
5. **脚本执行队列化**：消除与 Quagga/FRR vtysh 并发调用的时序冲突。

### 阶段三：Backlog / 评估搁置（高成本/低收益/已有成熟替代）
- **IPv6 全面重构**：建议引导用户使用 FRR nhrpd，不再建议在 opennhrp 代码中大修。
- **内核组播转发卸载 / 内置 Zserv 客户端**：技术耦合度过高且外部依赖复杂，暂不建议列入近期排期。
- **IGMP Snooping**：视后续是否有纯组播业务专网需求再行排期。
