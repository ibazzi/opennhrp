# OpenNHRP TODO 与当前代码对齐评估

核对日期：2026-09-21。管理接口改进已实现；Unique Bit 完整处理已撤回。

本文保留功能事项的逐项源码评估。项目总体情况见 [项目现状](../README.md)。第 9 项已实现；其他事项仍为源码评估，第 2 项通用停机 Purge 未实现。

## 统计与代码布局

TODO 共 **26 个条目**（按 `- ` 开头计数，不是 26 行），其中 map 地址倒置检测重复一次，因此有 **25 个独立事项**。下表保留 IPv6-over-IPv4 与 IPv[46]-over-IPv6 两项，分别对应协议地址与 NBMA 地址族支持。

当前代码分布：

- [nhrp/core](../nhrp/core)：地址、接口、peer、报文、服务端协议，以及重启用的 peer 快照。
- [nhrp/ha](../nhrp/ha)：Spoke 候选探测与选择、Hub owner/副本管理、managed HA 等。
- [nhrp/platform](../nhrp/platform)：Netlink、PF_PACKET、事件循环与日志。
- [nhrp/opennhrp.c](../nhrp/opennhrp.c)、[nhrp/admin.c](../nhrp/admin.c)：启动、配置及管理接口。

优先级含义：**高**为明确的协议正确性或管理响应完整性问题；**中**为需要场景复现或行为设计的改进；**低/按需**为缺少实际需求或性能证据的扩展。复杂度为源码评估，不是工期承诺。

## 逐项评估

各分类内部按 **高 → 中 → 维护项 → 低 → 按需** 排序；按规模、按流量归入按需事项，同级保持原有顺序。

### 协议与 peer 生命周期

| # | TODO 事项 | 当前代码证据与结论 | 优先级 / 后续路径 |
| --- | --- | --- | --- |
| 1 | 正确处理唯一性标志位（Unique Bit） | **未实现。** Hub 不再因同一协议地址的 NBMA/NAT-OA 变化返回 Code 14，新的动态注册按既有替换路径更新绑定。 | **待重新设计。** 后续实现必须把稳定 Spoke 身份与可变化的 NBMA/NAT-OA 分开，不能再次把地址变化误判为抢注。 |
| 2 | 优雅停机时发送清除请求（Purge Request） | **通用停机 Purge 未实现；已有重启恢复路径。** [opennhrp.c](../nhrp/opennhrp.c) 退出事件循环后停止 HA 子进程、保存 peer 快照并清理资源；[nhrp_peer_cache.c](../nhrp/core/nhrp_peer_cache.c) 保存可恢复的普通 dynamic/cached/shortcut-route，排除 HA dynamic 状态。已有注册相关 Purge 不等于停机遍历通知。 | **中 / 中复杂度。** 先确定永久退出与平滑重启的通知语义，避免无条件 Purge 抵消快照恢复。远端失效时间依赖 holding time、探测及 HA 状态，不能统一断言需要等待数十分钟至数小时。 |
| 3 | NHS 根据已注册租约直接回复解析请求 | **未实现通用动态 lease 直答。** [nhrp_packet.c](../nhrp/core/nhrp_packet.c) 接收分发仅在目标匹配 `LOCAL_ADDR` 时进入本地处理，其他 Resolution Request 走转发；[nhrp_server.c](../nhrp/core/nhrp_server.c) 的本地回复使用本机 NBMA，并非直接返回目标动态 lease。 | **中 / 中复杂度。** 需要同时调整接收分发与回复构造，检查 lease 有效性、NAT、HA 有效 owner 和协议允许的应答条件，不能只改 handler。 |
| 4 | 移除 REPLACED 标志，改用续租状态机并完善 MTU 回调 | **仍未完成。** [nhrp_peer.h](../nhrp/core/nhrp_peer.h) 保留 `NHRP_PEER_FLAG_REPLACED`，server 替换注册及 peer 释放仍依赖它抑制下线脚本。已有部分原地更新不能代表整个生命周期改为 renew。 | **中 / 高复杂度。** 先覆盖 NBMA/MTU 更新、脚本次数、内核邻居及 HA 投影生命周期，再决定局部简化范围。 |
| 5 | 核心节点链路未就绪时避免生成负缓存 | **未见通用 Core 就绪判断。** [nhrp_peer.c](../nhrp/core/nhrp_peer.c) 的解析失败路径区分错误回复和超时：前者可能转 negative，后者删除 incomplete；连接失败也有 negative 路径。 | **中 / 中复杂度。** 先确定实际产生 negative 的路径与 Core 拓扑定义，不能直接把“active core 数为零”作为已有可用条件。 |
| 6 | 处理 /16 捷径目标与 /24 子网委托的冲突 | **需要场景复现。** [nhrp_peer.c](../nhrp/core/nhrp_peer.c) 的 `decide_route()` 已在同等 exact/up 条件下选择更长前缀，因此不能归因为“缺少 LPM”。TODO 描述的是细分捷径被发现或创建前就被已有大网段遮蔽。 | **中 / 待复现。** 检查 Traffic Indication、已有路由命中及 Resolution Reply 前缀安装链，添加 /16→/24 的最小拓扑验证后再定位。 |
| 7 | BGP 下一跳变化时发送清除请求 | **已有路由事件监听，缺少明确的远端通知闭环。** [sysdep_netlink.c](../nhrp/platform/sysdep_netlink.c) 已处理 `RTM_NEWROUTE/RTM_DELROUTE` 并更新本地 peer；不能把“开始监听 Netlink”当作新增实现。尚未见下一跳变化与曾解析客户端的定向 Purge 关联。 | **中 / 中高复杂度。** 复用现有事件，核对本地失效和远端持有捷径分别如何收敛，再决定是否追踪请求者。 |
| 8 | 直连失败时通过前向 NHS 列表选择中继 | **未见按该列表选择中继的完整路径。** [nhrp_peer.c](../nhrp/core/nhrp_peer.c) 创建 Forward Transit NHS 扩展，但 `nhrp_peer_handle_resolution_reply()` 主要消费首个 CIE 与 NAT 扩展，没有建立列表驱动的直连失败回退。 | **按需 / 中高复杂度。** 先复现直连失败并确认中继的数据面可达性、循环防护和恢复条件；Spoke 的 HA Hub 选择不能替代这一功能。 |

### 配置与管理接口

| # | TODO 事项 | 当前代码证据与结论 | 优先级 / 后续路径 |
| --- | --- | --- | --- |
| 9 | 管理接口非阻塞写入与可恢复枚举 | **已实现。** [admin.c](../nhrp/admin.c) 统一缓冲普通回复、HA monitor 和异步回复，使用 EV_WRITE 处理短写/EAGAIN；普通回复排空后关闭。每连接最多缓冲 256 KiB，枚举在 128 KiB 高水位暂停，每轮检查至多 128 个 peer，单轮发送预算 64 KiB。游标在 peer 删除前推进，分段命令按偏移追加。 | **高 / 已实现。** 实时枚举不保证事务快照或输出顺序，新插入项留给下次查询。无 I/O 进展 10 秒断开，异步业务等待保留业务超时；monitor 超限断开。固定格式化缓冲限制写入长度。 |
| 10 | 支持配置重载（SIGHUP / opennhrpctl reload） | **已实现。** [opennhrp.c](../nhrp/opennhrp.c) 的信号处理调用 `nhrp_reload_config()`；[admin.c](../nhrp/admin.c) 提供 `reload`、`config reload`。重载包含静态 peer 标记清扫及 HA 配置处理。 | **维护项。** [run-managed.sh](../tests/netns/run-managed.sh) 已有 reload、配置保存和地址协调场景。仍需区分普通 reload 与 `ha managed reload`；代码存在不代表所有配置变更均具备事务回滚保证。 |
| 11 | 检测 map 配置中 NBMA 地址与协议地址颠倒 | **未实现语义倒置检测。** [opennhrp.c](../nhrp/opennhrp.c) 的 `map` 分支进行地址解析，NBMA 可为主机名；[admin.c](../nhrp/admin.c) 也有 `map add` 入口。非本机目标 Registration 的日志提示不是配置倒置检测。 | **低 / 中复杂度。** 仅在接口和路由证据明确时告警；公网/私网属性不能可靠推断配置正误，NBMA 也可合法使用私网。若实现，应覆盖配置加载、reload 与管理入口。 |
| 12 | 降低进程权限并以非 root 用户运行 | **未实现完整降权。** 启动、Raw/Netlink socket、外部脚本及 HA 子进程均涉及权限；[opennhrp-script](../etc/opennhrp-script) 执行路由/邻居变更。 | **按需 / 中高复杂度。** 先列出初始化后持续需要的操作与子进程权限，不能只在启动后调用一次降权函数。是否使用 libcap-ng 取决于最终部署方案。 |

### 查找与数据面

| # | TODO 事项 | 当前代码证据与结论 | 优先级 / 后续路径 |
| --- | --- | --- | --- |
| 13 | 为 PF_PACKET 接口使用内存映射 | **未实现。** [sysdep_pfpacket.c](../nhrp/platform/sysdep_pfpacket.c) 使用 `recvmsg()/sendmsg()`，没有 PACKET_RX_RING/TX_RING 配置。 | **低 / 中复杂度。** 只有采样证实系统调用或拷贝占主要成本时再做 PACKET_MMAP，并验证延迟、队列与错误处理。 |
| 14 | 按协议地址进行哈希查找，并缓存未完成条目的路由查询 | **未实现通用协议地址 hash。** [nhrp_peer.c](../nhrp/core/nhrp_peer.c) 维护 NBMA hash，协议地址选择通过接口 peer 链表枚举；链表是带前后链接的 `list_head`，不是单链表。新 peer-cache 文件用于磁盘快照，不是查找缓存。 | **按规模 / 中复杂度。** 先测查询量和枚举耗时；需要优化时优先为精确查找建索引，保留前缀、类型、接口及 HA 可用性筛选。没有测量依据不能断言千级 Spoke 已有严重 CPU 瓶颈。 |
| 15 | 将组播转发卸载到内核 | **未实现。** [sysdep_pfpacket.c](../nhrp/platform/sysdep_pfpacket.c) 的 `send_multicast()` 在用户态遍历接口 multicast peer 并逐个 `sendmsg()`，接收队列固定 16 项，满时丢弃最旧项。 | **按流量 / 高复杂度。** 先测复制成本和丢包，再评估部署内核支持；不预设必须修改 ip_gre 或引入 eBPF。 |
| 16 | IGMP 侦听与组播中继优化 | **未实现按组成员维护的转发。** [sysdep_pfpacket.c](../nhrp/platform/sysdep_pfpacket.c) 按接口 multicast peer 列表复制，没有 IGMP 加入/离开成员表。 | **按需 / 高复杂度。** 先明确业务组播需求及成员老化、查询器和 WAN 中继行为。 |

### 结构与外部集成

| # | TODO 事项 | 当前代码证据与结论 | 优先级 / 后续路径 |
| --- | --- | --- | --- |
| 17 | 将 nhrp_peer 拆分为多个源文件 | **源码目录已分层，peer 核心仍集中。** [nhrp_peer.c](../nhrp/core/nhrp_peer.c) 当前约 2300 行；独立的 [nhrp_peer_cache.c](../nhrp/core/nhrp_peer_cache.c) 负责重启快照，查找、状态机与脚本执行仍在 peer 文件中。 | **低 / 中复杂度。** 文件行数本身不是拆分理由；随实际修改按清晰边界提取，避免预建 cache/fsm/script 三层。 |
| 18 | 清理内部 nhrp_packet_send_* 接口 | **保留多个有不同职责的入口。** [nhrp_packet.c](../nhrp/core/nhrp_packet.c) 包含普通发送、请求回调及定时重传等路径；存在多个函数不能证明冗余。 | **低 / 待具体问题。** 先核对调用者、packet 引用生命周期和重试语义，只合并明确重复部分。 |
| 19 | 根据往返时延（RTT）设置 BGP 权重 | **脚本功能未实现；已有 HA 质量选择。** [opennhrp-script](../etc/opennhrp-script) 没有 RTT→BGP 配置逻辑；[nhrp_ha.c](../nhrp/ha/nhrp_ha.c) 已按候选质量进行 Spoke Hub 选择，并支持持久化手动选择。这与 BGP 权重不是同一机制。 | **低 / 按集成评估。** 仅要求 Spoke 选 Hub 时复用 HA；明确需要 BGP 策略联动时再约定指标、迟滞和更新方式，不能认定只是极低难度脚本。 |
| 20 | 以逐包内核路由查询替代本地路由跟踪 | **已有内核查询接口，尚未替代本地路由跟踪。** [sysdep_netlink.c](../nhrp/platform/sysdep_netlink.c) 的 `kernel_route()` 使用 `RTM_GETROUTE`，同时仍通过路由事件维护 local peer。 | **低 / 中复杂度。** 先明确 off-NBMA 查询点和同步查询成本，再评估是否替换；无需新建一套 Netlink 查询基础设施。 |
| 21 | 串行执行 interface-up、nhs-up 和 nhs-down 脚本 | **未实现跨 peer 全局串行化。** [nhrp_peer.c](../nhrp/core/nhrp_peer.c) 的 `nhrp_peer_run_script()` 使用 fork/exec 与每 peer 异步事件；没有覆盖所有相关事件的全局 FIFO。 | **按需 / 中复杂度。** 若冲突仅发生于外部 vtysh，可先在用户脚本层锁定对应操作；只有要求 daemon 内部事件顺序时再增加队列，并评估慢脚本阻塞后续事件。 |
| 22 | 支持多 CIE、负载均衡与等价多路径（ECMP） | **编解码支持 CIE 列表，解析后的多路径行为未实现。** [nhrp_peer.c](../nhrp/core/nhrp_peer.c) 处理 Resolution Reply 时选择首个 CIE；默认 route-up 脚本安装单下一跳。 | **按需 / 高复杂度。** 需要多路径状态、失效处理及路由安装配套；不能只改 CIE 编解码，也不能把 HA 候选列表当作 ECMP。 |
| 23 | 通过 Zserv 协议与 Quagga 通信 | **未实现。** 当前路由安装通过 [opennhrp-script](../etc/opennhrp-script) 和用户脚本，没有内置 Zserv 客户端。 | **按需 / 高复杂度。** 仅在确定目标路由守护进程及协议版本后评估，避免无需求维护第二套控制接口。 |
| 24 | 支持在 IPv4 承载网络上传输 IPv6 | **未支持完整 IPv6 协议地址路径。** [nhrp_address.h](../nhrp/core/nhrp_address.h) 的 `NHRP_MAX_ADDRESS_LEN` 为 6；[sysdep_netlink.c](../nhrp/platform/sysdep_netlink.c) 的路由处理限制 `PF_INET`，快照协议前缀解析限制为 32。 | **按需 / 高复杂度。** 单独规划 IPv6 overlay：地址长度、编码、前缀、Netlink、HA、快照及脚本测试。并非只改一个常量，也没有证据表明必须几乎重写整个工程。 |
| 25 | 支持在 IPv6 承载网络上传输 IPv4 和 IPv6 | **未支持完整 IPv6 NBMA 路径。** 同样受最大地址长度约束，另需检查 [nhrp_address.c](../nhrp/core/nhrp_address.c)、[sysdep_pfpacket.c](../nhrp/platform/sysdep_pfpacket.c)、隧道发现和 HA 端点处理的地址族假设。 | **按需 / 高复杂度。** 与上一项分阶段评估；当前代码评估不构成任何外部产品支持 IPv6 DMVPN 的选型保证。 |

## 建议执行顺序与验证边界

1. **维护已实现项**：保留 HA 副本回归，以及 admin 短写、慢读、可恢复枚举与生命周期检查。
2. **先复现再调整行为**：/16 与 /24 委托、Core 启动 negative cache、BGP 下一跳变更、NHS lease 直答各自需要最小拓扑；停机 Purge 先与重启快照语义对齐。不要把这些事项直接视为低风险快速修复。
3. **按证据决定扩展**：协议地址索引、PACKET_MMAP、组播卸载以规模测试为依据；ECMP、IPv6、Zserv 和降权依据实际部署需求单独规划。目录重组不要求继续拆文件。

本次验证：

- `make -j4 test`：构建及单元测试通过，包含新增 [test_admin.c](../tests/test_admin.c) 的短写、EINTR/EAGAIN、游标删除/插入、枚举预算、异步回复、monitor 超限立即断开和断连检查；该测试的 ASan/UBSan 检查通过。
- [test-legacy-spoke.py](../tests/netns/test-legacy-spoke.py)：隔离网络中验证 legacy/HA/Vendor 注册、续租、同步、角色切换、邻居与 GRE 转发。
- [test-peer-cache.py](../tests/netns/test-peer-cache.py)：v1 快照保存、恢复、失效/非法记录处理和恢复后的 GRE 转发。
- [test-admin.py](../tests/netns/test-admin.py)：4000 条路由的慢读输出完整性、其他控制请求响应、枚举期间删除/插入、分段命令、写半关闭、monitor、断连及超时通过。路由注入按批次等待处理，避免将 Netlink 队列容量混入管理接口测试。
- [run-managed.sh](../tests/netns/run-managed.sh)：覆盖质量迁移、Follower 接管、端点切换、健康降级、GRE 接口恢复、认证回切、多数派隔离、成员退出和集群销毁。

`make check-format`、`git diff --check` 及文档编号/链接检查通过。最终完整 HA 回归日志为 `/tmp/opennhrp-todo-managed-final6.log`，隔离测试产物保留在 `/tmp/opennhrp-ha-managed-netns.VeKZEH`。

未提交、部署或重启现有服务，未验证真实设备和外部厂商客户端。
