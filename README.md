# OpenNHRP 项目现状

核对日期：2026-09-18。源码基线：`6499650`。

OpenNHRP 是 Linux 上的 IPv4 NHRP 实现，配合多点 GRE（mGRE）维护协议地址与 NBMA 地址映射、动态注册、邻居和捷径路由。本仓库还实现托管多 Hub HA、Spoke 独立选路和注册状态复制。IPsec 由外部系统独立配置，程序不管理 VICI/XFRM 或 IPsec 生命周期。

## 组件与目录

| 路径 / 程序 | 职责 |
| --- | --- |
| `opennhrp` | 配置加载、NHRP 报文、peer 生命周期、内核邻居和事件脚本 |
| `opennhrpctl` | Unix socket 管理客户端，以及 HA 邀请、加入和密钥操作 |
| `opennhrp-ha` | 由主进程启动和监管的 HA 协调器 |
| [nhrp/core](nhrp/core) | 地址、接口、报文、注册、peer 和重启快照 |
| [nhrp/ha](nhrp/ha) | 候选选择、owner、认证、复制、仲裁、持久状态及 Join |
| [nhrp/platform](nhrp/platform) | Netlink、PF_PACKET、事件循环和日志 |
| [etc](etc) | 配置示例和路由事件脚本 |
| [man](man) | daemon、控制命令、配置和脚本手册 |
| [tests](tests) | 单元测试、隔离网络测试和实机测试脚本 |
| [debian](debian)、[openwrt](openwrt) | 软件包构建文件 |

Manager 与 Agent 是独立项目；本仓库提供其使用的管理接口和 Witness 协议，不包含管理平台服务端或 Web 界面。

## 已实现能力

### NHRP 与管理接口

- 静态映射、动态注册、地址解析、捷径路由、重定向及用户态组播复制。
- Registration Unique 约束：拒绝冲突绑定并返回 Code 14，保留有效绑定；允许同绑定续租，检查 NAT 原始地址和有效 HA 副本。非唯一注册采用单绑定替换，不提供多路径绑定。
- `SIGHUP`、`opennhrpctl reload` 和 `config reload` 支持配置重载，包含静态 peer 清扫和 HA 配置更新。
- 管理回复使用非阻塞发送队列，处理短写及 EAGAIN；peer 枚举可分批暂停和恢复。每连接缓冲上限 256 KiB，无 I/O 进展 10 秒断开；实时枚举不是事务快照。
- `SIGINT` / `SIGTERM` 退出时保存未过期的普通 dynamic、cached 和 shortcut-route 状态，启动时按原过期时间恢复，并重新执行脚本和邻居注入。快照保留唯一性标志，不保存 HA active member、候选评分或 owner 状态。

### 托管多 Hub HA

- Hub 使用 `enable-ha`；空状态目录初始化 Primary，Backup 通过一次性 Invite 加入，先作为 learner，复制追平后晋升 active。
- Hub 共享逻辑网关协议地址及前缀，每台有独立 NBMA。最多 32 个 Hub，每成员最多 4 个 endpoint，每 Hub 最多 4 个健康目标。
- Spoke 使用普通 `map ... register`，收到 Hub List 后自动发现候选，只向当前 active Hub 保持注册，迁移时向目标 Hub 注册并更新邻居。
- 每个 Spoke 根据丢包、RTT 和 priority 进行 Hub 质量选择，包含评分差门槛、持续时间和迁移冷却。Spoke 的 `active_member` 与 Hub 集群 Leader 是不同状态。
- Hub 管理直接注册、退役 owner 和 replica shadow，通过 snapshot、delta、commit index 和 digest 同步并恢复状态。
- 1–2 个 active Hub 在未启用 Witness 时使用 `legacy` 策略；两 Hub 可由外部 Manager 提供 Witness 租约；3–32 个 active Hub 使用多数派仲裁。`legacy` 分区可能出现短暂多 Leader。
- 接口下线或健康探测失败可触发隔离与接管；自动回切固定 Primary 要求认证、健康和复制同步。
- Join 使用 Ed25519、X25519 和 AES-256-GCM；HA 支持 HMAC 认证、密钥轮换和带认证的持久状态。
- 不带 HA 扩展的 Spoke 仍由原注册 Hub 服务，其注册不参与 HA 复制，原 Hub 故障时不能自动迁移。

部署、仲裁与运维细节见 [托管多 Hub HA](doc/opennhrp-hub-ha-design.md)。

## 构建与安装

需要 GNU make、C 编译器、pkg-config、c-ares 开发库及 OpenSSL 开发库；HA 使用的 raw-key API 要求 OpenSSL 1.1.1 或更新版本。Debian/Ubuntu 对应开发包为 `libc-ares-dev`、`libssl-dev`。

```sh
make -j4
make test
```

程序输出位于 `build/nhrp/`：`opennhrp`、`opennhrpctl`、`opennhrp-ha`。安装到临时目录以检查文件布局：

```sh
make install DESTDIR=/tmp/opennhrp-stage
```

默认安装路径为 `/usr/sbin`、`/etc/opennhrp`、`/usr/share/man` 和 `/usr/share/doc/opennhrp`；正式安装使用 `make install`，会写入这些系统目录。

`make deb` 调用 `dpkg-buildpackage`。当前 `debian/control` 未声明 `libssl-dev`，干净构建环境需补齐该依赖。仓库内 `openwrt/Makefile` 固定下载指定 Git revision，安装列表仅含 `opennhrp` 和 `opennhrpctl`，没有完整声明当前 HA 的程序和加密依赖，不能直接作为当前工作树完整 HA 包的证明。

## 基本运行配置

运行需要 Linux IPv4 mGRE、Netlink、PF_PACKET 及相应网络管理权限，事件脚本使用 `iproute2`。按拓扑配置转发、路由和防火墙。示例接口创建：

```sh
ip tunnel add gre1 mode gre key 1234 ttl 64
ip addr add 10.255.255.2/24 dev gre1
ip link set gre1 up
```

Spoke 配置示例，其中 `192.0.2.1` 必须替换为实际可达的 Hub NBMA：

```text
interface gre1
  map 10.255.255.1/24 192.0.2.1 register
  shortcut
  redirect
  non-caching

interface lo
  shortcut-destination
```

默认配置为 `/etc/opennhrp/opennhrp.conf`，事件脚本为 `/etc/opennhrp/opennhrp-script`。脚本处理邻居关联和路由事件，并调用具有执行权限的 `/etc/opennhrp/user-script`。

默认管理 socket 为 `/var/run/opennhrp.socket`，HA 协调器 socket 为 `/var/run/opennhrp-ha.socket`；HA 状态及 `peer-cache.state` 默认位于 `/etc/opennhrp/ha`，可通过 `-H` 指定目录。敏感状态和 Spoke keyring 应保持所有者专用权限。

```sh
opennhrpctl show
opennhrpctl ha show interface gre1 format json
```

完整参数见 [opennhrp(8)](man/opennhrp.8)、[opennhrpctl(8)](man/opennhrpctl.8)、[opennhrp.conf(5)](man/opennhrp.conf.5)。

## 当前限制

- 支持 IPv4 over IPv4 mGRE；IPv6 overlay 和 IPv6 NBMA 尚无完整实现。
- 没有通用停机 Purge 遍历通知；重启恢复依赖快照，远端失效由租约和探测等机制决定。
- 没有通用的 NHS 动态租约直答、多 CIE ECMP、基于 Forward NHS 列表的中继选择或 BGP 下一跳变化定向 Purge 闭环。
- 没有完整的非 root 降权、map 地址语义倒置检测或跨 peer 全局脚本串行队列。
- 协议地址查询仍有链表枚举路径；PF_PACKET 使用 `recvmsg/sendmsg`，组播按 peer 在用户态复制，无 PACKET_MMAP、内核组播卸载或 IGMP 成员表。
- 没有内置 Zserv 客户端或按 RTT 调整 BGP 权重的脚本功能。

具体源码证据及需复现场景见 [功能覆盖评估](doc/opennhrp-todo-assessment.md)。

## 验证入口与证据范围

```sh
make -j4 test
sudo python3 tests/netns/test-peer-cache.py
sudo python3 tests/netns/test-legacy-spoke.py
sudo python3 tests/netns/test-admin.py
sudo tests/netns/run-managed.sh
```

单元测试覆盖扩展、wire、认证、持久状态、Join、复制、回切、协调器和管理输出。隔离网络测试覆盖快照恢复、Unique 注册、慢读管理输出、质量迁移、owner 与邻居、GRE 转发、Witness、多数派、隔离恢复及成员退出。

仓库内 2026-09-18 的[验证记录](doc/opennhrp-todo-assessment.md#建议执行顺序与验证边界)记载上述单元和隔离网络回归通过；这是已有记录，不表示本次文档整理重新执行了网络测试。另有带日期的 [HA 验证报告](doc/opennhrp-hub-ha-test-report.md)。本地测试不证明真实设备、云 NAT、外部厂商客户端或生产网络已经验证。

netns 测试需要 root、iproute2、iptables、Python 3 和相应内核支持。`tests/real/` 为实机测试入口，执行前需核对目标与配置。

## 许可证

OpenNHRP 使用 [MIT License](MIT-LICENSE.txt)；内嵌 libev 使用 [BSD 双条款 / GPLv2+ 双许可证](libev/LICENSE)。链接依赖包括 c-ares 和 OpenSSL，其许可证随各自发行版本提供。
