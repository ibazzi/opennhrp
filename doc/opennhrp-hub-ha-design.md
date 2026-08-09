# OpenNHRP 托管多 Hub HA

本文是当前 HA 配置、运行和故障处理的主文档。验证范围与最近结果见
[`opennhrp-hub-ha-test-report.md`](opennhrp-hub-ha-test-report.md)。

## 1. 组件与边界

- Hub：在 mGRE 接口上配置 `enable-ha`，共享同一个 Protocol Address/prefix，
  各自拥有独立的 NBMA endpoint。
- Spoke：继续使用普通 `map ... register`。收到托管 Hub List 后自动建立暖注册，
  无需维护一份单独的 HA Hub 配置。
- `opennhrp-ha`：由 `opennhrp` 自动启动和监管。Hub 模式负责成员、复制、选举、
  仲裁和 failback；Spoke 模式负责候选 Hub 探测与切换。
- Manager Witness：仅在恰好两个 active Hub 时提供第三票。它通过 Hub 协调器
  socket 下发短租约，不参与 NHRP 数据面。

OpenNHRP 只管理 IPv4 mGRE/NHRP，不建立或监测 IPsec，也不接入 VICI/XFRM。
如需 IPsec，由外部系统独立管理。

## 2. 仲裁策略

只有 `active` 成员有投票权；新 Join 的 `learner` 追平注册 snapshot 和 digest 后
才由 Leader 晋升。

| active Hub 数 | `policy` | 可服务条件 |
| --- | --- | --- |
| 1–2，Witness 未启用 | `legacy` | 本地 active Hub 可服务；网络分区时可能短暂多 Leader |
| 2，Witness 已启用 | `manager-witness` | 本地票加健康对端票，或本地票加有效 Manager 租约，达到 2/3 |
| 3–32 | `hub-majority` | term、Leader 和角色一致的健康 Hub 达到 `N/2+1` |

三台及以上 active Hub 自动使用 Hub 多数派；少数分区中的旧 Leader 会自隔离。
两 Hub Witness 模式下，租约最长 3000 ms，epoch 必须一致，term 不得倒退，
sequence 必须严格递增。Manager 与其中一个 Hub 同时不可达时，没有第二票的
Leader 会自隔离。

两个 Hub 都无法联系 Manager、但彼此健康且 term、Leader、commit index 和
digest 一致时，可在 30 秒后协同回退到 `legacy`，避免 Manager 长期故障造成
不必要停机。该回退不适用于两个 Hub 彼此分区的场景。

## 3. 最小部署

### 3.1 Primary

`gre-ha` 必须只有一个活动 IPv4 Protocol Address。`advertise` 是有序 NBMA
endpoint，不能填写共享 Protocol Address；每个 Hub 最多四个唯一单播 IPv4。

```text
interface gre-ha
  enable-ha member-id hub-primary advertise 150.158.214.148 advertise 10.0.4.17
  ha-health-target 119.29.29.29
  ha-health-target 223.5.5.5
```

托管目录完全为空时，首次启动会原子初始化 Primary。状态不完整、损坏或与接口
Protocol Address/prefix 不一致时启动失败，已有状态不会被覆盖。

非 NAT 环境中，如果 GRE local/NBMA 可可靠推导，可以省略 `advertise`。云 NAT
环境应显式填写外部可达地址；协调器监听 `0.0.0.0:49002`，出站源地址由系统
路由和 NAT 决定，不要求 advertised address 能在本机 bind。

### 3.2 Backup Join

在当前 Leader 上创建一次性 Invite：

```sh
opennhrpctl ha invite create --member-id hub-backup1 --format plain
```

Invite 默认十分钟有效，包含 secret，不能写入日志、工单或公开命令行。Backup
接口必须已经配置与集群完全相同的 Protocol Address/prefix，然后交互式执行：

```sh
opennhrpctl ha join --interface gre-ha \
  --advertise-address 49.234.145.47 \
  --advertise-address 10.0.12.5
```

命令从终端或标准输入读取 Invite。Join 使用 Ed25519 身份、临时 X25519、
AES-256-GCM 和 Leader 签名；完成后成员先以 learner 身份加入。Backup 必须先
Join 再首次使用以下配置启动，否则空目录会初始化为另一个独立 Primary：

```text
interface gre-ha
  enable-ha
  ha-health-target 119.29.29.29
  ha-health-target 223.5.5.5
```

Join 下发当前集群状态和认证 keyring。

### 3.3 Spoke

Spoke 只配置共享逻辑网关：

```text
interface gre-ha
  map 10.20.0.1/24 150.158.214.148 register
```

Registration Request 携带非强制 HA 探测。普通 Hub 忽略它并保持传统行为；托管
Hub 返回 Hub List 后，Spoke 建立暖注册，在第一个 HA neighbor 成功提交后休眠
传统 map。普通非 HA 配置不受影响。

需要认证时，在 Hub 导出 keyring 并通过可信通道复制：

```sh
opennhrpctl ha key export-spoke --output /tmp/gre-ha.keys
install -m 0600 /tmp/gre-ha.keys /etc/opennhrp/ha/gre-ha.keys
```

Spoke 从 `/etc/opennhrp/ha/<interface>.keys` 自动加载。文件存在时必须有效且权限
为 `0600`；已经认证过的 Spoke 不会因 keyring 消失而降级为未认证模式。

## 4. Endpoint 与健康探测

显式 `advertise` 列表是完整替换语义。任意 Hub 可修改自己的列表并 reload；
成员通过已认证连接提交给 Leader，再由 Leader 更新 manifest 并复制。仍需保留
的地址必须继续写在配置中，成员不能从本机修改其他 Hub。

Leader 会在认证成功后把 Hub TCP 实际源地址作为 observed endpoint，排在显式
地址之后；源地址变化时替换旧 observed 地址。完整列表仍最多四个。

每个 Hub 可配置最多四个 `ha-health-target`：

- 每轮并行探测，任一目标回复即成功，单轮 deadline 为 800 ms；
- 健康时探测间隔按 1、2、4、8、10 秒增长；
- 任一失败轮把间隔降回 1 秒，连续三轮全部失败后隔离；
- 故障后连续十轮成功才重新加入；
- 未配置目标时，仅以 mGRE 接口 `IFF_UP` 判断本地可服务性。

配置 reload 会原地替换 endpoint 和健康目标，不需要重启 `opennhrp`。恢复节点
先保持隔离，连接 active 成员并学习当前 term/Leader 后才重新投影注册。

## 5. 两 Hub Witness

仅当恰好两个 active Hub、两端连接已认证且同步时才应启用。以下命令面向 Manager
实现，必须发送到每台 Hub 的协调器 socket；默认路径为
`/var/run/opennhrp-ha.socket`。

```text
ha witness prepare epoch <32-hex>
ha witness activate epoch <32-hex>
ha witness lease epoch <32-hex> term <term> holder <member> sequence <n> ttl-ms <1..3000>
ha witness show --format json
```

推荐控制顺序：

1. 为本轮生成非零 128-bit epoch，对两台 Hub 执行 `prepare`；进入 preparing 后
   Hub 会先停止对外承担 Leader，防止半配置状态继续服务。
2. 两台都确认相同 epoch 后执行 `activate`。
3. 读取当前最高 term，选择唯一 holder，以更高或相同合法 term、严格递增
   sequence 向两台 Hub 周期发送 lease。
4. 持续读取 `ha witness show --format json` 或 `ha cluster show --format json`，
   以 `quorum_available`、`manager_vote`、`peer_vote` 和 `lease_remaining_ms`
   判断是否可以服务。

epoch 和租约只属于协调器运行期。协调器重启后，Manager 必须重新执行 prepare、
activate 和 lease；在重新获得合法票之前，两个 Hub 不会依靠旧租约恢复服务。

第三个 learner 晋升为 active 后自动切换为 `hub-majority`，不再使用 Manager 票。

## 6. 复制、选举与 failback

TCP 49002 复用 Join 和 Hub 复制。Join 由 `ONHJ` 前导区分；复制帧使用长度前缀
和 HMAC，Hub HELLO 另带 Ed25519 签名。Leader 复制成员 manifest、注册
snapshot/delta、match index 和 digest；digest 不一致时触发 snapshot resync。

候选 Hub 按 priority 选择，同 priority 按 member ID。任何 Hub 要成为可服务
Leader，除本地接口和网络健康外，还必须满足当前仲裁策略。双 Leader 重新连通后
根据认证 term/Leader 收敛，不能以固定超时重新宣称旧 term。

自动 failback 只回到固定 Primary：Primary 认证且持续健康 120 秒，并且 Backup
的 snapshot match index 和 digest 已同步后，Backup 发起认证 transfer。失败后
按 300、900、1800 秒退避，probation 为 120 秒；`force` 只跳过时间门槛，不跳过
认证、健康、复制同步或 transfer ACK。

## 7. 持久状态与安全边界

默认托管目录 `/var/lib/opennhrp/ha` 的主要文件：

- `cluster.state`：cluster、成员、term、Leader、Invite、manifest revision 和
  Witness 模式；
- `registrations.state`：注册 snapshot；
- `seen.state`：最高已认证 term/commit；
- `identity.key`：本机 Ed25519 私钥；
- `keys`：current 和可选 next PSK。

文件要求同一 euid 所有、权限 `0600`；写入使用锁、临时文件、fsync 和原子
rename，并由 HKDF 派生的 state key 做 HMAC。状态输出只暴露 key ID。

Invite、keyring 和身份私钥均为敏感信息。共享 PSK 的 Spoke 仍可能伪造 NHRP
报文，underlay GRE 和 TCP 49002 的来源限制仍是必要边界。

## 8. 运维命令

本地状态命令：

```text
ha invite create/list/revoke/delete
ha members show
ha member set/enable/disable/remove
ha key export-spoke
ha key rotate prepare/commit
ha join
```

发往 Hub 协调器 socket 的命令：

```text
ha cluster show --format json
ha replication show --format json
ha key status --format json
ha failback show --format json
ha failback request [force]
ha witness show --format json
```

Spoke 状态：

```sh
opennhrpctl ha show interface gre-ha format json
```

重点字段包括 `active_member`、候选 `ready`、`selected_address`、
`service_available`、`isolated`、`term`、`commit_index`、`digest`、
`policy`、`votes/required` 和 `quorum_available`。

## 9. 兼容性与限制

- 纯 IPv4 mGRE，最多 32 个 Hub、每成员四个 endpoint、每 Hub 四个健康目标；
- 所有 Hub/Spoke 共享一个逻辑 Protocol Address/prefix；
- `ha-local-nbma` 只覆盖某个 Hub 的本地 GRE/NBMA 目的地址，不启用 HA，也不
  改变注册身份；
- 旧 `ha-hub`、`ha-member-id`、`ha-cluster-id`、`ha-auth`、`ha-auth-key`、
  `ha-state-file`、`ha-map` 和人工 `generation` 不属于当前配置语法；
- Managed HA 的 X25519/Ed25519 raw-key API 需要 OpenSSL 1.1.1 或更新版本。

## 10. 验证入口

```sh
make -C tests test
sudo tests/netns/run-managed.sh
```

前者覆盖 wire、认证、持久状态、Join、复制、failback 和仲裁单元测试；后者覆盖
自动 Primary、两个 Backup Join、Spoke 自动升级、两 Hub Witness、Manager/Hub
分区自隔离、安全回退、三 Hub 多数派、接口/健康故障、复制和 failback。
