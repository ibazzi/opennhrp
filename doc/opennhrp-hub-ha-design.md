# OpenNHRP 托管多 Hub HA

本文是当前 HA 配置、运行和故障处理的主文档。验证范围与最近结果见
[`opennhrp-hub-ha-test-report.md`](opennhrp-hub-ha-test-report.md)。

## 1. 组件与边界

- Hub：在 mGRE 接口上配置 `enable-ha`，共享同一个 Protocol Address/prefix，
  各自拥有独立的 NBMA endpoint。
- Spoke：继续使用普通 `map ... register`。收到托管 Hub List 后自动发现候选并向 active Hub 注册，
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
Hub 返回 Hub List 后，Spoke 只在当前 active Hub 保持注册，其他 Hub 只作为迁移
候选。active Hub 故障时，Spoke 将注册迁移到目标 Hub，再提交新的 HA neighbor。
普通非 HA 配置不受影响。

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

Spoke 从私网 bootstrap 重启时，Hub 可能仍保留经公网 NAT 建立的唯一地址绑定。
收到“唯一地址已注册”的回复后，Spoke 仍检查回复来源、请求代次、Hub List 及
配置要求的认证；通过验证的列表用于发现其他端点，不代表注册成功。
尚无 active Hub 时，清除被拒绝端点的首选标记，随后尝试同一 Hub 的其他端点；
成功注册的端点成为新的首选，避免后台探测切回冲突路径。只有重新注册成功并完成
可用性检查后才能启用。已有 active Hub 的端点故障转移继续遵守原有租约规则。
其他设备的不同 NBMA / NAT 原始地址仍受唯一地址保护；不会自动删除旧 owner，
也不会将拒绝回复当成成功。如果没有可恢复原绑定的端点，仍保持注册失败。

### 4.1 测量与评分

每个 Spoke 独立探测各候选 Hub，并按各自当前选中 endpoint 的链路质量评分；
Hub 和 Manager 不替 Spoke 做路径选择。质量统计只保留当前选中 endpoint 的已完成
探测，endpoint 变化会清空历史。

`loss_pct` 是最近 60 秒的滚动累计失败率，包含超时和无效回复，不等于纯物理
丢包率。实现使用 60 个一秒桶，保留当前秒及前 59 秒：

```text
loss_pct = 100 * sum(failures) / sum(completed_probes)
```

空桶不补样本，第 61 秒淘汰最老的一秒。60 秒窗口降低偶发失败的影响；连续失败
另由探测状态机快速判定。

评分 RTT 独立按时间平滑：`α = 1 - exp(-Δt / 2秒)`，
`R = R + α * (sample - R)`。首个样本或超过 30 秒无有效回复后重新初始化。
原有 `SRTT = 0.875 * SRTT + 0.125 * sample`、RTTVAR、RTO 和探测调度
只用于故障检测；主用、备用的探测频率和最小 RTO 不同。切换主备角色不清空
质量历史。窗口无样本或最近有效 RTT 超过 30 秒时测量无效，最终得分为 0。

延时分使用 150ms 为半分点的三次 Hill 曲线，范围为 0～20 分。低延时之间仍有
小幅差异，中高延时的惩罚加速增长：

```text
normalized_rtt = quality_rtt_ms / 150
latency_score = 20 / (1 + normalized_rtt ^ 3)

score = 70 * max(0, 1 - loss_pct / 20)
+ latency_score
+ 10 * min(priority, 100) / 100
```

总分最后统一四舍五入。150ms 的延时分为 10；失败率达到 20% 时失败率分为 0。
不维护历史固有延时基线，不额外惩罚相对涨幅。继续使用 OpenNHRP 探测，
不引入 Babel 报文或路由通告。总分权重及以下迁移门槛属于本项目策略，
不是 RFC 9616 规定的参数。

当前固定参数如下，不提供运行时配置项：

| 参数 | 数值 |
|---|---:|
| 失败率滚动窗口 | 60 秒 |
| RTT 平滑时间常数 | 2 秒 |
| RTT 测量失效时间 | 30 秒 |
| 失败率 / 延时 / 优先级权重 | 70 / 20 / 10 |
| 失败率零分点 | 20% |
| RTT 半分点 / Hill 指数 | 150ms / 3 |
| 质量迁移分差 / 保持时间 | 10 分 / 15 秒 |
| 迁移后冷却 | 30 秒 |
| 小分差优先级回迁保持时间 | 120 秒 |
| endpoint 不可达连续失败数 | 3 次，并满足 RTO 截止时间 |

### 4.2 候选资格与持续失败

候选只有同时满足以下条件才有有效得分：

- Hub 报告 `serviceable=true`；
- 当前选中 endpoint 可达；
- 状态为 `ready`，或它是当前 active Hub 且状态为 `suspect`；
- 需要认证时，候选认证有效；
- 如果候选是当前 active Hub，它的注册仍有效；备用 Hub 无需预先注册，实际迁移时
  才注册。

不可服务、endpoint 不可达、认证失败或测量无效均使最终得分为 0。注册回复不能
覆盖探测得到的可服务状态。

持续失败走独立的快速状态路径：第一次连续失败把候选标记为 `suspect`；成功回复
会清零连续失败计数；连续三次失败且超过自适应 RTO 截止时间后，选中 endpoint
被标记为不可达，最终得分为 0。当前 active Hub 的注册暂时保留，由协调器按正常
迁移规则选择新 owner；备用候选一旦 `suspect` 就不能成为迁移目标。

### 4.3 候选排序与决策

每个 protocol service 保存独立决策状态。可用候选按以下键从高到低排序：

```text
term -> score -> priority -> member ID 字典序较小者
```

迁移决策按以下顺序执行：

```text
没有 active Hub：
    等待 term/priority/member 排序先序更高但仍在初始化的候选完成探测
    然后立即启用当前最佳 ready 候选

候选最高 term < active term：
    不迁移

候选最高 term > active term：
    只迁移到该 term 中声明的 ready/authenticated Leader
    原因记为 stale-term，不等待评分滞回或冷却

手动模式且当前 active 得分非 0：
    仅在当前认证 Leader 与保存的 manual_leader 一致时迁移到手动目标
    手动目标暂不可用时保持当前 Hub，不改选其他质量候选

手动模式且当前 active 得分为 0：
    暂时跳过手动约束，按自动评分选择可用 Hub 兜底

仍在迁移后 30 秒冷却期：
    不进行普通质量迁移

目标得分 - active 得分 >= 10：
    优势连续保持 15 秒后迁移，原因记为 quality

0 < 目标优势 < 10 且目标 priority 更高：
    优势连续保持 120 秒后回迁，原因记为 failback

其他情况：
    保持当前 Hub
```

15 秒和 120 秒等待期间会固定第一个仍合格的目标，不因另一备用 Hub 短暂得到更高
分而重置。目标失去资格或优势、目标 endpoint/term 变化、当前成员或当前 endpoint/
term 变化、选择模式变化时，等待重新计时。15 秒质量迁移与 120 秒优先级回迁之间
切换时也不复用已等待时间；选择模式变化还会清除迁移冷却。

没有合格候选时保留现有内核 neighbor 并继续探测。当前 Hub 得分为 0 或明确不可
服务也不会绕过 15 秒质量滞回；只有没有 active、较高 term 和有效手动选择走各自
的专用分支。

### 4.4 迁移事务

协调器从 monitor 事件读取 `generation`，发送带 `expect-generation` 的
`ha activate`，防止基于旧快照提交迁移。核心按以下顺序执行：

1. 重新检查目标存在、未禁用且没有其他迁移正在进行；
2. 目标尚未 ready 时立即探测，尚未注册时先完成 HA Registration；
3. 异步写入目标 neighbor，并等待 netlink ACK；
4. ACK 成功后再次检查目标仍为 `ready` 且质量资格有效；
5. 提交新的 HA peer、`active_member` 和 owner term/index，并递增 generation；
6. 向旧 Hub 发送带 registration ID 和 owner 版本的 release，撤销旧有效 owner；
7. 旧 Hub 的复制 shadow 按原生命周期保留，随后继续探测并协调内核状态。

目标失效、generation 不匹配、注册失败或 netlink 提交失败都会终止本次迁移，且不
启动 30 秒冷却。只有从一个 active Hub 成功迁移到另一个 Hub 后才开始冷却。
同一 Hub 的 endpoint 更换仍要完成对应注册，不能只替换 neighbor 地址。

### 4.5 状态与日志

JSON 和文本状态同时提供评分 RTT、窗口完成数与失败数、最近有效回复年龄、
测量有效性和未舍入的分项分数：`quality_rtt_ms`、`quality_samples`、
`quality_failures`、`last_quality_reply_age_ms`、`quality_valid`、`loss_score`、
`latency_score`、`priority_score`。`srtt_ms` 仍用于超时估计；没有 RTT 或回复时间
时对应新字段输出 `null`。无窗口样本时 `loss_pct` 输出 100，须结合
`quality_valid=false` 区分测量不足。旧 RTT 可显示但失效后不计延时分；即使分项
分数较高，可用性和认证限制仍可将最终 `score` 置零。

启用核心 `-v` 会同时启用 Spoke 协调器 `-v`。DEBUG 决策日志仅在原因、当前成员
或目标变化时记录，包含成员、分数、原因、等待时间和剩余冷却时间。
原因包括 `no-eligible-target`、`initial-wait`、`initial`、`current-best`、
`margin-small`、`quality-wait`、`quality`、`failback-wait`、`failback`、
`cooldown`、`manual-selection`、`manual`、`term-blocked` 和 `stale-term`；
实际迁移成功、失败仍保留现有日志。不新增协调器状态同步接口。

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

默认托管目录 `/etc/opennhrp/ha` 的主要文件：

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
ha leave
ha destroy --force
```

非 Primary 成员可主动 `leave`；当前 Leader 会先从签名成员清单删除它，退出节点
收到认证 ACK 后才隔离数据面、清除本机 HA 状态并停止协调器。Leader 必须先完成
领导权转移再退出。固定 Primary 不能 leave，只能在自身为 Leader 且所有成员在线并
已认证时执行 `destroy --force`，向全体成员分发认证销毁命令。退出或销毁后应先从
配置删除 `enable-ha`，再重启 `opennhrp`，否则配置仍会要求建立新的 HA 状态。

Spoke 状态：

```sh
opennhrpctl ha show interface gre-ha format json
```

重点字段包括 `active_member`、候选 `ready`、`selected_address`、`srtt_ms`、
`loss_pct`、`score`、
`service_available`、`isolated`、`term`、`commit_index`、`digest`、
`policy`、`votes/required` 和 `quorum_available`。

## 9. 兼容性与限制

- 纯 IPv4 mGRE，最多 32 个 Hub、每成员四个 endpoint、每 Hub 四个健康目标；
- 所有 Hub/Spoke 共享一个逻辑 Protocol Address/prefix；
- 未携带 HA 注册扩展的普通 Spoke 留在原注册 Hub，该 Hub 降为 standby
  后仍接受普通注册并转发；这些注册不参与 HA 复制。原 Hub 宕机时旧版 Spoke
  不会自动迁移。HA 能力复用现有 HA/Vendor bootstrap 扩展识别；
- `SIGINT`/`SIGTERM` 优雅退出会在 `-H` 状态目录的 `peer-cache.state` 中保存
  未过期的普通 dynamic 注册，以及 Spoke 学习到的 cached 邻接和 shortcut
  route；启动时按原绝对过期时间恢复，并重新执行 `peer-up`/`route-up` 和邻居
  注入。`HA_ACTIVE`、`active_member`、候选评分和 HA owner 状态不进入该快照；
- `ha-local-nbma` 只覆盖某个 Hub 的本地 GRE/NBMA 目的地址，不启用 HA，也不
  改变注册身份；
- 旧 `ha-hub`、`ha-member-id`、`ha-cluster-id`、`ha-auth`、`ha-auth-key`、
  `ha-state-file`、`ha-map` 和人工 `generation` 不属于当前配置语法；
- Managed HA 的 X25519/Ed25519 raw-key API 需要 OpenSSL 1.1.1 或更新版本。

## 10. 验证入口

```sh
make compile
make -C tests test
sudo python3 tests/netns/test-peer-cache.py
sudo python3 tests/netns/test-legacy-spoke.py
sudo tests/netns/run-managed.sh
```

单元测试覆盖 wire、认证、持久状态、Join、复制、failback 和仲裁；
`test-peer-cache.py` 覆盖 legacy dynamic、Spoke learned peer 的优雅重启恢复和
无效快照处理；`run-managed.sh` 覆盖自动 Primary、两个 Backup Join、Spoke 自动
升级、两 Hub Witness、Manager/Hub 分区自隔离、安全回退、三 Hub 多数派、接口/
健康故障、复制和 failback。

`test-legacy-spoke.py` 使用真实报文模拟旧版 Spoke，覆盖注册能力分类、多个 CIE、
standby 续注册、旧 HA 缓存替换及同步冲突，并检查内核邻居和 GRE ping；
它不替代实际旧版二进制兼容性验证。
