# OpenNHRP 托管多 Hub HA 验证状态

本文只记录当前源码的验证状态。架构、配置和操作流程见
[`opennhrp-hub-ha-design.md`](opennhrp-hub-ha-design.md)。

## 2026-08-18 当前工作区

| 验证 | 结果 | 覆盖 |
| --- | --- | --- |
| `make -j2` | 通过 | `opennhrp`、`opennhrp-ha`、`opennhrpctl` 编译与链接 |
| `make -C tests test` | 通过 | extension、Hub List、HMAC、seen、control、snapshot store、delta、failback、managed state、Join、coordinator |
| `tests/test_ha_join`（允许 loopback socket） | 通过 | Witness active 模式下的加密在线 Join |
| `sudo tests/netns/run-managed.sh` | 通过 | 三 Hub、Spoke、Witness、复制、隔离、接管、恢复和 failback |
| `git diff --check` | 通过 | 当前未提交差异无 whitespace error |

本轮没有安装软件包、修改实机服务、部署远端节点或执行实机长跑。

## netns 覆盖矩阵

`tests/netns/run-managed.sh` 在独立 network namespace 和临时目录中验证：

- `enable-ha` 自动初始化 Primary；
- 两个一次性 Invite、两个 Backup Join、learner 自动晋升和 manifest 复制；
- 普通 `map ... register` Spoke 自动升级为 HA，并同时验证公网/私网 endpoint
  选择和 `ha-local-nbma`；
- 配置 reload 对本机 endpoint 和健康目标执行完整替换，不重启协调器；
- 两个 Standby 同时重连，重启 Standby 不会替换正在服务的 Primary；
- snapshot/delta/digest 同步、stale Leader frame 拒绝和 failback transfer；
- 健康目标自适应探测、单目标故障不迁移、全部目标故障隔离、十轮恢复；
- `gre-ha down` 后本机隔离、Backup 接管、Spoke 迁移和恢复节点重入；
- 两 Hub Witness 的 prepare/activate/lease、Manager 与 Hub 联合分区自隔离、
  5 秒内业务恢复、Manager 丢失后的 peer vote 和安全协同回退；
- 三个 active Hub 使用 `hub-majority`，单 Hub Leader 分区被隔离，2/3 分区继续
  服务且全程没有两个可服务 Leader；
- 已 claimed Invite 可单独删除，不会删除对应 Hub 成员。

最近一次完整输出结束于：

```text
validating three-Hub majority fences a one-Hub Leader partition
managed Invite, three-Hub reconnect, gre-ha isolation and takeover passed
```

## 结果解释

- “单元测试通过”只证明本机逻辑和编码边界，不等于真实网络故障注入通过。
- “netns 通过”证明当前构建在受控三 Hub 拓扑完成整套流程，不代表不同内核、
  云 NAT、防火墙或真实公网抖动环境已验证。
- 历史实机 P95 数据属于当时构建和拓扑，不作为当前未提交工作区的性能结论。
- 生产安装、服务重启和远端验证必须单独授权，并重新记录构建标识、拓扑和每轮
  故障结果。

## 复现

```sh
make -j2
make -C tests test
sudo tests/netns/run-managed.sh
```

运行 netns 测试需要 root、`iproute2`、iptables、mGRE 和 network namespace
支持。默认在退出时清理临时 namespace 和目录；排障时可设置
`KEEP_FAILED_ARTIFACTS=1` 保留失败现场。
