# AgentOS 完整方案缺口矩阵

对照完整 AgentOS 方案（Windows/macOS Runtime、Mode 0/1/2、内核捕获、WinRE、Effect Capability）与当前仓库实现。

更新时间：2026-07-16

## 已实现（可验证）

| 能力 | 状态 | 证据 |
|------|------|------|
| 用户态事务状态机（begin/prepare/commit/rollback/recover/verify） | 已实现 | `TransactionEngine` + CLI + self-test |
| 声明式 file / registry / service / scheduled-task scope | 已实现 | CLI flags + engines |
| 三方冲突检测 | 已实现 | self-test conflict case |
| Job Object 子进程约束（run） | 已实现 | `WindowsJobRunner` |
| Detached multi-step transaction | 已实现 | Pattern Bridge 集成 |
| Journal hash chain | 已实现 | `TransactionJournal` |
| baseline/after integrity index | 已实现 | `EvidenceIntegrity` |
| 恢复前 staging 预检 + fail-closed | 已实现 | `PrepareRestore` / 负向 self-test |
| store scrub | 已实现 | `agentos scrub` + self-test |
| GC（terminal only） | 已实现 | `agentos gc` |
| VSS baseline（elevated Full mode） | 已实现（能力探测） | `VssShadowCopyProvider` + `doctor` |
| Sandboxie Mode 0 adapter | 已实现（可选依赖） | `SandboxieAdapter` |
| Pattern 任务自动事务 / fail-closed / 独占确认 | 已实现 | Pattern sidecar/bridge/tests |
| NTFS ADS 捕获与回滚 | 已实现 | `NativeFileInfo` + `FileSnapshotEngine` |
| file identity / hardlink count 元数据 | 已捕获 | FileIndex/HardLinkCount（恢复不保证保留 inode） |
| sparse/encrypted/compressed 标志 | 已捕获 | FileEntry 标志位 |
| store ACL hardening | 已实现 | `StoreProtection.HardenRoot` |
| evidence MAC (CurrentUser DPAPI) | 已实现 | `evidence.mac` + self-test |

| hardlink group 元数据 | 已捕获 | HardLinkGroupKey/HardLinkPaths + self-test |

| 计划任务结构化元数据 | 已实现 | XML parse author/principal/actions/triggers |

| Pattern 自动 scope 声明 | 已实现 | declareRecoveryScopes 显式/启发式 registry/service/task |

## 部分实现 / 有边界

| 能力 | 状态 | 说明 |
|------|------|------|
| Mode 2 Full Recovery | 部分 | 有 VSS metadata 路径，但非内核写前拦截 |
| 服务恢复 | 部分增强 | `sc.exe` + registry 结构化 start type/binary/account/deps；非完整 SCM API |
| 计划任务恢复 | 部分增强 | `schtasks.exe` XML + 结构化元数据；非 Task Scheduler COM |
| hardlink group 恢复 | 部分 | 组元数据已捕获；回滚仍按路径重建，不重建 NTFS link graph |
| 覆盖率报告 | 部分 | coverageNotes 静态说明，非动态 per-object coverage graph |
| 签名发布 | 部分 | SHA-256 报告有，Authenticode 仍为 `NotSigned` |

## 未实现（当前环境/阶段阻塞）

| 能力 | 阻塞原因 | 建议阶段 |
|------|----------|----------|
| File System Minifilter 写前 before-image | 需 WDK、驱动工程、签名与 HLK | Phase B |
| Registry Callback 内核归因 | 需内核组件 | Phase B |
| Process Notify / token 继承上下文 | 需内核组件 | Phase B |
| WFP Effect Broker | 需 callout 驱动与策略通道 | Phase B |
| WinRE 离线恢复 | 需恢复环境 agent、BitLocker、幂等计划 | Phase C |
| macOS Endpoint Security / APFS clonefile Runtime | 非当前 Windows 仓库目标，且需 Apple entitlement | Phase E |
| evidence root 强 broker/TPM MAC | CurrentUser DPAPI MAC 已落地；跨用户 broker/TPM 身份仍缺 | Phase D |
| Authenticode / EV 驱动签名 | 需证书与发布流水线 | Phase D |
| 100k/10k 故障注入矩阵 | 需专用测试农场 | Phase D |
| 多写事务并发与依赖图 | 产品明确单写事务 | 后续 |

## 本仓库可继续推进的优先序

1. hardlink 组元数据已捕获；完整 link graph 恢复仍待。
2. 服务/任务 provider 均已结构化增强；COM/SCM 原生 API 仍待。
3. store ACL + CurrentUser DPAPI evidence MAC 已完成。
4. Pattern 自动声明 registry/service/task scopes 已完成。
5. 发布签名流水线仍需证书。

在完成 Phase B/C/D 门槛前，产品表述必须保持：

> 用户态声明 scope 的条件式恢复层，不是完整系统事务沙箱或 EDR 边界。
