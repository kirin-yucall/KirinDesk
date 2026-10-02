# relay-server — KirinDesk 中继服务器（含中继互联 token 管理）

公钥轮换命令（`pubkey rotate`）、旧版宽限开关（`--ix-legacy-grace`），以及
互联 token 的语义与共享流程。基础部署（端口/token/密钥/目录库）见仓库根
`release/server/README.md`。

## 1. 互联 token ≠ 客户端登录 token

| | 客户端登录 token | 中继互联 token |
|---|---|---|
| 谁用 | 设备（客户端）登录本中继 | 中继服务器之间互联推送认证 |
| 谁校验 | 本中继校验登录连接 | **目标中继**校验推给它的目录推送 |

两者是不同的凭据，**可同可不同**（互不影响）。客户端登录 token 与互联
token 的区分口径由用户裁定，不得混用表述。

## 2. 互联 token 管理命令（CLI）

所有命令都是短事务操作（操作 `relay.db` 后立即退出，不进入服务主循环），
可与长驻服务进程并存（SQLite WAL 单写者 + busy_timeout 5s 承接；高峰期
建议先停服再批量操作）。库路径沿用 `--relay-db`（默认
`~/.kirin_desk/relay.db`）。

```bash
# 列出互联 token（token 列只显示前 8 位前缀；全量只在 add 时打印一次）
relay-server tokens list
# 生成并登记一枚互联 token（≥32B 随机 base64url；label 必填，空 label 拒绝）
relay-server tokens add --label "B 中继的 home 设备"
# 软撤销（行保留；撤销即时生效 = 下一次携带该 token 的推送被拒）
relay-server tokens revoke <id>
```

`tokens list` 输出列：`ID | LABEL | TOKEN | SOURCE | TARGET_DOMAIN |
CREATED_AT | STATE`。`SOURCE=cli` 为本机管理员登记（对本机全部入站推送
生效）；`SOURCE=device` 为设备表单上交的转发凭证缓存（本机推送时自动携带，
不参与本机校验）。

（`token_hash` = hex(sha256(token))，零明文落库）——全量 token 仅
`tokens add` 时打印一次，此后任何命令与库内数据都无法还原明文；请像密码
一样保管（遗失 = `tokens revoke <id>` 撤销旧行后重新 `tokens add` 并向
对端重新分发）。`device` 缓存行按 C-6 裁定维持明文（推送时需原样取出
转发给目标中继）。schema v3→v4 迁移在服务启动时自动完成（一次性，cli 行
明文就地哈希化）。

## 3. 互联 token 共享流程（不同中继 token 各自独立）

1. **目标中继 B 管理员**生成：`relay-server tokens add --label "A 的 home"`，
   把打印出来的全量 token 交给用户（或 A 中继管理员）。每个中继的 token
   各自独立生成、独立撤销。
2. 用户在客户端（home = A 的设备）「允许中继服务器发现」表单高级区填入
   目标中继 B 的域名 + 该 token。
3. 设备上交后，home 中继 A 缓存该 token（`source=device`，按目标域
   last-writer-wins），并在向 B 推送目录时自动携带（加密帧体内，不经明文）。
4. B 校验推送帧内 token 与本机 `tokens add` 登记的活跃行：命中 = 受理；
   无 token / 不匹配 / 已撤销 = **整批拒收** + `push rejected` 审计行。
5. 撤销即时生效：B 侧 `tokens revoke <id>` 后，A 的下一次推送即被拒。
   A 侧重新提交表单（新 token）后恢复推送。

> **撤销 ≠ 立即清除（C-7 裁定口径，务必知悉）**：`tokens revoke` 只断
> 后续推送（撤销语义 = 断推送，**不级联清除** B 侧此前已应用的目录条
> 目）。B 侧已收下的 A 侧条目至多存续一个 TTL（默认 24h，`--push-entry-ttl`
> 可配；或随下一批数据的缺行撤销自然清除）。**需要立即抹除时，正确顺序
> 是：先在 A 侧清空目录（删除后经推送传播），确认 B 侧条目消失后再执行
> `tokens revoke`。** 隐私残留窗口上限 = 一个 TTL。

注意：A 侧没有某目标的转发凭证时，**跳过**对该目标的推送并输出

## 4. 旧版本互通与宽限开关 `--ix-legacy-grace`


- **默认关（推荐，fail-closed）**：收到旧版中继（`RELAY-DIR/2`，推送无
  token）一律拒收，审计 reason=`legacy_no_token`。
- **开（迁移期放行）**：`relay-server --ix-legacy-grace ...` 收到旧版握手
  按旧五门受理（不验 token）。**两端都升级完成后应关闭本开关。**
  （unix 秒 UTC）启用宽限至该时刻，**过点（含等界）自动 fail-closed**
  恢复严格校验（忘关自愈收紧，不再依赖人的记性）。到期后若迁移确未完成，
  重启前先确认对端升级状态再显式延期——到期瞬间未完成迁移的旧 home 推送
  会被拒收（`legacy_no_token` 审计行可见，reason 含 `expired` 可辨「到期
  自动收紧」与「人工关断」）。显式给出即隐含启用宽限；与 `--ix-legacy-grace`
  同给 = until 优先；非法时间戳 = 拒启（fail-closed 不猜）；到期时刻已在
  过去的配置 = 启动 WARN（宽限即启即失效）。
- 纯手工 `--ix-legacy-grace`（无到期界）仍可用，但启动会 WARN 提示「bypass
  无自动关闭机制」——迁移期短暂排障用，勿长期持有。
- 旧版中继收到新版帧 = 解码必败（既有混合版本自限制）；因此旧 home 中继
  下的新版客户端向新版 B 推送会经由旧 home 转发失败——升级对端中继或
  临时开宽限，是两种解法。
- 客户端表单填入 token 需要**新版客户端**；旧客户端表单没有 token 输入位，
  其条目推给新版 B 会被默认拒收（同样走宽限/升级口径）。

## 5. 服务器公钥轮换 `pubkey rotate`

```bash
relay-server pubkey rotate
# 默认操作 ~/.kirin_desk/relay_server_key.pem；可用 --server-key <PATH> 指定
```

行为：旧密钥文件自动备份为 `relay_server_key.pem.bak` → 生成全新 Ed25519
密钥对覆写原文件 → 打印新公钥（base64）与 79 字符指纹。rotate 后**必须**
依次完成 1-3（第 4 条在新链路验证生效后做）：

1. **本域 DNS TXT 公钥记录必须同步更新**——对端以 DNS TXT 现场解析值做
   TOFU 互证，记录不同步 = 对端拒连（`TOFU mismatch`）；
2. **已预置本中继公钥的客户端必须更新**（表单公钥 / 同步源 TOFU 值）；
3. **重启服务进程生效**（进程启动时加载密钥）；
4. **新链路验证生效后，删除旧私钥备份 `relay_server_key.pem.bak`**
   留盘。


服务进程启动起在 server key 同目录维护 `<key 文件名>.epoch_hw`（默认
`~/.kirin_desk/relay_server_key.pem.epoch_hw`），内容 = 目录 epoch 高水位
（十进制一行）。用途：relay.db 丢失/重装/损坏重建后，库内 epoch 行随库
消失、目录 epoch 从 1 重启，对端会按互联推送门③ `stale epoch < last`
对端拒收即刻解除。运维口径：

- **随 key 同等对待**：换机迁移/灾备预案中，`relay.db` 可以不带，
  `<key>.epoch_hw` 应与 key 一起保留/复制（它归属签名身份）；
- **误删后果轻微**：sidecar 缺失/损坏 = 退回自然追平现状（对端拒收直至
  epoch 追平），不拒启、不影响本域功能；文件随时可安全删除后重启重建；
- **pubkey rotate 后**：新 key = 新 sidecar 路径（新身份从零起算，对端按
  新 source fp 记账，无 stale 面）。


| 审计行 | 含义 |
|---|---|
