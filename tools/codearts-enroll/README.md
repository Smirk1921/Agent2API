# CodeArts 账号迁移工具

两个脚本，均只依赖 Node.js >= 22.5（内置 `node:sqlite`），不需要安装任何 npm 包。

| 脚本 | 作用 | 是否写库 |
| --- | --- | --- |
| `check-codearts.mjs` | 体检：槽状态、版本一致性、待补结算日志 | 只读 |
| `enroll-codearts.mjs` | 给导入的账号补 `_hostCredentialVersion` 与 Ready 槽 | 默认 dry-run，`--apply` 才写 |

## 为什么需要补登记

v3.5 起 CodeArts 自动续期只认 `codearts_refresh_slots` 里的 Ready 槽；账号文件导入
只写 `accounts` 行，不建槽。缺槽时刷新会报
「CodeArts 当前账号没有可用的受控续期登记」，需要本工具按宿主存储格式补齐。

## 用法

```powershell
# 体检（服务运行中也可以）
node check-codearts.mjs --db "<data>\agent2api.db" --key "<data>\account.key"

# 补登记（必须先停服务并备份）
node enroll-codearts.mjs --db "<data>\agent2api.db" --key "<data>\account.key"
node enroll-codearts.mjs --db "<data>\agent2api.db" --key "<data>\account.key" --apply
```

`<data>` 默认是安装目录下的 `data`（服务端）或桌面端的配置目录。

## 结果含义

- `keep`：已登记且版本一致，不改。
- `enroll`：缺槽，补登记。
- `reset`：槽存在但不是 Ready 或版本不一致，重置为 Ready。
- `skip`：缺少 `oauth_context` / PKCE 不自洽 / 账号行解不开，需要重新登录，脚本不动。

## 注意

- 写库前必须停服务，并备份 `agent2api.db` 与 `account.key`。
- 同一批 refresh token 只能有一台机器在刷新；迁移时先在源实例停用再在目标实例启用。
- refresh token 绝对有效期约 30 天，轮换不延长，目标机器需要常开维护。
