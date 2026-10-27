# 原生 LDAP / Active Directory 登录与部署

本文针对以官方 WeKnora v0.8.3 标签为基线、包含原生 LDAP 功能的二开版本；实际发布版本以构建提交和仓库 `VERSION` 为准。LDAP 功能最初在 v0.8.0 基线上开发，迁入 v0.8.3 后，升级旧部署还必须单独评估官方版本的变更及数据库迁移，不能把它当作仅替换 LDAP 代码。LDAP 由后端直接认证；原有邮箱密码与 OIDC 入口继续独立存在。配置使用应用进程环境变量，Bind 密码不通过系统设置 API 或页面管理，以避免把目录凭据存入应用数据库或返回给浏览器。默认使用 AD 的 `objectGUID` 和 `userAccountControl` 属性；其他 LDAP 目录须配置不可变身份属性与账号状态属性。

## 目录和身份安全前提

- 目录管理员必须保证所选搜索范围内的 `mail` 属性由可信目录管理，且每个允许登录的账号的邮箱全局唯一。账号首次使用 LDAP 时可能按邮箱匹配已有 WeKnora 用户；在启用前，应核实所有现有账号和目录账号的邮箱归属。初次绑定已有账号还必须由管理员在 `LDAP_EXISTING_USER_ALLOWLIST` 中明确列出其邮箱（逗号分隔，大小写不敏感）；默认空名单拒绝绑定已有账号。未经验证的目录不能开启邮箱信任。`LDAP_EMAIL_DOMAINS` 为必填的可信邮箱域名列表（逗号分隔、精确域名）；开启 `LDAP_TRUST_EMAIL` 同时表示管理员确认邮箱属性写入权限受到控制。
- 邮箱唯一性查询依赖目录的属性相等匹配规则。管理员必须确认邮箱属性使用不区分大小写的匹配（例如 `caseIgnoreMatch`），并在整个搜索范围内实施不区分大小写的唯一性约束；使用 `caseExactMatch` 的目录可能漏掉仅大小写不同的重复邮箱，不能在未补齐这一保障时启用邮箱信任。
- 查询账号必须完整看到所有配置 Base DN 内参与登录及邮箱查重的对象，并能读取身份、邮箱和状态属性；ACL 隐藏的重复项无法由应用发现。上线前验证目录权限和唯一性约束。
- 使用稳定、唯一的目录标识 `LDAP_DIRECTORY_ID`。不要把现有标识换给其他目录，也不要在无迁移方案时更改它。默认使用 AD `objectGUID` 作为身份标识；账号改名或移动 OU 时应保留该对象身份。删除并重建 AD 对象不是同一身份。
- 只授予查询账号读取目标 OU 中所需属性的权限。保证禁用账号不会通过配置的筛选规则；应用也会检查 AD 的账号禁用状态。目录用户禁用后，新的 LDAP 登录会被拒绝；已有 WeKnora 会话不会自动联动撤销，仍可能继续有效及刷新。需要立即终止访问时，应撤销该用户全部 WeKnora 会话并确认生效。现有 `POST /api/v1/auth/logout` 由用户本人调用，可撤销该用户的全部 access/refresh token；管理员可通过 `POST /api/v1/system/admin/users/reset-password` 重置该用户本地密码并撤销所有会话，但此操作会改变本地登录凭据，且不能重置自己的账号。请按现有管理员权限与密码策略操作并妥善保管新密码。单独标记用户不活跃不能代替会话撤销。
- 检查部署中系统设置的实际值：数据库中的认证设置可能覆盖环境变量。目标部署应使用 `tenantless` 默认空间策略，并关闭普通用户自助创建空间；通过管理员邀请授予成员权限。已有用户资料、系统管理员和空间角色不会因 LDAP 登录而改写。
- 使用 HTTPS 保护浏览器到 WeKnora 的登录链路；LDAP 连接必须使用 StartTLS 或 LDAPS、验证服务器证书链和主机名。证书中的名称应覆盖 LDAP URL 的主机名。
- 登录限流按客户端 IP 在每个应用进程内执行（30 次/分钟），不跨副本共享。配置 `WEKNORA_TRUSTED_PROXIES` 为实际受信任代理的 IP/CIDR，确保边缘代理覆盖客户端提供的 `X-Forwarded-For`，限制客户端直接访问后端；多副本部署还应在边缘统一限流。不要把任意私网客户端当作可信代理。

## 配置

以下示例变量供应用容器读取。`LDAP_USER_BASE_DNS` 用分号分隔完整 DN；额外过滤器与转义后的用户名精确匹配条件同时生效。以下为示例，不含密码：

```dotenv
LDAP_ENABLED=true
LDAP_URL=ldap://ad.example.com:389
LDAP_STARTTLS=true
LDAP_CA_FILE=/run/weknora-ldap/ca.pem
LDAP_BIND_DN=CN=weknora-reader,OU=Service Accounts,DC=example,DC=com
LDAP_BIND_PASSWORD_FILE=/run/weknora-ldap/bind-password
LDAP_USER_BASE_DNS=OU=Employees,DC=example,DC=com;OU=Contractors,DC=example,DC=com
LDAP_USER_FILTER=(&(objectClass=user)(!(objectClass=computer))(!(objectClass=group))(!(userAccountControl:1.2.840.113556.1.4.803:=2))(mail=*))
LDAP_USERNAME_ATTRIBUTE=sAMAccountName
LDAP_EMAIL_ATTRIBUTE=mail
LDAP_DISPLAY_NAME_ATTRIBUTE=cn
LDAP_ID_ATTRIBUTE=objectGUID
LDAP_ACCOUNT_STATUS_MODE=ad
LDAP_CONNECT_TIMEOUT=5s
LDAP_OPERATION_TIMEOUT=10s
LDAP_TRUST_EMAIL=true
LDAP_EMAIL_DOMAINS=example.com
LDAP_EXISTING_USER_ALLOWLIST=user@example.com
LDAP_DIRECTORY_ID=example-production
WEKNORA_AUTH_DEFAULT_TENANT_MODE=tenantless
WEKNORA_TENANT_SELF_SERVICE_CREATION_ENABLED=false
```

`LDAP_ENABLED` 默认关闭；`LDAP_URL` 使用 `ldap://` 时必须启用 StartTLS，也可使用 `ldaps://`。`LDAP_CA_FILE` 为 PEM CA 证书路径，追加到系统信任根；没有自定义 CA 时可省略。使用正确的证书而不是关闭验证。超时使用 Go duration 格式。密码文件与 `LDAP_BIND_PASSWORD` 安全环境变量二选一；优先使用受限文件，切勿把密码写入源码、镜像、仓库、示例文件或日志。环境变量可能被容器管理权限持有者读取。

`LDAP_ID_ATTRIBUTE` 默认为 `objectGUID`，其他 LDAP 可使用例如 `entryUUID` 的唯一、不可变属性。`LDAP_ACCOUNT_STATUS_MODE=ad` 校验 AD `userAccountControl`；对于其他 LDAP 可配置 `LDAP_ACCOUNT_STATUS_MODE=active-value`，并设置 `LDAP_ACCOUNT_STATUS_ATTRIBUTE` 和 `LDAP_ACCOUNT_STATUS_ACTIVE_VALUE`，属性缺失、多值或不等于启用值时拒绝。变更身份属性或目录标识会影响已绑定身份，须先制定迁移方案。

`LDAP_USER_FILTER` 是额外目录筛选条件，不含用户名占位符。系统把输入作为数据转义并与用户名属性组合。多个 OU 中匹配到不同对象、同一邮箱对应多个目录对象、邮箱缺失或冲突时拒绝登录；不要通过放宽过滤器来绕过冲突。错误应从服务器侧不含凭据的诊断排查，界面不区分账号不存在和密码错误。

LDAP 验证成功后，若没有匹配的 WeKnora 账号，系统按现有注册及默认空间策略自动创建用户；后续登录应匹配同一账号。若已有账号，首次关联必须先核实邮箱归属并满足上述允许名单要求。管理员应核对身份冲突后再处理，不能直接放宽已有账号允许名单。

LDAP 身份关联使用现有 `system_settings` 表中的内部保留键，分别记录目录身份哈希与用户 ID 的双向关系，LDAP 功能本身不新增表或修改数据库结构；这些内部记录不在系统设置界面显示。新版 WeKnora 主线可能包含其他数据库迁移，升级旧版本前仍须检查迁移和回滚兼容性。删除用户后关联记录仍会保留，以阻止目录身份自动绑定到其他账号。确需重新绑定时，先备份数据库，由管理员核实目录身份、原账号及权限，再审慎处理相关内部记录；不要批量清理这些键。首次创建用户与写入关联是两个步骤：若关联失败，登录会失败且可能留下未绑定用户，管理员应核实后处理。

邮箱目前仅接受可打印 ASCII 地址，国际化邮箱地址会被拒绝；这是为避免目录和数据库之间大小写折叠规则不一致。

将上面的配置保存为宿主机受限文件 `/opt/weknora/ldap.env`（不包含密码本身），在现有 Compose 覆盖文件中为 `app` 添加该环境文件和只读挂载（源路径应替换为服务器上的实际文件路径）：

```yaml
services:
  app:
    env_file:
      - /opt/weknora/ldap.env
    volumes:
      - /srv/weknora/ldap/<CA文件>:/run/weknora-ldap/ca.pem:ro
      - /srv/weknora/ldap/<密码文件>:/run/weknora-ldap/bind-password:ro
```

这只是附加片段，保留所有现有 Compose 文件及覆盖项。文件必须能由容器内 `appuser` 读取，同时在宿主机上只向必要的管理员和该进程开放读取；可用 `docker run --rm --entrypoint id <应用镜像> appuser` 查看 UID/GID 并按实际环境设置 ACL。不要为了排障使密码文件全员可读，也不要打印文件内容。只读挂载并不限制 Docker 管理员读取；轮换密码后按实际凭据加载方式重建应用容器。检查目录 DNS、端口及 CA 链：StartTLS 握手失败时登录安全失败，不会退回明文 LDAP。

Compose 中显式 `environment` 的值优先于 `env_file`；仓库默认 Compose 已显式设置两个 `WEKNORA_*` 空间策略，因此要通过现有 Compose 变量来源或覆盖文件设置它们，并核对数据库中的系统设置实际值，不能仅依赖上面的环境文件。

## 构建二开版本

在干净的 Linux 构建机或相应构建环境中检出经审核的发布提交（例如 Fork 中 `release/v0.8.3-ldap` 的提交），记录完整 commit 和镜像摘要。不要使用旧的 v0.8.0 功能分支来构建 v0.8.3 发布。不得把服务器密码和 CA 私钥复制到构建上下文。项目的 `docker/Dockerfile.app` 默认启用 anydoc 构建，构建可能耗时；应维持现有部署所需功能，不要为缩短时间随意禁用。

```bash
# 仓库根目录；tag 使用实际发布提交，避免覆盖已有镜像标签
COMMIT=$(git rev-parse --short=12 HEAD)
docker build -f docker/Dockerfile.app \
  --build-arg VERSION_ARG="$(cat VERSION)" --build-arg COMMIT_ID_ARG="$COMMIT" \
  -t "weknora-app-ldap:$COMMIT" .
./scripts/build_frontend_dist.sh
# 如部署使用项目自带 frontend 容器，构建其 Nginx 镜像：
docker build --build-arg VITE_FRONTEND_COMMIT="$COMMIT" -t "weknora-ui-ldap:$COMMIT" ./frontend
```

脚本执行 `npm ci`、`npm run build`，生成 `frontend/dist`；前端 Dockerfile 是多阶段构建，会在镜像构建时重新执行这些步骤，不依赖宿主机的 `dist`。如由宿主机 Nginx 直接提供静态文件，将完整 dist 发布到独立版本目录；注意同时更新 `index.html`、哈希 assets 和运行时 `config.js`，并核对当前站点的运行时配置及 Nginx API 代理目标。前端容器的入口脚本在启动时生成 `config.js`，直接托管时需按实际部署提供对应配置。不要把开发环境的 API 地址带入生产。无论哪种方式，均使用与后端配套的同一提交构建，先在隔离环境验证。

## 上线前、切换和验收

1. 确认维护窗口、当前镜像 ID/标签、Git 版本、Compose 启动命令及全部 `-f` 文件、`.env`、挂载、网络、外部地址和宿主机 Nginx 配置。备份这些配置（敏感文件受限保存），记录数据库 schema 版本和恢复方法。检查镜像入口脚本可能执行的自动迁移；先评估迁移兼容性和回滚，必要时在副本演练。不要对生产数据库执行未经验证的降级迁移。
2. 做可恢复性验证过的数据库一致性备份，并备份对象存储、上传文件、配置及实际使用的向量数据等；对 PostgreSQL 可按既有备份规范使用 `pg_dump`，其他数据库和外部存储使用相应的原生备份。快照或导出要与写入时点协调。不要用 `docker compose down -v`，也不要重建或删除现有数据卷。
3. 在原有 Compose 文件组合之后追加一份仅覆盖 `app.image` 的发布文件，指定固定的二开镜像标签；沿用现有数据库、存储、环境、网络、挂载、Compose 覆盖配置和 sandbox 设置。追加 LDAP 环境及上述只读挂载，确认密码文件权限和容器内 DNS/证书。先用原有全部 `-f` 参数加发布覆盖执行 `docker compose ... config --quiet` 检查配置；完整渲染输出可能含敏感值，不要公开。
4. 按原有 Compose 文件组合执行 `docker compose ... up -d --no-deps --no-build app`，检查健康状态及不含敏感信息的日志。该命令有短暂重启窗口。不要运行全栈 `pull` 或使用会改变其他服务镜像的操作。若使用项目 frontend 容器，同样通过发布覆盖指定固定 UI 镜像，确认依赖后仅重建 frontend；保留宿主机 Nginx 上游、TLS、WebSocket、上传大小和超时配置。
5. 若宿主机 Nginx 直接托管静态文件，将 dist 放入新版本目录，保持原版本目录，检查文件所有权及原站 `config.js`；通过站点既有的版本目录或符号链接切换，并用 `nginx -t` 验证配置后按既有流程 reload。保持 `/api/`、`/files`、`/r/` 和其他现有代理路由，避免 SPA fallback 吞掉接口；保留旧 hash 资源足够长时间，以支持仍打开旧页面的用户。若宿主机 Nginx 只是代理项目 frontend 容器，不需要替换宿主机静态文件。
6. 在部署入口验收：LDAP 正确密码成功；错误及空密码、禁用账号、目录中重复用户名或邮箱均安全失败；CA 或 LDAP 不可用不回退；已允许匹配的已有账号登录后核对用户 ID、系统权限及各空间成员角色；新用户保持 tenantless，管理员邀请后可正常访问和切换空间。验证本地密码、OIDC、邀请、管理员、文件及 sandbox 核心流程。若使用 HTTP 而未在其他代理层提供 HTTPS，浏览器到服务器之间的企业密码会明文传输；LDAP 到域控的 StartTLS 不会加密这一段。不要记录密码或令牌。

Compose `--no-deps` 仅在既有依赖确实运行且健康时使用；具体发布参数应以现场实际配置为准。禁止将完整 `docker inspect`、Compose 配置或认证请求体贴入公开日志。

## 回滚与后续合并

保留发布前镜像及静态版本目录。发生问题时，先核实数据库迁移对旧程序的兼容性，再恢复原发布覆盖中的 app 和 UI 镜像引用并使用相同 Compose 文件组合、`--no-deps --no-build` 重建相应服务；宿主机静态站则切回原版本目录并验证 Nginx。保留所有数据卷、原配置和 sandbox 设置。验证旧版本登录、空间、数据和沙箱。LDAP 功能本身不新增数据库表或修改表结构，但新版主线可能有其他迁移；回滚时应保留身份关联数据，以便重新升级后沿用。恢复数据库备份会丢失备份后的写入，须经维护窗口和业务确认。

后续同步官方稳定版本时，以已包含二开改动的 Fork 定制分支为基础创建升级分支，再合并选定的官方发布标签。不要强推覆盖已有分支，也不要把保留在旧基线的功能分支当作 v0.8.3 定制分支。以下命令以 `release/v0.8.3-ldap` 为起点，升级分支名称和标签需替换为实际值；`upstream` 应指向官方仓库。

```bash
git checkout release/v0.8.3-ldap
git pull --ff-only origin release/v0.8.3-ldap
git fetch upstream --tags
git checkout -b upgrade/example-release
git merge vX.Y.Z
```

其中 `vX.Y.Z` 是占位符，须替换为实际选择的官方稳定版本标签。逐项审查认证、身份绑定、数据库兼容性、前端和配置冲突，运行后端测试及前端构建，在隔离环境演练上述完整验收；确认无误后再合入自己的定制分支或发布新的定制分支，用新的不可变标签重新构建镜像和静态文件。保留原版本与备份直至完成验收。同步仓库不会自动更新正在运行的服务器。
