# Sealpath

Sealpath 是一个 Go HTTP 后端，用显式信任根、制品字节、分离签名、证书链、撤销列表和版本化策略形成可复核的发行验证决定。它不会访问操作系统的根库，也不会自动联网补取证据。

需要 Go 1.25 或更新版本，无第三方 Go 依赖。默认监听本机回环地址。

```sh
go build ./...
go run ./cmd/sealpath -listen 127.0.0.1:8435 -state var/sealpath-state.json
```

另一个终端可运行完整生产流程演示：

```sh
go run ./cmd/sample -workflow bundle
go run ./cmd/sample -workflow compare
go run ./cmd/sample -workflow unknown
```

每次演示默认生成真正的临时 Ed25519 签名密钥、三级证书链和带签名的 CRL，在独立临时目录启动真实 HTTP 服务，再执行相应工作流；退出时清理临时状态。演示不会连接你已经启动的实例，也不会导出私钥。`examples/release.json` 是可读取的公共样例材料；重新生成可使用 `go run ./cmd/sample -emit /tmp/sealpath-release.json`。样例核验时刻固定为 `2026-11-16T00:00:00Z`，不要用当前墙钟替换后期待相同结果。

可用 `-algorithm rsa_pss_sha256` 或 `-algorithm ecdsa_sha256` 生成其他算法的制品签名，证书签发仍使用 Ed25519。

可选演示：`certificates`、`trust`、`artifact`、`signature`、`policy`、`revocation`、`verify`、`unknown`、`history`、`bundle`、`compare`、`restart`、`retire`、`ocsp-responder`、`ocsp-accept`、`ocsp-verify`、`ocsp-conflict`、`ocsp-retire`。演示是有界的真实使用流程，初始化基线尚未附带自动化测试套件。

## 接入顺序

1. 向 `POST /v1/certificates` 提交单张 PEM 证书，正文为 `{"pem":"..."}`；证书身份为 DER 的 SHA-256。
2. 向 `POST /v1/trust-sets` 提交 `id`、`name`、`roots` 和 `expected_revision`。首次创建使用修订号 0，根必须是已经接收的自签 CA。
3. 向 `POST /v1/artifacts` 提交 `name`、`media_type`、Base64 编码的 `content`，可附 `expected_digest`。
4. 向 `POST /v1/signatures` 提交 `artifact_id`、`certificate_id`、`algorithm`、Base64 编码的 `value`。接收阶段先验证制品签名，尚不表示接收方已经信任此证书。
5. 向 `POST /v1/policies` 提交 `id`、`expected_version`、`algorithms`、`revocation`、`max_artifact_bytes`，可附 `subject_contains`。策略每次追加不可变版本。
6. 向 `POST /v1/revocations` 提交 `issuer_id` 与 CRL 的 `pem`。根到中间证书、中间到签名证书分别需要自己的撤销证据。
7. 可选：向 `POST /v1/ocsp-responders` 提交 `id`、`issuer_id`、`certificate_id`、`certificates` 与 `expected_revision`，单独登记接收方认可的状态响应机构。`issuer_id` 是它代表的 CA；`certificate_id` 是其签名证书（CA 自身或带 OCSP signing 用途的委托证书）；`certificates` 限定它能回答哪些证书。修订号从 0 开始，可更新范围或签发证书；`POST /v1/ocsp-responders/{id}/retire` 退役后不再接受新响应，也不再参与新决定。
8. 可选：向 `POST /v1/ocsp-responses` 提交 `responder_id` 与响应的 `pem`。接收时校验签名、ResponderID、CertID 的签发者与序列号，以及该证书是否在当前授权范围内；`produced_at` 不得倒退。
9. 向 `POST /v1/decisions` 提交 `signature_id`、`trust_set_id`、`policy_id` 和明确的 RFC3339 `at`。可指定 `policy_version`；省略时固定本次请求看到的最新版本。

支持的制品签名算法为 `ed25519`、`rsa_pss_sha256`（至少 2¹¹ 位，盐长等于哈希长度）、`ecdsa_sha256`（ASN.1）。RSA/ECDSA 对制品 SHA-256 进行核验，Ed25519 对完整字节核验，二者不能混用输入语义。

决定的 `verdict`：

| 值 | 含义 |
|---|---|
| `trusted` | 策略、制品签名、代码签名路径及所需撤销检查均成立 |
| `rejected` | 至少一项检查明确失败 |
| `indeterminate` | 没有明确失败，但缺少当时有效的撤销资料 |
| `trusted_with_warning` | `best_effort` 策略允许保留撤销不确定性；调用方必须检查警告 |

撤销检查可同时使用 CRL 与 OCSP。对每个非根证书，选择在 `at` 已生效且 `next_update` 未过的、由当前认可且未退役机构签署、且 CertID 与该证书及签发者一致的响应中最新的一个。新鲜响应提供更高可用性：CRL 缺失、过期或未知时，明确的 `good` 足以满足 `required` 策略。但新鲜响应不能抹掉已确认的密钥泄露撤销——CRL 在响应 `this_update` 之前或当时已生效的撤销仍然拒绝，OCSP 自身的撤销也仍然拒绝。退役机构不再参与新决定，即使其旧响应尚未过期；已形成的决定保留当时的机构修订号，重放与离线复核仍以该修订为准。

无效请求和不存在的引用返回 HTTP 错误；领域判断失败一般仍形成可查询的决定，不能仅检查 HTTP 200 就放行发行。

## 查询与复核

`GET /v1/decisions/{id}` 读取历史决定；后续策略、信任集合或 CRL 变化不会覆盖其捕获证据。`GET /v1/decisions/{id}/bundle` 导出 `sealpath-evidence-v1` 包，`POST /v1/evidence/replay` 用包内材料重新求值。`GET /v1/evidence/compare?left=<id>&right=<id>` 比较两个决定的请求、路径、策略、根和撤销依据。

重放成功只说明**内部自洽**，不是外部来源认证。攻击者可以自己签发一套根并出具自洽证据。接收方必须通过自己的渠道认可信任根或出具方；此服务目前不签名证据包，也不联网查询 OCSP、透明日志或可信时间戳。OCSP 响应只由调用方显式提交，服务不会主动向响应机构请求。

另外提供 `GET /health`、证书/信任集合/撤销列表/OCSP 响应机构/OCSP 响应/决定集合查询、按 ID 读取制品与签名、按 ID 读取策略版本，以及 `GET /v1/events`。事件是本机接收顺序，不是防篡改日志。

## 运行与数据边界

- 单进程拥有一个 JSON 状态文件；只保证本进程内并发原子性。不要让两个进程写同一路径，也不要在运行时直接编辑文件。
- 更新先写同目录临时文件并同步，再重命名；写入失败不会更新内存状态。启动时检查版本、内容身份、签名引用、CRL 签发关系和决定材料摘要。状态文件不提供对恶意本机篡改的来源认证。
- 备份先停写并正常退出，再复制完整状态文件；恢复到独立目录后启动，核对历史决定与证据包。跨机器断电耐久性取决于文件系统，不能仅凭重命名推断远端存储保证。
- 单制品最大 4 MiB，已接收制品总字节数最大 64 MiB；证书最大 64 KiB，单 CRL 最大 1 MiB，单 OCSP 响应最大 64 KiB，HTTP 正文最大 16 MiB。全部状态和捕获证据保存在内存/JSON 中，适合有界验证服务。
- 每个决定当前捕获全部已接收证书、CRL 和 OCSP 材料，可能包含无关发行方资料。导出前需审核披露范围，原包摘要不允许静默裁剪。
- 服务没有账户或网络访问控制。默认回环监听；远程访问应由受控网关提供 TLS 和调用权限。请求日志不记录制品内容或私钥。

容器构建：`docker build -f deploy/Dockerfile -t sealpath .`；运行：`docker run --rm -p 127.0.0.1:8435:8435 -v sealpath-state:/state sealpath`。数据卷使用镜像中的非 root 运行身份；容器可用性应在目标 Docker 环境另行核实。

领域范围、持久化边界与代码职责见 `PROJECT_SPEC.md`。
