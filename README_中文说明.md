# SSDF Week 6 实验包 — 中文说明

提交文件是英文的，与 Week 5 保持一致。本文件只给你自己看，**不要放进提交的 zip**（run_lab.sh 打包时不会带上它）。

## 1. 目录结构

```
ssdf-week6-lab/
├── .github/workflows/hardened_pipeline.yml   ← 交付物 1（Task 1）
├── .github/dependabot.yml                    ← Task 4.3 自动 PR
├── renovate.json                             ← Task 4.3 备选（只启用其中一个）
├── policy/attestation.rego                   ← 交付物 3（Task 3）
├── policy/attestation_test.rego              ← 16 个策略单元测试
├── policy/exceptions.json                    ← CVE 豁免清单（默认为空）
├── policy/fixtures/*.json                    ← 合规 / 篡改两种测试输入
├── app/main.py                               ← 实验给的原代码（未改动）
├── app/requirements.txt                      ← Week 5 的版本 + sha256 锁定，删除了 PyYAML
├── Dockerfile                                ← 多阶段构建、base 固定 digest、非 root
├── scripts/                                  ← provenance / 策略输入 / 修复报告
├── pipeline_findings.md                      ← Task 1 找到的 10 个问题
├── reference/deploy.yml                      ← Task 1 的原始文件（即 Week 5 ci_hardened.yml）
└── run_lab.sh                                ← 一键运行 Task 2–4 并打包
```

运行后会生成：`sbom.cyclonedx.json`（交付物 2）、`verification_log.txt`（交付物 4）、`remediation_report.md`、`evidence/`、`cosign.key/.pub`，以及 `ShuchenMeng_SSDF_Week6.zip`。

## 2. Mac 上的运行步骤

```bash
brew install cosign syft grype conftest
# 先打开 Docker Desktop，确认 docker info 能正常输出
cd ssdf-week6-lab
chmod +x run_lab.sh
./run_lab.sh
```

- 需要联网：会拉取镜像、下载漏洞库，签名会上传到 Sigstore 公共透明日志 Rekor
- 本地 registry 使用 `localhost:5001`，因为 macOS 的 AirPlay 占用了 5000 端口
- 耗时大约 10 分钟，其中首次下载 grype 漏洞库最慢
- `cosign.key` 是实验用的密钥，密码为空。**不要提交，也不要上传到 GitHub**（已写进 `.gitignore`）

## 3. 结果怎么看

`verification_log.txt` 末尾有 SUMMARY：

| 项目 | 期望结果 |
|---|---|
| Signature (cosign verify) | PASS |
| SBOM attestation | PASS |
| SLSA provenance | PASS |
| Untrusted key rejected | PASS（用错误公钥验证必须失败） |
| Policy gate (conftest) | PASS，或见第 5 节 |

日志里还包含两个负向测试：用不受信任的公钥验证被拒绝、篡改过的元数据被策略拦截。这两项是证明"门禁确实有效"的证据，可以在报告里引用。

## 4. 关于作业里的几处问题（可写进报告）

- `cosign attache sbom` 是拼写错误，正确的是 `attach`。`attach sbom` 在 cosign 里已弃用，而且上传的 SBOM **不带签名**。脚本仍然按作业原文执行了一次，然后用 `cosign attest --type cyclonedx` 生成真正签名的 SBOM，策略检查的是后者。
- 作业没有提供 `deploy.yml`，这里用你 Week 5 的 `ci_hardened.yml` 作为原始文件。
- `click 8.3.3` 故意保持 Week 5 的版本（最新是 8.5.0），这样 remediation report 能标出"过时依赖"，Dependabot 也会自动开 PR，正好演示 Task 4.3。

## 5. 如果 Policy gate 是 FAIL

最常见的原因是 `python:3.11-slim` 的 Debian 层带有 High/Critical CVE。请查看 `remediation_report.md` 里的 Critical/High 表：

- **fix state = fixed**：说明上游已有补丁。执行 `docker pull python:3.11-slim` 拉取最新镜像后重跑即可。
- **fix state = not-fixed / wont-fix**：上游没有补丁。在 `policy/exceptions.json` 里加一条带理由和到期日的风险接受记录，然后重跑：

```json
{
  "vulnerability_exceptions": [
    {
      "id": "CVE-XXXX-XXXXX",
      "package": "包名（与报告一致）",
      "justification": "No upstream fix; package not used by the Flask app at runtime.",
      "expires": "2026-12-31T00:00:00Z"
    }
  ]
}
```

策略要求理由至少 20 个字符，而且到期日必须晚于当前时间。这正是 SSDF RV.2.1 的做法：不是忽略漏洞，而是有记录、有期限地接受风险。

## 6. GitHub 部分（Task 1 流水线、Task 4.3 自动 PR）

1. 新建一个仓库 `ssdf-week6-lab`，推送整个目录（`cosign.key` 已被 .gitignore 排除）
2. Settings → Environments → 新建 `production`，可以加 required reviewer
3. push 到 main 后，Actions 会依次跑：source-gates → release（keyless 签名） → verify（conftest） → deploy
4. Settings → Code security → 开启 Dependabot。几分钟后会出现 click 的升级 PR，截图作为 Task 4.3 的证据

## 7. 用 Claude Code 让 Claude 在你电脑上直接执行

在 Claude Code 里打开这个文件夹，然后粘贴下面这段：

> 这个目录是 SSDF Week 6 实验。请先读 README_中文说明.md，然后：
> 1. 检查 docker、cosign、syft、grype、conftest 是否已安装，缺少的用 brew 安装
> 2. 运行 ./run_lab.sh
> 3. 如果 Policy gate 是 FAIL，读 remediation_report.md：fix state 为 fixed 的，拉取最新基础镜像后重跑；not-fixed/wont-fix 的先列出来给我确认，不要自己加豁免
> 4. 最后告诉我 SUMMARY 各项结果，以及 zip 的位置
