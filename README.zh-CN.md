# ProofAudit

代码仓库：https://github.com/SinkaiZhang/proofaudit

ProofAudit 是一套可靠性优先、失败关闭的数学证明审计研究框架。它将形式有效性、语义忠实性、来源可信度、反例与证伪证据、审查者独立性分别治理，避免把某一类证据错误地当成完整数学认证。

本仓库目前是 alpha 研究实现。系统中的 `PASS` 只表示：一个固定版本的主张在固定策略下关闭了全部必需证据槽。它不表示脱离来源、语义边界和信任依赖的绝对数学认证。

## 核心不变量

- 只有 `PASS + VERIFIED` 的 adapter 可以产生证据闭合或终止性数学裁决。
- 每个必需义务显式声明 typed evidence slots。
- route 使用 `any` 或 `all`，不同证据类型不能通过总分相互抵消。
- 必需证据槽开放、P0/P1 风险、通用门禁失败或 assurance 要求不足都会阻断 `PASS`。
- 基础设施错误进入 `REQUIRES_REVIEW`，不能误报成数学 `FAIL`。
- 已验证反例进入 `FAIL`；已验证命题错配进入 `SCOPE_MISMATCH`。

## 安装与运行

```bash
python -m pip install -e .
proofaudit validate --case examples/minimal/case.json
proofaudit run --case examples/minimal/case.json --artifact-dir artifacts
proofaudit report \
  --trace artifacts/minimal-exact-arithmetic/audit_trace.json \
  --output artifacts/report.html
```

Linux 是规范运行环境，Windows 通过 WSL2 支持。`integrations/dsh` 是可选集成，Python CLI 不依赖 DSH。

## 隔离端到端测试

案例可以声明 `test_e2e` 契约。核心会在临时目录中生成测试夹具、运行正式审计引擎、要求所有阶段和最终治理门禁通过，然后销毁原始 trace，只保留 `VERIFIED_TEST_ONLY` 脱敏摘要。

```bash
proofaudit test-e2e \
  --case examples/minimal/case.json \
  --output /tmp/proofaudit-test-e2e.json \
  --timeout-ms 60000
```

`VERIFIED_TEST_ONLY` 只证明软件链路可达，绝不能作为数学裁决、专家意见或 benchmark ground truth。

## 发布预检

```bash
python scripts/release_preflight.py \
  --output artifacts/release-preflight/result.json \
  --wheel-output-dir artifacts/release-preflight/wheel
```

该命令构建 wheel，在全新虚拟环境中安装，检查打包的 schema 和 console script，运行单元测试、案例验证和最小 E2E。只有全部通过后才保存候选 wheel。

## 仓库边界

本仓库只保存运行内核、schema、adapter interface、报告生成器、DSH 集成、发布工具和可再分发的小型夹具。大型审计案例、语义 mutants、冻结标签和实验 split 放在独立的 `proofaudit-benchmark` 数据仓库中。

未经授权不得重新分发第三方论文 PDF、Lean 仓库、模型输出或其他受限材料。案例应记录来源、版本、哈希、许可证、再分发状态和再生成方法。

## 研究状态

v0.1 建立公开软件契约和可复现执行路径。关于系统可靠性的学术结论仍需要冻结 benchmark、独立标注、外部专家审核和预注册实验，不能由本仓库或 `TEST_ONLY` 结果直接推出。

进一步说明见：

- `docs/architecture.md`
- `docs/research_protocol.md`
- `docs/disclosure_policy.md`
- `docs/repository-boundary.md`
- `docs/releases/v0.1.0.md`

## 许可证

核心代码采用 Apache-2.0。benchmark 原创标注和文档在独立仓库中采用 CC BY 4.0；第三方材料保留各自许可证。
