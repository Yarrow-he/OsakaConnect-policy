# OsakaConnect-policy（草稿，未推送）

Osaka 代码组的门禁策略仓库。私有，保持私有。main 受 ruleset `policy-main` 保护（禁更新、删除、强推），平时只有闸口 App（Integration 5592067）能绕过。`.github/workflows/` 的文件由 Hao Yin 临时给 Repository admin 开放行、用自己账号推，推完马上关（Hao Yin 2026-11-03 定）。工作 App 没装在这里。

## 文件
1. `required-checks.yaml`：main 的必过检查清单，唯一名单。
2. `key-acceptance-tests.yaml`：关键验收测试清单（现有 8 组全部列入，Hao Yin 已定）。
3. `pr-size.yaml`：200 行阈值、排除路径名单、日志函数名单、注释语法。
4. `ci-approval-class.yaml`：Hao Yin 档五类的路径和关键字规则。
5. `scripts/`：检查器 `gate.py`（pr-size、ci-approval-class、owner-approval、gate-summary，纯逻辑、只用标准库）和样例测试 `test_gate.py`，改动一律算权限类。
6. `.github/workflows/policy-checks.yml`：每 5 分钟给 OsakaConnect 的 PR 写 pr-size、ci-approval-class、owner-approval、gate-summary。取数据、跑检查器、写结果分三个 job，跑检查器的 job 没有任何令牌和 secrets（不另外断网，Hao Yin 已接受同类联网风险）。
7. `.github/workflows/policy-publish.yml`：每 5 分钟发布已合并的提案、写 policy-published，然后同步分支保护（同步即漂移修复）。`policy-rollback.yml`：只有 Hao Yin 能触发的回滚、作废、引导入口。`policy-sync-protection.yml`：被前两者调用。`gatelib.py`：这几个 workflow 的内联逻辑，放在 `.github/workflows/` 下，和 workflow 一样只能临时管理员放行推。
8. `state/state.json`：唯一状态记录（generation、暂停、已处理到的业务提交、每个提案结果、divergence、历史）。格式、发布和恢复流程、手动回滚步骤见 `STATE.md`。

## 怎么改
0. 首次上线：本仓库初始内容和 OsakaConnect 的 `policy-proposals/` 同名文件要逐字节一致；state.json 的 processed_through 设为放入 `policy-proposals/` 那次合并的提交号，active 记初始策略提交号，generation=1。
1. 测试在 OsakaConnect 的 `ci/` 分支改 `policy-proposals/` 下的同名文件，开普通 PR。
2. 审阅审，组长批。命中 Hao Yin 档（secrets、权限、关键验收测试清单、pr-size 阈值和名单、删必过检查或放宽分档）的，`owner-approval` 要核到 Hao Yin 对当前 head 的批准。
3. 组长合并进 OsakaConnect main。
4. `policy-publish` 轮询到合并，核对后用 gate App 复制进本仓库，并在 OsakaConnect 的合并提交上写 `policy-published` 结果；必过检查清单的 branch_protection 层有变化就在同一次运行里调用 `policy-sync-protection` 同步分支保护，两步都成功才写 `policy-published` 成功。
5. 本仓库 `.github/` 下的 workflow 不自动发布，算权限类。ruleset 只放行闸口 App，而 GitHub 要求 App 有 Workflows 权限才能推 workflow 文件，闸口 App 不加这项权限；改 workflow 一律走临时管理员放行（步骤见 `t/new7_deploy.md` 附录）。

## 实现要求
1. 任何 job 都不检出、不执行 OsakaConnect PR 的代码，只经 API 读 tree、blob 和评审；检出本仓库可以。
2. `owner-approval` 在 PR 新提交和 Hao Yin 提交、修改、撤回评审后的下一次轮询都重算，核对批准者、状态 APPROVED、评审对应的提交号等于 PR 当前 head。
3. 闸口 App 没有 actions:read，核不了业务检查来自哪个 workflow 文件；改为同名、同来源（GitHub Actions）的检查每个 check suite 的最新一次都要 success，PR 新加同名假 job 盖不掉真 job 的失败。
4. 新检查加进必过前，要在普通 PR 和提案 PR 上都跑出结果。
5. 改检查器的提案，由 OsakaConnect 的 `.github/workflows/policy-selftest.yml`（改它算权限类）拿固定样例跑新脚本：先用 `contents: read` 的 job 把候选脚本存成 artifact，再在 `permissions: {}`、不用 secrets 的 job 里跑；托管 runner 默认能联网，这点靠审阅。gate-summary 要求它在这类 PR 上为 success。闸口令牌不跑候选脚本。
7. 撤销一个加了必过检查的提案，等于删必过检查，按第⑤类要 Hao Yin 批；紧急时由 Hao Yin 触发恢复入口回滚。
8. 已知残留风险（Hao Yin 已接受共用工作 App）：非 main 分支没有 ruleset，bot 之间互推、强推分支只靠规则，组长靠结论板提交号和 `--match-head-commit` 兜底。
6. 发布失败、同步失败、积压超过 30 分钟，都让对应 workflow 失败，GitHub 会发失败通知（上线时实测 Hao Yin 能收到）；调度整体停摆由组长规则兜底（门禁检查 60 分钟没出来就停合并）。

## 组长 App osaka-lead
1. 只有 Checks 读写，只装在 OsakaConnect。组长核对完审阅、测试结论都写着当前 head、CI 和门禁检查都绿后，用 `/opt/osaka/as_lead.sh approve <PR号> <head>` 在 head 上写 `lead-merge-approved`。
2. 它在分支保护里是必过检查，来源锁定 osaka-lead 的 app_id；gate-summary 也核对来源。工作 App 没有 Checks 写权限，闸口 App 的写结果 job 不接受这个名字。
3. 私钥在共用机器上，别的 bot 理论上读得到。所以它防的是误操作（比如写手误合并），不是恶意。

## 规则
1. 任何 bot 不直接改本仓库，不用、不读闸口 App 私钥。私钥目前还在本机；发布链端到端验证通过后，只留在本仓库 Actions secrets（environment `gate`），从本机删除。
2. 所有 PR 一律按当前生效策略（策略仓库 main）检查；PR 自己对 `policy-proposals/` 的改动要合并、发布后才生效。
3. 本仓库连不上、无法回滚时，所有合并暂停，组长报告 Hao Yin。
4. 检查坏了先回滚：每个已发布 PR 是本仓库的一个提交，回滚只 revert 其中的策略文件，不倒退 processed_through，在 state.json 里把该提案记 rolled_back、追加 history 回滚记录、登记 divergence（否则轮询会把坏提案再发一次）；改过分支保护的要一起恢复。回滚由 Hao Yin 手动触发 `policy-rollback`（带 `rollback=<发布提交号>` 或 `skip=<PR号>`），它和发布串行、有超时，不依赖可能已坏的检查器。之后按常规流程修。
5. 发布、同步、恢复逻辑在 `.github/workflows/gatelib.py`，不调用 `scripts/`。`scripts/` 里的检查器只在 checks job 里跑，那里的令牌只有读和写 check 的权限；改检查器一律算权限类，要 Hao Yin 批。
6. OsakaConnect 的 `v*` tag 受 ruleset `protect-v-tags` 保护：可创建，不可删除、移动、强推，无人可绕过。
