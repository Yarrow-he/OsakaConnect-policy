# 策略状态记录（实现版，2026-11-04 按 Yarrow"最简、只修严重问题"简化）

## 1. 唯一状态文件 `state/state.json`
```json
{
 "schema": 1,
 "generation": 3,                         // 每次发布、回滚、作废、引导 +1；gate-summary 和 as_lead.sh 用它
 "paused": null,                          // 只在上线引导前是 {"by": "bootstrap"}；暂停时 publish 不发布，checks 给所有 PR 写 gate-summary=failure
 "processed_through": "<OsakaConnect 合并提交号>",   // 已处理到的提案合并
 "active": {"from_merge": "<sha>", "pr": 123, "generation": 3},
 "proposals": {"123": {"merge": "<sha>", "head": "<sha>", "result": "published|failed|skipped|rolled_back", "reason": "...", "generation": 3}},
 "divergence": [{"path": "scripts/gate.py", "business_blob": "<sha|null>", "effective_blob": "<sha|null>"}],
 "history": [{"generation": 3, "kind": "publish|rollback|skip|bootstrap", "pr": 123, "from_merge": "<sha>", "rollback_of": "<sha>"}]
}
```
- 生效策略 = 策略仓库 main 当前内容。每次发布、回滚、作废都是**一个**提交：策略文件和 state.json 一起改，用 Git Data API 建提交后非强制更新 main；远端变了就失败（retryable），下一轮从头读。所以没有多阶段事务，也不需要续跑、接管。
- 有没有待发布的提案：`processed_through` 和 OsakaConnect main 的 `policy-proposals/` 目录树 sha 不同就算有。有就让所有 PR 的 gate-summary=failure，`as_lead.sh merge` 也沿 first-parent 链独立再查一次。

## 2. 发布（policy-publish，每 5 分钟）
1. paused 不为空 => 不发布；没有待发布 => noop。
2. 沿 main 的 first-parent 链找 processed_through 之后第一个改了 `policy-proposals/` 的提交 M，核对：两个父提交；对应 PR 的 head 是第二个父提交；该 head 上最新的 gate-summary（闸口 App 写的、给这个 PR）是 success（它已核过业务 CI、分档和 Yarrow 批准）；改动路径都在写死的白名单里，不是符号链接或子模块；基线：策略仓库现有内容 = M 第一个父提交里的内容；登记了 divergence 的文件只接受"恢复成生效内容"的补偿提案，并清掉登记。
3. 通过 => 同一个提交写策略文件 + state（generation+1、processed_through=M），再在 M 上写 `policy-published=success`。
4. 不通过 => 在 state 里记该提案 failed 和原因（只记一次），job 失败（GitHub 通知 Yarrow），队列停在这里，等 Yarrow `skip` 或在业务仓库修。
5. 每次运行最后都调用 policy-sync-protection：把 OsakaConnect main 的必过检查对齐策略仓库 main 上 `required-checks.yaml` 的 branch_protection 层和 strict（gate-summary、lead-merge-approved 已在线上时不删）。所以分支保护没有单独的"同步阶段"，下一轮自动收敛。

## 3. 恢复（policy-rollback，只有 Yarrow 能触发，三选一）
- `rollback=<策略仓库发布提交号>`：只把那次发布改的策略文件恢复成发布前内容（文件发布后又被改过就拒绝，先回滚后面的），提案记 rolled_back，文件登记 divergence，generation+1，不倒退 processed_through。之后同步分支保护。组长在业务仓库提交补偿 revert，发布时清掉登记。
- `skip=<PR号>`：作废发布失败、卡住队列的提案：processed_through 前进到它的合并，记 skipped，它改的文件登记 divergence，不改策略文件。
- `bootstrap=<引导合并提交号>`：上线第 9 步。核对业务仓库该提交的 `policy-proposals/` 和策略仓库逐个 blob 一致后，paused=null、processed_through=该提交、generation+1。

## 4. 已按 Yarrow 决定不做的（低概率，出问题再补）
合并时核对策略版本、回滚时冻结合并（merge-freeze）、selftest 断网、门禁停摆自动检测、旧 CI 结果、合并后批准审计、ETag 缓存、多阶段事务和接管。

## 5. 手动回滚（Actions 本身坏了时的兜底；Yarrow 用自己的账号，按临时管理员放行操作）
1. 通知组长暂停合并；在策略仓库 Actions 里 Disable policy-checks、policy-publish，取消正在跑的运行。
2. 打开放行（`policy-main` → Bypass list → Repository admin）。
3. clone 策略仓库，`git revert --no-commit <发布提交号>`，再 `git restore --staged --worktree state/`（state 不能倒退）。
4. 手工改 state.json：generation+1；该提案 result=rolled_back；改过的文件登记进 divergence；history 追加一条 rollback。和策略文件放在同一个提交里，`git push`（不强推）。
5. 被回滚的提案改过必过检查的：在 OsakaConnect → Settings → Branches → main 按回滚后的 `required-checks.yaml` 手动恢复。
6. 关闭放行并刷新确认绕过名单只剩闸口 App；修好 Actions 后 Enable 两个 workflow，手动跑一次 policy-checks。
