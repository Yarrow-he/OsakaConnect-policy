#!/usr/bin/env python3
"""门禁检查器（纯逻辑，无网络、无令牌）。

policy-checks 的 compute job 运行：python3 gate.py <in目录> <out目录>
  in/config.json  {pr_size, ci_class, required, key_tests}（fetch 用 yq 从生效策略转成 JSON）
  in/global.json  {generation, paused, pending, owner}
  in/prs/<PR>.json 每个 PR 的数据（见 fetch）
输出 out/<PR>.json {pr, head, checks:[{name, conclusion|None, title, summary}]}，conclusion=None 表示还没出结果。
只依赖标准库，改本文件算权限类。
"""
import hashlib, json, os, re, sys

OWN = ("pr-size", "ci-approval-class", "owner-approval")
NOT_IN_SUMMARY = ("gate-summary", "lead-merge-approved") + OWN
ACTIONS_APP = 15368
# 真名检查：源码里不写明文。名字用拆开的正则（大小写、空格/下划线/点/连字符/连写都算），邮箱只存 sha256。
REALNAME_RE = re.compile(r"(?<![a-z])ha[o][\s_.\-]*yi[n](?![a-z])", re.I)
BAD_EMAIL_SHA = {"12bc2f211a7d8c1a7b4924029b7e26250821d2ee3199d8aa16041700397409b5"}
EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+")
LANG = {".py": "python", ".kt": "kotlin", ".cs": "csharp", ".kts": "kts", ".yml": "yaml",
        ".yaml": "yaml", ".sh": "shell", ".ps1": "powershell"}
SCHEMA = {
    "pr-size.yaml": {"threshold", "exclude_paths", "scaffold_temp", "log_functions", "comment_syntax"},
    "required-checks.yaml": {"repo", "branch", "strict", "branch_protection", "gate_verified"},
    "key-acceptance-tests.yaml": {"tests"},
    "ci-approval-class.yaml": {"yarrow_classes", "proposal_paths", "scope"},
}
PROPOSAL_RE = re.compile(r"^policy-proposals/((required-checks|key-acceptance-tests|pr-size|ci-approval-class)\.yaml"
                         r"|scripts/[A-Za-z0-9._-]+(/[A-Za-z0-9._-]+)*)$")


def glob_re(pat):
    out, i = "", 0
    while i < len(pat):
        if pat.startswith("**/", i):
            out += "(?:.*/)?"; i += 3
        elif pat.startswith("**", i):
            out += ".*"; i += 2
        elif pat[i] == "*":
            out += "[^/]*"; i += 1
        elif pat[i] == "?":
            out += "[^/]"; i += 1
        else:
            out += re.escape(pat[i]); i += 1
    return re.compile("^" + out + "$")


def match_any(path, pats):
    return any(glob_re(p).match(path) for p in pats)


def lang_of(path):
    for ext, lang in LANG.items():
        if path.endswith(ext):
            return lang
    return None


_STR = re.compile(r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'')


def is_log_line(s, funcs):
    for f in funcs:
        if s.startswith(f + "("):
            m = re.match(re.escape(f) + r"\((.*)\)\s*;?$", s)
            if not m:
                return False
            args = _STR.sub('""', m.group(1))
            return "(" not in args and ")" not in args and "=" not in args
    return False


def count_patch(path, patch, cfg):
    """数一个文件补丁里要计入的改动行（+ 和 - 行，去掉空行、注释、单条日志调用）。"""
    lang = lang_of(path)
    syn = (cfg.get("comment_syntax") or {}).get(lang, {}) if lang else {}
    line_d = syn.get("line", [])
    blocks = syn.get("block", [])
    logs = (cfg.get("log_functions") or {}).get(lang, []) if lang else []
    n = 0
    in_block = None          # 当前块注释的结束符
    prev_code = ""           # 上一条非空代码行（用来判断 docstring 位置）
    at_file_start = False
    for raw in patch.split("\n"):
        if raw.startswith("@@"):
            in_block, prev_code = None, ""
            at_file_start = bool(re.match(r"@@ -\d+(,\d+)? \+1(,|\s)", raw))
            continue
        if not raw or raw[0] not in " +-" or raw.startswith("\\"):
            continue
        kind, s = raw[0], raw[1:].strip()
        comment = False
        if in_block:
            comment = True
            if in_block in s:
                in_block = None
        elif s == "":
            comment = True
        elif any(s.startswith(d) for d in line_d):
            comment = True
        else:
            for op, cl in blocks:
                if s.startswith(op):
                    comment = True
                    if cl not in s[len(op):]:
                        in_block = cl
                    break
            if not comment and lang == "python" and syn.get("docstring_only") and s[:3] in ('"""', "'''"):
                q = s[:3]
                pos = at_file_start and prev_code == "" or re.match(r"^(async\s+def|def|class)\b.*:\s*(#.*)?$", prev_code)
                if pos:
                    comment = True
                    if q not in s[3:]:
                        in_block = q
        if not comment and logs and is_log_line(s, logs):
            comment = True
        if s and not comment:
            prev_code = s
        if kind in "+-" and not comment:
            n += 1
    return n


def pr_size(files, cfg):
    """返回 (conclusion, summary)。"""
    total, binaries, lines = 0, [], []
    ex = (cfg.get("exclude_paths") or []) + (cfg.get("scaffold_temp") or [])
    for f in files:
        path = f["filename"]
        if match_any(path, ex) and (not f.get("previous_filename") or match_any(f["previous_filename"], ex)):
            continue
        if f.get("binary"):
            c = 1; binaries.append(path)
        elif f.get("patch") is None:
            c = f.get("additions", 0) + f.get("deletions", 0)   # 补丁太大没给：按原始行数计，偏严
        else:
            c = count_patch(path, f["patch"], cfg)
        total += c
        if c:
            lines.append(f"{path}: {c}")
    th = int(cfg["threshold"])
    summ = f"计入 {total} 行（阈值 {th}）\n" + "\n".join(lines)
    if binaries:
        summ += "\n二进制文件（各按 1 行）：" + ", ".join(binaries)
    return ("success" if total <= th else "failure"), summ


def _rc_set(d):
    s = set()
    for layer in ("branch_protection", "gate_verified"):
        for e in (d or {}).get(layer) or []:
            s.add((layer, e["context"], json.dumps(e.get("expected_source"), sort_keys=True)))
    return s


GATE_APP = 5592067
GATE_WRITES = ("pr-size", "ci-approval-class", "owner-approval", "gate-summary")
LEAD_APP = 5594597


def validate(name, d):
    """提案 YAML 的结构校验（第 n7impl1 轮 A②、B①②）：坏配置发布后会让全仓卡死，所以合并前就报红。"""
    errs = []
    if name == "required-checks.yaml":
        for layer in ("branch_protection", "gate_verified"):
            if not isinstance(d.get(layer) or [], list):
                errs.append(f"{layer} 不是列表"); continue
            for e in d.get(layer) or []:
                c = e.get("context") if isinstance(e, dict) else None
                a = (e.get("expected_source") or {}).get("app_id") if isinstance(e, dict) else None
                if not isinstance(c, str) or not c or type(a) is not int:
                    errs.append(f"{layer} 条目缺 context 或 app_id 不是整数：{e}"); continue
                if a == GATE_APP and c not in GATE_WRITES:
                    errs.append(f"{c}：闸口 App 不写这个检查（只写 {', '.join(GATE_WRITES)}），先改 policy-checks")
                if a == LEAD_APP and c != "lead-merge-approved":
                    errs.append(f"{c}：组长 App 只写 lead-merge-approved")
        if not isinstance(d.get("strict"), bool):
            errs.append("strict 不是 true/false")
    elif name == "ci-approval-class.yaml":
        sc = d.get("scope")
        if not isinstance(sc, dict) or not isinstance(sc.get("branch_kinds"), list) \
                or not all(isinstance(k, dict) and isinstance(k.get("prefix"), str) and k["prefix"].endswith("/")
                           and (k.get("paths") == "global" or isinstance(k.get("paths"), list)) for k in sc["branch_kinds"]):
            errs.append("scope.branch_kinds 结构不对（每项要 prefix 以 / 结尾、paths 为列表或 global）")
        if not ((d.get("yarrow_classes") or {}).get("6_protected_config") or {}).get("paths"):
            errs.append("缺 6_protected_config.paths")
    elif name == "key-acceptance-tests.yaml":
        tests = d.get("tests")
        if not isinstance(tests, list) or not tests:
            errs.append("tests 为空或不是列表")
        for t in tests or []:
            if not (isinstance(t, dict) and all(isinstance(t.get(k), str) and t.get(k) for k in ("id", "entry", "job"))
                    and isinstance(t.get("paths"), list) and all(isinstance(x, str) for x in t["paths"])):
                errs.append(f"关键验收测试条目字段不全：{t}")
    elif name == "pr-size.yaml":
        if type(d.get("threshold")) is not int:
            errs.append("threshold 不是整数")
        for k in ("exclude_paths", "scaffold_temp"):
            if not isinstance(d.get(k) or [], list):
                errs.append(f"{k} 不是列表")
    return errs


def in_prefixes(path, prefixes):
    """board.json scope 的写法：以 / 结尾是目录前缀，否则是整文件。"""
    return any(path == p or (p.endswith("/") and path.startswith(p)) for p in prefixes)


def _shown(path):
    return "（文件名含敏感内容，不显示）" if _bad(path) else path


def board_perm(board, task_keys, module_keys):
    """board.json 里和权限有关的部分：任务/进度类顶层键以外的全部，modules 只留 module_keys。"""
    if not isinstance(board, dict):
        return None
    out = {k: v for k, v in board.items() if k not in task_keys and k != "modules"}
    mods = board.get("modules")
    out["modules"] = [{k: m.get(k) for k in module_keys} if isinstance(m, dict) else m for m in mods] \
        if isinstance(mods, list) else mods
    return out


def scope_check(pr, ci_cfg):
    """业务 PR 的改动范围检查（替代业务仓库的 check-scope.sh）。返回 (errors, reasons)。
    范围只读业务仓库 main 上 board.json 的 scope/modules（fetch 取，PR 里的那份不生效）；
    分支名只用来选范围，不给任何例外；受保护路径（第 6 类）进 Yarrow 档，不靠关键词；
    删除、改名（新旧两个路径）照常检查；分支对不上模块也对不上 branch_kinds 就拦。只报规则和路径，不回显内容。"""
    sc = ci_cfg.get("scope")
    if not isinstance(sc, dict):
        return ["scope 配置缺失"], []
    errs, reasons = [], []
    if pr.get("base_ref") != "main":
        return [f"base 分支不是 main（{pr.get('base_ref')!r}）"], []
    ref = pr.get("head_ref")
    if not isinstance(ref, str) or not ref:
        return ["读不到 PR 的 head 分支名"], []
    mb = pr.get("main_board")
    if not isinstance(mb, dict) or not isinstance(mb.get("scope"), dict) or not isinstance(mb.get("modules"), list):
        return ["读不到业务仓库 main 上 board.json 的 scope/modules"], []
    glob_ = mb["scope"].get("global") or []
    strs = lambda x: isinstance(x, list) and all(isinstance(i, str) for i in x)
    if not strs(glob_) or not all(isinstance(m, dict) and strs(m.get("paths") or []) for m in mb["modules"]):
        return ["main 上 board.json 的 scope.global 或 modules[].paths 不是字符串列表"], []
    if not all(strs(sc.get(k) or []) for k in ("module_extra", "board_task_keys", "board_module_keys")):
        return ["ci-approval-class 的 scope 配置类型不对"], []
    prot = (ci_cfg["yarrow_classes"].get("6_protected_config") or {}).get("paths") or []
    if not prot:
        return ["ci-approval-class 缺 6_protected_config"], []
    mod, best = None, -1
    for m in mb["modules"]:
        b = m.get("branch") if isinstance(m, dict) else None
        if isinstance(b, str) and b and (ref == b or ref.startswith(b + "-")) and len(b) > best:
            mod, best = m, len(b)
    if mod is not None:
        allowed, label = list(mod.get("paths") or []) + list(sc.get("module_extra") or []), f"模块 {mod.get('id')}"
    else:
        kind = next((k for k in sc.get("branch_kinds") or [] if ref.startswith(k["prefix"])), None)
        if kind is None:
            return [f"分支 {ref} 对不上 main 上 board.json 的任何模块，也不属于 {[k['prefix'] for k in sc.get('branch_kinds') or []]}"], []
        allowed = glob_ if kind["paths"] == "global" else kind["paths"]
        label = f"{kind['prefix']} 类分支"
    for f in pr.get("files") or []:
        for p in [f["filename"]] + ([f["previous_filename"]] if f.get("previous_filename") else []):
            if match_any(p, prot):
                reasons.append(f"6_protected_config: {_shown(p)}")
                continue
            if PROPOSAL_RE.match(p):
                continue        # 策略提案路径由提案白名单和第 2~5 类管，不走 board.json 范围
            if not in_prefixes(p, glob_):
                errs.append(f"scope: {_shown(p)} 不在 main 的 scope.global 里")
            elif not in_prefixes(p, allowed):
                errs.append(f"scope: {_shown(p)} 超出{label}的范围")
    bc = pr.get("board_change")
    if bc is not None:
        if bc.get("error"):
            errs.append("board.json 解析失败（内容不回显）")
        else:
            tk, mk = sc.get("board_task_keys") or [], sc.get("board_module_keys") or ["id", "branch", "paths"]
            b, h = board_perm(bc.get("base"), tk, mk), board_perm(bc.get("head"), tk, mk)
            if b != h:
                keys = sorted(k for k in set(b or {}) | set(h or {}) if (b or {}).get(k) != (h or {}).get(k)) if b and h else ["整个文件"]
                reasons.append(f"7_board_scope: board.json 权限相关字段变了：{', '.join(keys)}")
    return errs, reasons


def approval_class(files, yamls, ci_cfg, ps_cfg, known_checks=(), extra=((), ())):
    """返回 (conclusion, cls, reasons)。cls: yarrow|regular。yamls: {路径: {base, head, error}}（JSON 化后的提案 YAML）。"""
    errors, reasons = list(extra[0]), list(extra[1])
    classes = ci_cfg["yarrow_classes"]
    for f in files:
        names = [f["filename"]] + ([f["previous_filename"]] if f.get("previous_filename") else [])
        for p in names:
            if p.startswith("policy-proposals/") and (p.startswith("policy-proposals/.github/") or not PROPOSAL_RE.match(p)):
                errors.append(f"不允许的提案路径：{p}")
            for cname, rule in classes.items():
                pats = [x for x in (rule.get("paths") or []) if not x.startswith("policy-repo:")]
                if match_any(p, pats):
                    reasons.append(f"{cname}: {p}")
        changed = []
        for ln in (f.get("patch") or "").split("\n"):
            if ln[:1] in "+-" and not ln.startswith(("+++", "---")):
                changed.append(ln[1:])
        txt = "\n".join(changed)
        for pat in classes.get("1_secrets", {}).get("diff_patterns") or []:
            if re.search(pat, txt):
                reasons.append(f"1_secrets: {f['filename']} 命中 {pat}"); break
        if f["filename"].startswith(".github/"):
            for pat in classes.get("2_permissions", {}).get("diff_patterns") or []:
                if re.search(pat, txt):
                    reasons.append(f"2_permissions: {f['filename']} 命中 {pat}"); break
    builtin = ps_cfg.get("comment_syntax") or {}
    for path, v in sorted(yamls.items()):
        name = path.rsplit("/", 1)[-1]
        if v.get("error"):
            errors.append(f"{path} 解析失败：{v['error']}"); continue
        base, head = v.get("base"), v.get("head")
        if head is not None:
            if not isinstance(head, dict):
                errors.append(f"{path} 顶层不是映射"); continue
            unknown = set(head) - SCHEMA.get(name, set())
            if unknown:
                errors.append(f"{path} 有未知键：{sorted(unknown)}")
            errors += [f"{path}: {e}" for e in validate(name, head)]
        if name == "key-acceptance-tests.yaml" and base != head:
            reasons.append(f"3_key_acceptance_list: {path}")
        elif name == "pr-size.yaml":
            b, h = base or {}, head or {}
            for k in ("threshold", "exclude_paths", "scaffold_temp", "log_functions"):
                if b.get(k) != h.get(k):
                    reasons.append(f"4_pr_size: {path} 的 {k}")
            for lang, syn in (h.get("comment_syntax") or {}).items():
                cand = builtin.get(lang)
                if cand is None or not set(syn.get("line", [])) <= set(cand.get("line", [])) \
                        or not {tuple(x) for x in syn.get("block", [])} <= {tuple(x) for x in cand.get("block", [])} \
                        or syn.get("docstring_only", cand.get("docstring_only")) != cand.get("docstring_only"):
                    errors.append(f"{path} comment_syntax.{lang} 不在内置候选里")
        elif name == "required-checks.yaml":
            b, h = base or {}, head or {}
            if _rc_set(b) - _rc_set(h):
                reasons.append(f"5_loosen_gate: {path} 删除或改宽了必过检查")
            if b.get("strict") is True and h.get("strict") is not True:
                reasons.append(f"5_loosen_gate: {path} strict 变宽")
            if base is not None and (b.get("repo") != h.get("repo") or b.get("branch") != h.get("branch")):
                reasons.append(f"5_loosen_gate: {path} 改了 repo/branch")
            try:
                for layer, ctx, src in sorted(_rc_set(h) - _rc_set(b)):
                    if json.loads(src).get("app_id") == ACTIONS_APP and ctx not in known_checks:
                        errors.append(f"{path}: 新加的业务检查 {ctx} 在本 PR head 上还没出现过，可能写错名字，会卡死全仓")
            except (KeyError, TypeError, AttributeError):
                pass   # 结构错误上面 validate 已报
        elif name == "ci-approval-class.yaml" and base != head:
            reasons.append(f"5_loosen_gate: {path}（分档规则任何改动都按第⑤类）")
    if errors:
        return "failure", "error", "\n".join(errors + reasons)
    if reasons:
        return "success", "yarrow", "Yarrow 档：\n" + "\n".join(sorted(set(reasons)))
    return "success", "regular", "常规档"


def owner_approval(cls, reviews, head, owner):
    if cls == "regular":
        return "success", "常规档，不需要 Yarrow 批准"
    if cls != "yarrow":
        return "failure", "分档失败，无法判断"
    last = None
    for r in reviews:          # API 按时间顺序返回
        if (r.get("user") or "").lower() == owner.lower() and r.get("state") in ("APPROVED", "CHANGES_REQUESTED", "DISMISSED"):
            last = r
    if last and last["state"] == "APPROVED" and last.get("commit_id") == head:
        return "success", f"Yarrow 已批准当前 head {head[:10]}"
    return "failure", "Yarrow 档：需要 Yarrow 对当前 head 的批准"


def check_status(runs, name, app_id):
    """同名、同来源的检查：每个 check suite 取最新一次，全部 success 才算过。
    闸口 App 没有 actions:read，核不了 workflow 路径；按 suite 全部要求 success，PR 新加同名假 job 也盖不掉真 job 的失败。"""
    latest = {}
    for r in runs:
        if r["name"] == name and r["app_id"] == app_id:
            k = r.get("suite")
            if k not in latest or r["id"] > latest[k]["id"]:
                latest[k] = r
    if not latest:
        return None, "还没有结果"
    if any(r["status"] != "completed" for r in latest.values()):
        return None, "还在跑"
    bad = [r["conclusion"] for r in latest.values() if r["conclusion"] != "success"]
    return ("failure", f"结论 {bad}") if bad else ("success", "success")


def key_tests(kcfg, head_paths, ci_jobs):
    tests = (kcfg or {}).get("tests") or []
    if not tests:
        return ["关键验收测试清单为空或缺失"]
    if head_paths is None or ci_jobs is None:
        return ["读不到 head 的文件树或 ci.yml"]
    errs = []
    for t in tests:
        for p in t.get("paths") or []:
            if p not in head_paths:
                errs.append(f"{t['id']}: 缺文件 {p}")
        job = (ci_jobs.get("jobs") or {}).get(t.get("job"))
        if job is None:
            errs.append(f"{t['id']}: ci.yml 没有 job {t.get('job')}")
        elif t["entry"] not in json.dumps(job, ensure_ascii=False):
            errs.append(f"{t['id']}: job {t['job']} 没引用 {t['entry']}")
    return errs


def _bad(text):
    text = text or ""
    if REALNAME_RE.search(text):
        return True
    return any(hashlib.sha256(m.rstrip(".-").lower().encode()).hexdigest() in BAD_EMAIL_SHA for m in EMAIL_RE.findall(text))


def realname(pr):
    """返回命中位置列表（不回显命中的内容）。只看新增行、文件名、提交信息、作者/提交者、PR 标题正文。"""
    hits = []
    for k, f in enumerate(pr.get("files") or [], 1):
        where = f"第 {k} 个文件" if _bad(f["filename"]) else f["filename"]   # 文件名本身带真名就只报序号
        if where != f["filename"]:
            hits.append(where + "的文件名")
        added = [ln[1:] for ln in (f.get("patch") or "").split("\n") if ln.startswith("+") and not ln.startswith("+++")]
        if any(_bad(x) for x in added):
            hits.append(where + " 的新增行")
    m = pr.get("meta")
    if m is None:
        return ["缺 PR 元数据"]
    if _bad(m.get("title")):
        hits.append("PR 标题")
    if _bad(m.get("body")):
        hits.append("PR 正文")
    for i, c in enumerate(m.get("commits") or [], 1):
        if _bad(c.get("message")):
            hits.append(f"第 {i} 个提交的提交信息")
        if any(_bad(x) for x in c.get("names") or []):
            hits.append(f"第 {i} 个提交的作者/提交者")
    return hits


ME = ("Yarrow", "318895665+Yarrow-he@users.noreply.github.com")
GH_WEB = ("GitHub", "noreply@github.com")   # 网页上 Update branch / merge 生成的提交，提交人是 GitHub


def author_check(pr):
    """每个提交的作者和提交人都得是 Yarrow 加 noreply；网页生成的提交只放行提交人。只报序号和字段。"""
    hits = []
    for i, c in enumerate((pr.get("meta") or {}).get("commits") or [], 1):
        n = list(c.get("names") or []) + [None] * 4
        if tuple(n[0:2]) != ME:
            hits.append(f"第 {i} 个提交的作者")
        if tuple(n[2:4]) not in (ME, GH_WEB):
            hits.append(f"第 {i} 个提交的提交人")
    return hits


def evaluate(pr, cfg, glob):
    """算一个 PR 的四个门禁检查。返回 checks 列表。"""
    out = []
    if glob.get("paused"):
        msg = f"策略暂停（{glob['paused'].get('by')}），gen={glob['generation']}"
        return [{"name": "gate-summary", "conclusion": "failure", "title": "策略暂停", "summary": msg}]
    if pr.get("incomplete"):
        why = "数据不全：" + pr["incomplete"]
        return [{"name": n, "conclusion": "failure", "title": "数据不全", "summary": why} for n in OWN + ("gate-summary",)]
    files = pr["files"]
    try:
        c, s = pr_size(files, cfg["pr_size"])
    except Exception as e:  # 一个检查器出错只让它自己失败
        c, s = "failure", f"pr-size 出错：{e!r}"
    out.append({"name": "pr-size", "conclusion": c, "title": "pr-size", "summary": s})
    try:
        known = {r["name"] for r in pr.get("check_runs") or [] if r["app_id"] == ACTIONS_APP} | set(pr.get("check_names") or [])
        extra = scope_check(pr, cfg["ci_class"])
        c2, cls, s2 = approval_class(files, pr.get("proposal_yaml") or {}, cfg["ci_class"], cfg["pr_size"], known, extra)
    except Exception as e:
        c2, cls, s2 = "failure", "error", f"ci-approval-class 出错：{e!r}"
    out.append({"name": "ci-approval-class", "conclusion": c2, "title": f"class={cls}", "summary": s2})
    c3, s3 = owner_approval(cls, pr.get("reviews") or [], pr["head"], glob["owner"])
    out.append({"name": "owner-approval", "conclusion": c3, "title": "owner-approval", "summary": s3})

    fails, pend = [], []
    rn = realname(pr)
    if rn:
        fails.append("真名：不能出现用户真名或个人邮箱，一律写 Yarrow，邮箱用 GitHub noreply。位置：" + "；".join(rn))
    au = author_check(pr)
    if au:
        fails.append("作者：作者和提交人都要写 Yarrow 和 noreply 邮箱。不对的：" + "；".join(au))
    for o in out:
        if o["conclusion"] != "success":
            fails.append(f"{o['name']}: {o['conclusion']}")
    if glob.get("pending"):
        fails.append("有已合并未发布的策略提案，等发布后重检：" + glob["pending"])
    rc = cfg["required"]
    for e in (rc.get("branch_protection") or []) + (rc.get("gate_verified") or []):
        if e["context"] in NOT_IN_SUMMARY:
            continue
        st, why = check_status(pr.get("check_runs") or [], e["context"], e["expected_source"]["app_id"])
        if st is None:
            pend.append(f"{e['context']}: {why}")
        elif st != "success":
            fails.append(f"{e['context']}: {why}")
    if any(f["filename"].startswith("policy-proposals/scripts/") or
           (f.get("previous_filename") or "").startswith("policy-proposals/scripts/") for f in files):
        st, why = check_status(pr.get("check_runs") or [], "policy-selftest", ACTIONS_APP)
        if st is None:
            pend.append(f"policy-selftest: {why}")
        elif st != "success":
            fails.append(f"policy-selftest: {why}")
    fails += key_tests(cfg.get("key_tests"), set(pr["head_paths"]) if pr.get("head_paths") is not None else None,
                       pr.get("ci_jobs"))
    if fails:
        concl, title = "failure", "门禁未通过"
    elif pend:
        concl, title = None, "等待其他检查"
    else:
        concl, title = "success", "门禁通过"
    summ = "\n".join(fails + pend) or "全部通过"
    out.append({"name": "gate-summary", "conclusion": concl, "title": title, "summary": f"gen={glob['generation']}\n" + summ})
    return out


def main(ind, outd):
    cfg = json.load(open(os.path.join(ind, "config.json")))
    glob = json.load(open(os.path.join(ind, "global.json")))
    os.makedirs(outd, exist_ok=True)
    pdir = os.path.join(ind, "prs")
    for fn in sorted(os.listdir(pdir)):
        pr = json.load(open(os.path.join(pdir, fn)))
        try:
            checks = evaluate(pr, cfg, glob)
        except Exception as e:
            checks = [{"name": "gate-summary", "conclusion": "failure", "title": "检查器出错", "summary": repr(e)}]
        with open(os.path.join(outd, f"{pr['pr']}.json"), "w") as fh:
            json.dump({"pr": pr["pr"], "head": pr["head"], "checks": checks}, fh, ensure_ascii=False)


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])
