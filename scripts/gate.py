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
    "pr-size.yaml": {"threshold", "exclude_paths", "scaffold_temp", "log_functions", "comment_syntax",
                     "breakdown_over", "breakdown_categories"},
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


def _interp_risky(args):
    """插值 { ... }（含嵌套）里有 ()= 就视为含调用/赋值。按配对花括号扫，不丢外层。"""
    i, n = 0, len(args)
    while i < n:
        if args[i] == "{":
            depth, j, body = 1, i + 1, []
            while j < n and depth:
                if args[j] == "{":
                    depth += 1
                elif args[j] == "}":
                    depth -= 1
                if depth:
                    body.append(args[j])
                j += 1
            if any(ch in "".join(body) for ch in "()="):
                return True
            i = j
        else:
            i += 1
    return False


def is_log_line(s, funcs):
    """单条日志调用、参数里无函数调用或赋值才排除。插值（含嵌套字典参数）里有 ()= 的，整行计入。"""
    for f in funcs:
        if s.startswith(f + "("):
            m = re.match(re.escape(f) + r"\((.*)\)\s*;?$", s)
            if not m:
                return False
            args = m.group(1)
            if _interp_risky(args):
                return False
            args = _STR.sub('""', args)
            return "(" not in args and ")" not in args and "=" not in args
    return False

def count_patch(path, patch, cfg, full=None, collect=None):
    """数一个文件补丁里要计入的行：只数新文件里的运行代码（规则【PR 行数检查】），纯删除不计，
    去掉空行、注释、单条日志调用。
    full={"old": 旧文件全文, "new": 新文件全文} 时（第五轮），按两侧整份文件逐行算注释状态，再按 hunk 头的行号对上补丁：
    + 行新侧是运行代码就计入；上下文行旧侧不是运行代码、新侧是（删掉了块注释边界，哪怕边界在别的 hunk 里）也计入。
    没有全文时退回按 hunk 局部跟踪（第三轮的做法）。
    多行字符串（Python/Kotlin/C# 的三引号）里的行一律算运行代码，里面的 /* # 不当注释（第五轮评审：偏严，不会漏计）。
    collect 是列表时，把“旧侧不是运行代码、新侧是”的上下文/补丁外行的内容追加进去（给密钥扫描用）。"""
    lang = lang_of(path)
    syn = (cfg.get("comment_syntax") or {}).get(lang, {}) if lang else {}
    line_d = syn.get("line", [])
    blocks = syn.get("block", [])
    logs = (cfg.get("log_functions") or {}).get(lang, []) if lang else []
    tq = {"python": ('"""', "'''"), "kotlin": ('"""',), "kts": ('"""',), "csharp": ('"""',)}.get(lang, ())

    def code_after(rest):
        """块注释结束后剩下的部分是不是运行代码。"""
        rest = rest.strip()
        if rest == "" or any(rest.startswith(d) for d in line_d):
            return False
        for op, cl in blocks:
            if rest.startswith(op):
                r2 = rest[len(op):]
                return cl in r2 and code_after(r2.split(cl, 1)[1])
        return True

    def classify(s, st):
        """这一行是不是“不计入”（注释/空行/日志），并更新这一侧的状态 st。"""
        comment = False
        if st.get("str"):            # 在多行字符串里：整行是代码，看有没有收尾
            kind = st["str"]
            if kind == "tq":
                if s.count(st["q"]) % 2 == 1:
                    st.pop("str", None); st.pop("q", None)
            elif kind == "csharp_verb":
                if s.replace('""', "").count('"') % 2 == 1:
                    st.pop("str", None)
            elif kind == "ps_here_d":
                if s.rstrip().endswith('"@'):
                    st.pop("str", None)
            elif kind == "ps_here_s":
                if s.rstrip().endswith("'@"):
                    st.pop("str", None)
            else:  # 旧格式兼容：直接存引号本身
                if s.count(kind) % 2 == 1:
                    st.pop("str", None)
            st["prev"] = s or st["prev"]
            return False
        if st["blk"]:
            cl = st["blk"]
            if cl in s:
                st["blk"] = None
                comment = not code_after(s.split(cl, 1)[1])
            else:
                comment = True
        elif s == "":
            comment = True
        elif any(s.startswith(d) for d in line_d):
            comment = True
        else:
            for op, cl in blocks:
                if s.startswith(op):
                    rest = s[len(op):]
                    if cl not in rest:
                        comment, st["blk"] = True, cl
                    else:
                        comment = not code_after(rest.split(cl, 1)[1])   # /* x */ run(); 这种整行计入
                    break
            if not comment and lang == "python" and syn.get("docstring_only") and s[:3] in ('"""', "'''"):
                q = s[:3]
                pos = st["start"] and st["prev"] == "" or re.match(r"^(async\s+def|def|class)\b.*:\s*(#.*)?$", st["prev"])
                if pos:
                    st["start"] = False   # 第七轮：首条 docstring 位置只用一次
                    if q not in s[3:]:
                        comment, st["blk"] = True, q
                    else:
                        comment = not code_after(s[3:].split(q, 1)[1])  # """note"""; update() 整行计入
        if not comment and logs and is_log_line(s, logs):
            comment = True
        if not comment:
            opened = False
            for q in tq:             # 三引号未收尾
                if s.count(q) % 2 == 1:
                    st["str"], st["q"] = "tq", q; opened = True; break
            if not opened and lang == "csharp":
                i = s.find('@"')
                if i >= 0 and s[i+2:].replace('""', "").count('"') % 2 == 0:
                    st["str"] = "csharp_verb"; opened = True
            if not opened and lang == "powershell":
                if '@"' in s and not s.rstrip().endswith('"@'):
                    st["str"] = "ps_here_d"
                elif "@'" in s and not s.rstrip().endswith("'@"):
                    st["str"] = "ps_here_s"
        if s and not comment:
            st["prev"] = s
        return comment

    def flags(text):
        """整份文件逐行：True=运行代码。下标从 1 开始（0 位占位）。"""
        st = {"blk": None, "prev": "", "start": True}
        ls = (text or "").split("\n")      # 和 git/GitHub 补丁一样只按 \n 分行
        if ls and ls[-1] == "":
            ls.pop()
        return [False] + [not classify(x.rstrip("\r").strip(), st) for x in ls], [""] + ls

    n = 0
    if isinstance(full, dict) and isinstance(full.get("old"), str) and isinstance(full.get("new"), str):
        (fo, _), (fn, tn) = flags(full["old"]), flags(full["new"])
        # 补丁外没出现的行两侧原样对应（按 hunk 间的偏移），注释边界在别处被删，这些行也会从注释变成代码，一样要数
        po = pn = 1
        def gap(upto_new):
            nonlocal po, pn, n
            while pn < upto_new:
                if pn >= len(fn) or po >= len(fo):
                    raise ValueError("补丁和全文对不上")
                if fn[pn] and not fo[po]:
                    n += 1
                    if collect is not None:
                        collect.append(tn[pn])
                po += 1; pn += 1
        i = j = None
        for raw in patch.split("\n"):
            m = re.match(r"@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@", raw)
            if m:
                i0, j0 = int(m.group(1)), int(m.group(3))
                i = i0 if m.group(2) != "0" else i0 + 1        # ",0" 时行号指的是前一行
                j = j0 if m.group(4) != "0" else j0 + 1
                gap(j)
                if po != i:
                    raise ValueError("补丁和全文对不上")
                continue
            if not raw or raw[0] not in " +-" or raw.startswith("\\") or i is None:
                continue
            if raw[0] == "-":
                i += 1
            elif raw[0] == "+":
                if j >= len(fn):
                    raise ValueError("补丁行号超出新文件")   # 全文和补丁对不上：pr-size 报错（偏严）
                n += fn[j]; j += 1
            else:
                if i >= len(fo) or j >= len(fn):
                    raise ValueError("补丁行号超出文件")
                if fn[j] and not fo[i]:
                    n += 1
                    if collect is not None:
                        collect.append(tn[j])
                i += 1; j += 1
            po, pn = i, j
        gap(len(fn))
        if po != len(fo):
            raise ValueError("补丁和全文对不上")
        return n
    old = new = None
    for raw in patch.split("\n"):
        if raw.startswith("@@"):
            m = re.match(r"@@ -(\d+)(?:,\d+)? \+(\d+)", raw)
            old = {"blk": None, "prev": "", "start": bool(m and m.group(1) in ("0", "1"))}
            new = {"blk": None, "prev": "", "start": bool(m and m.group(2) in ("0", "1"))}
            continue
        if not raw or raw[0] not in " +-" or raw.startswith("\\") or new is None:
            continue
        kind, s = raw[0], raw[1:].strip()
        if kind == "-":
            classify(s, old)
        elif kind == "+":
            if not classify(s, new):
                n += 1
        else:
            was = classify(s, old)
            if not classify(s, new) and was:
                n += 1
    return n


def first_match(path, pats):
    for p in pats:
        if glob_re(p).match(path):
            return p
    return None


def pr_size(files, cfg):
    """返回 (conclusion, summary)。summary 列出逐文件计数，以及每个不计入文件命中的名单项（排除理由）。"""
    total, binaries, lines, excluded, approx_bad = 0, [], [], [], []
    ex_paths, scaf = cfg.get("exclude_paths") or [], cfg.get("scaffold_temp") or []
    for f in files:
        path = f["filename"]
        names = [path] + ([f["previous_filename"]] if f.get("previous_filename") and f.get("status") != "copied" else [])
        hits = [first_match(x, ex_paths) or first_match(x, scaf) for x in names]
        if all(hits):
            why = "；".join(f"{_shown(x)} 命中{'排除路径' if first_match(x, ex_paths) else '临时脚手架'} {h}" for x, h in zip(names, hits))
            excluded.append(f"{_shown(path)}: 不计入（{why}）")
            continue
        if f.get("binary"):
            c = 1; binaries.append(_shown(path))
        elif f.get("patch_approx"):
            approx_bad.append(path); continue
        elif f.get("patch") is None:
            c = f.get("additions", 0)   # 取数端没补出补丁时的兜底：只按新增行数计（不扣注释，偏严；删除不计）
            lines.append(f"{_shown(path)}: {c}（缺补丁，按新增行数计）")
            total += c
            continue
        else:
            c = count_patch(path, f["patch"], cfg, f.get("full"))
        total += c
        if c:
            lines.append(f"{_shown(path)}: {c}" + ("（补丁由取数端按文件内容补出）" if f.get("patch_synth") else ""))
    th = int(cfg["threshold"])
    summ = f"计入 {total} 行（阈值 {th}）\n" + "\n".join(lines)
    try:
        bd = breakdown(files, cfg)
    except Exception as e:   # 分类只是展示，出错不影响 pr-size 结论
        bd = f"分类行数算不出（{type(e).__name__}，不影响结论）"
    if bd:
        summ += "\n" + bd
    if binaries:
        summ += "\n二进制文件（各按 1 行）：" + ", ".join(binaries)
    if excluded:
        summ += "\n不计入的文件：\n" + "\n".join(excluded)
    if approx_bad:
        summ += "\n超过 10MB、不在排除名单里的文件无法精确计数，拆小或请 Yarrow 处理：" + ", ".join(_shown(p) for p in approx_bad)
    return ("success" if total <= th and not approx_bad else "failure"), summ


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
            for i, e in enumerate(d.get(layer) or []):
                c = e.get("context") if isinstance(e, dict) else None
                a = (e.get("expected_source") or {}).get("app_id") if isinstance(e, dict) else None
                if not isinstance(c, str) or not c or type(a) is not int:
                    errs.append(f"{layer} 第 {i+1} 条缺 context 或 app_id 不是整数"); continue
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
                           and (k.get("paths") == "global" or isinstance(k.get("paths"), list)
                                and all(isinstance(x, str) and x for x in k["paths"])) for k in sc["branch_kinds"]):
            errs.append("scope.branch_kinds 结构不对（每项要 prefix 以 / 结尾、paths 为列表或 global）")
        for k in ("branch_name_patterns", "bookkeeping_paths"):
            v = (sc or {}).get(k) if isinstance(sc, dict) else None
            if not (isinstance(v, list) and v and all(isinstance(x, str) and x for x in v)):
                errs.append(f"scope.{k} 缺失或不是非空字符串列表")
        mo = (sc or {}).get("bookkeeping_mix_ok_prefixes") if isinstance(sc, dict) else None
        if mo is not None and not (isinstance(mo, list) and all(isinstance(x, str) and x.endswith("/") for x in mo)):
            errs.append("scope.bookkeeping_mix_ok_prefixes 要是以 / 结尾的字符串列表")
        for x in ((sc or {}).get("branch_name_patterns") or []) if isinstance(sc, dict) else []:
            try:
                re.compile(x) if isinstance(x, str) else None
            except re.error:
                errs.append("scope.branch_name_patterns 有写错的正则")
        if not ((d.get("yarrow_classes") or {}).get("6_protected_config") or {}).get("paths"):
            errs.append("缺 6_protected_config.paths")
        if not isinstance(d.get("yarrow_classes"), dict):
            errs.append("yarrow_classes 不是映射")
        yc = d.get("yarrow_classes") if isinstance(d.get("yarrow_classes"), dict) else {}
        for cn, c in yc.items():
            if not isinstance(c, dict):
                errs.append(f"yarrow_classes.{cn} 不是映射"); continue
            for k in ("paths", "rules"):
                v = c.get(k)
                if v is not None and not (isinstance(v, list) and all(isinstance(x, str) and x for x in v)):
                    errs.append(f"{cn}.{k} 不是非空字符串列表")   # 第三轮：坏正则发布后会让相关 PR 一直报“出错”，合并前就拦
            for k in ("diff_patterns", "env_name_patterns"):
                v = c.get(k) if isinstance(c, dict) else None
                if v is None:
                    continue
                if not (isinstance(v, list) and all(isinstance(x, str) for x in v)):
                    errs.append(f"{cn}.{k} 不是字符串列表"); continue
                for x in v:
                    try:
                        re.compile(x)
                    except re.error:
                        errs.append(f"{cn}.{k} 有写错的正则")
    elif name == "key-acceptance-tests.yaml":
        tests = d.get("tests")
        if not isinstance(tests, list) or not tests:
            errs.append("tests 为空或不是列表")
        for i, t in enumerate(tests or []):
            if not (isinstance(t, dict) and all(isinstance(t.get(k), str) and t.get(k) for k in ("id", "entry", "job"))
                    and isinstance(t.get("paths"), list) and all(isinstance(x, str) for x in t["paths"])):
                errs.append(f"关键验收测试条目字段不全（第 {i+1} 条，不回显内容）")
    elif name == "pr-size.yaml":
        if type(d.get("threshold")) is not int:
            errs.append("threshold 不是整数")
        if "breakdown_over" in d and type(d["breakdown_over"]) is not int:
            errs.append("breakdown_over 不是整数")
        bc = d.get("breakdown_categories") or []
        if not (isinstance(bc, list) and all(isinstance(c, dict) and isinstance(c.get("name"), str)
                                              and isinstance(c.get("paths"), list)
                                              and all(isinstance(x, str) and x for x in c["paths"]) for c in bc)):
            errs.append("breakdown_categories 结构不对（每项要 name 和 paths 列表）")
        for k in ("exclude_paths", "scaffold_temp"):
            if not isinstance(d.get(k) or [], list):
                errs.append(f"{k} 不是列表")
    return errs


def in_prefixes(path, prefixes):
    """board.json scope 的写法：以 / 结尾是目录前缀，否则是整文件。"""
    return any(path == p or (p.endswith("/") and path.startswith(p)) for p in prefixes)


def _shown(path):
    return "（文件名含敏感内容，不显示）" if _bad(path) else path


def redact(text):
    """检查摘要出站前的兜底：真名和个人邮箱一律换成占位符。"""
    if not text:
        return text
    text = REALNAME_RE.sub("（已脱敏）", text)
    def hide(m):
        return "（已脱敏）" if hashlib.sha256(m.group(0).rstrip(".-").lower().encode()).hexdigest() in BAD_EMAIL_SHA else m.group(0)
    return EMAIL_RE.sub(hide, text)


def board_perm(board, task_keys, module_keys):
    """board.json 里和权限有关的部分：任务/进度类顶层键以外的全部，modules 只留 module_keys。"""
    if not isinstance(board, dict):
        return None
    out = {k: v for k, v in board.items() if k not in task_keys and k != "modules"}
    mods = board.get("modules")
    out["modules"] = [{k: m.get(k) for k in module_keys} if isinstance(m, dict) else m for m in mods] \
        if isinstance(mods, list) else mods
    return out



def breakdown(files, cfg):
    """PR 总改动（新增+删除，不论计不计入）超过 breakdown_over 时返回分类行数说明，否则返回空串。只输出，不影响结论。
    改名按新路径归类；类别按 breakdown_categories 顺序取第一个命中，都不命中算“运行代码和配置”。"""
    over = cfg.get("breakdown_over")
    if type(over) is not int:
        return ""
    tot = sum(int(f.get("additions") or 0) + int(f.get("deletions") or 0) for f in files)
    if tot <= over:
        return ""
    cats = cfg.get("breakdown_categories") or []
    agg = {}
    for f in files:
        name = next((c["name"] for c in cats if match_any(f["filename"], c.get("paths") or [])), "运行代码和配置")
        a, b = agg.get(name, (0, 0))
        agg[name] = (a + int(f.get("additions") or 0), b + int(f.get("deletions") or 0))
    rows = [f"{k}: +{a} -{b}" for k, (a, b) in sorted(agg.items(), key=lambda kv: -sum(kv[1]))]
    return f"总改动 {tot} 行（超过 {over}），分类：\n" + "\n".join(rows)


def lint(pr, ci_cfg):
    """分支命名、记账文件不混进功能 PR。返回失败原因列表（只报规则和路径，不回显内容）。"""
    sc = ci_cfg.get("scope") or {}
    out = []
    pats, bk = sc.get("branch_name_patterns"), sc.get("bookkeeping_paths")
    if not (isinstance(pats, list) and pats and isinstance(bk, list) and bk):
        return ["lint 配置缺失（scope.branch_name_patterns / bookkeeping_paths）"]
    ref = pr.get("head_ref")
    try:
        ok = isinstance(ref, str) and any(re.fullmatch(p, ref) for p in pats)
    except re.error:
        return ["lint 配置里的分支命名正则写错了"]
    if not ok:
        out.append(f"分支命名：{_shown(ref) if isinstance(ref, str) else ref!r} 不符合 <端>/<模块>-<序号>、ci/<内容>-<序号> 或 lead/、tests/、bookkeeping/ 加名字")
    # 改名看新旧两端；复制（copied）旧文件没动，只看新路径
    paths = [p for f in pr.get("files") or [] for p in [f["filename"]]
             + ([f["previous_filename"]] if f.get("previous_filename") and f.get("status") != "copied" else [])]
    book = [p for p in paths if in_prefixes(p, bk)]
    other = [p for p in paths if not in_prefixes(p, bk)]
    mix_ok = isinstance(ref, str) and any(ref.startswith(x) for x in (sc.get("bookkeeping_mix_ok_prefixes") or []))
    if book and other and not mix_ok:
        out.append("记账文件不许夹在功能 PR 里，单独开 bookkeeping/ PR：" + ", ".join(_shown(p) for p in sorted(set(book))[:10]))
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
        for p in [f["filename"]] + ([f["previous_filename"]] if f.get("previous_filename") and f.get("status") != "copied" else []):
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


def env_maps(node, where="", out=None):
    """收集 YAML（已转 JSON）里所有 env 映射的 (位置, 变量名, 值)，位置按键路径和列表下标记，同名同值出现在两处也分开算。"""
    out = set() if out is None else out
    if isinstance(node, dict):
        for k, v in node.items():
            if k == "env" and isinstance(v, dict):
                out |= {(where, str(a), json.dumps(b, sort_keys=True, ensure_ascii=False)) for a, b in v.items()}
            env_maps(v, f"{where}/{k}", out)
    elif isinstance(node, list):
        seen = {}
        for i, v in enumerate(node):
            # 第四轮：列表项（主要是 steps）有 id 按 id、有 name 按 name+同名序号认位置，都没有才用下标；
            # 这样前面插一步不会让后面没改的步骤 env 全算“改动”。同名同值出现两处仍分开算。
            if isinstance(v, dict) and isinstance(v.get("id"), str) and v["id"]:
                k = f"id={v['id']}"
            elif isinstance(v, dict) and isinstance(v.get("name"), str) and v["name"]:
                k = f"name={v['name']}"
            elif isinstance(v, dict) and any(isinstance(v.get(x), str) and v[x] for x in ("uses", "run")):
                # 第五轮：没 id 没 name 的步骤按 uses+run+with 的内容指纹认（不含 env）；同指纹按出现序号区分。
                # 步骤本身改了内容就认成新步骤，它的 env 会算“删一份、加一份”（偏严，不会漏）。
                fp = json.dumps({x: v.get(x) for x in ("uses", "run", "with", "shell", "working-directory")}, sort_keys=True)
                k = "fp=" + hashlib.sha256(fp.encode()).hexdigest()[:16]
            else:
                k = None
            if k:
                seen[k] = seen.get(k, 0) + 1
                env_maps(v, f"{where}[{k}#{seen[k]}]", out)
            else:
                env_maps(v, f"{where}[{i}]", out)
    return out


def _cancel_moved(removed, added):
    """第六轮：匿名步骤之间不再按变量名+值抵消（把密钥挪到另一条命令必须进 Yarrow）。
    id/name 认的步骤路径不含 uses/run，版本升级本身不会制造假改动。"""
    return removed, added


def secret_env(gh_yaml, pats):
    """.github/ 下 YAML 的 env 映射里，新增、删除或改动了名字像密钥、或值引用 secrets 的变量 => 1_secrets。
    返回 (errors, reasons)。整份解析（含 flow 写法、多行值），解析失败报红。只报文件和变量名，不报值。"""
    errs, reasons = [], []
    for path, v in sorted((gh_yaml or {}).items()):
        if v.get("error"):
            errs.append(f"{_shown(path)} 解析失败，无法检查 env：{v['error']}"); continue
        b, h = env_maps(v.get("base")), env_maps(v.get("head"))
        b, h = _cancel_moved(b - h, h - b)
        # 只看变了的 (位置, 名称, 值)：别的位置上没改动的同名 secrets 引用不算（第三轮）
        hit = sorted({n for _, n, x in b ^ h if any(re.search(p, n) for p in pats) or re.search(r"(?i)secrets\s*[.\[]", x)})
        if hit:
            reasons.append(f"1_secrets: {_shown(path)} 的 env 变量 {', '.join(hit)} 有改动")
    return errs, reasons


def approval_class(files, yamls, ci_cfg, ps_cfg, known_checks=(), extra=((), ()), gh_yaml=None):
    """返回 (conclusion, cls, reasons)。cls: yarrow|regular。yamls: {路径: {base, head, error}}（JSON 化后的提案 YAML）。"""
    errors, reasons = list(extra[0]), list(extra[1])
    classes = ci_cfg["yarrow_classes"]
    e2, r2 = secret_env(gh_yaml, (classes.get("1_secrets") or {}).get("env_name_patterns") or [])
    errors += e2; reasons += r2
    for f in files:
        names = [f["filename"]] + ([f["previous_filename"]] if f.get("previous_filename") and f.get("status") != "copied" else [])
        for p in names:
            if p.startswith("policy-proposals/") and (p.startswith("policy-proposals/.github/") or not PROPOSAL_RE.match(p)):
                errors.append(f"不允许的提案路径：{p}")
            for cname, rule in classes.items():
                pats = [x for x in ((rule or {}).get("paths") or []) if not x.startswith("policy-repo:")]
                if match_any(p, pats):
                    reasons.append(f"{cname}: {_shown(p)}")
        changed = []
        for ln in (f.get("patch") or "").split("\n"):
            if ln[:1] in "+-":   # patch 只含 hunk，没有文件头；以 ++/-- 开头的内容行也要看
                changed.append(ln[1:])
        if f.get("full"):
            # 第五轮评审：删掉块注释边界后“变成代码”的旧行不是 +/- 行，也要扫（只追加内容，不回显）
            try:
                count_patch(f["filename"], f.get("patch") or "", ps_cfg, f["full"], changed)
            except ValueError:
                errors.append(f"{_shown(f['filename'])}: 补丁和全文对不上，无法完整扫描")
        txt = "\n".join(changed)
        for pat in f.get("approx_hits") or []:
            reasons.append(f"1_secrets: {_shown(f['filename'])}（大文件，全文命中 {pat}）"); break
        for pat in (classes.get("1_secrets") or {}).get("diff_patterns") or []:
            if re.search(pat, txt):
                reasons.append(f"1_secrets: {_shown(f['filename'])} 命中 {pat}"); break
        if f["filename"].startswith(".github/"):
            for pat in (classes.get("2_permissions") or {}).get("diff_patterns") or []:
                if re.search(pat, txt):
                    reasons.append(f"2_permissions: {_shown(f['filename'])} 命中 {pat}"); break
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
    """返回命中位置列表（不回显命中的内容）。只看新增行、文件名、提交信息、作者/提交者、PR 标题正文和 PR 评论（含审查意见）。"""
    hits = []
    for k, f in enumerate(pr.get("files") or [], 1):
        where = f"第 {k} 个文件" if _bad(f["filename"]) else f["filename"]   # 文件名本身带真名就只报序号
        if where != f["filename"]:
            hits.append(where + "的文件名")
        added = [ln[1:] for ln in (f.get("patch") or "").split("\n") if ln.startswith("+")]   # patch 只含 hunk，没有文件头
        if any(_bad(x) for x in added):
            hits.append(where + " 的新增行")
    m = pr.get("meta")
    if m is None:
        return ["缺 PR 元数据"]
    if _bad(m.get("title")):
        hits.append("PR 标题")
    if _bad(m.get("body")):
        hits.append("PR 正文")
    for k, t in enumerate(m.get("comments") or [], 1):
        if _bad(t):
            hits.append(f"第 {k} 条 PR 评论")
    for i, c in enumerate(m.get("commits") or [], 1):
        if _bad(c.get("message")):
            hits.append(f"第 {i} 个提交的提交信息")
        if any(_bad(x) for x in c.get("names") or []):
            hits.append(f"第 {i} 个提交的作者/提交者")
    return hits


ME = ("Yarrow", "318895665+Yarrow-he@users.noreply.github.com")


def author_check(pr):
    """PR 里每个提交的作者和提交人都得是 Yarrow 加 noreply，没有例外。
    规则只豁免“合并 PR 时 GitHub 生成的合并提交”，那个提交在 main 上、不在 PR 的提交列表里；
    网页上 Update branch、网页编辑生成的提交（提交人是 GitHub）一律拦，分支要在本地合并 main 后经 as_work.sh 推。只报序号和字段。"""
    hits = []
    for i, c in enumerate((pr.get("meta") or {}).get("commits") or [], 1):
        n = list(c.get("names") or []) + [None] * 4
        if tuple(n[0:2]) != ME:
            hits.append(f"第 {i} 个提交的作者")
        if tuple(n[2:4]) != ME:
            hits.append(f"第 {i} 个提交的提交人")
    return hits


def evaluate(pr, cfg, glob):
    """算一个 PR 的四个门禁检查。返回 checks 列表。"""
    out = []
    if glob.get("paused"):
        msg = f"策略暂停（{glob['paused'].get('by')}），gen={glob['generation']}"
        return [{"name": "gate-summary", "conclusion": "failure", "title": "策略暂停", "summary": redact(msg)}]
    if pr.get("incomplete"):
        why = "数据不全：" + pr["incomplete"]
        return [{"name": n, "conclusion": "failure", "title": "数据不全", "summary": redact(why)} for n in OWN + ("gate-summary",)]
    files = pr["files"]
    try:
        c, s = pr_size(files, cfg["pr_size"])
    except Exception as e:  # 一个检查器出错只让它自己失败
        c, s = "failure", f"pr-size 出错：{e!r}"
    out.append({"name": "pr-size", "conclusion": c, "title": "pr-size", "summary": s})
    try:
        known = {r["name"] for r in pr.get("check_runs") or [] if r["app_id"] == ACTIONS_APP} | set(pr.get("check_names") or [])
        extra = scope_check(pr, cfg["ci_class"])
        c2, cls, s2 = approval_class(files, pr.get("proposal_yaml") or {}, cfg["ci_class"], cfg["pr_size"], known, extra,
                                     pr.get("github_yaml"))
    except Exception as e:
        c2, cls, s2 = "failure", "error", f"ci-approval-class 出错：{e!r}"
    out.append({"name": "ci-approval-class", "conclusion": c2, "title": f"class={cls}", "summary": s2})
    c3, s3 = owner_approval(cls, pr.get("reviews") or [], pr["head"], glob["owner"])
    out.append({"name": "owner-approval", "conclusion": c3, "title": "owner-approval", "summary": s3})

    fails, pend = [], []
    rn = realname(pr)
    if rn:
        fails.append("真名：不能出现用户真名或个人邮箱，一律写 Yarrow，邮箱用 GitHub noreply。位置：" + "；".join(rn))
    try:
        fails += ["lint: " + x for x in lint(pr, cfg["ci_class"])]
    except Exception as e:
        fails.append(f"lint 出错：{type(e).__name__}")
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
           (f.get("status") != "copied" and (f.get("previous_filename") or "").startswith("policy-proposals/scripts/")) for f in files):
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
    for c in out:   # 第六轮：出站前统一脱敏
        c["title"] = redact(str(c.get("title") or ""))
        c["summary"] = redact(str(c.get("summary") or ""))
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
            checks = [{"name": "gate-summary", "conclusion": "failure", "title": "检查器出错", "summary": f"检查器出错：{type(e).__name__}"}]
        with open(os.path.join(outd, f"{pr['pr']}.json"), "w") as fh:
            json.dump({"pr": pr["pr"], "head": pr["head"], "checks": checks}, fh, ensure_ascii=False)


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])
