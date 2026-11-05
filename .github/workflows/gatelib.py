#!/usr/bin/env python3
"""闸口 workflow 的内联逻辑（取数据、写结果、发布、回滚、作废、引导、同步分支保护）。
放在 .github/workflows/ 下，和 workflow 一样只能由 Yarrow 临时管理员放行推送；不读、不跑任何 PR 代码。
令牌只从环境变量读，不打印。用法见各 workflow。
"""
import base64, json, urllib.parse, os, re, subprocess, sys, tempfile, time, urllib.error, urllib.request

BIZ = "Yarrow-he/OsakaConnect"
POL = "Yarrow-he/OsakaConnect-policy"
GATE_APP = 5592067
OWNER = "Yarrow-he"
OWN_CHECKS = ("pr-size", "ci-approval-class", "owner-approval", "gate-summary")
NEVER_REMOVE = ("gate-summary", "lead-merge-approved")
# 发布映射写死在这里（不读可被提案改的配置）：policy-proposals/<X> -> 策略仓库 <X>
PROPOSAL_RE = re.compile(r"^((required-checks|key-acceptance-tests|pr-size|ci-approval-class)\.yaml"
                         r"|scripts/[A-Za-z0-9._-]+(/[A-Za-z0-9._-]+)*)$")


class Retry(Exception):
    """推送冲突、5xx、限流：本轮失败，下一轮重来。"""


class Reject(Exception):
    """内容、授权、基线核对失败：要 Yarrow 处理（作废或回滚）。"""


def api(method, path, tok, body=None, raw=False, ok404=False):
    url = path if path.startswith("https://") else "https://api.github.com/" + path
    h = {"Authorization": "Bearer " + os.environ[tok], "Accept": "application/vnd.github.raw" if raw else "application/vnd.github+json",
         "X-GitHub-Api-Version": "2022-11-28"}
    data = json.dumps(body).encode() if body is not None else None
    if data:
        h["Content-Type"] = "application/json"
    for attempt in range(3):
        try:
            with urllib.request.urlopen(urllib.request.Request(url, data, h, method=method), timeout=60) as r:
                b = r.read()
                return b.decode() if raw else (json.loads(b) if b else None)
        except urllib.error.HTTPError as e:
            if e.code == 404 and ok404:
                return None
            if e.code >= 500 or e.code == 429 or (e.code == 403 and "rate limit" in e.read().decode(errors="replace").lower()):
                if attempt < 2:
                    time.sleep(5 * (attempt + 1)); continue
                raise Retry(f"{method} {path}: HTTP {e.code}")
            if e.code in (409, 422) and method in ("PATCH", "POST", "PUT"):
                raise Retry(f"{method} {path}: HTTP {e.code}（可能是推送冲突）")
            raise
        except (urllib.error.URLError, TimeoutError) as e:
            if attempt < 2:
                time.sleep(5); continue
            raise Retry(f"{method} {path}: {e}")


def pages(path, tok, key=None, limit=20):
    out = []
    sep = "&" if "?" in path else "?"
    for p in range(1, limit + 1):
        d = api("GET", f"{path}{sep}per_page=100&page={p}", tok)
        items = d[key] if key else d
        out += items
        if len(items) < 100:
            return out
    raise Retry(f"{path} 超过 {limit} 页")


def yaml_json(text):
    r = subprocess.run(["yq", "-o=json", "."], input=text, capture_output=True, text=True, timeout=30)
    if r.returncode:
        raise ValueError("YAML 解析失败（出错内容不回显，防止带出密钥）")
    return json.loads(r.stdout) if r.stdout.strip() else None


def commit_tree(repo, sha, tok):
    if not re.fullmatch(r"[0-9a-f]{40}", sha):   # git/commits 只认提交号；分支名先解析
        sha = api("GET", f"repos/{repo}/git/ref/heads/{sha}", tok)["object"]["sha"]
    return api("GET", f"repos/{repo}/git/commits/{sha}", tok)["tree"]["sha"]


def subtree_sha(repo, commit, sub, tok):
    for e in api("GET", f"repos/{repo}/git/trees/{commit_tree(repo, commit, tok)}", tok)["tree"]:
        if e["path"] == sub and e["type"] == "tree":
            return e["sha"]
    return None


def blobs(repo, tree_sha, tok):
    """{路径: (mode, type, sha)}，完整递归；截断就当失败。"""
    if tree_sha is None:
        return {}
    d = api("GET", f"repos/{repo}/git/trees/{tree_sha}?recursive=1", tok)
    if d.get("truncated"):
        raise Retry("tree 被截断")
    return {e["path"]: (e["mode"], e["type"], e["sha"]) for e in d["tree"] if e["type"] != "tree"}


def read_state(tok, ref="main"):
    return json.loads(api("GET", f"repos/{POL}/contents/state/state.json?ref={ref}", tok, raw=True))


def latest_run(tok, sha, name, app_id, latest_only=False):
    f = "latest" if latest_only else "all"
    runs = [r for r in pages(f"repos/{BIZ}/commits/{sha}/check-runs?check_name={name}&app_id={app_id}&filter={f}", tok, "check_runs")
            if r["app"]["id"] == app_id]
    return max(runs, key=lambda r: r["id"]) if runs else None


def pending_reason(state, tok):
    """processed_through 和 main 的 policy-proposals 目录不同 => 有已合并未发布的提案。"""
    pt = state.get("processed_through")
    if not pt:
        return "processed_through 未初始化"
    if subtree_sha(BIZ, pt, "policy-proposals", tok) != subtree_sha(BIZ, "main", "policy-proposals", tok):
        return f"{pt[:10]}..main 改了 policy-proposals/"
    return ""


def gh_output(**kw):
    if os.environ.get("GITHUB_OUTPUT"):
        with open(os.environ["GITHUB_OUTPUT"], "a") as f:
            for k, v in kw.items():
                f.write(f"{k}={v}\n")


# ---------------- policy-checks ----------------

def fetch(policy_dir, ind, fetchd):
    tok = "BIZ_TOKEN"
    state = json.load(open(os.path.join(policy_dir, "state/state.json")))
    policy_sha = subprocess.check_output(["git", "-C", policy_dir, "rev-parse", "HEAD"], text=True).strip()
    cfg = {}
    for k, fn in (("pr_size", "pr-size.yaml"), ("ci_class", "ci-approval-class.yaml"),
                  ("required", "required-checks.yaml"), ("key_tests", "key-acceptance-tests.yaml")):
        cfg[k] = yaml_json(open(os.path.join(policy_dir, fn)).read())
    main_sha = api("GET", f"repos/{BIZ}/commits/main", tok)["sha"]
    pending = "" if state.get("paused") else pending_reason(state, tok)
    main_board = None if state.get("paused") else board_at(main_sha, tok)   # scope 名单只认 main 上已合并的那份
    os.makedirs(os.path.join(ind, "prs"), exist_ok=True)
    os.makedirs(fetchd, exist_ok=True)
    listed = []
    for p in pages(f"repos/{BIZ}/pulls?state=open&base=main", tok):
        n, head, base = p["number"], p["head"]["sha"], p["base"]["sha"]
        d = {"pr": n, "head": head, "head_ref": p["head"]["ref"], "base_ref": p["base"]["ref"], "main_board": main_board}
        listed.append({"pr": n, "head": head})
        if not state.get("paused"):
            try:
                d.update(pr_data(n, head, base, tok, cfg))
                d["meta"] = pr_meta(n, p, tok)
            except Exception as e:  # 一个 PR 取不全只让它自己失败
                d["incomplete"] = f"{type(e).__name__}: {str(e)[:200]}"
        json.dump(d, open(os.path.join(ind, "prs", f"{n}.json"), "w"))
    glob = {"generation": state["generation"], "paused": state.get("paused"), "pending": pending, "owner": OWNER}
    json.dump(cfg, open(os.path.join(ind, "config.json"), "w"))
    json.dump(glob, open(os.path.join(ind, "global.json"), "w"))
    json.dump({"generation": state["generation"], "paused": state.get("paused"), "processed_through": state.get("processed_through"),
               "policy_sha": policy_sha, "main_sha": main_sha, "run_id": os.environ.get("GITHUB_RUN_ID", "local"),
               "at": int(time.time()), "prs": listed}, open(os.path.join(fetchd, "fetch.json"), "w"))
    print(f"fetch: {len(listed)} 个 PR，gen={state['generation']}，paused={bool(state.get('paused'))}，pending={pending or '无'}")


def board_at(ref, tok):
    """业务仓库某提交上的 board.json（解析后的 JSON）；不存在返回 None，解析失败返回 {"error": ...}。不打印内容。"""
    t = api("GET", f"repos/{BIZ}/contents/board.json?ref={ref}", tok, raw=True, ok404=True)
    if t is None:
        return None
    try:
        return json.loads(t)
    except ValueError:
        return {"error": "board.json 不是合法 JSON"}


def pr_meta(n, p, tok):
    """真名检查用：PR 标题正文和 PR 内各提交的提交信息、作者/提交者。"""
    cs = [{"message": c["commit"]["message"], "names": [c["commit"]["author"]["name"], c["commit"]["author"]["email"],
                                                         c["commit"]["committer"]["name"], c["commit"]["committer"]["email"]]}
          for c in pages(f"repos/{BIZ}/pulls/{n}/commits", tok, limit=3)]
    # PR 评论：对话评论、逐行审查评论、审查意见正文（真名检查用；只传文字，不传作者）
    com = [c.get("body") or "" for c in pages(f"repos/{BIZ}/issues/{n}/comments", tok)]
    com += [c.get("body") or "" for c in pages(f"repos/{BIZ}/pulls/{n}/comments", tok)]
    com += [r.get("body") or "" for r in pages(f"repos/{BIZ}/pulls/{n}/reviews", tok)]
    return {"title": p.get("title") or "", "body": p.get("body") or "", "commits": cs, "comments": [x for x in com if x]}


SYNTH_MAX = 10_000_000   # 精确补丁的单侧上限（字节）；超过就改做近似补丁（见 synth_patch）
SCAN_MAX = 100_000_000   # 能取到并扫描的单侧上限（GitHub raw 内容接口上限 100MB）；超过才判数据不全
FULL_MAX = SYNTH_MAX     # 带回两侧全文给 pr-size 算跨 hunk 注释状态的单侧上限（第五轮评审：和精确补丁同限，不留 hunk 局部的缺口）
BLOCK_EXT = (".py", ".kt", ".kts", ".cs", ".ps1")   # 有块注释或 docstring 的语言（和 gate.py 的 LANG 对应）；只有这些要带全文


def synth_patch(f, mb, head, tok, want_full=False, need=True, cfg=None):
    """按 merge-base 和 head 两边的文件内容在本地算 patch，并按需带回两侧全文。返回 (patch, approx, full)。
    该存在的一侧取不到（None）就抛 ValueError（不当成空文件）；空字符串是合法空文件。
    copied 按新增处理（旧侧为空）。
    第五轮：两侧都不超过 SYNTH_MAX 用 git diff 算精确补丁；超过 SYNTH_MAX、不超过 SCAN_MAX 时不算精确 diff，
    改按行多重集合做“近似补丁”（新侧多出来的行记 +，旧侧多出来的行记 -，线性时间），真名和密钥扫描照样扫到每一条
    新增/删除内容，pr-size 对近似补丁按 GitHub 给的新增行数计（偏严，排除名单内的不计）。超过 SCAN_MAX 才判数据不全。"""
    old_path = f.get("previous_filename") or f["filename"]
    q = lambda x: urllib.parse.quote(x, safe="/")
    old = new = ""
    if f["status"] not in ("added", "copied"):
        old = api("GET", f"repos/{BIZ}/contents/{q(old_path)}?ref={mb}", tok, raw=True, ok404=True)
    if f["status"] != "removed":
        new = api("GET", f"repos/{BIZ}/contents/{q(f['filename'])}?ref={head}", tok, raw=True, ok404=True)
    if old is None or new is None:
        raise ValueError(f"{f['filename']} 取不到{'旧' if old is None else '新'}版内容")
    if len(old) > SCAN_MAX or len(new) > SCAN_MAX:
        if not need:
            return None, False, None
        raise ValueError(f"{f['filename']} 超过 {SCAN_MAX} 字节，取不到完整内容做扫描")
    if len(old) > SYNTH_MAX or len(new) > SYNTH_MAX:
        if not need:
            return None, False, None
        return approx_patch(_lines(old), _lines(new)), True, {"hits": scan_hits(old, new, cfg)}
    full = {"old": old, "new": new} if want_full and len(old) <= FULL_MAX and len(new) <= FULL_MAX else None
    if not need:
        return None, False, full   # 只要全文，补丁 compare 已给
    return make_patch(_lines(old), _lines(new)), False, full


def _lines(t):
    """只按 \n 分行（和 git、GitHub 补丁一致；splitlines 会在 \x0c、U+2028 等处多分）。"""
    ls = t.split("\n")
    if ls and ls[-1] == "":
        ls.pop()
    return ls


def scan_hits(old, new, cfg):
    """大文件（近似补丁）用：多重集合差看不到“挪了位置的密钥引用”，所以对两侧全文跑 1_secrets 的 diff_patterns，
    任一侧命中就记类名（保守：大文件里只要有密钥引用就进 Yarrow 档）。只用配置里的正则（数据），不执行策略代码。只回类名和正则。"""
    yc = ((cfg or {}).get("ci_class") or {}).get("yarrow_classes") or {}
    out = []
    for pat in (yc.get("1_secrets") or {}).get("diff_patterns") or []:
        try:
            if re.search(pat, old) or re.search(pat, new):
                out.append(pat)
        except re.error:
            out.append(pat)   # 坏正则：保守算命中
    return out


def approx_patch(a, b):
    """大文件用：按行多重集合求差。不是最小 diff（挪动的行不算改动），但每条新出现的内容都在 + 行里、
    每条消失的内容都在 - 行里，够真名和密钥扫描用。"""
    from collections import Counter
    ca, cb = Counter(a), Counter(b)
    plus, minus = [], []
    left = dict(ca)
    for x in b:
        if left.get(x, 0) > 0:
            left[x] -= 1
        else:
            plus.append(x)
    left = dict(cb)
    for x in a:
        if left.get(x, 0) > 0:
            left[x] -= 1
        else:
            minus.append(x)
    if not plus and not minus:
        return ""
    return "\n".join([f"@@ -1,{len(a)} +1,{len(b)} @@"] + ["-" + x for x in minus] + ["+" + x for x in plus])


PATCH_TIMEOUT = 60   # 补一个文件补丁的时间上限（秒）；超时判数据不全，不拖住整轮取数


def make_patch(a, b, n=3):
    """unified diff 的 hunk 部分（不含文件头）。第三轮改用 git diff --no-index（Myers），避免 difflib 关掉 autojunk 后
    重复行多时平方级变慢；子进程带超时；不读全局/系统 git 配置，关掉外部 diff 和 textconv。"""
    with tempfile.TemporaryDirectory() as d:
        pa, pb = os.path.join(d, "a"), os.path.join(d, "b")
        for pth, ls in ((pa, a), (pb, b)):
            with open(pth, "w", encoding="utf-8", newline="") as fh:
                fh.write("\n".join(ls) + ("\n" if ls else ""))
        env = {"PATH": "/usr/bin:/bin", "HOME": d, "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_CONFIG_NOSYSTEM": "1", "LC_ALL": "C.UTF-8"}
        try:
            r = subprocess.run(["git", "diff", "--no-index", "--no-ext-diff", "--no-textconv", "--no-color", "--text",
                                "--diff-algorithm=myers", f"-U{n}", "--", pa, pb],
                               capture_output=True, timeout=PATCH_TIMEOUT, env=env, cwd=d)
        except subprocess.TimeoutExpired:
            raise ValueError(f"补补丁超过 {PATCH_TIMEOUT} 秒")
        if r.returncode not in (0, 1):
            raise ValueError("git diff 补补丁失败")
    lines = r.stdout.decode("utf-8").split("\n")
    i = next((k for k, x in enumerate(lines) if x.startswith("@@")), len(lines))
    return "\n".join(x for x in lines[i:] if x and not x.startswith("\\"))


def pr_data(n, head, base, tok, cfg):
    cmp = api("GET", f"repos/{BIZ}/compare/{base}...{head}?per_page=100", tok)
    if cmp["files"] is None or len(cmp["files"]) >= 300:
        return {"incomplete": "改动文件超过 300 个，拆小 PR"}
    mb = cmp["merge_base_commit"]["sha"]
    files = []
    for f in cmp["files"]:
        changes = f.get("additions", 0) + f.get("deletions", 0)
        files.append({"filename": f["filename"], "status": f["status"], "previous_filename": f.get("previous_filename"),
                      "patch": f.get("patch"), "additions": f.get("additions", 0), "deletions": f.get("deletions", 0),
                      "binary": "patch" not in f and changes == 0 and f["status"] not in ("renamed", "copied")})
    for x in files:
        # copied 不管 compare 给没给补丁，都按“旧侧为空、新文件全文”重补（第五轮评审：否则复制后改一行只算一行、未改行不扫）
        need = not x["binary"] and (x["status"] == "copied" or (x["patch"] is None and x["additions"] + x["deletions"] > 0))
        # 第五轮：有块注释/docstring 的源码，就算 compare 给了补丁也取两侧全文，供跨 hunk 注释判断
        want_full = not x["binary"] and x["status"] in ("modified", "renamed") and x["filename"].endswith(BLOCK_EXT)
        if need or want_full:
            try:
                # 第四轮：不再 import 策略里的 gate.py（取数进程持令牌，不执行计数器代码）
                p, approx, full = synth_patch(x, mb, head, tok, want_full, need, cfg)
                if need:
                    x["patch"], x["patch_synth"], x["patch_approx"] = p, True, approx
                if approx:
                    x["approx_hits"] = (full or {}).get("hits") or []
                elif full is not None:
                    x["full"] = full
            except UnicodeDecodeError:   # 有增删行数却不是 UTF-8：不能当二进制按 1 行放过
                if not need:
                    continue   # 只是为了取全文：取不成就退回 hunk 局部判断，补丁本身 compare 已给
                if x["status"] == "copied" and x["additions"] + x["deletions"] == 0:
                    x["binary"] = True; continue   # 复制的二进制文件（GitHub 报零增删）按二进制计
                return {"incomplete": "有文件不是 UTF-8 文本，补不出补丁（文件名不回显）"}
            except (ValueError, urllib.error.HTTPError) as e:
                return {"incomplete": "补丁缺失且补不出来（详情不回显，防文件名/路径泄露）"}
    reviews = [{"user": (r.get("user") or {}).get("login"), "state": r["state"], "commit_id": r.get("commit_id")}
               for r in pages(f"repos/{BIZ}/pulls/{n}/reviews", tok)]
    # 只按名字取要核的外部检查（n7impl1 A①：闸口自己每轮写的检查会累积，不能整列 filter=all）
    want = {(e["context"], e["expected_source"]["app_id"]) for layer in ("branch_protection", "gate_verified")
            for e in cfg["required"].get(layer) or [] if e["context"] not in OWN_CHECKS + NEVER_REMOVE}
    want.add(("policy-selftest", 15368))
    runs = []
    for name, app in sorted(want):
        runs += [{"id": r["id"], "name": r["name"], "app_id": r["app"]["id"], "status": r["status"], "conclusion": r["conclusion"],
                  "suite": (r.get("check_suite") or {}).get("id")}
                 for r in pages(f"repos/{BIZ}/commits/{head}/check-runs?check_name={name}&app_id={app}&filter=all", tok, "check_runs")]
    names = sorted({r["name"] for r in pages(f"repos/{BIZ}/commits/{head}/check-runs?app_id=15368&filter=latest", tok, "check_runs")})
    tree = api("GET", f"repos/{BIZ}/git/trees/{head}?recursive=1", tok)
    if tree.get("truncated"):
        return {"incomplete": "head 文件树被截断"}
    head_paths = [e["path"] for e in tree["tree"] if e["type"] == "blob"]
    ci = api("GET", f"repos/{BIZ}/contents/.github/workflows/ci.yml?ref={head}", tok, raw=True, ok404=True)
    ci_jobs = yaml_json(ci) if ci else None
    yamls = {}
    for f in files:
        for path in {f["filename"], f.get("previous_filename") or f["filename"]}:
            if re.match(r"^policy-proposals/[^/]+\.ya?ml$", path):
                v = {}
                try:
                    b = api("GET", f"repos/{BIZ}/contents/{path}?ref={mb}", tok, raw=True, ok404=True)
                    h = api("GET", f"repos/{BIZ}/contents/{path}?ref={head}", tok, raw=True, ok404=True)
                    v = {"base": yaml_json(b) if b is not None else None, "head": yaml_json(h) if h is not None else None}
                except ValueError as e:
                    v = {"error": str(e)}
                yamls[path] = v
    gh_yaml = {}   # .github/ 下改动的 YAML：两边整份解析，给 1_secrets 的 env 检查用
    for f in files:
        for path, ref in ((f.get("previous_filename") or f["filename"], mb), (f["filename"], head)):
            if path.startswith(".github/") and re.search(r"\.ya?ml$", path):
                v = gh_yaml.setdefault(f["filename"], {})
                side = "base" if ref == mb else "head"
                if (side == "base" and f["status"] in ("added", "copied")) or (side == "head" and f["status"] == "removed"):
                    v[side] = None; continue
                try:
                    t = api("GET", f"repos/{BIZ}/contents/{urllib.parse.quote(path, safe='/')}?ref={ref}", tok, raw=True, ok404=True)
                    if t is None:
                        v["error"] = f"取不到 {side} 版"
                    else:
                        v[side] = yaml_json(t)
                except (ValueError, UnicodeDecodeError):
                    v["error"] = f"{side} 版 YAML 解析失败"   # 不回显异常文本（可能带出错行里的密钥）
                except urllib.error.HTTPError as e:
                    v["error"] = f"取 {side} 版失败（HTTP {e.code}）"
    board_change = None
    if any("board.json" in (f["filename"], f.get("previous_filename")) for f in files):
        b, h = board_at(mb, tok), board_at(head, tok)
        board_change = {"error": "解析失败"} if any(isinstance(x, dict) and set(x) == {"error"} for x in (b, h)) else {"base": b, "head": h}
    return {"merge_base": mb, "files": files, "board_change": board_change, "reviews": reviews, "check_runs": runs, "check_names": names, "head_paths": head_paths,
            "ci_jobs": ci_jobs, "proposal_yaml": yamls, "github_yaml": gh_yaml}


def write(outd, fetch_json):
    fj = json.load(open(fetch_json))
    st = read_state("POL_TOKEN")
    if (st["generation"], st.get("paused"), st.get("processed_through")) != (fj["generation"], fj.get("paused"), fj.get("processed_through")):
        print("策略状态在取数据后变了，本轮不写（下一轮重算）"); return
    wrote = 0
    for item in fj["prs"]:
        n, head = item["pr"], item["head"]
        fn = os.path.join(outd, f"{n}.json")
        if not os.path.exists(fn):
            print(f"PR #{n}: compute 没有输出，跳过"); continue
        o = json.load(open(fn))
        if o.get("pr") != n or o.get("head") != head:
            raise Reject(f"PR #{n}: compute 输出和 fetch 名单不符")
        if api("GET", f"repos/{BIZ}/pulls/{n}", "CK_TOKEN")["head"]["sha"] != head:
            print(f"PR #{n}: head 已变，跳过"); continue
        ext = f"pr:{n}:head:{head}:v:{fj['policy_sha']}:run:{fj['run_id']}:gen={fj['generation']}:at={fj['at']}:main={fj['main_sha']}"
        for c in o["checks"]:
            if c["name"] not in OWN_CHECKS:
                continue        # 只写这四个名字，尤其不写 lead-merge-approved
            body = {"name": c["name"], "head_sha": head, "external_id": ext,
                    "output": {"title": str(c.get("title"))[:200], "summary": str(c.get("summary"))[:60000]}}
            done = c.get("conclusion") in ("success", "failure")
            body.update(status="completed", conclusion=c["conclusion"]) if done else body.update(status="in_progress")
            old = latest_run("CK_TOKEN", head, c["name"], GATE_APP, latest_only=True)
            if old and (done or old["status"] != "completed") and (old.get("external_id") or "").startswith(f"pr:{n}:head:{head}:"):
                # 同一 PR、同一 head：改写最新那条（id 不变，仍是最新），不每 5 分钟新建一条（n7impl1 A①）
                api("PATCH", f"repos/{BIZ}/check-runs/{old['id']}", "CK_TOKEN", {k: v for k, v in body.items() if k != "head_sha"})
            else:
                api("POST", f"repos/{BIZ}/check-runs", "CK_TOKEN", body)
            wrote += 1
    print(f"write: 写了 {wrote} 个检查")


# ---------------- 写策略仓库（Git Data API，一次发布 = 一个提交，不强推） ----------------

def commit_policy(base_sha, changes, state, msg):
    """changes: {路径: (mode, blob_sha) 或 None=删除}。state 一起写进同一提交。返回新提交号。"""
    tree = []
    for path, v in sorted(changes.items()):
        tree.append({"path": path, "mode": v[0] if v else "100644", "type": "blob", "sha": v[1] if v else None})
    tree.append({"path": "state/state.json", "mode": "100644", "type": "blob",
                 "content": json.dumps(state, ensure_ascii=False, indent=1, sort_keys=True) + "\n"})
    t = api("POST", f"repos/{POL}/git/trees", "POL_TOKEN", {"base_tree": commit_tree(POL, base_sha, "POL_TOKEN"), "tree": tree})
    c = api("POST", f"repos/{POL}/git/commits", "POL_TOKEN", {"message": msg, "tree": t["sha"], "parents": [base_sha]})
    api("PATCH", f"repos/{POL}/git/refs/heads/main", "POL_TOKEN", {"sha": c["sha"], "force": False})
    return c["sha"]


def copy_blob(sha):
    content = api("GET", f"repos/{BIZ}/git/blobs/{sha}", "BIZ_TOKEN")["content"]
    new = api("POST", f"repos/{POL}/git/blobs", "POL_TOKEN", {"content": content.replace("\n", ""), "encoding": "base64"})["sha"]
    if new != sha:
        raise Reject(f"复制 blob {sha} 后 sha 不一致")


def biz_git():
    """业务仓库的只读裸克隆（不含文件内容，不检出、不执行任何代码），只用来走 first-parent 历史（n7impl1 A③）。"""
    d = os.path.join(tempfile.mkdtemp(), "biz.git")
    url = os.environ.get("GATE_BIZ_GIT") or f"https://github.com/{BIZ}.git"
    cfg = []
    if url.startswith("https://"):
        basic = base64.b64encode(f"x-access-token:{os.environ['BIZ_TOKEN']}".encode()).decode()
        cfg = ["-c", f"http.extraheader=Authorization: Basic {basic}"]
    r = subprocess.run(["git", *cfg, "clone", "--quiet", "--bare", "--filter=blob:none", "--single-branch", "--branch", "main", url, d],
                       capture_output=True, text=True, timeout=600)
    if r.returncode:
        raise Retry("克隆业务仓库失败：" + r.stderr.replace(os.environ.get("BIZ_TOKEN", "-"), "***")[-300:])
    return d


def next_proposal(state):
    """沿 main 的 first-parent 链找 processed_through 之后第一个改了 policy-proposals/ 的提交。"""
    pt = state["processed_through"]
    d = biz_git()
    run = lambda *a: subprocess.run(["git", "-C", d, *a], capture_output=True, text=True)
    if run("merge-base", "--is-ancestor", pt, "main").returncode:
        raise Reject("processed_through 不是业务仓库 main 的祖先")
    out = run("rev-list", "--first-parent", "--reverse", f"{pt}..main", "--", "policy-proposals").stdout.split()
    if not out:
        return None, None
    m = out[0]
    return m, run("rev-list", "--parents", "-n", "1", m).stdout.split()[1:]


def proposal_diff(p1, m):
    a = blobs(BIZ, subtree_sha(BIZ, p1, "policy-proposals", "BIZ_TOKEN"), "BIZ_TOKEN")
    b = blobs(BIZ, subtree_sha(BIZ, m, "policy-proposals", "BIZ_TOKEN"), "BIZ_TOKEN")
    out = {}
    for path in set(a) | set(b):
        if a.get(path) != b.get(path):
            for side in (a.get(path), b.get(path)):
                if side and (side[1] != "blob" or side[0] not in ("100644", "100755")):
                    raise Reject(f"policy-proposals/{path} 是符号链接、子模块或特殊模式")
            if not PROPOSAL_RE.match(path):
                raise Reject(f"policy-proposals/{path} 不在发布白名单")
            out[path] = (a.get(path), b.get(path))
    return out


def check_required(b64):
    """发布前再核一次 required-checks.yaml：坏了会让全仓卡死（n7impl1 A②）。"""
    try:
        rc = yaml_json(base64.b64decode(b64).decode())
        for layer in ("branch_protection", "gate_verified"):
            for e in rc.get(layer) or []:
                a = e["expected_source"]["app_id"]
                if not isinstance(e["context"], str) or type(a) is not int:
                    raise ValueError(e)
                if a == GATE_APP and e["context"] not in OWN_CHECKS:
                    raise ValueError(f"闸口不写 {e['context']}")
        if rc.get("repo") != BIZ or rc.get("branch") != "main" or not isinstance(rc.get("strict"), bool):
            raise ValueError("repo/branch/strict")
    except (ValueError, KeyError, TypeError, AttributeError) as e:
        raise Reject(f"required-checks.yaml 无效：{e}")


def publish():
    head = api("GET", f"repos/{POL}/git/ref/heads/main", "POL_TOKEN")["object"]["sha"]
    state = read_state("POL_TOKEN", head)
    if state.get("paused"):
        print(f"paused（{state['paused'].get('by')}），本轮不发布"); return
    if not pending_reason(state, "BIZ_TOKEN"):
        print("noop：没有待发布的提案"); return
    m, parents = next_proposal(state)
    if not m:
        print("noop：policy-proposals 净改动为零"); return
    n = None
    try:
        if len(parents) != 2:
            raise Reject(f"{m[:10]} 不是合并提交（只接受两个父提交的合并）")
        p1, p2 = parents
        prs = [p for p in api("GET", f"repos/{BIZ}/commits/{m}/pulls", "BIZ_TOKEN") if p.get("merge_commit_sha") == m]
        if len(prs) != 1:
            raise Reject(f"{m[:10]} 找不到对应 PR")
        n = prs[0]["number"]
        if prs[0]["head"]["sha"] != p2:
            raise Reject(f"PR #{n} 的 head 不是合并提交的第二个父提交")
        gs = latest_run("BIZ_TOKEN", p2, "gate-summary", GATE_APP)
        if not gs or gs["status"] != "completed" or gs["conclusion"] != "success" or not (gs.get("external_id") or "").startswith(f"pr:{n}:head:{p2}:"):
            raise Reject(f"PR #{n} head 上最新的 gate-summary 不是 success")
        diff = proposal_diff(p1, m)
        cur = blobs(POL, commit_tree(POL, head, "POL_TOKEN"), "POL_TOKEN")
        div = {d["path"]: d for d in state.get("divergence", [])}
        changes, cleared = {}, []
        for path, (before, after) in sorted(diff.items()):
            c, b, a = (cur.get(path) or (None, None, None))[2], (before or (None, None, None))[2], (after or (None, None, None))[2]
            if path in div:
                if a != c:
                    raise Reject(f"{path} 有回滚/作废登记，只接受恢复成生效内容的补偿提案")
                cleared.append(path)
            elif c != b:
                raise Reject(f"{path} 基线不符：策略仓库现有内容不等于合并前业务仓库的内容")
            else:
                if after and path == "required-checks.yaml":
                    check_required(api("GET", f"repos/{BIZ}/git/blobs/{a}", "BIZ_TOKEN")["content"])
                if after:
                    copy_blob(a)
                changes[path] = (after[0], a) if after else None
    except Reject as e:
        rec = (state.get("proposals") or {}).get(str(n or m))
        if not rec or rec.get("result") != "failed" or rec.get("merge") != m:
            st = dict(state)
            st.setdefault("proposals", {})[str(n or m)] = {"merge": m, "result": "failed", "reason": str(e)}
            commit_policy(head, {}, st, f"publish failed PR #{n} ({m})")
        raise
    g = state["generation"] + 1
    st = dict(state, generation=g, processed_through=m, active={"from_merge": m, "pr": n, "generation": g})
    st["divergence"] = [d for d in state.get("divergence", []) if d["path"] not in cleared]
    st.setdefault("proposals", {})[str(n)] = {"merge": m, "head": p2, "result": "published", "generation": g}
    st.setdefault("history", []).append({"generation": g, "from_merge": m, "pr": n, "kind": "publish"})
    new = commit_policy(head, changes, st, f"publish PR #{n} ({m})")
    print(f"已发布 PR #{n}：{sorted(changes)}，清掉登记 {cleared}，策略提交 {new}，gen={g}")
    api("POST", f"repos/{BIZ}/check-runs", "BIZ_TOKEN", {"name": "policy-published", "head_sha": m, "status": "completed",
        "conclusion": "success", "external_id": m, "output": {"title": "已发布", "summary": f"策略提交 {new}，gen={g}"}})


def rollback(c):
    if not re.fullmatch(r"[0-9a-f]{40}", c):
        raise Reject("rollback 要 40 位策略提交号")
    head = api("GET", f"repos/{POL}/git/ref/heads/main", "POL_TOKEN")["object"]["sha"]
    if api("GET", f"repos/{POL}/compare/{c}...{head}", "POL_TOKEN")["status"] not in ("ahead", "identical"):
        raise Reject("这个提交不在策略仓库 main 上")
    cm = api("GET", f"repos/{POL}/git/commits/{c}", "POL_TOKEN")
    mm = re.match(r"publish PR #(\d+) ", cm["message"])
    if not mm:
        raise Reject("这不是发布提交")
    n = mm.group(1)
    state = read_state("POL_TOKEN", head)
    if (state.get("proposals") or {}).get(n, {}).get("result") != "published":
        raise Reject(f"PR #{n} 不是已发布状态")
    a = blobs(POL, commit_tree(POL, cm["parents"][0]["sha"], "POL_TOKEN"), "POL_TOKEN")
    b = blobs(POL, cm["tree"]["sha"], "POL_TOKEN")
    cur = blobs(POL, commit_tree(POL, head, "POL_TOKEN"), "POL_TOKEN")
    changes, div = {}, list(state.get("divergence", []))
    for path in sorted(set(a) | set(b)):
        if path.startswith("state/") or a.get(path) == b.get(path):
            continue
        if cur.get(path) != b.get(path):
            raise Reject(f"{path} 发布后又被改过，先回滚后面的发布")
        changes[path] = (a[path][0], a[path][2]) if path in a else None
        div = [d for d in div if d["path"] != path] + [{"path": path, "business_blob": b[path][2] if path in b else None,
                                                         "effective_blob": a[path][2] if path in a else None}]
    g = state["generation"] + 1
    st = dict(state, generation=g, divergence=div)
    st["proposals"][n] = dict(st["proposals"][n], result="rolled_back", generation=g)
    st.setdefault("history", []).append({"generation": g, "kind": "rollback", "pr": int(n), "rollback_of": c})
    new = commit_policy(head, changes, st, f"rollback PR #{n} ({c})")
    print(f"已回滚 PR #{n}：{sorted(changes)}，策略提交 {new}，gen={g}")


def skip(n):
    """n：PR 号；找不到 PR 的失败提案用合并提交号。"""
    head = api("GET", f"repos/{POL}/git/ref/heads/main", "POL_TOKEN")["object"]["sha"]
    state = read_state("POL_TOKEN", head)
    rec = (state.get("proposals") or {}).get(str(n))
    if not rec or rec.get("result") != "failed":
        raise Reject(f"PR #{n} 不是发布失败的提案，不能作废")
    m, parents = next_proposal(state)
    if m != rec["merge"]:
        raise Reject("它不是下一个待发布的提案")
    cur = blobs(POL, commit_tree(POL, head, "POL_TOKEN"), "POL_TOKEN")
    div = list(state.get("divergence", []))
    for path, (_, after) in proposal_diff(parents[0], m).items():
        eff = cur[path][2] if path in cur else None
        biz = after[2] if after else None
        div = [d for d in div if d["path"] != path]
        if eff != biz:
            div.append({"path": path, "business_blob": biz, "effective_blob": eff})
    g = state["generation"] + 1
    st = dict(state, generation=g, processed_through=m, divergence=div)
    st["proposals"][str(n)] = dict(rec, result="skipped", generation=g)
    st.setdefault("history", []).append({"generation": g, "kind": "skip", "pr": str(n), "from_merge": m})
    commit_policy(head, {}, st, f"skip {n} ({m})")
    print(f"已作废 PR #{n}，gen={g}")


def bootstrap(m):
    """上线第 9 步：引导合并 m 之后，核对业务仓库 policy-proposals/ 和策略仓库逐字节一致，再解除 bootstrap 暂停。"""
    head = api("GET", f"repos/{POL}/git/ref/heads/main", "POL_TOKEN")["object"]["sha"]
    state = read_state("POL_TOKEN", head)
    if (state.get("paused") or {}).get("by") != "bootstrap":
        raise Reject("只有 paused=bootstrap 时能引导")
    if api("GET", f"repos/{BIZ}/compare/{m}...main", "BIZ_TOKEN")["status"] not in ("ahead", "identical"):
        raise Reject("引导提交不在业务仓库 main 上")
    biz = blobs(BIZ, subtree_sha(BIZ, m, "policy-proposals", "BIZ_TOKEN"), "BIZ_TOKEN")
    pol = {k: v for k, v in blobs(POL, commit_tree(POL, head, "POL_TOKEN"), "POL_TOKEN").items() if PROPOSAL_RE.match(k)}
    if {k: v[2] for k, v in biz.items()} != {k: v[2] for k, v in pol.items()}:
        raise Reject("业务仓库 policy-proposals/ 和策略仓库内容不一致")
    g = state["generation"] + 1
    st = dict(state, generation=g, paused=None, processed_through=m, active={"from_merge": m, "pr": None, "generation": g})
    st.setdefault("history", []).append({"generation": g, "kind": "bootstrap", "from_merge": m})
    commit_policy(head, {}, st, f"bootstrap ({m})")
    print(f"引导完成，gen={g}")


# ---------------- 分支保护 ----------------

def sync(policy_dir, dry):
    rc = yaml_json(open(os.path.join(policy_dir, "required-checks.yaml")).read())
    if rc.get("repo") != BIZ or rc.get("branch") != "main" or not isinstance(rc.get("strict"), bool):
        raise Reject("required-checks.yaml 的 repo/branch/strict 不对")
    url = f"repos/{BIZ}/branches/main/protection/required_status_checks"
    online = api("GET", url, "ADMIN_TOKEN")
    if online.get("contexts") and not online.get("checks"):
        raise Reject("线上是旧式 contexts 格式，不猜")
    have = {(c["context"], c.get("app_id")) for c in online["checks"]}
    want = {(e["context"], e["expected_source"]["app_id"]) for e in rc.get("branch_protection") or []}
    named = {c for c, _ in want}
    want |= {x for x in have if x[0] in NEVER_REMOVE and x[0] not in named}   # 这两项只能 Yarrow 手动删
    if have == want and online["strict"] == rc["strict"]:
        print(f"分支保护一致（{len(have)} 项，strict={online['strict']}）"); return
    print(f"分支保护不一致：多 {sorted(have - want)}，少 {sorted(want - have)}，strict {online['strict']}->{rc['strict']}")
    if dry:
        sys.exit(1)
    body = {"strict": rc["strict"], "checks": [{"context": c, "app_id": a} for c, a in sorted(want)]}
    api("PATCH", url, "ADMIN_TOKEN", body)
    back = api("GET", url, "ADMIN_TOKEN")
    if {(c["context"], c.get("app_id")) for c in back["checks"]} != want or back["strict"] != rc["strict"]:
        raise Reject("PATCH 后读回不一致")
    print("分支保护已同步并读回一致")


def main(argv):
    cmd = argv[1]
    try:
        if cmd == "fetch":
            fetch(argv[2], argv[3], argv[4])
        elif cmd == "write":
            write(argv[2], argv[3])
        elif cmd == "publish":
            publish()
        elif cmd == "rollback":
            rollback(argv[2])
        elif cmd == "skip":
            skip(argv[2])
        elif cmd == "bootstrap":
            bootstrap(argv[2])
        elif cmd == "sync":
            sync(argv[2], argv[3:] == ["--dry-run"])
        else:
            raise SystemExit(f"未知命令 {cmd}")
    except Retry as e:
        print(f"::error::retryable：{e}"); sys.exit(1)
    except Reject as e:
        print(f"::error::rejected：{e}"); sys.exit(1)


if __name__ == "__main__":
    main(sys.argv)
