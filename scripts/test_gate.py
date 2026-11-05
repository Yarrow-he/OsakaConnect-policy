"""gate.py 的固定样例测试（只用标准库）。policy-selftest 和本地都跑：python3 -m unittest -v test_gate"""
import copy, json, os, tempfile, unittest
import gate

PS = {"threshold": 200, "exclude_paths": ["tests/**", "**/*.md", "policy-proposals/*.yaml"], "scaffold_temp": [],
      "log_functions": {"python": ["logger.info"], "kotlin": ["Log.d"]},
      "comment_syntax": {"python": {"line": ["#"], "docstring_only": True}, "kotlin": {"line": ["//"], "block": [["/*", "*/"]]}}}
CI = {"yarrow_classes": {
    "1_secrets": {"paths": [], "diff_patterns": ["(?i)secrets\\s*[.\\[]", "(?i)private[_-]?key", "(?i)osaka[_-]?[a-z0-9_]*[_-]?key"]},
    "2_permissions": {"paths": ["policy-repo:scripts/**", "policy-proposals/scripts/**", ".github/CODEOWNERS"],
                      "diff_patterns": ["permissions\\s*:"]},
    "3_key_acceptance_list": {"paths": ["policy-proposals/key-acceptance-tests.yaml"]},
    "4_pr_size": {"paths": []}, "5_loosen_gate": {"rules": []},
    "6_protected_config": {"paths": [".codex/**", ".claude/**", ".github/workflows/**", "scripts/check-*.sh"]},
    "7_board_scope": {"paths": []}},
    "proposal_paths": [],
    "scope": {"module_extra": ["notes/", "board.json", "tests/"],
              "branch_kinds": [{"prefix": "lead/", "paths": "global"}, {"prefix": "tests/", "paths": ["tests/", "board.json"]}],
              "board_task_keys": ["version", "updated_at", "prs", "tasks", "decisions_log"],
              "board_module_keys": ["id", "branch", "paths"],
              "branch_name_patterns": ["^(server|android|windows)/[^/]+-[0-9]+$", "^ci/[^/]+-[0-9]+$",
                                       "^(lead|tests|bookkeeping)/[^/]+$"],
              "bookkeeping_paths": ["board.json", "notes/", "memory/", "reports/"],
              "bookkeeping_mix_ok_prefixes": ["tests/", "ci/"]}}
BOARD = {"version": 1, "tasks": [], "prs": {},
         "scope": {"global": ["src/", "tests/", "README.md", "board.json", "server/", "notes/", ".github/", "scripts/"],
                   "protected": [".codex/", ".claude/"]},
         "modules": [{"id": "server-core", "branch": "server/server-core", "paths": ["server/"], "state": "待写"}]}
RC = {"repo": "Yarrow-he/OsakaConnect", "branch": "main", "strict": False,
      "branch_protection": [{"context": "python", "expected_source": {"app_id": 15368}}],
      "gate_verified": [{"context": "pr-size", "expected_source": {"app_id": 5592067}}]}
KT = {"tests": [{"id": "t1", "entry": "tests/a.sh", "paths": ["tests/a.sh"], "job": "python"}]}
CFG = {"pr_size": PS, "ci_class": CI, "required": RC, "key_tests": KT}
HEAD = "h" * 40
GLOB = {"generation": 3, "paused": None, "pending": "", "owner": "Yarrow-he"}


def f(name, patch, **kw):
    return dict({"filename": name, "status": "modified", "patch": patch}, **kw)


def pr(files, **kw):
    d = {"pr": 7, "head": HEAD, "files": files, "reviews": [],
         "check_runs": [{"id": 1, "name": "python", "app_id": 15368, "status": "completed", "conclusion": "success", "suite": 9}],
         "meta": {"title": "t", "body": "", "commits": [{"message": "m", "names": list(gate.ME) * 2}]},
         "head_ref": "lead/x", "base_ref": "main", "main_board": copy.deepcopy(BOARD),
         "head_paths": ["tests/a.sh"], "ci_jobs": {"jobs": {"python": {"steps": [{"run": "bash tests/a.sh"}]}}}, "proposal_yaml": {}}
    d.update(kw)
    return d


def by_name(checks):
    return {c["name"]: c for c in checks}


class PrSize(unittest.TestCase):
    def test_comments_blank_logs_not_counted(self):
        p = "@@ -1,3 +1,8 @@\n x = 1\n+# comment\n+\n+logger.info(\"hi %s\", name)\n+logger.info(foo())\n+y = 2\n-z = 3\n"
        self.assertEqual(gate.count_patch("a.py", p, PS), 2)   # foo() 调用、y=2；删 z=3 不计

    def test_kotlin_block_comment(self):
        p = "@@ -5,2 +5,6 @@\n fun a() {\n+/* start\n+ still comment\n+ end */\n+val b = 1\n+Log.d(TAG, \"x\")\n }\n"
        self.assertEqual(gate.count_patch("A.kt", p, PS), 1)

    def test_docstring_only_at_docstring_position(self):
        p = '@@ -10,2 +10,6 @@\n def f():\n+    """doc\n+    more"""\n+    s = """not doc\n+    still string"""\n'
        self.assertEqual(gate.count_patch("a.py", p, PS), 2)

    def test_threshold_excludes_binary_and_unknown_patch(self):
        files = [f("src/a.py", "@@ -1 +1,201 @@\n" + "".join(f"+v{i} = {i}\n" for i in range(201))),
                 f("tests/x.py", "@@ -1 +1 @@\n+a=1\n"), f("README.md", "@@ -1 +1 @@\n+a\n")]
        self.assertEqual(gate.pr_size(files, PS)[0], "failure")
        files = [f("img.png", None, binary=True), f("big.cs", None, additions=150, deletions=49)]
        c, s = gate.pr_size(files, PS)
        self.assertEqual(c, "success"); self.assertIn("计入 151 行", s)   # 缺补丁兜底只按新增行数计，删除不计
        self.assertIn("缺补丁", s)
        files = [f("big.cs", None, additions=201, deletions=0)]
        self.assertEqual(gate.pr_size(files, PS)[0], "failure")

    def test_rename_out_of_excluded_counts(self):
        files = [f("src/b.py", "@@ -1 +1 @@\n-a = 1\n+a = 2\n", status="renamed", previous_filename="tests/b.py")]
        self.assertIn("计入 1 行", gate.pr_size(files, PS)[1])

    def test_pure_deletion_and_modification(self):
        self.assertEqual(gate.count_patch("a.py", "@@ -1,3 +0,0 @@\n-a = 1\n-b = 2\n-c = 3\n", PS), 0)
        self.assertEqual(gate.count_patch("a.py", "@@ -1,2 +1,2 @@\n-a = 1\n-b = 2\n+a = 3\n+b = 4\n", PS), 2)
        # 删掉一个块注释的开头：新文件一侧剩下的行变成运行代码，要计入
        p = "@@ -1,3 +1,2 @@\n-/* old\n x = 1\n+y = 2\n"
        self.assertEqual(gate.count_patch("A.kt", p, PS), 2)   # 第三轮：x = 1 从注释变成运行代码，也计入

    def test_exclusion_reasons(self):
        files = [f("tests/x.py", "@@ -1 +1 @@\n+a=1\n"), f("docs/a.md", "@@ -1 +1 @@\n+a\n"), f("src/a.py", "@@ -1 +1 @@\n+a = 1\n")]
        c, s = gate.pr_size(files, PS)
        self.assertIn("tests/x.py: 不计入（tests/x.py 命中排除路径 tests/**）", s)
        self.assertIn("docs/a.md: 不计入（docs/a.md 命中排除路径 **/*.md）", s)
        self.assertIn("src/a.py: 1", s)
        ps = dict(PS, scaffold_temp=["android/**"])
        self.assertIn("命中临时脚手架 android/**", gate.pr_size([f("android/b.kts", "@@ -0,0 +1 @@\n+x\n")], ps)[1])


class ApprovalClass(unittest.TestCase):
    def cls(self, files, yamls=None):
        return gate.approval_class(files, yamls or {}, CI, PS)

    def test_regular(self):
        self.assertEqual(self.cls([f("src/a.py", "@@\n+x=1\n")])[:2], ("success", "regular"))

    def test_scripts_path_and_secret_pattern(self):
        self.assertEqual(self.cls([f("policy-proposals/scripts/gate.py", "@@\n+x\n")])[1], "yarrow")
        self.assertEqual(self.cls([f("src/a.py", "@@\n+k = PRIVATE_KEY\n")])[1], "yarrow")

    def test_permission_pattern_only_in_github_dir(self):
        self.assertEqual(self.cls([f("src/a.py", "@@\n+permissions: x\n")])[1], "regular")
        self.assertEqual(self.cls([f(".github/workflows/ci.yml", "@@\n+permissions: write-all\n")])[1], "yarrow")

    def test_bad_proposal_path_fails(self):
        self.assertEqual(self.cls([f("policy-proposals/.github/workflows/x.yml", "@@\n+x\n")])[0], "failure")
        self.assertEqual(self.cls([f("policy-proposals/other.txt", "@@\n+x\n")])[0], "failure")

    def test_required_checks_remove_is_class5_add_is_regular(self):
        p = "policy-proposals/required-checks.yaml"
        ff = [f(p, "@@\n+x\n")]
        more = copy.deepcopy(RC); more["branch_protection"].append({"context": "lint", "expected_source": {"app_id": 15368}})
        self.assertEqual(gate.approval_class(ff, {p: {"base": RC, "head": more}}, CI, PS, {"lint"})[1], "regular")
        self.assertEqual(self.cls(ff, {p: {"base": RC, "head": more}})[0], "failure")    # 新业务检查在 head 上没出现过
        self.assertEqual(gate.approval_class(ff, {p: {"base": more, "head": RC}}, CI, PS, {"lint"})[1], "yarrow")
        bad = copy.deepcopy(RC); bad["gate_verified"].append({"context": "new-gate", "expected_source": {"app_id": 5592067}})
        self.assertEqual(self.cls(ff, {p: {"base": RC, "head": bad}})[0], "failure")     # 闸口不写这个检查
        bad = copy.deepcopy(RC); bad["gate_verified"].append({"context": "x", "expected_source": {"app_id": "15368"}})
        self.assertEqual(self.cls(ff, {p: {"base": RC, "head": bad}})[0], "failure")     # app_id 不是整数
        moved = copy.deepcopy(RC); moved["gate_verified"].append(moved["branch_protection"].pop())
        self.assertEqual(gate.approval_class(ff, {p: {"base": RC, "head": moved}}, CI, PS, {"python"})[1], "yarrow")

    def test_pr_size_keys_and_comment_syntax(self):
        p = "policy-proposals/pr-size.yaml"
        ff = [f(p, "@@\n+x\n")]
        h = copy.deepcopy(PS); h["threshold"] = 300
        self.assertEqual(self.cls(ff, {p: {"base": PS, "head": h}})[1], "yarrow")
        h = copy.deepcopy(PS); h["comment_syntax"]["python"]["line"] = ["#", "x"]
        self.assertEqual(self.cls(ff, {p: {"base": PS, "head": h}})[0], "failure")
        h = copy.deepcopy(PS); h["comment_syntax"]["python"]["docstring_only"] = False
        self.assertEqual(self.cls(ff, {p: {"base": PS, "head": h}})[0], "failure")
        h = copy.deepcopy(PS); h["bogus"] = 1
        self.assertEqual(self.cls(ff, {p: {"base": PS, "head": h}})[0], "failure")

    def test_key_tests_schema(self):
        p = "policy-proposals/key-acceptance-tests.yaml"
        ff = [f(p, "@@\n+x\n")]
        self.assertEqual(self.cls(ff, {p: {"base": KT, "head": {"tests": [{"id": "t1", "paths": []}]}}})[0], "failure")
        self.assertEqual(self.cls(ff, {p: {"base": KT, "head": {"tests": []}}})[0], "failure")

    def test_parse_error_fails(self):
        p = "policy-proposals/pr-size.yaml"
        self.assertEqual(self.cls([f(p, "@@\n+x\n")], {p: {"error": "bad"}})[0], "failure")


class Scope(unittest.TestCase):
    def run_(self, files, **kw):
        c = by_name(gate.evaluate(pr(files, **kw), CFG, GLOB))["ci-approval-class"]
        return c["conclusion"], c["title"], c["summary"]

    def test_module_branch_in_and_out(self):
        self.assertEqual(self.run_([f("server/a.py", "@@\n+x\n")], head_ref="server/server-core-2")[:2], ("success", "class=regular"))
        c, _, s = self.run_([f("src/a.py", "@@\n+x\n")], head_ref="server/server-core")
        self.assertEqual(c, "failure"); self.assertIn("超出模块 server-core", s)

    def test_fake_lead_setup_gets_no_exception(self):
        for p in (".codex/config.toml", ".claude/settings.json"):
            c, t, s = self.run_([f(p, "@@\n+x\n")], head_ref="lead/setup-x")
            self.assertEqual((c, t), ("success", "class=yarrow")); self.assertIn("6_protected_config", s)

    def test_delete_and_rename_checked(self):
        c, _, s = self.run_([f("admin/old.cs", "", status="removed")], head_ref="lead/x")
        self.assertEqual(c, "failure"); self.assertIn("admin/old.cs", s)
        c, _, s = self.run_([f("server/b.py", "", status="renamed", previous_filename="admin/b.py")], head_ref="server/server-core")
        self.assertEqual(c, "failure"); self.assertIn("admin/b.py", s)
        c, t, _ = self.run_([f("server/b.py", "", status="renamed", previous_filename=".codex/x")], head_ref="server/server-core")
        self.assertEqual((c, t), ("success", "class=yarrow"))
        c, t, _ = self.run_([f(".github/workflows/ci.yml", "", status="removed")], head_ref="lead/x")
        self.assertEqual((c, t), ("success", "class=yarrow"))

    def test_unknown_branch_blocked(self):
        for ref in ("feature/x", "android/android-shell", "server/server-cor"):
            self.assertEqual(self.run_([f("server/a.py", "@@\n+x\n")], head_ref=ref)[0], "failure", ref)
        self.assertEqual(self.run_([f("server/a.py", "@@\n+x\n")], head_ref="lead/x", base_ref="dev")[0], "failure")
        self.assertEqual(self.run_([f("server/a.py", "@@\n+x\n")], head_ref=None)[0], "failure")
        self.assertEqual(self.run_([f("server/a.py", "@@\n+x\n")], main_board=None)[0], "failure")
        bad = copy.deepcopy(BOARD); bad["scope"]["global"] = "server/"
        self.assertEqual(self.run_([f("server/a.py", "@@\n+x\n")], main_board=bad)[0], "failure")

    def test_skills_no_exception(self):
        self.assertEqual(self.run_([f(".codex/skills/a.md", "@@\n+x\n")], head_ref="tests/x")[1], "class=yarrow")
        self.assertEqual(self.run_([f("skills/a.md", "@@\n+x\n")], head_ref="tests/x")[0], "failure")

    def test_board_tasks_regular_scope_yarrow(self):
        h = copy.deepcopy(BOARD); h["tasks"].append({"id": 1}); h["modules"][0]["state"] = "完成"; h["version"] = 2
        ff = [f("board.json", "@@\n+x\n")]
        self.assertEqual(self.run_(ff, board_change={"base": BOARD, "head": h})[:2], ("success", "class=regular"))
        for mut in (lambda b: b["scope"]["global"].append("admin/"), lambda b: b["modules"][0]["paths"].append("src/"),
                    lambda b: b["modules"].append({"id": "x", "branch": "lead/x", "paths": []}), lambda b: b.update(newkey=1)):
            h = copy.deepcopy(BOARD); mut(h)
            c, t, s = self.run_(ff, board_change={"base": BOARD, "head": h})
            self.assertEqual((c, t), ("success", "class=yarrow")); self.assertIn("7_board_scope", s)
            self.assertNotIn("admin/", s.split("7_board_scope")[1])   # 不回显内容
        self.assertEqual(self.run_(ff, board_change={"base": BOARD, "head": None})[1], "class=yarrow")
        self.assertEqual(self.run_(ff, board_change={"error": "x"})[0], "failure")

    def test_workflow_and_check_scripts_yarrow(self):
        for p in (".github/workflows/ci.yml", ".github/workflows/new.yml", "scripts/check-scope.sh", "scripts/check-merge-scope.sh"):
            for ref in ("lead/x", "server/server-core"):
                c, t, s = self.run_([f(p, "@@\n+echo ok\n")], head_ref=ref)
                self.assertEqual(t, "class=yarrow", (p, ref))
                if ref == "lead/x":
                    self.assertEqual(c, "success")
        self.assertEqual(self.run_([f("scripts/other.sh", "@@\n+x\n")], head_ref="lead/x")[1], "class=regular")

    def test_scope_from_main_not_pr(self):
        # PR 里把 board.json scope 改宽：范围仍按 main，且 board 改动进 Yarrow 档
        h = copy.deepcopy(BOARD); h["scope"]["global"].append("admin/")
        c, _, s = self.run_([f("board.json", "@@\n+x\n"), f("admin/a.cs", "@@\n+x\n")], head_ref="lead/x",
                            board_change={"base": BOARD, "head": h})
        self.assertEqual(c, "failure"); self.assertIn("admin/a.cs 不在 main", s)

    def test_realname_path_not_echoed(self):
        nm = "ha" + "o_yi" + "n"
        c, _, s = self.run_([f("x/" + nm + ".txt", "@@\n+x\n")])
        self.assertEqual(c, "failure"); self.assertNotIn(nm, s)


class Owner(unittest.TestCase):
    def test_rules(self):
        R = lambda s, c=HEAD, u="Yarrow-he": {"user": u, "state": s, "commit_id": c}
        self.assertEqual(gate.owner_approval("regular", [], HEAD, "Yarrow-he")[0], "success")
        self.assertEqual(gate.owner_approval("yarrow", [R("APPROVED")], HEAD, "Yarrow-he")[0], "success")
        self.assertEqual(gate.owner_approval("yarrow", [R("APPROVED"), R("COMMENTED")], HEAD, "Yarrow-he")[0], "success")
        self.assertEqual(gate.owner_approval("yarrow", [R("APPROVED", "old")], HEAD, "Yarrow-he")[0], "failure")
        self.assertEqual(gate.owner_approval("yarrow", [R("APPROVED"), R("DISMISSED")], HEAD, "Yarrow-he")[0], "failure")
        self.assertEqual(gate.owner_approval("yarrow", [R("APPROVED", u="bot")], HEAD, "Yarrow-he")[0], "failure")
        self.assertEqual(gate.owner_approval("error", [R("APPROVED")], HEAD, "Yarrow-he")[0], "failure")


class Summary(unittest.TestCase):
    def ev(self, p, **g):
        return by_name(gate.evaluate(p, CFG, dict(GLOB, **g)))

    def test_all_green(self):
        c = self.ev(pr([f("src/a.py", "@@\n+x = 1\n")]))
        self.assertEqual(c["gate-summary"]["conclusion"], "success")
        self.assertIn("gen=3", c["gate-summary"]["summary"])

    def test_realname(self):
        nm = "Ha" + "o Yi" + "n"
        em = "someone@example.org"   # 虚构邮箱：测试时临时换掉 BAD_EMAIL_SHA，源码不带真实邮箱
        old = gate.BAD_EMAIL_SHA
        gate.BAD_EMAIL_SHA = {gate.hashlib.sha256(em.encode()).hexdigest()}
        self.addCleanup(setattr, gate, "BAD_EMAIL_SHA", old)
        ok = pr([f("src/a.py", "@@\n+x = 1\n-" + nm + "\n")])
        self.assertEqual(self.ev(ok)["gate-summary"]["conclusion"], "success")   # 删除真名不拦
        for v in (nm, nm.upper(), nm.replace(" ", ""), nm.replace(" ", "_"), nm.lower()):
            c = self.ev(pr([f("src/a.py", "@@\n+# by " + v + "\n")]))["gate-summary"]
            self.assertEqual(c["conclusion"], "failure", v)
            self.assertNotIn(v, c["summary"])
        meta = lambda **k: dict({"title": "t", "body": "", "commits": [{"message": "m", "names": list(gate.ME) * 2}]}, **k)
        for m in (meta(title="x " + nm), meta(body=nm.lower()),
                  meta(commits=[{"message": "fix per " + nm, "names": ["a", "b"]}]),
                  meta(commits=[{"message": "m", "names": ["Yarrow-he", em.upper()]}]),
                  meta(body="联系 " + em + "."), meta(body="<" + em + ">"),
                  meta(commits=[{"message": "m", "names": [nm.replace(" ", ""), "b"]}])):
            c = self.ev(pr([], meta=m))["gate-summary"]
            self.assertEqual(c["conclusion"], "failure", m)
            for v in (nm, nm.lower(), nm.replace(" ", ""), em, em.upper()):
                self.assertNotIn(v.lower(), c["summary"].lower())
        c = self.ev(pr([f(nm.lower() + ".md", "@@\n+" + nm + "\n")]))["gate-summary"]
        self.assertEqual(c["conclusion"], "failure")
        self.assertNotIn(nm.lower(), c["summary"].lower())
        self.assertEqual(self.ev(pr([], meta=meta(body="Yarrow shang" + "hao" + "yinx yarrow@x.com")))["gate-summary"]["conclusion"], "success")
        for cm in ([nm], ["ok", "感谢 " + nm.lower()], ["mail " + em]):
            c = self.ev(pr([], meta=meta(comments=cm)))["gate-summary"]
            self.assertEqual(c["conclusion"], "failure", cm)
            self.assertIn("PR 评论", c["summary"]); self.assertNotIn(nm.lower(), c["summary"].lower())
        self.assertEqual(self.ev(pr([], meta=meta(comments=["看起来没问题"])))["gate-summary"]["conclusion"], "success")
        p = pr([]); del p["meta"]
        self.assertEqual(self.ev(p)["gate-summary"]["conclusion"], "failure")

    def test_author(self):
        me, web = list(gate.ME), ["GitHub", "noreply@github.com"]
        meta = lambda *cs: {"title": "t", "body": "", "commits": [{"message": "m", "names": n} for n in cs]}
        self.assertEqual(self.ev(pr([], meta=meta(me * 2, me * 2)))["gate-summary"]["conclusion"], "success")
        c = self.ev(pr([], meta=meta(me * 2, me + web)))["gate-summary"]   # 网页 Update branch 生成的提交不再放行
        self.assertEqual(c["conclusion"], "failure"); self.assertIn("第 2 个提交的提交人", c["summary"])
        for bad, where in ((["osaka-work[bot]", "x@users.noreply.github.com"] + me, "第 1 个提交的作者"),
                           (me + ["osaka-gate[bot]", "y@users.noreply.github.com"], "第 1 个提交的提交人"),
                           (web + web, "第 1 个提交的作者"), (["Yarrow", "a@b.c"] + me, "第 1 个提交的作者"), (me, "第 1 个提交的提交人")):
            c = self.ev(pr([], meta=meta(bad)))["gate-summary"]
            self.assertEqual(c["conclusion"], "failure", bad)
            self.assertIn(where, c["summary"])
        c = self.ev(pr([], meta=meta(me * 2, me + ["osaka-gate[bot]", "z"])))["gate-summary"]
        self.assertIn("第 2 个提交的提交人", c["summary"])

    def test_paused_and_pending_and_incomplete(self):
        self.assertEqual(self.ev(pr([]), paused={"by": "bootstrap"})["gate-summary"]["conclusion"], "failure")
        self.assertEqual(self.ev(pr([]), pending="x")["gate-summary"]["conclusion"], "failure")
        c = self.ev(pr([], incomplete="300 files"))
        self.assertTrue(all(x["conclusion"] == "failure" for x in c.values()))

    def test_business_check_pending_failure_and_fake_suite(self):
        runs = [{"id": 1, "name": "python", "app_id": 15368, "status": "in_progress", "conclusion": None, "suite": 9}]
        self.assertIsNone(self.ev(pr([], check_runs=runs))["gate-summary"]["conclusion"])
        self.assertIsNone(self.ev(pr([], check_runs=[]))["gate-summary"]["conclusion"])
        runs = [{"id": 1, "name": "python", "app_id": 15368, "status": "completed", "conclusion": "failure", "suite": 9},
                {"id": 2, "name": "python", "app_id": 15368, "status": "completed", "conclusion": "success", "suite": 10}]
        self.assertEqual(self.ev(pr([], check_runs=runs))["gate-summary"]["conclusion"], "failure")
        runs = [{"id": 1, "name": "python", "app_id": 15368, "status": "completed", "conclusion": "failure", "suite": 9},
                {"id": 3, "name": "python", "app_id": 15368, "status": "completed", "conclusion": "success", "suite": 9}]
        self.assertEqual(self.ev(pr([], check_runs=runs))["gate-summary"]["conclusion"], "success")   # 同 suite 重跑取最新
        runs = [{"id": 1, "name": "python", "app_id": 99, "status": "completed", "conclusion": "success", "suite": 9}]
        self.assertIsNone(self.ev(pr([], check_runs=runs))["gate-summary"]["conclusion"])               # 别的来源不认

    def test_yarrow_needs_approval_and_selftest(self):
        files = [f("policy-proposals/scripts/gate.py", "@@\n+x = 1\n")]
        c = self.ev(pr(files))
        self.assertEqual(c["owner-approval"]["conclusion"], "failure")
        self.assertEqual(c["gate-summary"]["conclusion"], "failure")
        rv = [{"user": "Yarrow-he", "state": "APPROVED", "commit_id": HEAD}]
        self.assertIsNone(self.ev(pr(files, reviews=rv))["gate-summary"]["conclusion"])   # 等 policy-selftest
        runs = pr([])["check_runs"] + [{"id": 5, "name": "policy-selftest", "app_id": 15368, "status": "completed",
                                        "conclusion": "success", "suite": 11}]
        self.assertEqual(self.ev(pr(files, reviews=rv, check_runs=runs))["gate-summary"]["conclusion"], "success")

    def test_key_tests(self):
        self.assertEqual(self.ev(pr([], head_paths=[]))["gate-summary"]["conclusion"], "failure")
        self.assertEqual(self.ev(pr([], ci_jobs={"jobs": {"python": {}}}))["gate-summary"]["conclusion"], "failure")
        cfg = dict(CFG, key_tests={"tests": []})
        self.assertEqual(by_name(gate.evaluate(pr([]), cfg, GLOB))["gate-summary"]["conclusion"], "failure")

    def test_size_failure_blocks_summary(self):
        big = f("src/a.py", "@@ -1 +1,201 @@\n" + "".join(f"+v{i} = {i}\n" for i in range(201)))
        self.assertEqual(self.ev(pr([big]))["gate-summary"]["conclusion"], "failure")

    def test_main_end_to_end(self):
        d = tempfile.mkdtemp()
        os.makedirs(f"{d}/in/prs")
        json.dump(CFG, open(f"{d}/in/config.json", "w")); json.dump(GLOB, open(f"{d}/in/global.json", "w"))
        json.dump(pr([f("src/a.py", "@@\n+x = 1\n")]), open(f"{d}/in/prs/7.json", "w"))
        gate.main(f"{d}/in", f"{d}/out")
        o = json.load(open(f"{d}/out/7.json"))
        self.assertEqual((o["pr"], o["head"], len(o["checks"])), (7, HEAD, 4))


class R3Fixes(unittest.TestCase):
    def test_comment_boundary_removed_in_hunk(self):
        p = "@@ -1,3 +1,1 @@\n-/*\n run();\n-*/\n"
        self.assertEqual(gate.count_patch("A.kt", p, PS), 1)
        big = "@@ -1,603 +1,201 @@\n" + "".join("-/*\n run();\n-*/\n" for _ in range(201))
        self.assertEqual(gate.count_patch("A.kt", big, PS), 201)

    def test_code_after_block_close(self):
        self.assertEqual(gate.count_patch("A.kt", "@@ -0,0 +1,2 @@\n+/* note\n+*/ run();\n", PS), 1)
        self.assertEqual(gate.count_patch("A.kt", "@@ -0,0 +1,2 @@\n+/* note\n+*/ // c\n", PS), 0)
        self.assertEqual(gate.count_patch("A.kt", "@@ -1,2 +1,2 @@\n /* a\n */\n", PS), 0)   # 上下文没变不计

    def test_secret_env_position(self):
        base = {"jobs": {"a": {"steps": [{"env": {"REGISTRY": "${{ secrets.REGISTRY }}"}}, {"env": {"REGISTRY": "ghcr.io/x"}}]}}}
        head = copy.deepcopy(base); head["jobs"]["a"]["steps"][1]["env"]["REGISTRY"] = "ghcr.io/y"
        e, r = gate.secret_env({".github/workflows/x.yml": {"base": base, "head": head}}, ["(?i)token"])
        self.assertEqual(r, [])
        head["jobs"]["a"]["steps"][0]["env"]["REGISTRY"] = "plain"
        e, r = gate.secret_env({".github/workflows/x.yml": {"base": base, "head": head}}, ["(?i)token"])
        self.assertEqual(len(r), 1)

    def test_validate_bad_regex(self):
        d = copy.deepcopy(CI); d["yarrow_classes"]["1_secrets"]["env_name_patterns"] = ["(unclosed"]
        self.assertTrue(any("正则" in x for x in gate.validate("ci-approval-class.yaml", d)))
        d["yarrow_classes"]["1_secrets"]["env_name_patterns"] = "x"
        self.assertTrue(any("字符串列表" in x for x in gate.validate("ci-approval-class.yaml", d)))


class R4Fixes(unittest.TestCase):
    def test_step_insert_not_secret_change(self):
        st = {"id": "pub", "env": {"NPM_TOKEN": "${{ secrets.NPM }}"}}
        base = {"runs": {"steps": [st]}}
        head = {"runs": {"steps": [{"run": "echo hi"}, copy.deepcopy(st)]}}
        self.assertEqual(gate.secret_env({".github/a/action.yml": {"base": base, "head": head}}, ["(?i)token"])[1], [])
        named = {"name": "pub", "env": {"NPM_TOKEN": "x"}}
        b2 = {"steps": [named]}; h2 = {"steps": [{"run": "x"}, copy.deepcopy(named)]}
        self.assertEqual(gate.secret_env({".github/a.yml": {"base": b2, "head": h2}}, ["(?i)token"])[1], [])
        h3 = {"steps": [copy.deepcopy(named), copy.deepcopy(named)]}   # 新增第二份相同 env 仍算新增
        self.assertEqual(len(gate.secret_env({".github/a.yml": {"base": b2, "head": h3}}, ["(?i)token"])[1]), 1)

    def test_copied_uses_new_path_only(self):
        c, s = gate.pr_size([f("tests/fx.py", "@@ -0,0 +1 @@\n+x = 1\n", status="copied", previous_filename="src/h.py")], PS)
        self.assertIn("tests/fx.py: 不计入", s)

    def test_bad_class_structure(self):
        for bad in (None, "x", {"paths": [1]}):
            d = copy.deepcopy(CI); d["yarrow_classes"]["1_secrets"] = bad
            self.assertTrue(gate.validate("ci-approval-class.yaml", d), bad)
        d = copy.deepcopy(CI); d["scope"]["branch_kinds"] = [{"prefix": "x/", "paths": [None]}]
        self.assertTrue(gate.validate("ci-approval-class.yaml", d))
        d = copy.deepcopy(CI); d["yarrow_classes"]["1_secrets"] = None   # 消费端不崩
        c, cls, s = gate.approval_class([f("src/a.py", "@@\n+x\n")], {}, d, PS)
        self.assertNotEqual(cls, "error")


class R5Fixes(unittest.TestCase):
    def test_full_content_cross_hunk(self):
        old = "/*\na\nb\nc\nd\ne\nf\ng\nh\n*/\n"
        new = "a\nb\nc\nd\ne\nf\ng\nh\n"
        p = "@@ -1,4 +1,3 @@\n-/*\n a\n b\n c\n@@ -7,4 +6,3 @@\n f\n g\n h\n-*/\n"
        self.assertEqual(gate.count_patch("A.kt", p, PS, {"old": old, "new": new}), 8)   # a~h 全变成代码，含两个 hunk 之间没出现在补丁里的 d、e
        # 只改块注释里面的一行：新增行在注释里，不计
        o2 = "x = 1\n/*\n" + "c\n" * 10 + "old\n*/\n"; n2 = "x = 1\n/*\n" + "c\n" * 10 + "new\n*/\n"
        self.assertEqual(gate.count_patch("A.kt", "@@ -11,3 +11,3 @@\n c\n-old\n+new\n */\n", PS, {"old": o2, "new": n2}), 0)
        self.assertEqual(gate.count_patch("A.kt", "@@ -11,3 +11,3 @@\n c\n-old\n+new\n */\n", PS), 1)   # 没全文旧做法误计

    def test_full_mismatch_raises_to_failure(self):
        c = by_name(gate.evaluate(pr([f("A.kt", "@@ -1,1 +1,1 @@\n-a\n+b\n", full={"old": "", "new": ""})]), CFG, GLOB))["pr-size"]
        self.assertEqual(c["conclusion"], "failure")

    def test_python_docstring_full(self):
        old = 'def f():\n    """doc\n    x = 1\n    """\n    return 1\n'
        new = 'def f():\n    """doc\n    x = 2\n    """\n    return 1\n'
        self.assertEqual(gate.count_patch("a.py", "@@ -3,1 +3,1 @@\n-    x = 1\n+    x = 2\n", PS, {"old": old, "new": new}), 0)

    def test_fingerprint_steps(self):
        st = {"run": "npm publish", "env": {"NPM_TOKEN": "${{ secrets.NPM }}"}}
        b = {"steps": [st]}; h = {"steps": [{"run": "echo prep"}, copy.deepcopy(st)]}
        self.assertEqual(gate.secret_env({".github/a.yml": {"base": b, "head": h}}, ["(?i)token"])[1], [])
        u = {"uses": "actions/x@v1", "with": {"a": 1}, "env": {"NPM_TOKEN": "${{ secrets.NPM }}"}}
        self.assertEqual(gate.secret_env({".github/a.yml": {"base": {"steps": [u]}, "head": {"steps": [{"uses": "actions/y@v1"}, copy.deepcopy(u)]}}},
                                         ["(?i)token"])[1], [])
        h2 = {"steps": [dict(st, run="npm publish --tag x")]}   # 第六轮：匿名步骤内容变了就算 env 位置变了（偏严）；给步骤加 id 可避免
        self.assertEqual(len(gate.secret_env({".github/a.yml": {"base": b, "head": h2}}, ["(?i)token"])[1]), 1)
        h2id = {"steps": [dict(st, id="pub", run="npm publish --tag x")]}
        b_id = {"steps": [dict(st, id="pub")]}
        self.assertEqual(gate.secret_env({".github/a.yml": {"base": b_id, "head": h2id}}, ["(?i)token"])[1], [])  # 有 id：只改 run 不算
        ub = {"steps": [{"uses": "v/publish@v1", "env": {"NPM_TOKEN": "${{ secrets.NPM }}"}}]}
        uh = {"steps": [{"uses": "v/publish@v2", "env": {"NPM_TOKEN": "${{ secrets.NPM }}"}}]}   # 匿名只升版本：偏严，算
        self.assertEqual(len(gate.secret_env({".github/a.yml": {"base": ub, "head": uh}}, ["(?i)token"])[1]), 1)
        h3 = {"steps": [copy.deepcopy(st), copy.deepcopy(st)]}   # 一模一样的两步：第二份算新增
        self.assertEqual(len(gate.secret_env({".github/a.yml": {"base": b, "head": h3}}, ["(?i)token"])[1]), 1)
        bare = {"env": {"NPM_TOKEN": "x"}}   # 没 id/name/uses/run 才按位置
        self.assertEqual(len(gate.secret_env({".github/a.yml": {"base": {"steps": [bare]}, "head": {"steps": [{"run": "y"}, bare]}}},
                                             ["(?i)token"])[1]), 1)

    def test_approx_counts_additions(self):
        c, s = gate.pr_size([f("src/a.py", "@@ -1,1 +1,1 @@\n+x\n", patch_approx=True, additions=300)], PS)
        self.assertEqual(c, "failure"); self.assertIn("无法精确计数", s)


class R5bFixes(unittest.TestCase):
    def test_uncomment_secret_scanned(self):
        old = "/*\nval k = PRIVATE_KEY\nx\ny\nz\nw\nv\n*/\n"; new = "val k = PRIVATE_KEY\nx\ny\nz\nw\nv\n"
        p = "@@ -1,2 +1,1 @@\n-/*\n val k = PRIVATE_KEY\n@@ -7,2 +6,1 @@\n v\n-*/\n"
        c, cls, s = gate.approval_class([f("A.kt", p, full={"old": old, "new": new})], {}, CI, PS)
        self.assertEqual(cls, "yarrow")
        c, cls, s = gate.approval_class([f("A.kt", p)], {}, CI, PS)   # 没全文：扫不到（旧行为，留作对照）
        self.assertEqual(cls, "regular")

    def test_secrets_case_insensitive(self):
        b = {"steps": [{"run": "x", "env": {}}]}; h = {"steps": [{"run": "x", "env": {"AUTH": "${{ SECRETS.PROD }}"}}]}
        self.assertEqual(len(gate.secret_env({".github/a.yml": {"base": b, "head": h}}, [])[1]), 1)

    def test_copied_source_not_scoped(self):
        p = pr([f("tests/fx.py", "@@\n+x\n", status="copied", previous_filename="server/a.py")], head_ref="tests/t1")
        errs, reasons = gate.scope_check(p, CI)
        self.assertEqual(errs, [])
        c, cls, s = gate.approval_class([f("tests/w.yml", "@@\n+x\n", status="copied", previous_filename=".github/workflows/a.yml")], {}, CI, PS)
        self.assertEqual(cls, "regular")

    def test_kotlin_raw_string_not_comment(self):
        new = 'val t = """\n/*\n"""\n' + "run()\n" * 201
        old = 'val t = """\n/*\n"""\n'
        p = "@@ -3,0 +4,201 @@\n" + "+run()\n" * 201
        self.assertEqual(gate.count_patch("A.kt", p, PS, {"old": old, "new": new}), 201)
        pyo = 's = """\n# not comment\n"""\n'
        self.assertEqual(gate.count_patch("a.py", "@@ -0,0 +1,3 @@\n+s = \"\"\"\n+# not comment\n+\"\"\"\n", PS, {"old": "", "new": pyo}), 3)



class R6Fixes(unittest.TestCase):
    """第六轮确认漏洞的回归：来自 r6/verify 复现。"""

    def test_csharp_verbatim_not_comment(self):
        new = 'string text = @"\n/*\n";\n' + 'System.Console.WriteLine("work");\n' * 201
        old = 'string text = @"\n/*\n";\n'
        p = "@@ -3,0 +4,201 @@\n" + '+System.Console.WriteLine("work");\n' * 201
        self.assertEqual(gate.count_patch("A.cs", p, PS, {"old": old, "new": new}), 201)

    def test_powershell_here_string_not_comment(self):
        new = '@"\n<#\n"@\n' + 'Write-Host work\n' * 50
        old = '@"\n<#\n"@\n'
        p = "@@ -3,0 +4,50 @@\n" + "+Write-Host work\n" * 50
        self.assertEqual(gate.count_patch("a.ps1", p, PS, {"old": old, "new": new}), 50)

    def test_no_cross_command_cancel(self):
        b = {"steps": [{"run": "npm publish", "env": {"NPM_TOKEN": "${{ inputs.auth }}"}}]}
        h = {"steps": [{"run": "./other.sh", "env": {"NPM_TOKEN": "${{ inputs.auth }}"}}]}
        e, r = gate.secret_env({".github/actions/x/action.yml": {"base": b, "head": h}}, ["(?i)token"])
        self.assertEqual(len(r), 1)

    def test_summary_paths_redacted(self):
        nm = "Ha" + "o Yi" + "n"; fn = nm.replace(" ", "_") + ".png"
        c, s = gate.pr_size([{"filename": fn, "status": "added", "binary": True, "additions": 0, "deletions": 0, "patch": None}], PS)
        self.assertNotIn(fn, s); self.assertNotIn(nm, s); self.assertIn("不显示", s)
        c2, cls, s2 = gate.approval_class([{"filename": ".github/workflows/" + fn + ".yml", "status": "modified", "patch": "@@\n+x\n"}], {}, CI, PS)
        self.assertNotIn(fn, s2); self.assertNotIn(nm, s2)
        e, r = gate.secret_env({".github/workflows/" + fn + ".yml": {"error": "YAML 解析失败"}}, [])
        self.assertTrue(all(fn not in x and nm not in x for x in e + r))
        # evaluate 出站脱敏
        from copy import deepcopy
        files = [{"filename": fn, "status": "added", "binary": True, "additions": 0, "deletions": 0, "patch": None}]
        p = pr(files); p["meta"]["title"] = "t"
        checks = by_name(gate.evaluate(p, CFG, GLOB))
        for c in checks.values():
            self.assertNotIn(nm, c["summary"]); self.assertNotIn(fn, c["summary"])
            self.assertNotIn(nm, c["title"])

    def test_log_interpolation_counts(self):
        self.assertFalse(gate.is_log_line('logger.info(f"{do_work()}")', ["logger.info"]))
        self.assertFalse(gate.is_log_line('Log.d(TAG, "${run()}")', ["Log.d"]))
        self.assertTrue(gate.is_log_line('logger.info("plain")', ["logger.info"]))
        self.assertTrue(gate.is_log_line('logger.info(f"x={y}")', ["logger.info"]))  # 插值无调用
        p = "@@ -0,0 +1,201 @@\n" + '+logger.info(f"{do_work()}")\n' * 201
        self.assertEqual(gate.count_patch("a.py", p, PS), 201)

    def test_private_key_case_insensitive(self):
        for src in ("private_key = 'x'", "PrivateKey = 'x'", "PRIVATE_KEY = 'x'", "osaka_work_key = 'x'", "OSAKA-WORK-KEY = 'x'"):
            c, cls, s = gate.approval_class([{"filename": "src/a.py", "status": "modified", "patch": "@@\n+" + src + "\n"}], {}, CI, PS)
            self.assertEqual(cls, "yarrow", src)




class R7Fixes(unittest.TestCase):
    def test_nested_fstring_log_counts(self):
        line = 'logger.info(f"{update({\'enabled\': True})}")'
        self.assertFalse(gate.is_log_line(line, ["logger.info"]))
        p = "@@ -0,0 +1,201 @@\n" + ("+" + line + "\n") * 201
        self.assertEqual(gate.count_patch("a.py", p, PS), 201)
        self.assertTrue(gate.is_log_line('logger.info(f"x={y}")', ["logger.info"]))

    def test_docstring_same_line_code_counts(self):
        line = '"""note"""; update()'
        p = "@@ -0,0 +1,201 @@\n" + ("+" + line + "\n") * 201
        self.assertEqual(gate.count_patch("a.py", p, PS), 201)
        self.assertEqual(gate.count_patch("a.py", p, PS, {"old": "", "new": (line + "\n") * 201}), 201)
        self.assertEqual(gate.count_patch("a.py", '@@ -0,0 +1,1 @@\n+"""only docstring"""\n', PS), 0)

    def test_validate_no_secret_echo(self):
        errs = gate.validate("key-acceptance-tests.yaml",
                             {"tests": [{"id": "t1", "entry": "x", "job": "j", "paths": "bad",
                                         "env": {"API_TOKEN": "sk_live_SECRETVALUE123"}}]})
        self.assertTrue(errs)
        blob = "\n".join(errs)
        self.assertNotIn("sk_live_SECRETVALUE123", blob)
        self.assertNotIn("API_TOKEN", blob)
        errs2 = gate.validate("required-checks.yaml",
                              {"branch_protection": [{"context": "x", "expected_source": {"app_id": "bad"},
                                                      "TOKEN": "sk_live_XYZ"}],
                               "gate_verified": [], "strict": True})
        self.assertTrue(errs2)
        self.assertNotIn("sk_live_XYZ", "\n".join(errs2))




class Lint(unittest.TestCase):
    def gs(self, p):
        return by_name(gate.evaluate(p, CFG, GLOB))["gate-summary"]

    def test_branch_names(self):
        for ok in ("server/server-core-1", "android/vpn.ui-12", "server/vpn_Core-2", "ci/cache-3", "ci/build_cache-1", "lead/x", "tests/t1", "bookkeeping/b-2"):
            self.assertEqual(gate.lint(pr([f("src/a.py", "@@\n+x = 1\n")], head_ref=ok), CI), [], ok)
        for bad in ("server/core", "Server/core-1", "feature/x-1", "ci/cache", "lead/", "server/a/b-1", "lead/a/b", "mac/x-1", "server/-1", "", None):
            r = gate.lint(pr([f("src/a.py", "@@\n+x = 1\n")], head_ref=bad), CI)
            self.assertTrue(any("分支命名" in x for x in r), bad)
        c = self.gs(pr([f("src/a.py", "@@\n+x = 1\n")], head_ref="feature/x-1"))
        self.assertEqual(c["conclusion"], "failure"); self.assertIn("lint: 分支命名", c["summary"])

    def test_bookkeeping_mix(self):
        mix = pr([f("src/a.py", "@@\n+x = 1\n"), f("notes/n.md", "@@\n+a\n")])
        self.assertTrue(any("记账" in x for x in gate.lint(mix, CI)))
        self.assertEqual(gate.lint(pr([f("board.json", "@@\n+{}\n"), f("memory/m.md", "@@\n+a\n")], head_ref="bookkeeping/b"), CI), [])
        mv = pr([f("src/n.md", "@@\n", previous_filename="notes/n.md")])   # 从记账目录搬出也算混
        self.assertTrue(any("记账" in x for x in gate.lint(mv, CI)))
        self.assertEqual(gate.lint(pr([f("notesx/a.py", "@@\n+x\n"), f("src/b.py", "@@\n+y\n")]), CI), [])   # 前缀按目录算

    def test_lint_cfg_missing(self):
        ci = copy.deepcopy(CI); del ci["scope"]["bookkeeping_paths"]
        self.assertTrue(gate.lint(pr([]), ci))

    def test_breakdown(self):
        files = [f("src/a.py", "@@\n+x\n", additions=400, deletions=50), f("tests/t.py", "@@\n+y\n", additions=200, deletions=0)]
        ps = dict(PS, breakdown_over=600, breakdown_categories=[{"name": "测试", "paths": ["tests/**"]}])
        _, s = gate.pr_size(files, ps)
        self.assertIn("总改动 650 行", s); self.assertIn("运行代码和配置: +400 -50", s); self.assertIn("测试: +200 -0", s)
        files[0]["deletions"] = 0
        self.assertNotIn("总改动", gate.pr_size(files, ps)[1])    # 刚好 600 不输出
        self.assertNotIn("总改动", gate.pr_size(files, PS)[1])    # 没配置不输出

    def test_validate_lint_cfg(self):
        self.assertTrue(any("branch_name_patterns" in e for e in gate.validate("ci-approval-class.yaml",
                        {"scope": {"branch_kinds": []}, "yarrow_classes": {"6_protected_config": {"paths": ["x"]}}})))
        self.assertTrue(gate.validate("pr-size.yaml", {"threshold": 1, "breakdown_over": "600"}))

    def test_breakdown_error_does_not_block(self):
        files = [f("src/a.py", "@@\n+x\n", additions="x", deletions=700)]
        c, s = gate.pr_size(files, dict(PS, breakdown_over=600, breakdown_categories=[]))
        self.assertEqual(c, "success"); self.assertIn("分类行数算不出", s)
        self.assertTrue(gate.validate("pr-size.yaml", {"threshold": 1, "breakdown_categories": [{"name": "a", "paths": [1]}]}))

    def test_bookkeeping_mix_ok_for_tests_ci(self):
        files = [f("tests/a.py", "@@\n+x\n"), f("board.json", "@@\n+{}\n")]
        for ok in ("tests/t1", "ci/cache-3"):
            self.assertEqual(gate.lint(pr(files, head_ref=ok), CI), [], ok)
        for bad in ("server/server-core-1", "lead/x", "android/a-1"):
            self.assertTrue(any("记账" in x for x in gate.lint(pr(files, head_ref=bad), CI)), bad)
        ci = copy.deepcopy(CI); del ci["scope"]["bookkeeping_mix_ok_prefixes"]   # 没配就不放行
        self.assertTrue(any("记账" in x for x in gate.lint(pr(files, head_ref="tests/t1"), ci)))
        d = copy.deepcopy(CI); d["scope"]["bookkeeping_mix_ok_prefixes"] = ["tests"]
        self.assertTrue(any("mix_ok" in e for e in gate.validate("ci-approval-class.yaml", d)))

    def test_copied_into_notes_not_mix(self):
        p = pr([f("notes/n.md", "@@\n+a\n", status="copied", previous_filename="src/t.md")], head_ref="bookkeeping/b")
        self.assertEqual(gate.lint(p, CI), [])


if __name__ == "__main__":
    unittest.main()


class SecretsEnv(unittest.TestCase):
    PATS = ["(?i)(secret|token|passw(or)?d|api[_-]?key|private[_-]?key|credential)"]
    CI2 = copy.deepcopy(CI)
    CI2["yarrow_classes"]["1_secrets"]["env_name_patterns"] = PATS

    def cls(self, base, head, name=".github/actions/a/action.yml"):
        return gate.approval_class([f(name, "@@\n+x\n")], {}, self.CI2, PS, gh_yaml={name: {"base": base, "head": head}})

    def test_env_secret_names_escalate(self):
        job = lambda env: {"runs": {"steps": [{"run": "x", "env": env}]}}
        for env in ({"CLIENT_SECRET": "abc"}, {"API_KEY": "${{ vars.X }}"}, {"db_password": "x"}, {"X": "${{ secrets.Y }}"}):
            c, cls, s = self.cls(job({}), job(env))
            self.assertEqual(cls, "yarrow", env); self.assertIn("1_secrets", s); self.assertNotIn("abc", s)
        c, cls, s = self.cls(job({"NPM_TOKEN": "a"}), job({"NPM_TOKEN": "b"}))   # 只改值也算
        self.assertEqual(cls, "yarrow")
        c, cls, s = self.cls(job({"NPM_TOKEN": "a"}), None)                       # 删掉也算
        self.assertEqual(cls, "yarrow")

    def test_env_plain_and_inputs_regular(self):
        c, cls, s = self.cls({"env": {"NODE_VERSION": "18"}}, {"env": {"NODE_VERSION": "20"}})
        self.assertEqual(cls, "regular")
        c, cls, s = self.cls({"inputs": {}}, {"inputs": {"token": {"required": True}}, "runs": {"steps": [{"with": {"token": "x"}}]}})
        self.assertEqual(cls, "regular")   # inputs:/with: 里的 token 不按 env 判

    def test_parse_error_red(self):
        c, cls, s = gate.approval_class([f(".github/actions/a/action.yml", "@@\n+x\n")], {}, self.CI2, PS,
                                        gh_yaml={".github/actions/a/action.yml": {"error": "bad"}})
        self.assertEqual(c, "failure")


class CommentEdge(unittest.TestCase):
    def test_block_comment_with_trailing_code_counts(self):
        p = "@@ -1 +1,2 @@\n+/* note */ run();\n+/* only */\n"
        self.assertEqual(gate.count_patch("A.kt", p, PS), 1)


class R2Fixes(unittest.TestCase):
    PATS = ["(?i)(secret|token|passw(or)?d|api[_-]?key|private[_-]?key|credential)", "(?i)(^|[_-])key($|[_-])"]
    CI2 = copy.deepcopy(CI)
    CI2["yarrow_classes"]["1_secrets"]["env_name_patterns"] = PATS

    def cls(self, base, head, name=".github/actions/a/action.yml"):
        return gate.approval_class([f(name, "@@\n+x\n")], {}, self.CI2, PS, gh_yaml={name: {"base": base, "head": head}})[1]

    def test_copy_env_to_second_step(self):
        st = lambda: {"run": "x", "env": {"NPM_TOKEN": "${{ inputs.auth }}"}}
        self.assertEqual(self.cls({"runs": {"steps": [st()]}}, {"runs": {"steps": [st(), st()]}}), "yarrow")

    def test_generic_key(self):
        for k in ("SIGNING_KEY", "DEPLOY_KEY", "SSH_KEY"):
            self.assertEqual(self.cls({"env": {}}, {"env": {k: "${{ vars.X }}"}}), "yarrow", k)
        self.assertEqual(self.cls({"env": {}}, {"env": {"MONKEY_MODE": "1"}}), "regular")

    def test_plusplus_lines_scanned(self):
        nm = "Ha" + "o Yi" + "n"
        files = [f("src/a.cs", "@@ -1 +1,2 @@\n x\n+++i; // " + nm + "\n")]
        self.assertIn("新增行", "；".join(gate.realname(pr(files))))
        c, cls, s = gate.approval_class([f("src/a.cs", "@@ -1 +1 @@\n+++i; Use(PRIVATE_KEY);\n")], {}, CI, PS)
        self.assertEqual(cls, "yarrow")
