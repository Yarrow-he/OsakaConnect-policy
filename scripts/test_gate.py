"""gate.py 的固定样例测试（只用标准库）。policy-selftest 和本地都跑：python3 -m unittest -v test_gate"""
import copy, json, os, tempfile, unittest
import gate

PS = {"threshold": 200, "exclude_paths": ["tests/**", "**/*.md", "policy-proposals/*.yaml"], "scaffold_temp": [],
      "log_functions": {"python": ["logger.info"], "kotlin": ["Log.d"]},
      "comment_syntax": {"python": {"line": ["#"], "docstring_only": True}, "kotlin": {"line": ["//"], "block": [["/*", "*/"]]}}}
CI = {"yarrow_classes": {
    "1_secrets": {"paths": [], "diff_patterns": ["PRIVATE_KEY"]},
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
              "board_module_keys": ["id", "branch", "paths"]}}
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
        self.assertEqual(gate.count_patch("a.py", p, PS), 3)   # foo() 调用、y=2、删 z=3

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
        self.assertEqual(c, "success"); self.assertIn("计入 200 行", s)

    def test_rename_out_of_excluded_counts(self):
        files = [f("src/b.py", "@@ -1 +1 @@\n-a = 1\n+a = 2\n", status="renamed", previous_filename="tests/b.py")]
        self.assertIn("计入 2 行", gate.pr_size(files, PS)[1])


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
        p = pr([]); del p["meta"]
        self.assertEqual(self.ev(p)["gate-summary"]["conclusion"], "failure")

    def test_author(self):
        me, web = list(gate.ME), ["GitHub", "noreply@github.com"]
        meta = lambda *cs: {"title": "t", "body": "", "commits": [{"message": "m", "names": n} for n in cs]}
        self.assertEqual(self.ev(pr([], meta=meta(me * 2, me + web)))["gate-summary"]["conclusion"], "success")
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


if __name__ == "__main__":
    unittest.main()
