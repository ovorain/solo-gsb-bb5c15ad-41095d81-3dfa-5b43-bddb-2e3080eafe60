"""符号链接风险分析测试：目标解析、链接链、循环、路径劫持、repair 跳过。"""

from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def _call(entries, repair=False):
    return client.post(
        "/api/v1/preflight", json={"entries": entries, "repair": repair}
    )


def _links(resp):
    return {s["index"]: s for s in resp["symlinks"]}


def _entries(resp):
    return {e["index"]: e for e in resp["entries"]}


def _plan(resp):
    return {e["index"]: e for e in resp["repair_plan"]["entries"]}


# ---------------------------------------------------------------------------
# 请求模型
# ---------------------------------------------------------------------------


def test_symlink_requires_link_target():
    r = _call([{"path": "x", "type": "symlink"}])
    assert r.status_code == 422


def test_file_entry_ignores_link_target():
    r = _call([{"path": "x", "type": "file", "link_target": "ignored"}])
    assert r.status_code == 200
    assert r.json()["entries"][0]["link_target"] is None


def test_symlink_echoes_link_target_and_is_listed_in_input_order():
    entries = [
        {"path": "a.txt", "type": "file"},
        {"path": "d/l1", "type": "symlink", "link_target": "x"},
        {"path": "d/l2", "type": "symlink", "link_target": "y"},
    ]
    resp = _call(entries).json()
    assert [s["index"] for s in resp["symlinks"]] == [2, 3]
    by = _links(resp)
    assert by[2]["link_target"] == "x"
    assert by[2]["link_path"] == "d/l1"
    assert _entries(resp)[2]["link_target"] == "x"
    assert resp["summary"]["symlinks"] == 2


# ---------------------------------------------------------------------------
# 目标解析：相对链接所在目录
# ---------------------------------------------------------------------------


def test_relative_target_resolved_against_link_parent():
    entries = [
        {"path": "dir/link", "type": "symlink", "link_target": "../other/target"},
        {"path": "top", "type": "symlink", "link_target": "./sub/./b"},
        {"path": "a/b/ln", "type": "symlink", "link_target": "../../x"},
    ]
    resp = _call(entries).json()
    by = _links(resp)
    assert by[1]["terminal"] == "dangling"
    assert by[1]["resolved_target"] == "other/target"
    assert by[1]["resolves_to_index"] is None
    hop = by[1]["chain"][0]
    assert hop["link_index"] == 1
    assert hop["resolves_to"] == "other/target"
    assert hop["risk"] is None
    assert hop["next_index"] is None
    assert by[2]["resolved_target"] == "sub/b"
    # a/b/ln 向上两级回到根，再取 x：仍在根内。
    assert by[3]["resolved_target"] == "x"
    assert by[3]["terminal"] == "dangling"


def test_backslashes_in_path_and_target_follow_windows_rules():
    entries = [
        {"path": "Docs\\link", "type": "symlink", "link_target": "..\\Real.TXT"},
        {"path": "real.txt", "type": "file"},
    ]
    resp = _call(entries).json()
    s = _links(resp)[1]
    assert s["link_path"] == "Docs/link"
    assert s["resolved_target"] == "Real.TXT"
    assert s["terminal"] == "entry"
    assert s["resolves_to_index"] == 2


def test_target_normalization_nfc_and_trimming():
    # 段尾点空格在 Windows 目标上被裁剪：d/x.   -> d/x
    entries = [
        {"path": "d/ln", "type": "symlink", "link_target": "x.  "},
        {"path": "d/x", "type": "file"},
    ]
    resp = _call(entries).json()
    assert _links(resp)[1]["resolves_to_index"] == 2


def test_target_landing_on_regular_entries():
    entries = [
        {"path": "d/ln1", "type": "symlink", "link_target": "../f.txt"},
        {"path": "d/ln2", "type": "symlink", "link_target": "../dir"},
        {"path": "f.txt", "type": "file"},
        {"path": "dir", "type": "directory"},
    ]
    resp = _call(entries).json()
    by = _links(resp)
    assert by[1]["terminal"] == "entry"
    assert by[1]["resolves_to_index"] == 3
    assert by[2]["terminal"] == "entry"
    assert by[2]["resolves_to_index"] == 4


def test_root_level_parent_traversal_escapes():
    entries = [
        {"path": "link", "type": "symlink", "link_target": "../x"},
        {"path": "d/link2", "type": "symlink", "link_target": "../../x"},
    ]
    resp = _call(entries).json()
    for s in resp["symlinks"]:
        assert s["terminal"] == "escape"
        assert s["resolved_target"] is None
        assert [h["code"] for h in s["risks"]] == ["SYMLINK_ESCAPE"]
        assert s["chain"][-1]["risk"] == "SYMLINK_ESCAPE"


def test_absolute_unc_and_drive_targets_escape():
    entries = [
        {"path": "d/a", "type": "symlink", "link_target": "/etc/passwd"},
        {"path": "d/b", "type": "symlink", "link_target": "\\\\server\\share"},
        {"path": "d/c", "type": "symlink", "link_target": "C:\\Windows"},
        {"path": "d/e", "type": "symlink", "link_target": "//host/share"},
    ]
    resp = _call(entries).json()
    for s in resp["symlinks"]:
        codes = {h["code"] for h in s["risks"]}
        assert codes == {"SYMLINK_ESCAPE"}
        assert s["terminal"] == "escape"


def test_windows_invalid_targets_are_bad_target():
    entries = [
        {"path": "d/a", "type": "symlink", "link_target": "CON"},
        {"path": "d/b", "type": "symlink", "link_target": "sub/LPT9"},
        {"path": "d/c", "type": "symlink", "link_target": "bad:name?.txt"},
        {"path": "d/e", "type": "symlink", "link_target": "sub/..."},
    ]
    resp = _call(entries).json()
    for s in resp["symlinks"]:
        assert s["terminal"] == "bad_target"
        assert [h["code"] for h in s["risks"]] == ["SYMLINK_BAD_TARGET"]
    assert resp["summary"]["symlink_risks"] == 4


def test_unsafe_link_path_is_not_analyzed():
    entries = [
        {"path": "../evil", "type": "symlink", "link_target": "whatever"},
        {"path": "safe/l", "type": "symlink", "link_target": "ok"},
    ]
    resp = _call(entries).json()
    by = _links(resp)
    assert by[1]["terminal"] == "unsafe_link"
    assert by[1]["chain"][0]["link_index"] == 1
    assert by[1]["risks"] == []
    assert by[2]["terminal"] == "dangling"
    # unsafe 计入 unsafe 而非风险链接。
    assert resp["summary"]["unsafe"] == 1
    assert resp["summary"]["symlink_risks"] == 0


# ---------------------------------------------------------------------------
# 链接链：跟随、循环、风险沿链传播
# ---------------------------------------------------------------------------


def test_chain_follows_multiple_links_and_lands():
    entries = [
        {"path": "root/a", "type": "symlink", "link_target": "b"},
        {"path": "root/b", "type": "symlink", "link_target": "../other/c"},
        {"path": "other/c", "type": "file"},
    ]
    resp = _call(entries).json()
    s = _links(resp)[1]
    assert s["terminal"] == "entry"
    assert s["resolves_to_index"] == 3
    assert s["resolved_target"] == "other/c"
    assert [(h["link_index"], h["next_index"]) for h in s["chain"]] == [
        (1, 2),
        (2, None),
    ]
    assert s["chain"][0]["resolves_to"] == "root/b"
    assert s["chain"][1]["resolves_to"] == "other/c"


def test_chain_escape_propagates_to_every_link_on_chain():
    entries = [
        {"path": "root/a", "type": "symlink", "link_target": "b"},
        {"path": "root/b", "type": "symlink", "link_target": "c"},
        {"path": "root/c", "type": "symlink", "link_target": "../../outside"},
    ]
    resp = _call(entries).json()
    by = _links(resp)
    for idx in (1, 2, 3):
        assert by[idx]["terminal"] == "escape"
        assert [r["code"] for r in by[idx]["risks"]] == ["SYMLINK_ESCAPE"]
        assert by[idx]["resolved_target"] is None
    # 每条链接的链从自身开始。
    assert [h["link_index"] for h in by[1]["chain"]] == [1, 2, 3]
    assert [h["link_index"] for h in by[2]["chain"]] == [2, 3]
    # 仅最后一跳带目标级风险。
    assert [h["risk"] for h in by[1]["chain"]] == [
        None,
        None,
        "SYMLINK_ESCAPE",
    ]


def test_chain_bad_target_propagates():
    entries = [
        {"path": "root/a", "type": "symlink", "link_target": "b"},
        {"path": "root/b", "type": "symlink", "link_target": "CON"},
    ]
    resp = _call(entries).json()
    by = _links(resp)
    assert by[1]["terminal"] == "bad_target"
    assert by[2]["terminal"] == "bad_target"


def test_three_link_cycle_reported_on_all_members():
    entries = [
        {"path": "d/a", "type": "symlink", "link_target": "b"},
        {"path": "d/b", "type": "symlink", "link_target": "c"},
        {"path": "d/c", "type": "symlink", "link_target": "A"},  # 大小写折叠闭环
    ]
    resp = _call(entries).json()
    by = _links(resp)
    expected_chain = {1: [1, 2, 3], 2: [2, 3, 1], 3: [3, 1, 2]}
    for idx, chain in expected_chain.items():
        assert by[idx]["terminal"] == "cycle"
        assert by[idx]["resolved_target"] is None
        assert [h["link_index"] for h in by[idx]["chain"]] == chain
        risks = by[idx]["risks"]
        assert [r["code"] for r in risks] == ["SYMLINK_CYCLE"]
        # related_index 为闭环上再次遇到的链接（即各链起点）。
        assert risks[0]["related_index"] == idx


def test_self_cycle():
    resp = _call(
        [{"path": "d/a", "type": "symlink", "link_target": "a"}]
    ).json()
    s = _links(resp)[1]
    assert s["terminal"] == "cycle"
    assert s["risks"][0]["code"] == "SYMLINK_CYCLE"
    assert s["risks"][0]["related_index"] == 1
    assert len(s["chain"]) == 1
    assert s["chain"][0]["next_index"] == 1


def test_chain_matching_uses_windows_comparison_key():
    # NFC + 大小写 + 段尾点空格抹平后，链接目标仍能命中下一跳。
    entries = [
        {"path": "d/Å-lnk", "type": "symlink", "link_target": "Next.  "},
        {"path": "d/NEXT", "type": "symlink", "link_target": "../../outside-x"},
    ]
    resp = _call(entries).json()
    s = _links(resp)[1]
    assert s["terminal"] == "escape"
    assert [h["link_index"] for h in s["chain"]] == [1, 2]


# ---------------------------------------------------------------------------
# 路径劫持
# ---------------------------------------------------------------------------


def test_symlink_ancestor_hijacks_file_and_directory():
    entries = [
        {"path": "d/link", "type": "symlink", "link_target": "../t"},
        {"path": "d/link/a.txt", "type": "file"},
        {"path": "d/link/sub", "type": "directory"},
        {"path": "d/link/sub/deep.txt", "type": "file"},
        {"path": "d/other/x.txt", "type": "file"},  # 不经链接，正常
    ]
    resp = _call(entries).json()
    s = _links(resp)[1]
    hijack_rels = [r["related_index"] for r in s["risks"] if r["code"] == "SYMLINK_HIJACK"]
    assert hijack_rels == [2, 3, 4]
    pairs = [(h["link_index"], h["entry_index"]) for h in resp["symlink_hijacks"]]
    assert pairs == [(1, 2), (1, 3), (1, 4)]
    by = _entries(resp)
    for i in (2, 3, 4):
        assert by[i]["hijacked_by_symlinks"] == [1]
        assert "SYMLINK_ANCESTOR" in [iss["code"] for iss in by[i]["issues"]]
    assert by[5]["hijacked_by_symlinks"] == []
    # 劫持不影响 safe（链接与普通条目路径词法上均合法）。
    assert all(by[i]["safe"] for i in (1, 2, 3, 4, 5))
    assert resp["summary"]["symlink_hijacks"] == 3
    assert resp["summary"]["symlink_risks"] == 1


def test_hijack_uses_windows_comparison_key():
    entries = [
        {"path": "DIR/LINK", "type": "symlink", "link_target": "z"},
        {"path": "dir/link/child", "type": "file"},
    ]
    resp = _call(entries).json()
    assert [(h["link_index"], h["entry_index"]) for h in resp["symlink_hijacks"]] == [
        (1, 2)
    ]


def test_escaping_link_still_hijacks_its_descendants():
    entries = [
        {"path": "d/link", "type": "symlink", "link_target": "../../evil"},
        {"path": "d/link/child.txt", "type": "file"},
    ]
    resp = _call(entries).json()
    s = _links(resp)[1]
    assert {r["code"] for r in s["risks"]} == {
        "SYMLINK_ESCAPE",
        "SYMLINK_HIJACK",
    }
    assert resp["summary"]["symlink_risks"] == 1
    assert resp["summary"]["symlink_hijacks"] == 1


def test_symlinks_excluded_from_collision_and_hierarchy():
    entries = [
        {"path": "d/a", "type": "symlink", "link_target": "x"},
        {"path": "D/A", "type": "symlink", "link_target": "y"},  # 同键不产生碰撞
        {"path": "d/a/child", "type": "file"},  # 祖先为链接→劫持而非文件层级冲突
        {"path": "f", "type": "file"},
        {"path": "f/g", "type": "file"},  # 普通文件层级冲突仍照常报告
    ]
    resp = _call(entries).json()
    assert resp["summary"]["collisions"] == 0
    assert resp["summary"]["hierarchy_conflicts"] == 1
    by = _entries(resp)
    assert by[1]["collision_group"] is None
    assert by[2]["collision_group"] is None
    assert by[3]["blocked_by_file_ancestors"] == []
    assert by[3]["hijacked_by_symlinks"] == [1]


# ---------------------------------------------------------------------------
# repair=true：symlink 与被劫持条目 skipped
# ---------------------------------------------------------------------------


def test_repair_skips_all_symlinks_and_hijacked_entries():
    entries = [
        {"path": "d/link", "type": "symlink", "link_target": "../t"},
        {"path": "d/link/child.txt", "type": "file"},
        {"path": "a.txt", "type": "file"},
        {"path": "A.TXT", "type": "file"},
        {"path": "../evil-link", "type": "symlink", "link_target": "z"},
    ]
    resp = _call(entries, repair=True).json()
    plan = _plan(resp)
    # 安全链接：SYMLINK；被劫持后代：SYMLINK_ANCESTOR；unsafe 链接：UNSAFE。
    assert plan[1]["skipped"] is True
    assert plan[1]["reasons"] == ["SYMLINK"]
    assert plan[1]["repaired_path"] is None
    assert plan[2]["skipped"] is True
    assert plan[2]["reasons"] == ["SYMLINK_ANCESTOR"]
    assert plan[2]["repaired_path"] is None
    assert plan[5]["skipped"] is True
    assert plan[5]["reasons"] == ["UNSAFE"]
    # 普通碰撞照常修复，且不受跳过条目影响。
    assert plan[3]["repaired_path"] == "a.txt"
    assert plan[4]["repaired_path"] == "A (1).TXT"
    rp = resp["repair_plan"]
    assert rp["skipped_count"] == 3
    assert rp["skipped_unsafe_count"] == 1
    assert rp["skipped_symlink_count"] == 1
    assert rp["skipped_hijacked_count"] == 1
    assert rp["renamed_count"] == 1
    assert rp["collisions_remaining"] == 0
    assert rp["hierarchy_conflicts_remaining"] == 0


def test_repair_hijacked_file_kept_out_of_blocks_and_recheck():
    # #2 文件 L/x（被劫持、跳过）原本阻挡 #3；#4 文件 u 阻挡 #5。
    # 跳过后 #2 不触发改名；u/v 仍按普通层级冲突修复。
    entries = [
        {"path": "L", "type": "symlink", "link_target": "t"},
        {"path": "L/x", "type": "file"},
        {"path": "L/x/y", "type": "file"},
        {"path": "u", "type": "file"},
        {"path": "u/v", "type": "file"},
    ]
    resp = _call(entries, repair=True).json()
    plan = _plan(resp)
    assert plan[2]["skipped"] is True
    assert plan[3]["skipped"] is True
    assert plan[4]["reasons"] == ["BLOCKS_DESCENDANT"]
    assert plan[4]["repaired_path"] == "u (1)"
    assert plan[5]["repaired_path"] == "u/v"
    rp = resp["repair_plan"]
    assert rp["skipped_hijacked_count"] == 2
    assert rp["hierarchy_conflicts_remaining"] == 0


def test_repair_collision_group_dissolved_by_skips():
    # 同键碰撞组 #1(symlink,跳过) + #2(普通存活)：组消解，#2 保留原名。
    entries = [
        {"path": "a", "type": "symlink", "link_target": "t"},
        {"path": "A", "type": "file"},
    ]
    resp = _call(entries, repair=True).json()
    plan = _plan(resp)
    assert plan[1]["skipped"] is True
    assert plan[2]["skipped"] is False
    assert plan[2]["reasons"] == []
    assert plan[2]["repaired_path"] == "A"
    assert resp["repair_plan"]["collisions_remaining"] == 0


def test_repair_false_still_contains_symlink_analysis():
    entries = [
        {"path": "d/l", "type": "symlink", "link_target": "../../x"},
    ]
    resp = _call(entries, repair=False).json()
    assert "repair_plan" not in resp
    assert len(resp["symlinks"]) == 1
    assert resp["symlinks"][0]["risks"][0]["code"] == "SYMLINK_ESCAPE"


def test_summary_mixes_regular_diagnostics_and_symlinks():
    entries = [
        {"path": "a.txt", "type": "file"},
        {"path": "A.TXT", "type": "file"},  # 普通碰撞
        {"path": "f", "type": "file"},
        {"path": "f/g", "type": "file"},  # 普通层级冲突
        {"path": "s", "type": "symlink", "link_target": "/abs"},  # 越界链接
        {"path": "s/child", "type": "file"},  # 被 #5 劫持
        {"path": "/unsafe-link", "type": "symlink", "link_target": "x"},
    ]
    resp = _call(entries).json()
    s = resp["summary"]
    assert s["total"] == 7
    assert s["unsafe"] == 1
    assert s["safe"] == 6
    assert s["collisions"] == 1
    assert s["collision_entries"] == 2
    assert s["hierarchy_conflicts"] == 1
    assert s["symlinks"] == 2
    # #7 自身 unsafe，不算风险链接；只有 #5 有风险。
    assert s["symlink_risks"] == 1
    assert s["symlink_hijacks"] == 1
    # 劫持列表按被劫持条目下标排序。
    assert [
        (h["link_index"], h["entry_index"]) for h in resp["symlink_hijacks"]
    ] == [(5, 6)]
