"""预检编排：规范化 → 同名碰撞分组 → 层级冲突检测（纯内存）。"""

from __future__ import annotations

from .normalize import Issue, IssueCode, IssueSeverity, NormalizedEntry, normalize_entry
from .repair import build_repair_plan
from .schemas import (
    CollisionGroup,
    CollisionMember,
    EntryType,
    HierarchyConflict,
    PreflightEntryOut,
    PreflightRepairResponse,
    PreflightRequest,
    PreflightResponse,
    Summary,
)


def _add_issue(entry: NormalizedEntry, issue: Issue) -> None:
    # 避免重复追加同一相关下标的问题。
    if issue.code in (IssueCode.BLOCKED_BY_FILE_ANCESTOR, IssueCode.BLOCKS_DESCENDANT):
        for existing in entry.issues:
            if (
                existing.code == issue.code
                and existing.related_index == issue.related_index
            ):
                return
    entry.issues.append(issue)


def _collision_groups(entries: list[NormalizedEntry]) -> dict[int, int]:
    """为安全条目按 comparison_key 分组，返回 entry.index -> group 编号。"""
    buckets: dict[str, list[NormalizedEntry]] = {}
    first_seen: dict[str, int] = {}
    for entry in entries:
        if entry.unsafe or entry.comparison_key is None:
            continue
        key = entry.comparison_key
        if key not in buckets:
            buckets[key] = []
            first_seen[key] = entry.index
        buckets[key].append(entry)

    # 组号按该组首次出现的下标排序分配。
    ordered_keys = sorted(first_seen, key=lambda k: first_seen[k])
    index_to_group: dict[int, int] = {}
    group_of_key: dict[str, int] = {}
    for group_no, key in enumerate(ordered_keys, start=1):
        if len(buckets[key]) < 2:
            continue
        group_of_key[key] = group_no
        for entry in buckets[key]:
            index_to_group[entry.index] = group_no
    return index_to_group


def _hierarchy_conflicts(
    entries: list[NormalizedEntry],
) -> list[tuple[NormalizedEntry, NormalizedEntry]]:
    """文件占据祖先路径 → 阻挡同名前缀后代，返回 (文件条目, 后代条目) 对。

    仅对安全条目计算。键为小写折叠后的路径段，故不同大小写/点空格变体也会匹配。
    """
    files_by_key: dict[str, list[NormalizedEntry]] = {}
    for entry in entries:
        if entry.unsafe or entry.entry_type != EntryType.FILE.value:
            continue
        files_by_key.setdefault(entry.comparison_key, []).append(entry)

    conflicts: list[tuple[NormalizedEntry, NormalizedEntry]] = []
    for descendant in entries:
        if descendant.unsafe:
            continue
        parts = descendant.key_parts
        for depth in range(1, len(parts)):  # 不含自身（depth == len(parts)）
            ancestor_key = "/".join(parts[:depth])
            for ancestor in files_by_key.get(ancestor_key, ()):
                conflicts.append((ancestor, descendant))
    # 稳定输出：按后代下标、再按祖先下标排序。
    conflicts.sort(key=lambda pair: (pair[1].index, pair[0].index))
    return conflicts


def run_preflight(request: PreflightRequest) -> PreflightResponse:
    normalized: list[NormalizedEntry] = [
        normalize_entry(index=i, entry_type=e.type.value, original_path=e.path)
        for i, e in enumerate(request.entries, start=1)
    ]

    index_to_group = _collision_groups(normalized)

    conflicts = _hierarchy_conflicts(normalized)
    blocked_by: dict[int, list[int]] = {}
    blocks: dict[int, list[int]] = {}
    hierarchy_out: list[HierarchyConflict] = []
    for ancestor, descendant in conflicts:
        blocked_by.setdefault(descendant.index, []).append(ancestor.index)
        blocks.setdefault(ancestor.index, []).append(descendant.index)
        _add_issue(
            ancestor,
            Issue(
                IssueCode.BLOCKS_DESCENDANT,
                IssueSeverity.INFO,
                f"文件占据祖先路径，会阻挡条目 #{descendant.index}（{descendant.canonical_path}）解包",
                related_index=descendant.index,
            ),
        )
        _add_issue(
            descendant,
            Issue(
                IssueCode.BLOCKED_BY_FILE_ANCESTOR,
                IssueSeverity.INFO,
                f"祖先路径已被条目 #{ancestor.index} 的文件（{ancestor.canonical_path}）占据，无法创建目录",
                related_index=ancestor.index,
            ),
        )
        hierarchy_out.append(
            HierarchyConflict(
                file_index=ancestor.index,
                file_canonical_path=ancestor.canonical_path,
                descendant_index=descendant.index,
                descendant_canonical_path=descendant.canonical_path,
            )
        )

    # 碰撞组明细（仅包含真实发生碰撞的组）。
    groups_detail: dict[int, dict] = {}
    for entry in normalized:
        group_no = index_to_group.get(entry.index)
        if group_no is None:
            continue
        detail = groups_detail.setdefault(
            group_no,
            {
                "group": group_no,
                "canonical_path": entry.canonical_path,
                "members": [],
            },
        )
        detail["members"].append(
            CollisionMember(index=entry.index, canonical_path=entry.canonical_path)
        )

    collision_groups = [
        CollisionGroup(**groups_detail[no])
        for no in sorted(groups_detail)
    ]
    group_members: dict[int, list[int]] = {
        no: [m.index for m in groups_detail[no]["members"]]
        for no in sorted(groups_detail)
    }

    # 碰撞提示问题。
    for entry in normalized:
        group_no = index_to_group.get(entry.index)
        if group_no is not None:
            _add_issue(
                entry,
                Issue(
                    IssueCode.COLLISION,
                    IssueSeverity.INFO,
                    f"规范化后与组 {group_no} 内的其他条目同名，解包时互相覆盖",
                ),
            )

    entry_out = [
        PreflightEntryOut(
            index=e.index,
            type=EntryType(e.entry_type),
            original_path=e.original_path,
            canonical_path=e.canonical_path,
            comparison_key=e.comparison_key,
            safe=not e.unsafe,
            collision_group=index_to_group.get(e.index),
            blocked_by_file_ancestors=blocked_by.get(e.index, []),
            blocks_descendants=blocks.get(e.index, []),
            issues=[
                {
                    "code": i.code,
                    "severity": i.severity,
                    "message": i.message,
                    "segment": i.segment,
                    "related_index": i.related_index,
                }
                for i in e.issues
            ],
        )
        for e in normalized
    ]

    unsafe_count = sum(1 for e in normalized if e.unsafe)
    summary = Summary(
        total=len(normalized),
        safe=len(normalized) - unsafe_count,
        unsafe=unsafe_count,
        collisions=len(collision_groups),
        collision_entries=len(index_to_group),
        hierarchy_conflicts=len(hierarchy_out),
    )

    if request.repair:
        repair_plan = build_repair_plan(
            entries=normalized,
            collision_groups=group_members,
            blocks=blocks,
            collisions_total=len(collision_groups),
            hierarchy_total=len(hierarchy_out),
        )
        return PreflightRepairResponse(
            target="windows",
            entries=entry_out,
            collision_groups=collision_groups,
            hierarchy_conflicts=hierarchy_out,
            summary=summary,
            repair_plan=repair_plan,
        )

    return PreflightResponse(
        target="windows",
        entries=entry_out,
        collision_groups=collision_groups,
        hierarchy_conflicts=hierarchy_out,
        summary=summary,
    )
