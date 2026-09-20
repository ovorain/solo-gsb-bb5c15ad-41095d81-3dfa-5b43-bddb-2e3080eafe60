"""符号链接风险分析（纯内存、不访问文件系统）。

分析在整批条目上进行，分三步：

1. **目标解析**：相对目标按链接所在目录做词法解析（``.``/``..``），绝对、UNC、
   盘符目标直接判为越界；解析结果再过一遍现有 Windows 规范化规则
   （保留设备名、非法字符等）。
2. **链接链追踪**：在整批条目中按目标路径（casefold 比较键）跟随后续符号链接，
   报告循环（``SYMLINK_CYCLE``）以及沿链传播的越界/非法目标风险。
3. **路径劫持**：普通文件/目录条目的任一祖先路径被符号链接占据即记为劫持
   （``SYMLINK_HIJACK``）——实际解包时该祖先会被替换成链接目标。
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .normalize import (
    Issue,
    IssueCode,
    IssueSeverity,
    NormalizedEntry,
    is_root_form,
    normalize_entry,
)
from .schemas import (
    EntryType,
    SymlinkChainHop,
    SymlinkHijack,
    SymlinkResolution,
    SymlinkRisk,
    SymlinkRiskCode,
)

# Windows 规范化错误码中，除“越界类”之外的非法目标错误。
_BAD_TARGET_CODES = frozenset(
    {
        IssueCode.RESERVED_NAME,
        IssueCode.INVALID_CHARACTER,
        IssueCode.EMPTY_TARGET,
        IssueCode.EMPTY_SEGMENT,
    }
)

_RISK_ORDER = {
    SymlinkRiskCode.SYMLINK_ESCAPE: 0,
    SymlinkRiskCode.SYMLINK_BAD_TARGET: 1,
    SymlinkRiskCode.SYMLINK_CYCLE: 2,
    SymlinkRiskCode.SYMLINK_HIJACK: 3,
}


@dataclass
class _Hop:
    link: NormalizedEntry
    resolves_to: str | None  # 目标根内的绝对解析路径（原始大小写）
    risk: SymlinkRiskCode | None  # 本跳目标级风险
    next_index: int | None  # 命中的下一个符号链接下标


@dataclass
class _Walk:
    hops: list[_Hop] = field(default_factory=list)
    terminal: str = "dangling"
    resolved_target: str | None = None
    resolves_to_index: int | None = None
    cycle_close: int | None = None


def _resolve_target(link: NormalizedEntry) -> tuple[str | None, SymlinkRiskCode | None]:
    """将链接目标相对链接所在目录解析为目标根内绝对路径。

    返回 ``(解析路径（原始大小写展示）, 目标级风险)``；
    风险非 None 时解析路径为 None（链不应继续跟随）。
    """
    target = link.link_target if link.link_target is not None else ""
    # 绝对路径 / UNC / 盘符目标锚定到目标根之外，直接越界。
    if target == "" or is_root_form(target):
        if target == "":
            return None, SymlinkRiskCode.SYMLINK_BAD_TARGET
        return None, SymlinkRiskCode.SYMLINK_ESCAPE

    # 词法解析：在链接父目录栈上处理 . 与 ..，越栈即逃逸。
    stack: list[str] = list(link.canonical_parts[:-1])
    for raw in target.replace("\\", "/").split("/"):
        if raw == "" or raw == ".":
            continue
        if raw == "..":
            if stack:
                stack.pop()
            else:
                return None, SymlinkRiskCode.SYMLINK_ESCAPE
            continue
        stack.append(raw)

    if not stack:
        return None, SymlinkRiskCode.SYMLINK_BAD_TARGET

    # 解析结果必须是合法的 Windows 目标路径；同时取得规范化（NFC、段尾裁剪）
    # 后的展示路径与比较键，供后续按整批条目匹配。
    probe = normalize_entry(
        index=-1, entry_type="file", original_path="/".join(stack)
    )
    errors = {
        i.code for i in probe.issues if i.severity == IssueSeverity.ERROR
    }
    if not errors:
        return probe.canonical_path, None
    if errors - _BAD_TARGET_CODES:
        # 绝对/UNC/盘符/词法越界：规范化后逃逸出目标根。
        return None, SymlinkRiskCode.SYMLINK_ESCAPE
    return None, SymlinkRiskCode.SYMLINK_BAD_TARGET


def _walk_chain(
    start: NormalizedEntry,
    links_by_key: dict[str, NormalizedEntry],
    regular_by_key: dict[str, NormalizedEntry],
) -> _Walk:
    """从某条链接出发沿整批条目追踪链接链，直至终止。

    每条链接独立走自己的链，因此越界/非法/循环风险天然沿链传播到链上每一条。
    """
    out = _Walk()
    seen: set[int] = {start.index}
    cur = start
    while True:
        resolved, risk = _resolve_target(cur)
        if risk is not None:
            out.hops.append(_Hop(cur, None, risk, None))
            out.terminal = (
                "escape"
                if risk == SymlinkRiskCode.SYMLINK_ESCAPE
                else "bad_target"
            )
            return out

        nxt = links_by_key.get(resolved.casefold())
        if nxt is not None:
            out.hops.append(_Hop(cur, resolved, None, nxt.index))
            if nxt.index in seen:
                out.terminal = "cycle"
                out.cycle_close = nxt.index
                return out
            seen.add(nxt.index)
            cur = nxt
            continue

        # 落到普通条目（文件/目录）或目标根内悬空，链终止。
        out.hops.append(_Hop(cur, resolved, None, None))
        landed = regular_by_key.get(resolved.casefold())
        if landed is not None:
            out.terminal = "entry"
            out.resolved_target = resolved
            out.resolves_to_index = landed.index
        else:
            out.terminal = "dangling"
            out.resolved_target = resolved
        return out


def analyze_symlinks(
    entries: list[NormalizedEntry],
) -> tuple[list[SymlinkResolution], list[SymlinkHijack], set[int], dict[int, list[int]]]:
    """对整批条目做符号链接风险分析。

    返回 ``(链接解析列表（按输入顺序）, 路径劫持对, 被劫持普通条目下标集合,
    链接下标 -> 被其劫持的普通条目下标列表)``。
    """
    by_index = {e.index: e for e in entries}
    safe_links = [
        e
        for e in entries
        if e.entry_type == EntryType.SYMLINK.value and not e.unsafe
    ]

    # 路径键 -> 该路径上的符号链接 / 普通条目（重复定义时以先出现者为准）。
    links_by_key: dict[str, NormalizedEntry] = {}
    for link in safe_links:
        links_by_key.setdefault(link.comparison_key, link)
    regular_by_key: dict[str, NormalizedEntry] = {}
    for entry in entries:
        if entry.entry_type != EntryType.SYMLINK.value and not entry.unsafe:
            regular_by_key.setdefault(entry.comparison_key, entry)

    # ---- 1) 链接链追踪（每条安全链接独立走链） --------------------------
    walks: dict[int, _Walk] = {
        link.index: _walk_chain(link, links_by_key, regular_by_key)
        for link in safe_links
    }

    # ---- 2) 路径劫持：普通条目的任一祖先被符号链接占据 -------------------
    hijacks_by_link: dict[int, list[int]] = {}
    hijacked: set[int] = set()
    hijack_pairs: list[tuple[int, int]] = []
    for entry in entries:
        if entry.entry_type == EntryType.SYMLINK.value or entry.unsafe:
            continue
        for depth in range(1, len(entry.key_parts)):
            link = links_by_key.get("/".join(entry.key_parts[:depth]))
            if link is None:
                continue
            hijacks_by_link.setdefault(link.index, []).append(entry.index)
            hijacked.add(entry.index)
            hijack_pairs.append((link.index, entry.index))

    # 被劫持普通条目的 issue（信息级；repair=true 时因此被跳过）。
    for link_index, entry_index in hijack_pairs:
        link = by_index[link_index]
        by_index[entry_index].issues.append(
            Issue(
                IssueCode.SYMLINK_ANCESTOR,
                IssueSeverity.INFO,
                f"祖先路径 {link.canonical_path} 是符号链接（条目 #{link.index}），"
                f"解包时该条目会被链接目标劫持",
                related_index=link.index,
            )
        )

    # ---- 3) 输出组装（按输入顺序） ---------------------------------------
    resolutions: list[SymlinkResolution] = []
    for link in entries:
        if link.entry_type != EntryType.SYMLINK.value:
            continue
        walk = walks.get(link.index)
        if walk is None:
            # 链接自身路径 unsafe：不参与解析。
            resolutions.append(
                SymlinkResolution(
                    index=link.index,
                    link_path=link.canonical_path,
                    link_target=link.link_target or "",
                    resolved_target=None,
                    resolves_to_index=None,
                    terminal="unsafe_link",
                    chain=[
                        SymlinkChainHop(
                            link_index=link.index,
                            link_path=link.canonical_path,
                            link_target=link.link_target or "",
                            resolves_to=None,
                            risk=None,
                            next_index=None,
                        )
                    ],
                    risks=[],
                )
            )
            continue

        risks: list[SymlinkRisk] = []
        if walk.terminal == "escape":
            risks.append(
                SymlinkRisk(
                    code=SymlinkRiskCode.SYMLINK_ESCAPE,
                    message="符号链接目标越出目标根（绝对/UNC/盘符路径或词法 .. 逃逸，"
                    "含沿链接链传播的越界）",
                )
            )
        elif walk.terminal == "bad_target":
            risks.append(
                SymlinkRisk(
                    code=SymlinkRiskCode.SYMLINK_BAD_TARGET,
                    message="符号链接目标不是合法的 Windows 目标路径"
                    "（保留设备名、非法字符或空目标，含沿链接链传播）",
                )
            )
        elif walk.terminal == "cycle":
            close = by_index[walk.cycle_close]
            risks.append(
                SymlinkRisk(
                    code=SymlinkRiskCode.SYMLINK_CYCLE,
                    message=f"链接链构成循环：沿链再次遇到条目 #{close.index}"
                    f"（{close.canonical_path}）",
                    related_index=close.index,
                )
            )
        for entry_index in sorted(hijacks_by_link.get(link.index, ())):
            entry = by_index[entry_index]
            risks.append(
                SymlinkRisk(
                    code=SymlinkRiskCode.SYMLINK_HIJACK,
                    message=f"本链接占据条目 #{entry.index}"
                    f"（{entry.canonical_path}）的祖先路径，构成路径劫持",
                    related_index=entry.index,
                )
            )
        risks.sort(key=lambda r: (_RISK_ORDER[r.code], r.related_index or 0))

        resolutions.append(
            SymlinkResolution(
                index=link.index,
                link_path=link.canonical_path,
                link_target=link.link_target or "",
                resolved_target=walk.resolved_target,
                resolves_to_index=walk.resolves_to_index,
                terminal=walk.terminal,
                chain=[
                    SymlinkChainHop(
                        link_index=h.link.index,
                        link_path=h.link.canonical_path,
                        link_target=h.link.link_target or "",
                        resolves_to=h.resolves_to,
                        risk=h.risk,
                        next_index=h.next_index,
                    )
                    for h in walk.hops
                ],
                risks=risks,
            )
        )

    hijack_pairs.sort(key=lambda pair: (pair[1], pair[0]))
    hijacks_out = [
        SymlinkHijack(
            link_index=li,
            link_path=by_index[li].canonical_path,
            entry_index=ei,
            entry_path=by_index[ei].canonical_path,
        )
        for li, ei in hijack_pairs
    ]
    return resolutions, hijacks_out, hijacked, hijacks_by_link
