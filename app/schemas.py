"""请求/响应模型（Pydantic v2）。"""

from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, Field, model_validator

from .normalize import IssueCode, IssueSeverity


class EntryType(str, Enum):
    FILE = "file"
    DIRECTORY = "directory"
    SYMLINK = "symlink"


class PreflightEntryIn(BaseModel):
    path: str = Field(..., description="待解包条目的原始路径")
    type: EntryType = Field(
        ..., description="条目类型：file、directory 或 symlink"
    )
    link_target: str | None = Field(
        default=None,
        description=(
            "符号链接目标（仅 type=symlink 时必填）。相对目标按链接所在目录解析；"
            "以 /、\\ 开头或带盘符的目标锚定到目标根之外"
        ),
    )

    @model_validator(mode="after")
    def _validate_link_target(self) -> "PreflightEntryIn":
        if self.type is EntryType.SYMLINK:
            if self.link_target is None:
                raise ValueError("type=symlink 时必须提供 link_target")
        return self


class PreflightRequest(BaseModel):
    entries: list[PreflightEntryIn] = Field(
        ..., min_length=1, description="待预检的条目列表（至少 1 条）"
    )
    repair: bool = Field(
        default=False,
        description="为 true 时生成确定性 repair_plan（同名碰撞与文件祖先冲突修复建议）",
    )


class IssueOut(BaseModel):
    code: IssueCode
    severity: IssueSeverity
    message: str
    segment: int | None = None
    related_index: int | None = None


class CollisionMember(BaseModel):
    index: int
    canonical_path: str


class CollisionGroup(BaseModel):
    group: int = Field(..., description="碰撞组编号（按首次出现顺序分配）")
    canonical_path: str = Field(..., description="该组对应的规范路径（展示用）")
    members: list[CollisionMember]


class HierarchyConflict(BaseModel):
    file_index: int = Field(..., description="作为祖先路径的文件条目下标")
    file_canonical_path: str
    descendant_index: int = Field(..., description="被阻挡的后代条目下标")
    descendant_canonical_path: str


class SymlinkRiskCode(str, Enum):
    SYMLINK_ESCAPE = "SYMLINK_ESCAPE"
    SYMLINK_BAD_TARGET = "SYMLINK_BAD_TARGET"
    SYMLINK_CYCLE = "SYMLINK_CYCLE"
    SYMLINK_HIJACK = "SYMLINK_HIJACK"


class SymlinkChainHop(BaseModel):
    link_index: int = Field(..., description="本跳所跟随的符号链接条目下标")
    link_path: str = Field(..., description="该链接自身的规范路径")
    link_target: str = Field(..., description="该链接的原始目标字符串")
    resolves_to: str | None = Field(
        ...,
        description=(
            "目标相对链接所在目录解析后的绝对路径（目标根内、Windows 合法）；"
            "越界/非法时为 null"
        ),
    )
    risk: SymlinkRiskCode | None = Field(
        ...,
        description=(
            "本跳目标级风险：SYMLINK_ESCAPE（越界）或 SYMLINK_BAD_TARGET"
            "（Windows 非法目标）；正常为 null"
        ),
    )
    next_index: int | None = Field(
        ...,
        description="目标命中的下一个符号链接下标；命中普通条目或悬空时为 null"
    )


class SymlinkRisk(BaseModel):
    code: SymlinkRiskCode
    message: str
    related_index: int | None = Field(
        default=None,
        description=(
            "相关条目下标：HIJACK 为被劫持的普通条目；"
            "CYCLE 为闭环中再次遇到的符号链接；其余为 null"
        ),
    )


class SymlinkResolution(BaseModel):
    index: int = Field(..., description="符号链接条目下标（从 1 开始，按输入顺序返回）")
    link_path: str = Field(..., description="链接自身的规范路径")
    link_target: str = Field(..., description="原始链接目标字符串")
    resolved_target: str | None = Field(
        ...,
        description=(
            "解析终点路径（目标根内）：可能命中普通条目或悬空；越界/非法/循环时为 null"
        ),
    )
    resolves_to_index: int | None = Field(
        ..., description="解析终点命中的普通条目下标；悬空或异常终止时为 null"
    )
    terminal: str = Field(
        ...,
        description=(
            "解析终止类型：entry（命中普通条目）、dangling（目标根内悬空）、"
            "escape（越界）、bad_target（Windows 非法目标）、cycle（循环）、"
            "unsafe_link（链接自身路径 unsafe，不参与解析）"
        ),
    )
    chain: list[SymlinkChainHop] = Field(
        ..., description="跟随到的链接链（至少包含链接自身这一跳）"
    )
    risks: list[SymlinkRisk] = Field(
        default_factory=list, description="该符号链接的风险（按风险码排序，相关下标升序）"
    )


class SymlinkHijack(BaseModel):
    link_index: int = Field(..., description="作为祖先路径的符号链接下标")
    link_path: str
    entry_index: int = Field(..., description="被劫持的普通文件/目录条目下标")
    entry_path: str


class PreflightEntryOut(BaseModel):
    index: int = Field(..., description="条目下标（从 1 开始，与输入顺序一致）")
    type: EntryType
    original_path: str
    canonical_path: str = Field(..., description="规范化路径（NFC、段尾已裁剪，正斜杠分隔）")
    comparison_key: str | None = Field(
        ..., description="Windows 等价比较键（小写折叠，仅安全条目可用）"
    )
    safe: bool
    link_target: str | None = Field(
        default=None, description="符号链接原始目标（仅 type=symlink）"
    )
    collision_group: int | None = Field(
        ..., description="所属同名碰撞组编号；无碰撞、不安全或 symlink 时为 null"
    )
    blocked_by_file_ancestors: list[int] = Field(
        default_factory=list, description="阻挡本条目的文件祖先下标列表"
    )
    blocks_descendants: list[int] = Field(
        default_factory=list, description="被本文件条目阻挡的后代下标列表（仅文件条目）"
    )
    hijacked_by_symlinks: list[int] = Field(
        default_factory=list,
        description="占据本条目录径祖先的符号链接下标（路径劫持；仅普通文件/目录条目）",
    )
    issues: list[IssueOut] = Field(default_factory=list)


class Summary(BaseModel):
    total: int
    safe: int
    unsafe: int
    collisions: int = Field(..., description="同名碰撞组数量")
    collision_entries: int
    hierarchy_conflicts: int
    symlinks: int = Field(..., description="符号链接条目数量")
    symlink_risks: int = Field(
        ...,
        description=(
            "符号链接风险条目数量（含 SYMLINK_ESCAPE / SYMLINK_BAD_TARGET / "
            "SYMLINK_CYCLE / SYMLINK_HIJACK 任一风险的链接数）"
        ),
    )
    symlink_hijacks: int = Field(
        ..., description="普通文件/目录被符号链接祖先劫持的条目数量"
    )


class RepairReason(str, Enum):
    COLLISION = "COLLISION"
    BLOCKS_DESCENDANT = "BLOCKS_DESCENDANT"
    UNSAFE = "UNSAFE"
    SYMLINK = "SYMLINK"
    SYMLINK_ANCESTOR = "SYMLINK_ANCESTOR"


class RepairEntry(BaseModel):
    index: int = Field(..., description="条目下标（与输入顺序一致，从 1 开始）")
    original_path: str = Field(..., description="原始输入路径")
    repaired_path: str | None = Field(
        ...,
        description=(
            "修复后路径（正斜杠分隔）。安全且未改名的条目等于 canonical_path；"
            "不安全条目为 null"
        ),
    )
    reasons: list[RepairReason] = Field(
        default_factory=list,
        description=(
            "修复原因：COLLISION（同名碰撞改让）、"
            "BLOCKS_DESCENDANT（文件阻挡后代而改名）；"
            "skipped 条目取 UNSAFE / SYMLINK / SYMLINK_ANCESTOR 的子集（固定顺序）"
        ),
    )
    skipped: bool = Field(
        ...,
        description=(
            "不参与改名与复检的条目恒为 true：不安全条目、所有符号链接、"
            "被符号链接祖先劫持的普通条目"
        ),
    )


class RepairPlan(BaseModel):
    entries: list[RepairEntry] = Field(
        ..., description="按输入顺序排列的逐条修复计划"
    )
    renamed_count: int = Field(..., description="实际改名的安全条目数量")
    skipped_count: int = Field(
        ...,
        description=(
            "跳过的条目数量：不安全条目 + 所有符号链接 + 被符号链接祖先劫持的条目"
        ),
    )
    skipped_unsafe_count: int = Field(..., description="因 unsafe 被跳过的条目数量")
    skipped_symlink_count: int = Field(..., description="被跳过的符号链接条目数量")
    skipped_hijacked_count: int = Field(
        ..., description="因被符号链接祖先劫持而跳过的普通条目数量"
    )
    collisions_remaining: int = Field(
        ..., description="按 repaired_path 复检后的同名碰撞组数（恒为 0）"
    )
    hierarchy_conflicts_remaining: int = Field(
        ..., description="按 repaired_path 复检后的文件祖先冲突对数（恒为 0）"
    )
    collisions_resolved: int = Field(
        ..., description="修复消除的同名碰撞组数（等于原 summary.collisions）"
    )
    hierarchy_conflicts_resolved: int = Field(
        ..., description="修复消除的文件祖先冲突对数（等于原 summary.hierarchy_conflicts）"
    )


class PreflightResponse(BaseModel):
    target: str = "windows"
    entries: list[PreflightEntryOut]
    collision_groups: list[CollisionGroup]
    hierarchy_conflicts: list[HierarchyConflict]
    symlinks: list[SymlinkResolution] = Field(
        default_factory=list,
        description="按输入顺序排列的每条符号链接解析链与风险",
    )
    symlink_hijacks: list[SymlinkHijack] = Field(
        default_factory=list,
        description="(link_index, entry_index) 路径劫持对（按被劫持条目下标排序）",
    )
    summary: Summary


class PreflightRepairResponse(PreflightResponse):
    repair_plan: RepairPlan


class HealthResponse(BaseModel):
    status: str
    service: str
