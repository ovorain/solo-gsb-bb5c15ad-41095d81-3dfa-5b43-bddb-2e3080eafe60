"""请求/响应模型（Pydantic v2）。"""

from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, Field

from .normalize import IssueCode, IssueSeverity


class EntryType(str, Enum):
    FILE = "file"
    DIRECTORY = "directory"


class PreflightEntryIn(BaseModel):
    path: str = Field(..., description="待解包条目的原始路径")
    type: EntryType = Field(..., description="条目类型：file 或 directory")


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


class PreflightEntryOut(BaseModel):
    index: int = Field(..., description="条目下标（从 1 开始，与输入顺序一致）")
    type: EntryType
    original_path: str
    canonical_path: str = Field(..., description="规范化路径（NFC、段尾已裁剪，正斜杠分隔）")
    comparison_key: str | None = Field(
        ..., description="Windows 等价比较键（小写折叠，仅安全条目可用）"
    )
    safe: bool
    collision_group: int | None = Field(
        ..., description="所属同名碰撞组编号；无碰撞或不安全时为 null"
    )
    blocked_by_file_ancestors: list[int] = Field(
        default_factory=list, description="阻挡本条目的文件祖先下标列表"
    )
    blocks_descendants: list[int] = Field(
        default_factory=list, description="被本文件条目阻挡的后代下标列表（仅文件条目）"
    )
    issues: list[IssueOut] = Field(default_factory=list)


class Summary(BaseModel):
    total: int
    safe: int
    unsafe: int
    collisions: int = Field(..., description="同名碰撞组数量")
    collision_entries: int
    hierarchy_conflicts: int


class RepairReason(str, Enum):
    COLLISION = "COLLISION"
    BLOCKS_DESCENDANT = "BLOCKS_DESCENDANT"
    UNSAFE = "UNSAFE"


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
            "BLOCKS_DESCENDANT（文件阻挡后代而改名）；skipped 条目为 [UNSAFE]"
        ),
    )
    skipped: bool = Field(..., description="不安全条目不参与修复，恒为 true")


class RepairPlan(BaseModel):
    entries: list[RepairEntry] = Field(
        ..., description="按输入顺序排列的逐条修复计划"
    )
    renamed_count: int = Field(..., description="实际改名的安全条目数量")
    skipped_count: int = Field(..., description="因不安全被跳过的条目数量")
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
    summary: Summary


class PreflightRepairResponse(PreflightResponse):
    repair_plan: RepairPlan


class HealthResponse(BaseModel):
    status: str
    service: str
