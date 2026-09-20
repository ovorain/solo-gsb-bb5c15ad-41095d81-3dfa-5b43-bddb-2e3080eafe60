"""跨平台压缩包路径预检 API。

仅对路径做内存中的词法分析，绝不访问文件系统。
"""

from __future__ import annotations

from fastapi import FastAPI

from .schemas import HealthResponse, PreflightRepairResponse, PreflightRequest
from .service import run_preflight

app = FastAPI(
    title="Archive Path Preflight API",
    description=(
        "压缩包路径预检：按 Windows 目标规则规范化路径、识别保留设备名，"
        "检测同名碰撞与文件-目录层级冲突；并对 symlink 条目做链接链追踪、"
        "循环检测与路径劫持分析。纯内存计算，不访问文件系统。"
    ),
    version="1.1.0",
)


@app.get("/health", response_model=HealthResponse, tags=["meta"])
def health() -> HealthResponse:
    return HealthResponse(status="ok", service="archive-path-preflight")


@app.get("/", include_in_schema=False)
def root() -> dict[str, str]:
    return {
        "service": "archive-path-preflight",
        "docs": "/docs",
        "health": "/health",
        "preflight": "POST /api/v1/preflight",
    }


@app.post(
    "/api/v1/preflight",
    response_model=None,  # repair=false 时响应不含 repair_plan；由 service 层返回具体模型
    responses={200: {"model": PreflightRepairResponse}},  # 仅供 OpenAPI 文档展示超集
    tags=["preflight"],
    summary="批量预检压缩包条目路径（repair=true 时附修复计划）",
)
def preflight(request: PreflightRequest):
    return run_preflight(request)
