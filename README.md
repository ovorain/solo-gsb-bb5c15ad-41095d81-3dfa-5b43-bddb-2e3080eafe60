# Archive Path Preflight API（压缩包路径预检 API）

使用 **Python + FastAPI + 纯内存计算** 的跨平台压缩包路径预检服务。
接收待解包条目的原始路径与 `file` / `directory` / `symlink` 类型，按 **Windows 目标规则**
规范化路径，识别危险条目，并输出同名碰撞组与文件-目录层级冲突；
符号链接条目额外做**风险分析**：目标越界、链接链循环与祖先路径劫持；
请求体传 `"repair": true` 还可得到确定性的改名修复计划（`repair_plan`）。

> 服务**只对路径字符串做词法分析，全程不访问文件系统**，不会读取或写入任何条目。

## 一键启动（Docker Compose，端口 8000）

```bash
docker compose up --build
```

启动后：

- API 服务：<http://localhost:8000>
- Swagger 文档：<http://localhost:8000/docs>
- 健康检查：<http://localhost:8000/health>

停止：`docker compose down`

依赖在**容器启动时**由 `docker/entrypoint.sh` 执行 `pip install -r requirements.txt`
安装（venv 位于 `/opt/venv`，以非 root 用户 `appuser` 运行）。

## 本地运行（非 Docker）

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements-dev.txt
uvicorn app.main:app --host 0.0.0.0 --port 8000

# 测试
pytest -q
```

## 接口

### `GET /health`

健康检查，返回：

```json
{ "status": "ok", "service": "archive-path-preflight" }
```

### `POST /api/v1/preflight`

请求体：

```json
{
  "entries": [
    { "path": "Docs\\ReadMe.txt", "type": "file" },
    { "path": "docs/readme.txt", "type": "file" },
    { "path": "../evil.bin", "type": "file" },
    { "path": "a/b", "type": "file" },
    { "path": "a/b/c.txt", "type": "file" },
    { "path": "docs/link", "type": "symlink", "link_target": "../../etc/passwd" }
  ],
  "repair": false
}
```

`type` 接受 `file`、`directory` 或 `symlink`；`symlink` 条目**必须**携带
`link_target`，其余类型不得携带（否则返回 422）。`repair` 为可选布尔值，省略或为 `false`
时响应与旧版完全一致（不含 `repair_plan` 字段）；为 `true` 时额外返回
确定性修复计划，见下文 [修复计划（repair=true）](#修复计划repairtrue)。
响应中的 `entries` **严格保持输入顺序**，`index` 从 1 开始。

响应关键字段：

| 字段 | 说明 |
| --- | --- |
| `entries[].canonical_path` | 规范路径：正斜杠 `/` 分隔、每段 Unicode NFC、段尾空格与句点已裁剪，保留原始大小写用于展示 |
| `entries[].link_target` | 符号链接目标（仅 `symlink` 条目有值，其余为 `null`） |
| `entries[].comparison_key` | Windows 等价比较键（在规范路径上做大小写折叠 `casefold`）；不安全条目为 `null` |
| `entries[].safe` | 是否可安全解包 |
| `entries[].collision_group` | 所属同名碰撞组编号，无碰撞为 `null` |
| `entries[].blocked_by_file_ancestors` | 占据本条目祖先路径的文件条目下标（层级冲突） |
| `entries[].blocks_descendants` | 本文件条目阻挡了哪些后代条目（仅文件条目） |
| `entries[].issues` | 规范化与符号链接风险分析过程中的问题（`severity` 为 `error` 或 `info`） |
| `collision_groups` | 碰撞组明细（含每个成员的下标与规范路径），按首次出现顺序编号 |
| `hierarchy_conflicts` | `(file_index, descendant_index)` 层级冲突对 |
| `symlink_analysis` | 符号链接风险分析（见下文），无链接时各列表为空 |
| `summary` | `total / safe / unsafe / collisions / collision_entries / hierarchy_conflicts / symlinks / symlink_cycles / symlink_hijacked` 计数 |

curl 示例：

```bash
curl -s http://localhost:8000/api/v1/preflight \
  -H 'Content-Type: application/json' \
  -d '{"entries":[{"path":"Docs\\ReadMe.txt","type":"file"},{"path":"docs/readme.txt","type":"file"}]}'
```

## 规范化规则（Windows 目标）

1. **统一分隔符**：`\` 与 `/` 均视为路径分隔符，输出统一为 `/`。
2. **大小写**：Windows 文件系统不区分大小写；保留原始大小写用于展示，
   碰撞/层级判断使用 `str.casefold()` 比较键。
3. **Unicode**：每个路径段做 **NFC** 规范化；发生转换时附带 `UNICODE_NORMALIZED` 信息。
4. **段尾空格/句点**：Windows 会忽略每段末尾的空格与 `.`，逐段 `rstrip(" .")`；
   发生裁剪时附带 `SEGMENT_TRIMMED` 信息（裁剪后可能造成同名碰撞）。
5. **保留设备名**：每段（含中间目录段）按首个 `.` 前的词干，不区分大小写识别
   `CON`、`PRN`、`AUX`、`NUL`、`CLOCK$`、`COM1`–`COM9`、`LPT1`–`LPT9`
   （如 `NUL.log`、`aux` 也算），命中标为 `RESERVED_NAME`。
6. **非法字符**：段内含 `< > : " / | ? *` 或 ASCII 控制字符（< 0x20）标为
   `INVALID_CHARACTER`。
7. 重复或结尾分隔符产生的空段会被折叠，并给出 `EMPTY_SEGMENT` 信息；
   段裁剪后为空（如 `"..."`）记为错误。
8. 规范化后没有任何有效段（如空路径或单独的 `.`）记为 `EMPTY_TARGET`。

## 判定为 unsafe 的情形（`severity = error`）

| code | 触发条件 |
| --- | --- |
| `ABSOLUTE_PATH` | 绝对路径（以 `/` 开头） |
| `UNC_PATH` | UNC 网络路径（以 `\\` 或 `//` 开头） |
| `DRIVE_PATH` | 盘符路径（如 `C:\…`、`D:/…`） |
| `TRAVERSAL_ESCAPE` | 词法遍历中 `..` 越过目标根（根内的 `a/../b` 合法） |
| `RESERVED_NAME` | 命中 Windows 保留设备名 |
| `INVALID_CHARACTER` | 含 Windows 非法文件名字符或控制字符 |
| `EMPTY_TARGET` | 规范化后路径为空 |
| `LINK_TARGET_ESCAPE` | 符号链接目标（或链接链途经的目标）越出目标根 |
| `LINK_TARGET_INVALID` | 符号链接目标为空、含非法字符或命中保留设备名 |
| `LINK_CYCLE` | 链接链存在循环，无法解析到最终目标 |
| `SYMLINK_ANCESTOR` | 文件/目录的祖先路径被符号链接占据（路径劫持） |

不安全条目仍会返回**尽力而为**的 `canonical_path` 与问题明细，方便展示与修复，
但**不参与**碰撞分组与层级冲突计算。

## 冲突检测

- **同名碰撞**：安全条目规范化后的 `comparison_key` 相同即落入同一碰撞组
  （大小写、NFC、段尾点/空格差异都会被抹平），组号按该组首次出现的顺序分配。
  符号链接不参与碰撞分组。
- **层级冲突**：若某**文件**条目的规范路径恰好是另一条目（文件、目录或符号
  链接）的祖先路径（如文件 `a/b` 与后代 `a/b/c.txt`），解包时无法在同名路径上
  创建目录，记为层级冲突。目录占据祖先路径属于正常布局，不报告；符号链接
  占据祖先路径属于路径劫持，见下文符号链接风险分析。

## 符号链接风险分析

`type` 为 `symlink` 的条目必须携带 `link_target`。服务对整批条目做
**纯词法**的链接风险分析（不访问文件系统），结果集中在响应的
`symlink_analysis` 字段：

```json
{
  "symlink_analysis": {
    "links": [
      {
        "index": 1,
        "original_path": "a/lnk",
        "link_target": "../b/lnk2",
        "resolved_target": "b/lnk2",
        "final_path": "b/real.txt",
        "chain": [
          { "index": 1, "path": "a/lnk" },
          { "index": 2, "path": "b/lnk2" },
          { "index": null, "path": "b/real.txt" }
        ],
        "risk_codes": [],
        "safe": true
      }
    ],
    "cycles": [{ "members": [3, 4] }],
    "hijacked_entries": [
      { "entry_index": 5, "canonical_path": "a/x.txt", "symlink_ancestors": [1] }
    ]
  }
}
```

- **目标解析**：`link_target` 以**链接所在目录**为基准，复用与条目路径相同的
  Windows 规范化规则（分隔符统一、NFC、段尾裁剪、保留名/非法字符检查、
  词法遍历）。解析结果越出目标根（绝对/UNC/盘符路径，或 `..` 越过根）记
  `LINK_TARGET_ESCAPE`；目标为空、含非法字符或命中保留设备名记
  `LINK_TARGET_INVALID`。
- **链接链追踪**：目标路径（或其中间祖先段）落在批内另一条链接的路径上时
  继续跟随（大小写折叠匹配），`chain` 依次列出自身、途经链接与最终终点
  （终点非链接，`index` 为 `null`）。链中再次遇到已访问链接即构成循环
  （`LINK_CYCLE`，`cycles` 按最小下标起始去重报告）；链途经越界链接时越界
  **沿链传播**（同样记 `LINK_TARGET_ESCAPE`）。`resolved_target` 为自身目标
  的根内解析，`final_path` 为全链解析终点（越界或循环时为 `null`）。
- **路径劫持**：普通 `file` / `directory` 条目的任一祖先路径被符号链接占据，
  即记 `SYMLINK_ANCESTOR`（`error`），并列入 `hijacked_entries`；被劫持条目
  视为不安全，退出碰撞分组、层级冲突与 repair 复检。符号链接自身位于另一
  链接之下时不报劫持。
- 每条链接的 `risk_codes` 取自 `LINK_TARGET_ESCAPE` / `LINK_TARGET_INVALID` /
  `LINK_CYCLE`；`links` 严格按输入顺序返回。链接条目**不参与**同名碰撞分组
  （同键冲突由链接风险分析覆盖），但仍可作为文件祖先阻挡的后代出现在
  层级冲突中。

## 修复计划（`repair=true`）

请求体加 `"repair": true` 后，响应在原有字段之外**额外**包含 `repair_plan`
（`repair` 省略或为 `false` 时该字段不出现，响应保持兼容）。原有诊断结果
（`collision_groups`、`hierarchy_conflicts`、`entries[].issues` 等）保持不变，
修复计划只是附加建议。

修复规则：

1. **只处理安全的 file/directory 条目**。不安全条目标记 `"skipped": true`、
   `repaired_path` 为 `null`、`reasons` 为 `["UNSAFE"]`，绝不改名，也不参与
   碰撞/层级复检。**所有符号链接一律 skipped**（`reasons` 为 `["SYMLINK"]`），
   不参与改名与复检；被符号链接祖先劫持的条目已属不安全，随之一并跳过。
2. **同名碰撞**：保留碰撞组中**最先出现且自身不阻挡后代**的条目（目录也算），
   其余条目在**末段扩展名前**插入 ` (n)`，n 从 1 递增。若组内所有条目都阻挡
   后代，则无保留者、全部改名。
3. **文件阻挡后代**：重命名**阻挡的文件本身**（被阻挡的后代保留原名）。
4. **扩展名切分**：以最后一个 `.` 为分隔点；以 `.` 开头的点文件
   （如 `.gitignore`）整体视为词干；无扩展名则在段尾追加。
   例：`readme.txt` → `readme (1).txt`，`tar.tar.gz` → `tar.tar (1).gz`，
   `Makefile` → `Makefile (1)`。
5. **候选校验**：每个候选名均按 Windows `comparison_key`（`casefold`）同时检查
   - 与任一**已占用路径**同名（碰撞）；
   - 候选为文件时占据已占用路径的祖先、或已占用文件是候选的祖先（层级冲突）。

   检查同时针对“已处理条目”和“确定保留原名的未来条目”，递增 n 直至两者均不
   冲突，因此整批复检结果恒为无冲突。
6. 无冲突的安全条目不改名，`reasons` 为空，`repaired_path` 等于 `canonical_path`。
   同一原因不会重复列出；同时命中碰撞与层级冲突的条目，
   `reasons` 为 `["COLLISION", "BLOCKS_DESCENDANT"]`。

`repair_plan` 结构：

```json
{
  "entries": [
    {
      "index": 2,
      "original_path": "Docs/ReadMe.TXT",
      "repaired_path": "Docs/ReadMe (1).TXT",
      "reasons": ["COLLISION"],
      "skipped": false
    }
  ],
  "renamed_count": 1,
  "skipped_count": 0,
  "collisions_remaining": 0,
  "hierarchy_conflicts_remaining": 0,
  "collisions_resolved": 1,
  "hierarchy_conflicts_resolved": 0
}
```

| 字段 | 说明 |
| --- | --- |
| `entries` | 按**输入顺序**逐条给出 `index`、`original_path`、`repaired_path`、`reasons`、`skipped` |
| `renamed_count` | 实际改名的安全条目数量 |
| `skipped_count` | 因不安全被跳过的条目数量 |
| `collisions_remaining` / `hierarchy_conflicts_remaining` | 按 `repaired_path` 复检的剩余两类冲突计数（恒为 `0`） |
| `collisions_resolved` / `hierarchy_conflicts_resolved` | 修复消除的两类冲突数量（分别等于原 `summary.collisions` 与 `summary.hierarchy_conflicts`） |

`reasons` 取值：`COLLISION`（同名碰撞改让）、`BLOCKS_DESCENDANT`
（文件阻挡后代而改名）、`UNSAFE`（不安全条目，含被符号链接祖先劫持）、
`SYMLINK`（符号链接，恒 skipped）。

curl 示例：

```bash
curl -s http://localhost:8000/api/v1/preflight \
  -H 'Content-Type: application/json' \
  -d '{"repair":true,"entries":[{"path":"a/b","type":"file"},{"path":"a/b/c.txt","type":"file"}]}'
```

## 项目结构

```
.
├── app/
│   ├── main.py          # FastAPI 路由（/health、/api/v1/preflight）
│   ├── normalize.py     # Windows 路径规范化与 unsafe 判定（纯函数）
│   ├── schemas.py       # Pydantic 请求/响应模型（含 repair_plan、symlink_analysis）
│   ├── service.py       # 碰撞分组、层级冲突与符号链接分析编排
│   ├── symlink.py       # 符号链接风险分析：目标越界、链接链循环、路径劫持（纯函数）
│   └── repair.py        # repair=true 确定性改名修复计划（纯函数）
├── tests/               # pytest 用例
├── docker/entrypoint.sh # 启动时安装依赖并启动服务
├── Dockerfile
├── docker-compose.yml
├── requirements.txt
└── requirements-dev.txt
```
