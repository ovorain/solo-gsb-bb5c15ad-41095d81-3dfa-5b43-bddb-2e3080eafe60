# Archive Path Preflight API（压缩包路径预检 API）

使用 **Python + FastAPI + 纯内存计算** 的跨平台压缩包路径预检服务。
接收待解包条目的原始路径与 `file` / `directory` / `symlink` 类型，按 **Windows 目标规则**
规范化路径，识别危险条目，并输出同名碰撞组与文件-目录层级冲突；
对 `symlink` 条目还会**按链接所在目录解析目标**、在整批条目上**追踪链接链**，
报告越界目标、循环与路径劫持。请求体传 `"repair": true` 还可得到确定性的改名修复计划
（`repair_plan`），其中所有符号链接及被链接祖先劫持的条目均标记 `skipped`。

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
    { "path": "docs/link", "type": "symlink", "link_target": "../shared/ReadMe.txt" }
  ],
  "repair": false
}
```

`type` 接受 `file`、`directory` 或 `symlink`。`symlink` 条目**必须**提供字符串字段
`link_target`（可为空串，表示空目标）；其余类型传 `link_target` 会被忽略。
`repair` 为可选布尔值，省略或为 `false`
时响应不含 `repair_plan` 字段；为 `true` 时额外返回
确定性修复计划，见下文 [修复计划（repair=true）](#修复计划repairtrue)。
响应中的 `entries` 与 `symlinks` **严格保持输入顺序**，`index` 从 1 开始。

响应关键字段：

| 字段 | 说明 |
| --- | --- |
| `entries[].canonical_path` | 规范路径：正斜杠 `/` 分隔、每段 Unicode NFC、段尾空格与句点已裁剪，保留原始大小写用于展示 |
| `entries[].comparison_key` | Windows 等价比较键（在规范路径上做大小写折叠 `casefold`）；不安全条目为 `null` |
| `entries[].link_target` | 符号链接的原始目标字符串（仅 `symlink` 条目，其余为 `null`） |
| `entries[].safe` | 是否可安全解包（链接目标风险不改变 `safe`，风险在 `symlinks[].risks` 报告） |
| `entries[].collision_group` | 所属同名碰撞组编号，无碰撞为 `null`（symlink 不参与碰撞分组） |
| `entries[].blocked_by_file_ancestors` | 占据本条目祖先路径的文件条目下标（层级冲突） |
| `entries[].blocks_descendants` | 本文件条目阻挡了哪些后代条目（仅文件条目） |
| `entries[].hijacked_by_symlinks` | 占据本条目祖先路径的符号链接下标（路径劫持，仅普通文件/目录条目） |
| `entries[].issues` | 规范化过程中的问题（`severity` 为 `error` 或 `info`） |
| `collision_groups` | 碰撞组明细（含每个成员的下标与规范路径），按首次出现顺序编号 |
| `hierarchy_conflicts` | `(file_index, descendant_index)` 层级冲突对 |
| `symlinks` | 每条符号链接的解析链与风险，**按输入顺序**；详见 [符号链接风险分析](#符号链接风险分析) |
| `symlink_hijacks` | `(link_index, entry_index)` 路径劫持对（按被劫持条目下标排序） |
| `summary` | `total / safe / unsafe / collisions / collision_entries / hierarchy_conflicts / symlinks / symlink_risks / symlink_hijacks` 计数 |

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

不安全条目仍会返回**尽力而为**的 `canonical_path` 与问题明细，方便展示与修复，
但**不参与**碰撞分组与层级冲突计算。

## 冲突检测

- **同名碰撞**：安全的普通文件/目录条目规范化后的 `comparison_key` 相同即落入同一
  碰撞组（大小写、NFC、段尾点/空格差异都会被抹平），组号按该组首次出现的顺序分配。
  符号链接不参与碰撞分组。
- **层级冲突**：若某**文件**条目的规范路径恰好是另一条普通条目（文件或目录）的
  祖先路径（如文件 `a/b` 与后代 `a/b/c.txt`），解包时无法在同名路径上创建目录，
  记为层级冲突。目录占据祖先路径属于正常布局，不报告。
  祖先路径是**符号链接**时不报层级冲突，而按下文路径劫持处理。

## 符号链接风险分析

`type=symlink` 的条目必须携带 `link_target`。分析全程仍是词法计算：
服务不读取任何真实链接，只把整批条目当作解包后将出现的路径集合来模拟。

### 目标解析（相对链接所在目录）

1. **链接自身路径**先按上面的 Windows 规则规范化；自身 unsafe 的链接
   （如 `../link`）不参与解析，其 `terminal` 为 `unsafe_link`。
2. **目标形态**：`link_target` 以 `/`、`\` 开头（绝对/UNC）或带盘符（`C:`）时，
   锚定到目标根之外，判为 `SYMLINK_ESCAPE`；空串判为 `SYMLINK_BAD_TARGET`。
3. **相对目标**以链接所在目录为基准做词法解析：`.` 原地，`..` 弹栈，
   越过目标根即 `SYMLINK_ESCAPE`。
4. 解析结果再过一遍 Windows 规范化：保留设备名、非法字符、裁剪后为空等
   记为 `SYMLINK_BAD_TARGET`；规范化后越界（绝对/UNC/盘符/词法逃逸）
   仍记为 `SYMLINK_ESCAPE`。段名同样做 NFC、段尾点空格裁剪与大小写折叠，
   用于在整批条目中匹配路径。
5. 目标命中另一符号链接则继续跟随；命中普通文件/目录则 `terminal=entry`
   （`resolves_to_index` 给出条目下标）；目标根内不存在则 `terminal=dangling`。

### 链接链与风险码

每条链接独立给出自己的解析链 `chain`（从链接自身开始，逐跳记录
`link_index / link_path / link_target / resolves_to / risk / next_index`）。
链接链上后段链接的越界/非法目标风险**沿链传播**——链上每一条链接都会得到相同的
`SYMLINK_ESCAPE` / `SYMLINK_BAD_TARGET` 风险；沿链再次遇到已访问链接时构成
**循环**（含自循环），链上每条链接报 `SYMLINK_CYCLE`，`related_index`
为闭环中再次遇到的链接下标。

| 风险 code | 触发条件 |
| --- | --- |
| `SYMLINK_ESCAPE` | 链接目标（或链上某跳的目标）越出目标根：绝对/UNC/盘符路径或词法 `..` 逃逸 |
| `SYMLINK_BAD_TARGET` | 目标为空或不是合法的 Windows 目标路径（保留设备名、非法字符、裁剪后为空） |
| `SYMLINK_CYCLE` | 链接链构成循环（沿链再次遇到已访问的符号链接） |
| `SYMLINK_HIJACK` | 本链接占据某个普通文件/目录条目的祖先路径，构成路径劫持 |

### 路径劫持（path hijack）

解包时符号链接会把其所在路径**替换**成链接目标。因此，只要某个**普通文件/目录**
条目的任一祖先路径（按 Windows comparison_key 匹配）被一条符号链接占据，该普通
条目就被**劫持**：

- 链接得到 `SYMLINK_HIJACK` 风险，`related_index` 为每个被劫持条目的下标；
- 被劫持条目的 `hijacked_by_symlinks` 给出占据其祖先的链接下标，
  并追加一条 `SYMLINK_ANCESTOR` 信息；
- 顶层 `symlink_hijacks` 给出全部 `(link_index, entry_index)` 对。

劫持与链接目标本身是否越界/循环无关——即使链接目标危险，它仍然占据着后代条目
词法路径上的祖先。

`symlinks[]` 按输入顺序排列，每项结构：

```json
{
  "index": 6,
  "link_path": "docs/link",
  "link_target": "../shared/ReadMe.txt",
  "resolved_target": "shared/ReadMe.txt",
  "resolves_to_index": null,
  "terminal": "dangling",
  "chain": [
    {
      "link_index": 6,
      "link_path": "docs/link",
      "link_target": "../shared/ReadMe.txt",
      "resolves_to": "shared/ReadMe.txt",
      "risk": null,
      "next_index": null
    }
  ],
  "risks": []
}
```

`terminal` 取值：`entry`（命中普通条目）、`dangling`（目标根内悬空）、
`escape`（越界）、`bad_target`（Windows 非法目标）、`cycle`（循环）、
`unsafe_link`（链接自身路径 unsafe）。

curl 示例：

```bash
curl -s http://localhost:8000/api/v1/preflight \
  -H 'Content-Type: application/json' \
  -d '{"entries":[{"path":"d/link","type":"symlink","link_target":"../../evil"},{"path":"d/link/a.txt","type":"file"}]}'
```

## 修复计划（`repair=true`）

请求体加 `"repair": true` 后，响应在原有字段之外**额外**包含 `repair_plan`
（`repair` 省略或为 `false` 时该字段不出现，响应保持兼容）。原有诊断结果
（`collision_groups`、`hierarchy_conflicts`、`entries[].issues` 等）保持不变，
修复计划只是附加建议。

修复规则：

1. **跳过条目**（`skipped: true`、`repaired_path: null`，绝不改名，也不占用修复后
   路径、不参与碰撞/层级复检）：
   - 所有**不安全**条目（含自身路径 unsafe 的符号链接），`reasons` 为 `["UNSAFE"]`；
   - 所有**符号链接**（安全链接 `reasons` 为 `["SYMLINK"]`）；
   - **被符号链接祖先劫持**的普通文件/目录，`reasons` 为 `["SYMLINK_ANCESTOR"]`。
2. **同名碰撞**：活跃（未跳过）成员中保留**最先出现且自身不阻挡活跃后代**的条目
   （目录也算），其余条目在**末段扩展名前**插入 ` (n)`，n 从 1 递增。
   若组内所有活跃成员都阻挡后代，则无保留者、全部改名；
   跳过成员使组内活跃成员不足 2 个时该组消解，存活者保留原名。
3. **文件阻挡后代**：当阻挡文件与被阻挡后代都参与修复时，重命名**阻挡的文件本身**
   （被阻挡的后代保留原名）；任一方被跳过时该阻挡关系不触发改名。
4. **扩展名切分**：以最后一个 `.` 为分隔点；以 `.` 开头的点文件
   （如 `.gitignore`）整体视为词干；无扩展名则在段尾追加。
   例：`readme.txt` → `readme (1).txt`，`tar.tar.gz` → `tar.tar (1).gz`，
   `Makefile` → `Makefile (1)`。
5. **候选校验**：每个候选名均按 Windows `comparison_key`（`casefold`）同时检查
   - 与任一**已占用路径**同名（碰撞）；
   - 候选为文件时占据已占用路径的祖先、或已占用文件是候选的祖先（层级冲突）。

   检查同时针对“已处理条目”和“确定保留原名的未来条目”，递增 n 直至两者均不
   冲突，因此整批复检结果恒为无冲突（跳过条目不参与复检）。
6. 无冲突的活跃条目不改名，`reasons` 为空，`repaired_path` 等于 `canonical_path`。
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
  "skipped_unsafe_count": 0,
  "skipped_symlink_count": 0,
  "skipped_hijacked_count": 0,
  "collisions_remaining": 0,
  "hierarchy_conflicts_remaining": 0,
  "collisions_resolved": 1,
  "hierarchy_conflicts_resolved": 0
}
```

| 字段 | 说明 |
| --- | --- |
| `entries` | 按**输入顺序**逐条给出 `index`、`original_path`、`repaired_path`、`reasons`、`skipped` |
| `renamed_count` | 实际改名的活跃条目数量 |
| `skipped_count` | 跳过的条目总数（= 下列三个跳过计数之和） |
| `skipped_unsafe_count` | 因 unsafe 跳过的条目数量（含 unsafe 符号链接） |
| `skipped_symlink_count` | 因是符号链接而跳过的安全条目数量 |
| `skipped_hijacked_count` | 因被符号链接祖先劫持而跳过的普通条目数量 |
| `collisions_remaining` / `hierarchy_conflicts_remaining` | 按 `repaired_path` 复检（仅活跃条目）的剩余两类冲突计数（恒为 `0`） |
| `collisions_resolved` / `hierarchy_conflicts_resolved` | 修复消除的两类冲突数量（分别等于原 `summary.collisions` 与 `summary.hierarchy_conflicts`） |

`reasons` 取值：`COLLISION`（同名碰撞改让）、`BLOCKS_DESCENDANT`
（文件阻挡活跃后代而改名）；skipped 条目取 `UNSAFE` / `SYMLINK` /
`SYMLINK_ANCESTOR`（各自固定一个）。

curl 示例：

```bash
curl -s http://localhost:8000/api/v1/preflight \
  -H 'Content-Type: application/json' \
  -d '{"repair":true,"entries":[{"path":"L","type":"symlink","link_target":"t"},{"path":"L/a.txt","type":"file"},{"path":"a/b","type":"file"},{"path":"a/b/c.txt","type":"file"}]}'
```

## 项目结构

```
.
├── app/
│   ├── main.py          # FastAPI 路由（/health、/api/v1/preflight）
│   ├── normalize.py     # Windows 路径规范化与 unsafe 判定（纯函数）
│   ├── schemas.py       # Pydantic 请求/响应模型（含 symlink 分析、repair_plan）
│   ├── service.py       # 碰撞分组、层级冲突与符号链接分析编排
│   ├── symlinks.py      # 符号链接目标解析、链接链追踪与路径劫持（纯函数）
│   └── repair.py        # repair=true 确定性改名修复计划（纯函数）
├── tests/               # pytest 用例
├── docker/entrypoint.sh # 启动时安装依赖并启动服务
├── Dockerfile
├── docker-compose.yml
├── requirements.txt
└── requirements-dev.txt
```
