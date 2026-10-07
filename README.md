# 基因组数据访问治理

这是一个只使用Python标准库和SQLite的模块化项目，默认端口为`8304`。所有业务规则集中在`src/rules.py`，`app.py`只负责组装依赖和启动服务。

## 模块结构

- `app.py`：命令行参数、依赖组装、启动和信号处理。
- `src/domain.py`：角色、数据结构、领域异常和基础校验。
- `src/rules.py`：状态机、权限、领域计算、冲突和跨对象校验。
- `src/repository.py`：SQLite建表、查询、事务和乐观锁。
- `src/service.py`：用例编排、幂等处理、版本控制和审计写入。
- `src/http_api.py`：HTTP路由、请求解析和统一错误响应。
- `src/audit.py`：实体操作审计时间线。
- `static/index.html`：最小演示页面。
- `tests/`：完整流程、规则和失败场景测试。

## 初始化与启动

```bash
python3 app.py --db ./data.db --port 8304
```

服务启动时会自动建表。`--host`可修改监听地址，`--db`可指定其他SQLite文件。

## 核心对象

- `dataset`：受控数据集；`application`：访问申请；`grant`：限时数据使用凭证。

## 字段范围账

数据集、申请、授权和审计串成一条字段范围账，取数不再默认给整表：

- 数据集用 `field_levels` 给字段分层，级别为 `public < internal < sensitive < restricted`，`classification_version` 随分级改动递增。
- 申请获批（`approve`）时按**当时**分级快照计算 `field_scope`（可用申请上的 `requested_level` 或审批时的 `approved_level` 控制上限），该快照作为历史账目保留。
- 范围确认 `confirm_scope`（`approved → scope_confirmed`）：两人同时确认同一申请时先写入的生效，后到的返回 409 并带 `conflict_id` 冲突编号。
- 授权签发（创建 `grant`）时把申请范围固定进 `scope`；`POST /api/entities/<id>/fetch` 取数只返回范围内字段，请求范围外字段直接 403 拒绝，并写 `fetch` 审计。
- 数据集 `reclassify` 改动分级后，同一事务内重算该数据集所有未终止授权（含已签发未取数的排队授权）的 `scope`，并逐条写 `scope_recompute` 审计。
- 批量签发 `POST /api/grants/batch`（`{"batch_id","items":[...]}`）：整批原子写入，任一失败整批撤回；同一 `batch_id` 重试只补没落下的授权。
- 审计员 `POST /api/audit/reconcile`（`{"dataset_id","external_field_levels"}`）拿授权范围和外部分级表对账，返回越权（`overreach`）与缺失（`missing`）字段差异，并写 `reconcile` 审计。

## 主要接口

- `GET /health`：健康检查。
- `GET /api/<kind>`：按对象类型查询，可用`?status=`过滤。
- `POST /api/<kind>`：创建对象；请求体为JSON。
- `GET /api/entities/<id>`：读取对象当前版本。
- `POST /api/entities/<id>/actions`：提交`{"action":"动作名","data":{...},"expected_version":数字}`。
- `POST /api/<kind>/batch`：批量创建；请求体`{"batch_id":"批次号","items":[...]}`，整批原子、按`batch_id`幂等重试。
- `POST /api/entities/<id>/fetch`：按授权范围取数；请求体`{"fields":[...]}`，越权字段直接拒绝。
- `POST /api/audit/reconcile`：审计员用外部分级表对账；请求体`{"dataset_id":"...","external_field_levels":{...}}`。
- `GET /api/audit`：读取审计记录。

请求身份通过`X-User-Id`和`X-Role`请求头传入。创建和动作的可执行角色由规则引擎控制。

## 测试

```bash
python3 -m unittest discover -s tests -v
```

## 局限

数据目录和授权凭证是治理流程演示，不包含真实数据下载、加密或机构身份联邦。
