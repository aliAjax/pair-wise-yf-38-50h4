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

数据集字段按敏感度分级（1=public … 4=restricted），见数据集 `data.fields`。申请获批时按当时分级定下可读字段（`data.field_scope`），签发授权时固定范围；取数只返回范围内字段，越权取范围外字段直接拒绝。

- `POST /api/grants/<id>/fetch`：请求体可带 `{"fields":[...]}`，省略则返回全部范围内字段；越权返回 `403`。
- `POST /api/datasets/<id>/reclassify`：请求体 `{"fields":[...],"expected_version":数字}`，可带 `Idempotency-Key` 头。一个事务内更新分级表并重算所有授权范围；范围被清空的授权置为 `revoked`，排队未取数的授权一起按新范围执行。失败整批回滚，带同一 `Idempotency-Key` 重试只补没落库的授权。
- `GET /api/grants/<id>/reconcile`：审计员拿授权固定范围与数据集当前分级表对账，返回 `valid`、`drift`、`stale`。
- `GET /api/datasets/<id>/reconcile`：数据集下所有授权的对账汇总。

## 主要接口

- `GET /health`：健康检查。
- `GET /api/<kind>`：按对象类型查询，可用`?status=`过滤。
- `POST /api/<kind>`：创建对象；请求体为JSON。
- `GET /api/entities/<id>`：读取对象当前版本。
- `POST /api/entities/<id>/actions`：提交`{"action":"动作名","data":{...},"expected_version":数字}`。
- `POST /api/<kind>/<id>/actions`：同上的等价路径。
- `GET /api/audit`：读取审计记录。

请求身份通过`X-User-Id`和`X-Role`请求头传入。创建和动作的可执行角色由规则引擎控制。

## 测试

```bash
python3 -m unittest discover -s tests -v
```

## 局限

数据目录和授权凭证是治理流程演示，不包含真实数据下载、加密或机构身份联邦。
