# mosdns 完整文档

本文档基于仓库当前代码（2025-10-31）自动梳理，聚焦本仓库可见实现与接口，帮助你在不依赖外部站点的情况下完成构建、配置、运行与二次开发。

## 目录

- 项目概览
- 快速开始
- 配置参考
- 插件清单
- HTTP API 与内置页面
- 监控与日志
- 目录结构
- 开发指引
- 常见问题（精简）
- 许可信息

---

## 项目概览

mosdns 是一款以插件为中心的 DNS 服务框架，提供监听（UDP/TCP/HTTP/QUIC）、上游转发、缓存、匹配路由、限速与审计等能力。核心在 `coremain` 包中完成配置解析、插件加载、HTTP API 注册与服务生命周期管理。

- 模块化：每个功能以插件形式存在，通过 `plugins` 链路组装。
- 可观测性：提供 `/metrics` 指标、审计日志 API、进程日志临时捕获与内置可视化页面。
- 可运维：支持作为系统服务安装与管理（依赖 `kardianos/service`）。

主要入口：`main.go` 调用 `coremain.Run()`，提供 `start` 与 `service` 两类子命令。

---

## 快速开始

### 构建

要求 Go 版本：`go 1.25.3`（见 `go.mod`）。

```bash
go build -o bin/mosdns .
```

### 运行

- 前台启动：`./bin/mosdns start -c /path/to/config.yaml`
- 指定工作目录：`./bin/mosdns start -d /path/to/workdir -c config.yaml`
- 安装为系统服务：`./bin/mosdns service install -d /path/to/workdir -c /path/to/config.yaml`
  - 管理命令：`service start|stop|restart|status` 等

### 生成与转换配置

项目内置配置工具（见 `tools/config.go`）：

- 生成模板：`mosdns config gen config.yaml`
- 转换格式：`mosdns config conv -i in.yaml -o out.json`

> 注：`release.py` 也会使用该工具生成打包用的 `config.yaml`。

---

## 配置参考

顶层配置结构对应 `coremain.Config`（YAML）：

```yaml
log:            # mlog.LogConfig
  level: info   # 日志级别，支持 zap 标准级别
  file: ""      # 为空输出到 stderr
  production: false # true 为 JSON 格式

include:        # 可选，按序包含其他配置文件（相对主配置路径）
  - extra.yaml

plugins:        # 插件链路，数组顺序即执行顺序
  - tag: forward_google
    type: forward
    args:
      upstreams:
        - addr: https://8.8.8.8/dns-query

api:            # HTTP API 监听地址
  http: ":8080"
```

插件实例结构（`coremain.PluginConfig`）：

```yaml
- tag: <可选，默认随机>   # 供其他插件引用
  type: <必填>            # 插件类型（见“插件清单”）
  args: <按插件定义>      # 插件自定义参数结构
```

加载规则：

- `include` 深度最大 8，超出会报错；
- `api.http` 非空时启动 API 与内置页面；
- 插件按顺序初始化，插件之间通过 `tag` 引用。

---

## 插件清单

插件入口集中在 `plugin/enabled_plugins.go`，以下为按类别归纳的“类型标识”清单（仅列出名称与直观用途，具体参数以对应目录实现为准）：

### Data Provider（数据提供）

- `domain_set`：域名集合提供/匹配源。
- `ip_set`：IP 集合提供/匹配源。
- `sd_set`：子域（subdomain）集合提供/匹配源。
- `si_set`：字符串或结构化（可能为 SNI/IP 等）集合源。

### Matcher（匹配器）

- `client_ip`：按客户端 IP 匹配。
- `cname`：按 CNAME 匹配。
- `env`：按运行环境变量匹配。
- `has_resp`：是否已有响应匹配。
- `has_wanted_ans`：是否命中目标答案匹配。
- `ptr_ip`：按 PTR 反向记录中的 IP 匹配。
- `qclass`：按查询类匹配。
- `qname`：按查询域名匹配。
- `qtype`：按查询类型匹配。
- `random`：随机匹配（概率/抽样用途）。
- `rcode`：按响应码匹配。
- `resp_ip`：按应答 IP 匹配。
- `string_exp`：字符串表达式匹配。

### Executable（可执行处理）

- `arbitrary`：自定义处理（占位/扩展）。
- `black_hole`：丢弃/黑洞处理。
- `cache`：DNS 缓存。
- `debug_print`：调试输出。
- `drop_resp`：丢弃响应。
- `dual_selector`：双路选择器。
- `ecs_handler`：EDNS Client Subnet 处理。
- `forward`：上游转发（含 `forward_edns0opt`）。
- `hosts`：本地 hosts 解析。
- `ipset`：写入系统 ipset（Linux）。
- `metrics_collector`：指标收集。
- `nftset`：写入 nftables 集合（Linux）。
- `query_summary`：查询统计摘要。
- `rate_limiter`：速率限制。
- `redirect`：请求重定向/改写入口。
- `reverse_lookup`：反向查询工具。
- `domain_output`：按域输出处理结果。
- `switcher1..9`：多档开关（外部值/文件驱动）。
- `aliapi`：阿里相关 API 集成（见源码）。
- `cname_remover`：移除 CNAME。
- `adguard`：AdGuard 集成/适配页面。
- `webinfo`：Web 信息呈现。
- `requery`：二次查询器（失败/重试策略）。
- `rewrite`：请求/响应改写。
- `sequence`：子链路串接器（含 `sequence/fallback`）。
- `sleep`：延迟/节流工具。
- `ttl`：TTL 调整。

### Server（入站/监听）

- `udp_server`：启动 UDP 监听，入口由 `args.entry` 指向下游链路（tag）。
- `tcp_server`：启动 TCP 监听。
- `http_server`：DoH 监听。
- `quic_server`：DoQ 监听。

> 以上清单来自 `plugin/enabled_plugins.go` 的显式注册，细节请对照各目录源码与 `Args` 结构体。

---

## HTTP API 与内置页面

当 `api.http` 设置为非空地址（如 `:8080`）时，以下接口/页面可用：

### 指标与调试

- `GET /metrics`：Prometheus 指标。
- `GET /debug/pprof/*`：pprof 调试端点。

### 进程日志捕获（v1）

- `POST /api/v1/capture/start`：开始捕获，JSON 请求体可选 `{"duration_seconds": 120}`（1–600）。
- `GET  /api/v1/capture/logs`：读取捕获到的日志（JSON）。

### 审计日志（v1）

- `POST /api/v1/audit/start`：开始记录。
- `POST /api/v1/audit/stop`：停止记录。
- `GET  /api/v1/audit/status`：状态。
- `GET  /api/v1/audit/logs`：获取日志列表。
- `POST /api/v1/audit/clear`：清空内存日志。
- `GET  /api/v1/audit/capacity`：获取容量（条数）。
- `POST /api/v1/audit/capacity`：设置容量（将清空现有日志）。

### 审计日志（v2）

- `GET /api/v2/audit/stats`：总查询数与平均耗时。
- `GET /api/v2/audit/rank/domain?limit=20`：域名排行。
- `GET /api/v2/audit/rank/client?limit=20`：客户端 IP 排行。
- `GET /api/v2/audit/rank/domain_set?limit=20`：域名集合维度排行。
- `GET /api/v2/audit/rank/slowest?limit=100`：最慢查询列表。
- `GET /api/v2/audit/logs?domain=&answer_ip=&cname=&client_ip=&q=&exact=&page=1&limit=50`：分页/过滤获取日志。

### 内置页面

- `GET /`：`www/mosdnsp.html`，简洁面板。
- `GET /graphic`：`www/mosdns.html`，图形面板。
- `GET /log`：`www/log.html`，图形日志页。
- `GET /plog`：`www/log_plain.html`，纯文本日志页。
- `GET /rlog`：`www/rlog.html`，实时日志页。
- `GET /adguard`：`www/adguard.html`，AdGuard 适配页。
- `GET /rlog.css`、`/rlog.js`：静态资源。

跨域策略：内置了严格的 CORS 处理，同源放行，非同源仅允许预检返回 403。

---

## 监控与日志

- 日志：`mlog.LogConfig` 控制级别（`level`）、输出文件（`file`）与格式（`production`）。
- 捕获：进程日志捕获会暂时提高日志级别，过期后恢复（见 `capture.go`）。
- 指标：`/metrics` 汇总 Go 进程与自定义指标，插件可向注册器登记（`GetMetricsReg()`）。

---

## 目录结构（精选）

- `coremain/`：
  - `run.go`：CLI 子命令（`start`、`service`）。
  - `config.go`：配置结构。
  - `mosdns.go`：主流程、API 注册、插件加载与生命周期管理。
  - `api*.go`、`capture.go`：审计/捕获 API 实现。
  - `www/`：内置静态页面与资源。
- `plugin/`：
  - `enabled_plugins.go`：内置插件注册清单。
  - `server/*`、`executable/*`、`matcher/*`、`data_provider/*` 等：插件实现。
- `pkg/`：通用库（缓存、上游、速率限制、DNS 工具等）。
- `tools/`：配置生成与转换子命令。
- `scripts/`：脚本（含 OpenWrt 初始化脚本）。
- `Dockerfile*`：容器构建文件。

---

## 开发指引（简要）

### 新增插件

1) 在 `plugin/<category>/<name>/` 新建实现，定义 `Args`；
2) 在 `init()` 中调用 `coremain.RegNewPluginFunc("<type>", Init, func() any { return new(Args) })`；
3) 将该包导入 `plugin/enabled_plugins.go`（匿名导入 `_ "..."`）；
4) 如需对外提供 HTTP 接口，使用 `bp.M().RegPluginAPI(tag, mux)` 注册路由；
5) 如需指标，使用 `bp.M().GetMetricsReg()` 注册 Prometheus 指标。

### 扩展 CLI / 工具

使用 `cobra` 在 `coremain` 或 `tools` 下添加子命令，并通过 `coremain.AddSubCmd()` 注册（如需）。

### 测试

```bash
go test ./...
```

---

## 常见问题（精简）

- 监听端口占用：确认系统服务未在运行或调整 `listen` 配置。
- 配置拆分：`include` 路径相对主配置文件目录；深度上限 8。
- 日志捕获无输出：确认已访问 `/api/v1/capture/start` 且仍在捕获窗口内。

---

## 许可信息

本项目采用 GNU GPLv3（见仓库 `LICENSE`）。

