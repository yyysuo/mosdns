# mosdns 项目说明

## 项目简介

mosdns 是一款使用 Go 实现的模块化 DNS 转发与过滤服务。项目通过插件化架构将监听、上游转发、缓存、匹配、限速等能力拆分为独立组件，便于按需组合配置。核心程序由 `coremain` 启动，支持命令行运行与系统服务部署，并提供日志捕获等运维接口。

## 仓库结构速览

- `main.go`：程序入口，注册版本子命令并启动 `coremain.Run()`。
- `coremain/`：命令行解析、配置加载（YAML）、服务生命周期管理、HTTP API（日志捕获）以及安装为系统服务的子命令。
- `plugin/`：内置插件集合，按职责划分为 `server`（TCP/UDP/QUIC 监听器）、`upstream`、`matcher`、`switch`、`mark`、`data_provider` 等子目录。
- `pkg/`：通用基础库，例如缓存实现（`cache`、`lru`、`concurrent_*`）、DNS 工具（`dnsutils`、`query_context`）、上游请求封装（`upstream`）、速率控制（`rate_limiter`）等。
- `mlog/`：项目使用的 zap 日志封装与动态级别控制。
- `tools/`、`scripts/`、`release.py`：辅助工具与发布脚本。

## 构建与运行

项目要求的 Go 版本为 `go1.25.3`（见 `go.mod`）。在仓库根目录执行以下命令即可编译主程序：

```bash
go build -o bin/mosdns .
```

常用运行方式：

- 前台启动：`./bin/mosdns start -c /path/to/config.yaml`
- 指定工作目录：`./bin/mosdns start -d /path/to/workdir -c config.yaml`
- 安装为系统服务：`./bin/mosdns service install -d /path/to/workdir -c /path/to/config.yaml`，随后可使用 `start`、`stop`、`restart`、`status` 等子命令管理。

## 配置要点

主配置使用 YAML 编写，对应 `coremain.Config`：

```yaml
log:        # 日志设置，见 mlog.LogConfig
include:    # 配置分片列表，按顺序加载
plugins:    # 插件链路，数组顺序即执行链路
  - tag: cache
    type: cache
    args: {...}
api:        # APIConfig，目前用于日志捕获 HTTP 服务地址
  http: ":8080"
```

- `include` 可拆分大型配置，便于复用。
- 每个 `plugins` 元素对应一个插件实例，`type` 映射到 `plugin/enabled_plugins.go` 注册的插件工厂，`args` 格式由插件定义。
- 若配置 `api.http`，程序将注册日志捕获接口：`POST /api/v1/capture/start`（启动日志抓取）与 `GET /api/v1/capture/logs`（读取抓取结果）。

## 插件与运行链路

插件按标签在运行时构建数据流，可实现：

- `server/*`：不同协议监听器，将 DNS 请求导入处理链。
- `upstream`：与上游 DNS（DoH/DoT/QUIC 等）通信。
- `matcher`、`switch`、`mark`：基于域名、IP 或自定义属性进行流量分流。
- `data_provider`：提供域名/IP 列表、hosts、nftables 集合等数据源。
- `cache`、`rate_limiter`、`executable` 等插件扩展缓存、速率控制或外部命令交互能力。

插件之间通过标签引用，形成灵活的处理拓扑。详细插件类型可参考 `plugin/enabled_plugins.go` 及各子目录文档。

## 日志与监控

- `mlog` 集成 zap，支持通过配置控制日志路径、级别与轮转策略。
- 当启用 HTTP API 时，可使用日志捕获功能进行临时调试，捕获时长默认 120 秒，可在请求体中自定义（1-600 秒）。
- 项目引入 `prometheus/client_golang`，相关指标由插件或核心组件暴露（如缓存命中率、请求计数等）。

## 测试与质量保障

仓库提供覆盖核心逻辑的单元测试，建议在提交前执行：

```bash
go test ./...
```

部分插件目录包含针对特定行为的测试（如 `plugin/enabled_plugin_test.go`），可用于验证配置解析与插件注册是否符合预期。

## 常见开发任务

- 新增插件：在 `plugin` 下创建目录，注册工厂方法到 `plugin/enabled_plugins.go`，并编写对应的配置解析与处理逻辑。
- 扩展 CLI：在 `coremain` 包内通过 `cobra.Command` 添加子命令，或使用 `coremain.AddSubCmd` 注册外部子命令。
- 发布流程：使用 `release.py` 生成预编译产物与校验信息，Docker 构建流程见 `Dockerfile` 与 `Dockerfile_buildx`。

## 进一步资料

更详细的使用手册、教程与示例可查阅项目 Wiki：https://irine-sistiana.gitbook.io/mosdns-wiki/

