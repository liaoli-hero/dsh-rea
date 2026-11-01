# dsh-rea

非官方 DeepSeek Harness 插件，为 [REA](https://github.com/morluto/rea) 提供按需调用的桥接。它注册 `rea_list`、`rea_cli` 和 `rea_tool` 三个工具，以便在会话中发现并调用 REA 能力。

## 前提

- DeepSeek Harness 及可用的 Node.js。
- 单独安装 `rea-agents`；本插件不包含 REA 引擎。有关安装和支持范围请参阅 [REA 项目](https://github.com/morluto/rea)。
- 插件目前声明与 `@deepseek-ai/dsh-tools` 0.2.1-rc.5 和 `@deepseek-ai/schemastery` 3.18.5 的兼容关系。其他版本尚未验证。

## 安装

```sh
dsh plugin --profile <profile> add github:liaoli-hero/dsh-rea
```

插件默认查找常见全局安装位置的 `rea-agents/scripts/rea.mjs`；如果找不到，请在插件配置中将 `reaEntry` 指向该文件的绝对路径。必要时使用 `nodePath` 指定 Node 可执行文件。

## 使用与限制

`rea_list` 发现能力，`rea_cli` 运行 REA 命令，`rea_tool` 按需调用 REA MCP 工具。可用功能取决于本机的 REA 版本、依赖及目标环境；部分操作会修改目标设备或文件，请先查看具体工具的作用。本仓库仅提供桥接，实际安装和跨平台兼容性尚未完成独立验收。

`package.json` 标注 MIT；REA 自身的许可与使用条件请以其上游项目为准。
