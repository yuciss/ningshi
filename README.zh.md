[English](README.md)

# 凝时

**版本 0.3.0**

凝时（Ningshi）是一个 KernelSU 模块。它可以帮你少刷手机，或者防止应用偷跑。

## 特色

- **启动即拦截。** 应用代码执行前就被停止。
- **规则设定。** 总是开启、锁屏封禁、时间段、时长上限 + 冷却期；支持单应用与共用计时池分组。
- **WebUI 配置。** 在网页内完成全部配置。
- **零残留。** 卸载不留任何痕迹。

## 环境要求

- KernelSU，arm64 设备
- 内核开启 kprobe，`/proc/kallsyms` 中存在 `binder_transaction` 符号

## 开发指南

### 目录结构

```
.
├── module/                 # 可刷入的模块内容（打包即压缩此目录）
│   ├── module.prop
│   ├── customize.sh        # 安装时检查（架构 + 符号）
│   ├── service.sh          # 开机 watchdog 拉起 daemon
│   ├── uninstall.sh        # 卸载时杀掉 daemon
│   ├── bin/                # 编译产物 ningshi（构建时复制进来）
│   └── webroot/            # KernelSU WebUI
│       ├── index.html
│       └── config.json
├── daemon/                 # 核心程序（Rust daemon + eBPF）
│   ├── src/                # 引擎、门钩、检测、socket 等
│   ├── bpf/gate.bpf.c      # kprobe / kretprobe 钩子
│   ├── build.sh            # 编译 BPF + 交叉编译 daemon
│   └── rules.example.json  # 规则示例
└── scripts/package.sh      # 一键编译 + 打包
```

### 构建

依赖 `clang`（编译 BPF）、Rust 工具链与 `aarch64-unknown-linux-musl` target、`cargo-zigbuild`。

```bash
cd daemon
./build.sh
# 产物：target/aarch64-unknown-linux-musl/release/ningshi
```

### 打包

`scripts/package.sh` 一键完成：编译 daemon → 把二进制放进 `module/bin/` → 把 `module/` 压缩成 `ningshi-vX.Y.Z.zip`（`module.prop` 位于 zip 根目录；打包还需 `zip` 命令）。

### 设备调试

```bash
adb push module/bin/ningshi /data/local/tmp/
adb shell su -c 'pkill ningshi; sleep 1; cp /data/local/tmp/ningshi /data/adb/modules/ningshi/bin/ningshi && chmod 755 /data/adb/modules/ningshi/bin/ningshi'
# watchdog 5 秒后自动拉起新二进制
```

daemon 自带 CLI：

```bash
ningshi status                       # 状态 JSON（封禁 uid / 用量 / 拦截计数）
ningshi reload                       # 重载 rules.json
ningshi extension <key> <minutes>    # 临时延时
ningshi version
ningshi clear_log
```

### 规则文件

`/data/adb/ningshi/rules.json` 是 WebUI 与 daemon 共用的唯一数据契约，字段见 `daemon/rules.example.json`；解析时未知字段会被忽略，便于向前兼容。

### 关键设计

- **拦截**：kprobe 在 `binder_transaction` 入口按 uid 判黑，第一个 handle≠0 的事务（`attachApplication`）标记 tgid，kretprobe 返回时发 `SIGKILL`。
- **检测**：前台 / 屏状态 / 包名→uid 全部读内核文件系统（cpuset / DRM / `packages.list`）。
- **失败方向**：所有检测失败时一律放行。周期性清扫兜底门钩漏掉的残留进程。
