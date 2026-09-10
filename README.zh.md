[English](README.md)

# 凝时

**版本 0.4.3**

凝时（Ningshi）是一个 KernelSU 模块。它可以帮你少刷手机，或者防止应用偷跑。

## 特色

- **启动即拦截。** 应用代码执行前就被停止。
- **规则设定。** 总是开启、锁屏封禁、时间段（可按星期）、时长上限 + 冷却期；支持单应用与共用计时池分组。
- **WebUI 配置。** 在网页内完成全部配置。

## 用法

每个应用（或组）可以组合四种规则：

- **总是开启** —— 一直封禁。
- **锁屏封禁** —— 屏幕关闭时封禁。
- **时间段** —— 选择时段与星期。时间段默认的含义是「仅窗内可用」，想要反过来（窗内禁止）就把策略切到*窗内禁止*。不选任何星期 = 每天。跨午夜的时间段归属于它开始的那一天（周一 22:00-07:00 覆盖周一夜里到周二早上）。
- **时长** —— 限制使用时长；用完后第二天重置，或进入**冷却期**封禁，冷却结束后自动重置。

**+5 / +20** 按钮是临时**延时**（每日封顶），真要用的时候可以临时放行。

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
adb shell su -c 'pkill -9 ningshi; sleep 1; cp /data/local/tmp/ningshi /data/adb/modules/ningshi/bin/ningshi && chmod 755 /data/adb/modules/ningshi/bin/ningshi'
# watchdog 5 秒后自动拉起新二进制
```

daemon 自带 CLI：

```bash
ningshi status                       # 状态 JSON（封禁 uid / 用量 / 拦截计数 / 门钩健康）
ningshi reload                       # 重载 rules.json
ningshi apply <文件>                 # 校验规则文件后再替换线上配置
ningshi extension <key> <minutes>    # 临时延时
ningshi version
ningshi clear_log
```

### 规则文件

`/data/adb/ningshi/rules.json` 是 WebUI 与 daemon 共用的唯一数据契约，字段见 `daemon/rules.example.json`；解析时未知字段会被忽略，便于向前兼容。

写入一律走 `ningshi apply`：daemon 先解析候选文件、确认没问题才替换线上文件，所以一次错误写入不可能让模块失去防护。最后一次解析成功的副本保留在 `rules.json.ok`，当线上文件读不出来时会回退到它（并在日志里明说）。声明了更高 schema 版本的文件会被拒绝，而不是按旧字段误读。

### 关键设计

- **拦截**：两个互相独立的内核锚点，任意一个可用即可工作；具体挂哪个符号由**探测当前内核实际有什么**决定（结果见 `status.gate.uid_switch_symbol`）。`commit_creds` 的 kretprobe 负责"进程刚切到被封 uid"——Linux 里任何一次身份切换都必经它，不管 Android 用哪个系统调用或命名空间机制，挂不上时回退到生成的 `__arm64_sys_setresuid` 包装；`binder_transaction` 的 kprobe/kretprobe 负责"新进程的第一个 handle≠0 事务"。用户态 killer 等到进程成为前台（`oom_score_adj == 0`，即 attach 握手完成）后，经 pidfd 发送 `SIGKILL`——被回收的 pid 无法让击杀落错目标；发送前还会再核对一次封禁名单，因为内核侧的标记可能比规则活得更久。
- **身份**：内核只回答"某个被封 uid 的进程出现了"。发信号前，killer 会读该进程自己的 `/proc/<pid>/cmdline`，要求它确实带着用户封禁的那个包名——这个名字是进程自己被赋予的，而不是从系统文件里读出来的。于是 `/data/system/packages.list` 只承担"uid 查表"，永远不是"这个进程是谁"的裁判：被新装应用回收的 uid 不可能被误杀（这类跳过计入 `status.gate.identity_skipped`）。
- **检测**：前台 / 屏状态 / 包名→uid 全部读内核文件系统（cpuset / DRM / `packages.list`）；pid 的 uid 直接取 `/proc/<pid>` 的属主（一次 stat，而不是解析每个进程的 status 文件；已在设备上逐进程核对一致）。
- **自适应调度**：daemon 只睡到"下一个可能发生变化"的时刻——下一个时间窗边界、延时/冷却到期、本地零点，或在有封禁项时的 60 秒清扫周期。没有任何时间相关规则时进入约 5 分钟的静默睡眠，而且 `/data/system` 里除 `packages.list` 之外的事件一律忽略。启动拦截发生在内核里，所以睡久一点不会削弱拦截。
- **单实例**：daemon 持有 flock，发现已有实例在跑就直接退出；两个实例会挂上两套钩子、两张互相覆盖的封禁表。
- **失败方向**：所有检测失败时一律放行。周期性清扫兜底门钩漏掉的残留进程。
- **健康可见**：`status.gate` 报告哪些锚点挂上了，以及内核侧计数（标记数、事件数、ringbuf 丢弃、跳过的击杀）；`rules_source` 说明当前规则来自线上文件、回退副本还是内置默认值。
