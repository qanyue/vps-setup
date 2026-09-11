# vps-setup

Debian / Ubuntu VPS 初始化脚本。

版本：`v26.09.11`

支持：Debian 10 – 13、Ubuntu LTS 20.04、22.04、24.04、26.04。

## 一键执行

```bash
apt-get update -y && apt-get install -y curl && bash <(curl -fsSL https://raw.githubusercontent.com/yahuisme/vps-setup/main/install.sh)
```

默认安装 `sudo curl wget ca-certificates`，配置时间同步、BBR、Swap、DNS 和 Fail2ban。
主机名、时区及 SSH 设置默认保留；交互模式另行询问主机名、SSH 端口及 root 密码。
默认不执行系统升级和清理；非交互模式仍执行全部默认项目，并非只执行显式指定的选项。

Swap 默认 `auto`：内存不足 1024 MiB 时取内存整数 MiB，低于 4096 MiB 时取 2048 MiB，否则取 4096 MiB。
DNS 默认 IPv4 为 `1.1.1.1 / 8.8.8.8`，IPv6 为 `2606:4700:4700::1111 / 2001:4860:4860::8888`；仅检测到 IPv6 时配置 IPv6 DNS。

## 非交互执行

```bash
apt-get update -y && apt-get install -y curl && curl -fsSLo install.sh https://raw.githubusercontent.com/yahuisme/vps-setup/main/install.sh && chmod +x install.sh && ./install.sh --hostname "hostname" --timezone "Asia/Hong_Kong" --swap 1024 --bbr --ip-dns "94.140.14.14 1.1.1.1" --ip6-dns "2a10:50c0::ad1:ff 2606:4700:4700::1111" --ssh-port 12345 --fail2ban --non-interactive
```

## 参数

```text
--hostname <name>        设置主机名
--timezone <tz>          设置时区
--swap <auto|MB|0>       设置 Swap；0 表示禁用全部 Swap
--ip-dns "主DNS 备用DNS"  设置 IPv4 DNS
--ip6-dns "主DNS 备用DNS" 设置 IPv6 DNS
--bbr                    启用 BBR
--no-bbr                 切换拥塞控制为 cubic
--fail2ban               启用 Fail2ban，保护 SSH
--no-fail2ban            跳过 Fail2ban 配置（不停止已有服务）
--ssh-port <port>        设置 SSH 端口
--ssh-password <pass>    设置 root 密码
--upgrade                执行系统 full-upgrade
--cleanup                执行 autoremove 和 apt clean
--non-interactive        非交互模式
-h, --help               显示帮助
```

## 注意

- 仅支持完整 VPS / 虚拟机，不支持容器。
- 主机名仅接受字母、数字和连字符，首尾须为字母或数字；时区使用 `Asia/Hong_Kong` 等名称。DNS 参数须用引号包含两个对应版本的 IP 地址；SSH 端口为 1–65535 的整数，不带前导零。
- 更换 SSH 端口前先放行防火墙和安全组。其他配置存在冲突端口或未包含脚本配置时中止，不修改其他 SSH 文件。
- 修改后保留当前 SSH 连接，另开连接验证。
- `--ssh-password` 会暴露在 shell 历史和进程参数中，建议交互输入。
- `--swap 0` 禁用全部 Swap；指定容量与现有总量不一致时统一替换为 `/swapfile`。失败恢复旧文件、启动配置和活动状态。
- BBR、systemd-resolved 和 Fail2ban 应用或验证失败时恢复原配置；恢复失败会明确报告。
- Fail2ban 保护最终有效的全部 SSH 端口；`--no-fail2ban` 跳过本次配置，已有服务保持不变。
- Fail2ban 默认永久封禁：SSH 在 5 分钟内失败 3 次即封禁，仅豁免 `127.0.0.1/8` 和 `::1`。
- `/etc/resolv.conf` 由其他 DNS 管理器维护时跳过直接修改。
- 重启默认否，非交互模式不自动重启。
- 日志：`/var/log/vps-init-日期时间.log`。
