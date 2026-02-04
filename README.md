# vps-setup
提升 VPS 原版系统开箱使用便捷性设置脚本

脚本支持 Debian 10 -13 和 Ubuntu 20.04 - 24.04

## 功能特点
- 常用软件包自动安装
- 主机名交互配置
- 时区自动配置
- 检查并开启时间同步
- BBR 自动开启
- Swap 自动配置
- DNS 自动配置
- ssh 端口和密码配置
- Fail2ban 自动配置
- vim 编辑器优化配置
- 系统更新和清理

## 设置项说明
### install.sh
- SSH: 可选修改端口与 root 密码；不做额外硬化。
- Fail2ban: 安装并启用，默认保护 22 端口和自定义 SSH 端口。
- BBR: 写入 `/etc/sysctl.d/99-bbr.conf` 并应用。
- DNS: 优先配置 systemd-resolved，否则写入 `/etc/resolv.conf`。
- Swap: 创建或重建 `/swapfile`，支持 auto/自定义大小。
- 时间同步: 启用 systemd-timesyncd，不回退到 chrony。
- Vim: 写入 `/etc/vim/vimrc.local` 并在 root 下引用。
- UFW: 不做管理。

### init.sh
- SSH: 使用 drop-in 配置，禁用 root 登录；无公钥时保留密码登录；支持保留 22 端口。
- 防火墙: 禁用 UFW（如存在），生成 nftables 规则并启用。
- Fail2ban: 写入 `/etc/fail2ban/jail.d/99-sshd.local` 并启用。
- 用户: 创建用户、加入 sudo，可选免密 sudo。
- ZRAM/Swap: 配置 zram-tools；创建 `/swapfile` 并写入 `/etc/fstab`。
- 时间同步: 配置并启用 chrony，屏蔽 systemd-timesyncd。
- Docker: 可选安装，支持把用户加入 docker 组。

## 一键脚本
```
apt install curl -y && bash <(curl -fsSL https://raw.githubusercontent.com/yahuisme/vps-setup/main/install.sh)
```
运行一键脚本后依次配置：
1. 自动检查并安装 sudo wget zip vim 常用应用
2. 询问是否设置主机名
3. 自动检测并设置 VPS 所在时区
4. 自动检查并开启时间同步
5. 默认开启 BBR
6. 自动配置 Swap
7. 自动配置 DNS（默认 ipv4 1.1.1.1 8.8.8.8 ; ipv6 2606:4700:4700::1111 2001:4860:4860::8888）
8. 询问是否修改 ssh 端口和密码
9. 自动安装并配置 Fail2ban，默认防护 22 和设置的其它 ssh 端口
10. 自动优化 vim 编辑器配置
11. 系统更新及清理

## 无交互自定义脚本
```
apt install curl -y && curl -o install.sh -fsSL https://raw.githubusercontent.com/yahuisme/vps-setup/main/install.sh && chmod +x install.sh && ./install.sh --hostname "hostname" --timezone "Asia/Hong_Kong" --swap "1024" --bbr-optimized --ip-dns "94.140.14.14 1.1.1.1" --ip6-dns "2a10:50c0::ad1:ff 2606:4700:4700::1111" --ssh-port 12345 --ssh-password 'woshimima' --fail2ban 12345 --non-interactive
```
运行无交互自定义脚本后依次配置：
1. 自动检查并安装 sudo wget zip vim 常用应用
2. 自动配置自定义主机名
3. 自动配置自定义时区
4. 自动检查并开启时间同步
5. 自动配置自定义 Swap
6. 默认开启 BBR 并根据 VPS 配置智能优化 TCP 网络参数
7. 自动配置自定义 DNS
8. 自动配置自定义 ssh 端口和 ssh 密码
9. 自动安装并配置 Fail2ban，防护 22 端口和自定义 ssh 端口
10. 自动优化 vim 编辑器配置
11. 系统更新及清理

## 配合 bin456789 一键 DD 脚本

https://github.com/bin456789/reinstall


一键 DD 脚本
```
curl -O https://raw.githubusercontent.com/bin456789/reinstall/main/reinstall.sh && bash reinstall.sh debian 13 --ssh-port 12345 --password woshimima && reboot
```

DD脚本的系统版本、 ssh 端口和 password 请自行修改
