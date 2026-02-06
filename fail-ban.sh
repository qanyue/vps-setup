#!/bin/bash

# ==============================================================================
# 安全加固脚本: 安装 Fail2ban + 禁用 SSH 密码登录
# ==============================================================================
set -euo pipefail

# --- 颜色定义 ---
readonly GREEN='\033[0;32m'
readonly RED='\033[0;31m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly NC='\033[0m'

# --- 权限检查 ---
if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}[ERROR] 请使用 sudo 或 root 权限运行此脚本。${NC}"
   exit 1
fi

log_info() { echo -e "${BLUE}[INFO] $1${NC}"; }
log_success() { echo -e "${GREEN}[OK] $1${NC}"; }
log_warn() { echo -e "${YELLOW}[WARN] $1${NC}"; }

# --- 核心功能：安装 Fail2ban ---
install_fail2ban() {
    log_info "1. 开始安装 Fail2ban..."
    
    export DEBIAN_FRONTEND=noninteractive
    if ! command -v fail2ban-client &>/dev/null; then
        apt-get update -qq
        apt-get install -y fail2ban -qq
    else
        log_info "Fail2ban 已安装，跳过安装步骤。"
    fi

    # 检测 SSH 端口
    local ssh_port="22"
    if [[ -f /etc/ssh/sshd_config ]]; then
        local config_port
        config_port=$(grep -oP '^\s*Port\s+\K\d+' /etc/ssh/sshd_config | tail -n1)
        [[ -n "$config_port" ]] && ssh_port="$config_port"
    fi
    log_info "当前 SSH 端口: $ssh_port"

    # 写入配置
    cat > /etc/fail2ban/jail.local << EOF
[DEFAULT]
bantime = -1
findtime = 300
maxretry = 3
backend = systemd
ignoreip = 127.0.0.1/8 ::1

[sshd]
enabled = true
port = $ssh_port
maxretry = 3
EOF

    systemctl unmask fail2ban >/dev/null 2>&1 || true
    systemctl enable fail2ban
    systemctl restart fail2ban
    log_success "Fail2ban 配置完成。"
}

# --- 核心功能：禁用 SSH 密码登录 ---
disable_password_auth() {
    log_info "2. 准备禁用 SSH 密码登录..."

    local ssh_config="/etc/ssh/sshd_config"
    
    # [安全检查] 检查是否存在 authorized_keys 文件
    # 简单的检查：root 目录或当前 sudo 用户目录下是否有 key
    local key_found=false
    if [[ -s /root/.ssh/authorized_keys ]]; then
        key_found=true
    elif [[ -n "${SUDO_USER:-}" ]] && [[ -s "/home/$SUDO_USER/.ssh/authorized_keys" ]]; then
        key_found=true
    fi

    if [[ "$key_found" = false ]]; then
        echo -e "${RED}======================================================${NC}"
        echo -e "${RED}[危险] 未检测到常见路径下的 SSH 密钥 (authorized_keys)！${NC}"
        echo -e "${RED}如果禁用了密码登录且没有密钥，你将被踢出服务器。${NC}"
        echo -e "${RED}======================================================${NC}"
        read -p "你确定你已经配置好密钥了吗？输入 'yes' 强制继续，其他键取消: " confirm
        if [[ "$confirm" != "yes" ]]; then
            log_warn "已取消禁用密码登录的操作。"
            return
        fi
    fi

    # 备份配置文件
    cp "$ssh_config" "${ssh_config}.bak.$(date +%F_%T)"
    log_info "已备份 SSH 配置文件。"

    # 修改配置
    # 1. 禁用 PasswordAuthentication
    if grep -q "^PasswordAuthentication" "$ssh_config"; then
        sed -i 's/^PasswordAuthentication.*/PasswordAuthentication no/' "$ssh_config"
    else
        echo "PasswordAuthentication no" >> "$ssh_config"
    fi

    # 2. 禁用 ChallengeResponseAuthentication (部分系统也用于密码验证)
    if grep -q "^ChallengeResponseAuthentication" "$ssh_config"; then
        sed -i 's/^ChallengeResponseAuthentication.*/ChallengeResponseAuthentication no/' "$ssh_config"
    else
        echo "ChallengeResponseAuthentication no" >> "$ssh_config"
    fi
    
    # 3. 确保 PubkeyAuthentication 开启
    if grep -q "^PubkeyAuthentication" "$ssh_config"; then
        sed -i 's/^PubkeyAuthentication.*/PubkeyAuthentication yes/' "$ssh_config"
    else
        echo "PubkeyAuthentication yes" >> "$ssh_config"
    fi

    # 测试并重启 SSH
    if sshd -t; then
        systemctl restart sshd
        log_success "SSH 密码登录已禁用 (PasswordAuthentication no)。"
    else
        log_error "SSH 配置文件校验失败，已还原备份。请手动检查。"
        cp "${ssh_config}.bak.$(date +%F_%T)" "$ssh_config"
        systemctl restart sshd
    fi
}

# --- 执行 ---
main() {
    install_fail2ban
    
    echo -e "\n------------------------------------------------"
    echo -e "${YELLOW}即将禁用 SSH 密码登录。请确认你已拥有 SSH 密钥！${NC}"
    echo -e "------------------------------------------------"
    # 如果你想全自动运行不询问，可以注释掉下面这行 read
    read -p "是否禁用密码登录？[y/N] " -r
    if [[ "$REPLY" =~ ^[Yy]$ ]]; then
        disable_password_auth
    else
        log_info "跳过禁用密码登录步骤。"
    fi

    echo -e "\n${GREEN}所有任务完成！${NC}"
}

main
