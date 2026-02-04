#!/usr/bin/env bash

set -Eeuo pipefail
IFS=$'\n\t'
umask 022

# ============================================================
# 0. 预检与配置 (交互式/可配置)
# ============================================================

if [[ -t 1 ]]; then
  RED=$'\033[0;31m'
  GREEN=$'\033[0;32m'
  YELLOW=$'\033[0;33m'
  CYAN=$'\033[0;36m'
  NC=$'\033[0m'
else
  RED=""
  GREEN=""
  YELLOW=""
  CYAN=""
  NC=""
fi

log()  { printf '%b\n' "${GREEN}$*${NC}"; }
warn() { printf '%b\n' "${YELLOW}$*${NC}" >&2; }
err()  { printf '%b\n' "${RED}$*${NC}" >&2; }

die() {
  err "错误：$*"
  exit 1
}

on_err() {
  err "发生错误 (行 $1): $2"
  err "已中止，请检查输出并修正后重试。"
}
trap 'on_err $LINENO "$BASH_COMMAND"' ERR

usage() {
  cat <<'EOF'
用法: sudo ./vps_init.sh [选项]

选项:
  --user <name>           新建或复用用户名
  --port <number>         SSH 端口
  --github <user>         GitHub 用户名(自动导入公钥)
  --pubkey <key>          直接粘贴公钥字符串
  --timezone <tz>         时区(如 UTC, Asia/Shanghai)
  --swap <mb>             Swap 大小(MB)，0 表示跳过
  --zram <percent>        ZRAM 占用内存百分比，0 表示跳过
  --upgrade | --no-upgrade
  --install-docker | --no-docker
  --keep-ssh22 | --drop-ssh22
  --allow-http | --no-http
  --extra-ports <list>    额外开放端口(逗号分隔，如 "8080,8443")
  --non-interactive       禁用交互，使用默认/参数值
  -y, --yes               自动确认(接受默认选择)
  -h, --help              显示帮助

可通过环境变量覆盖默认值:
  CFG_USER CFG_SSH_PORT CFG_GITHUB_USER CFG_PUBKEY CFG_TIMEZONE
  CFG_SWAP_SIZE_MB CFG_ZRAM_PERCENT CFG_FULL_UPGRADE CFG_INSTALL_DOCKER
  CFG_KEEP_SSH22 CFG_ALLOW_HTTP CFG_EXTRA_TCP_PORTS CFG_SUDO_NOPASSWD
  CFG_DOCKER_GROUP NON_INTERACTIVE AUTO_YES
EOF
}

require_root() {
  if [[ ${EUID} -ne 0 ]]; then
    err "此脚本必须以 root 权限运行。"
    err "请使用: sudo $0"
    exit 1
  fi
}

check_platform() {
  if ! command -v apt-get >/dev/null 2>&1; then
    die "未找到 apt-get，仅支持 Debian/Ubuntu 系统。"
  fi
  if ! command -v systemctl >/dev/null 2>&1; then
    die "未找到 systemctl，请确保系统使用 systemd。"
  fi
}

ask_yes_no() {
  local prompt="$1" default="${2:-no}" reply=""
  if [[ ${AUTO_YES} -eq 1 || ${NON_INTERACTIVE} -eq 1 ]]; then
    [[ "${default}" == "yes" ]] && return 0 || return 1
  fi
  while true; do
    if [[ "${default}" == "yes" ]]; then
      printf '%b' "${prompt} [Y/n]: "
    else
      printf '%b' "${prompt} [y/N]: "
    fi
    read -r reply
    reply=${reply:-$default}
    case "${reply}" in
      y|Y|yes|YES) return 0 ;;
      n|N|no|NO) return 1 ;;
      *) echo "请输入 y 或 n" ;;
    esac
  done
}

prompt_value() {
  local var="$1" prompt="$2"
  local input=""
  if [[ ${NON_INTERACTIVE} -eq 1 ]]; then
    return 0
  fi
  printf '%b' "${prompt}"
  read -r input
  if [[ -n "${input}" ]]; then
    printf -v "${var}" '%s' "${input}"
  fi
}

init_defaults() {
  local current_tz=""
  current_tz=$(timedatectl show -p Timezone --value 2>/dev/null || true)
  current_tz=${current_tz:-UTC}

  CFG_USER="${CFG_USER:-${SUDO_USER:-$(whoami)}}"
  if [[ "${CFG_USER}" == "root" || -z "${CFG_USER}" ]]; then
    CFG_USER="admin"
  fi
  CFG_SSH_PORT="${CFG_SSH_PORT:-22}"
  CFG_GITHUB_USER="${CFG_GITHUB_USER:-}"
  CFG_PUBKEY="${CFG_PUBKEY:-}"
  CFG_TIMEZONE="${CFG_TIMEZONE:-$current_tz}"
  CFG_SWAP_SIZE_MB="${CFG_SWAP_SIZE_MB:-2048}"
  CFG_ZRAM_PERCENT="${CFG_ZRAM_PERCENT:-70}"
  CFG_FULL_UPGRADE="${CFG_FULL_UPGRADE:-no}"
  CFG_INSTALL_DOCKER="${CFG_INSTALL_DOCKER:-no}"
  CFG_KEEP_SSH22="${CFG_KEEP_SSH22:-yes}"
  CFG_ALLOW_HTTP="${CFG_ALLOW_HTTP:-yes}"
  CFG_EXTRA_TCP_PORTS="${CFG_EXTRA_TCP_PORTS:-}"
  CFG_SUDO_NOPASSWD="${CFG_SUDO_NOPASSWD:-no}"
  CFG_DOCKER_GROUP="${CFG_DOCKER_GROUP:-no}"

  NON_INTERACTIVE="${NON_INTERACTIVE:-0}"
  AUTO_YES="${AUTO_YES:-0}"
}

parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --user) CFG_USER="$2"; shift 2 ;;
      --port) CFG_SSH_PORT="$2"; shift 2 ;;
      --github) CFG_GITHUB_USER="$2"; shift 2 ;;
      --pubkey) CFG_PUBKEY="$2"; shift 2 ;;
      --timezone) CFG_TIMEZONE="$2"; shift 2 ;;
      --swap) CFG_SWAP_SIZE_MB="$2"; shift 2 ;;
      --zram) CFG_ZRAM_PERCENT="$2"; shift 2 ;;
      --upgrade) CFG_FULL_UPGRADE="yes"; shift ;;
      --no-upgrade) CFG_FULL_UPGRADE="no"; shift ;;
      --install-docker) CFG_INSTALL_DOCKER="yes"; shift ;;
      --no-docker) CFG_INSTALL_DOCKER="no"; shift ;;
      --keep-ssh22) CFG_KEEP_SSH22="yes"; shift ;;
      --drop-ssh22) CFG_KEEP_SSH22="no"; shift ;;
      --allow-http) CFG_ALLOW_HTTP="yes"; shift ;;
      --no-http) CFG_ALLOW_HTTP="no"; shift ;;
      --extra-ports) CFG_EXTRA_TCP_PORTS="$2"; shift 2 ;;
      --non-interactive) NON_INTERACTIVE=1; shift ;;
      -y|--yes) AUTO_YES=1; shift ;;
      -h|--help) usage; exit 0 ;;
      *) die "未知参数: $1" ;;
    esac
  done
}

validate_config() {
  if [[ ! "${CFG_USER}" =~ ^[a-z_][a-z0-9_-]*$ ]]; then
    die "用户名不合法: ${CFG_USER}"
  fi
  if [[ "${CFG_USER}" == "root" ]]; then
    die "用户名不能为 root"
  fi
  if [[ ! "${CFG_SSH_PORT}" =~ ^[0-9]+$ || "${CFG_SSH_PORT}" -lt 1 || "${CFG_SSH_PORT}" -gt 65535 ]]; then
    die "SSH 端口必须为 1-65535 的数字"
  fi
  if [[ ! "${CFG_SWAP_SIZE_MB}" =~ ^[0-9]+$ ]]; then
    die "SWAP 大小必须为数字"
  fi
  if [[ ! "${CFG_ZRAM_PERCENT}" =~ ^[0-9]+$ || "${CFG_ZRAM_PERCENT}" -gt 100 ]]; then
    die "ZRAM 百分比必须为 0-100"
  fi
}

fetch_pubkeys() {
  if [[ -n "${CFG_PUBKEY}" ]]; then
    printf '%s\n' "${CFG_PUBKEY}"
    return 0
  fi
  if [[ -n "${CFG_GITHUB_USER}" ]]; then
    curl -fsSL "https://github.com/${CFG_GITHUB_USER}.keys"
    return 0
  fi
  return 1
}

ensure_ssh_include() {
  local ssh_cfg="/etc/ssh/sshd_config"
  local include_line='Include /etc/ssh/sshd_config.d/*.conf'
  if ! grep -qE '^[[:space:]]*Include[[:space:]]+/etc/ssh/sshd_config\.d/\*\.conf' "${ssh_cfg}"; then
    cp "${ssh_cfg}" "${ssh_cfg}.bak.$(date +%F_%H%M%S)"
    printf '%s\n%s\n' "${include_line}" "$(cat "${ssh_cfg}")" > "${ssh_cfg}"
  fi
  if grep -qE '^[[:space:]]*Port[[:space:]]+[0-9]+' "${ssh_cfg}"; then
    cp "${ssh_cfg}" "${ssh_cfg}.bak.$(date +%F_%H%M%S)"
    sed -i -E 's/^[[:space:]]*Port[[:space:]]+/# Port /' "${ssh_cfg}"
  fi
}

restart_ssh_service() {
  if systemctl list-unit-files | grep -q '^sshd\.service'; then
    systemctl restart sshd
  elif systemctl list-unit-files | grep -q '^ssh\.service'; then
    systemctl restart ssh
  else
    die "未找到 ssh/sshd 服务，无法重启"
  fi
}

install_packages() {
  log "[1/7] 更新系统并安装基础工具..."
  export DEBIAN_FRONTEND=noninteractive
  apt-get update
  if [[ "${CFG_FULL_UPGRADE}" == "yes" ]]; then
    apt-get -y upgrade
  fi

  local base_packages=(
    curl wget git unzip tmux tree vim sudo
    ca-certificates gnupg lsb-release apt-transport-https
    bind9-dnsutils zram-tools chrony fail2ban nftables
  )
  local optional_packages=(btop)

  apt-get install -y --no-install-recommends "${base_packages[@]}"
  if ! apt-get install -y --no-install-recommends "${optional_packages[@]}"; then
    warn "可选软件包安装失败（已跳过）：${optional_packages[*]}"
  fi
}

configure_user() {
  log "[2/7] 配置用户 ${CFG_USER}..."
  if id "${CFG_USER}" &>/dev/null; then
    echo "用户 ${CFG_USER} 已存在。"
  else
    useradd -m -s /bin/bash "${CFG_USER}"
    echo "用户 ${CFG_USER} 已创建。"
  fi

  usermod -aG sudo "${CFG_USER}"
  if [[ "${CFG_SUDO_NOPASSWD}" == "yes" ]]; then
    local sudoers_file="/etc/sudoers.d/90-${CFG_USER}-nopasswd"
    printf '%s ALL=(ALL) NOPASSWD:ALL\n' "${CFG_USER}" > "${sudoers_file}"
    chmod 440 "${sudoers_file}"
    visudo -c -f "${sudoers_file}"
  fi

  local user_home=""
  user_home=$(getent passwd "${CFG_USER}" | cut -d: -f6)
  [[ -n "${user_home}" ]] || die "无法获取用户家目录"

  install -d -m 700 -o "${CFG_USER}" -g "${CFG_USER}" "${user_home}/.ssh"
  local auth_keys="${user_home}/.ssh/authorized_keys"
  if [[ ! -f "${auth_keys}" ]]; then
    install -m 600 -o "${CFG_USER}" -g "${CFG_USER}" /dev/null "${auth_keys}"
  fi

  local has_keys="no"
  if [[ -s "${auth_keys}" ]]; then
    has_keys="yes"
  fi

  if pubkeys="$(fetch_pubkeys 2>/dev/null)"; then
    local tmp_keys tmp_filtered
    tmp_keys=$(mktemp)
    tmp_filtered=$(mktemp)
    printf '%s\n' "${pubkeys}" > "${tmp_keys}"
    grep -E '^(ssh-|ecdsa-|sk-)' "${tmp_keys}" > "${tmp_filtered}" || true
    if [[ -s "${tmp_filtered}" ]]; then
      cat "${auth_keys}" "${tmp_filtered}" | awk 'NF && !seen[$0]++' > "${auth_keys}.new"
      mv "${auth_keys}.new" "${auth_keys}"
      has_keys="yes"
      echo "已添加 SSH 公钥。"
    else
      warn "未获取到有效的公钥，请检查 GitHub 用户名或公钥内容。"
    fi
    rm -f "${tmp_keys}" "${tmp_filtered}"
  fi

  chown "${CFG_USER}:${CFG_USER}" "${auth_keys}"
  chmod 600 "${auth_keys}"

  SSH_HAS_KEYS="${has_keys}"
}

configure_ssh() {
  log "[3/7] 优化 SSH 配置 (端口: ${CFG_SSH_PORT})..."
  ensure_ssh_include
  install -d -m 755 /etc/ssh/sshd_config.d

  local ssh_dropin="/etc/ssh/sshd_config.d/99-hardening.conf"
  local ports="Port ${CFG_SSH_PORT}"
  if [[ "${CFG_KEEP_SSH22}" == "yes" && "${CFG_SSH_PORT}" != "22" ]]; then
    ports=$'Port 22\n'"${ports}"
  fi

  local pass_auth="no"
  if [[ "${SSH_HAS_KEYS}" != "yes" ]]; then
    pass_auth="yes"
    warn "未检测到有效 SSH 公钥，将保持密码登录启用以防锁死。"
  fi

  cat > "${ssh_dropin}" <<EOF
# Managed by vps_init.sh
${ports}
PermitRootLogin no
PasswordAuthentication ${pass_auth}
PubkeyAuthentication yes
KbdInteractiveAuthentication no
UsePAM yes
X11Forwarding no
ClientAliveInterval 60
ClientAliveCountMax 5
UseDNS no
LoginGraceTime 1m
StrictModes yes
PermitEmptyPasswords no
EOF

  sshd -t
  restart_ssh_service
  echo "SSH 服务已重启。"
}

configure_zram_swap_sysctl() {
  log "[4/7] 配置 ZRAM、Swap 与内核参数..."

  if [[ "${CFG_ZRAM_PERCENT}" -gt 0 ]]; then
    cat <<EOF > /etc/default/zramswap
ALGO=zstd
PERCENT=${CFG_ZRAM_PERCENT}
PRIORITY=100
EOF
    systemctl enable --now zramswap
  else
    systemctl disable --now zramswap || true
  fi

  if [[ "${CFG_SWAP_SIZE_MB}" -gt 0 ]]; then
    if ! swapon --show=NAME | grep -q '^/swapfile$'; then
      if [[ ! -f /swapfile ]]; then
        if command -v fallocate >/dev/null 2>&1; then
          fallocate -l "${CFG_SWAP_SIZE_MB}M" /swapfile
        else
          dd if=/dev/zero of=/swapfile bs=1M count="${CFG_SWAP_SIZE_MB}" status=progress
        fi
        chmod 600 /swapfile
      fi
      if ! file -s /swapfile | grep -q 'swap file'; then
        mkswap /swapfile
      fi
      swapon --priority -2 /swapfile
    fi
    grep -q '^/swapfile ' /etc/fstab || echo '/swapfile none swap sw,pri=-2 0 0' >> /etc/fstab
  else
    warn "Swap 已跳过 (SWAP_SIZE=0)"
  fi

  local sysctl_dropin="/etc/sysctl.d/99-vps-init.conf"
  cat <<EOF > "${sysctl_dropin}"
vm.swappiness=60
vm.vfs_cache_pressure=50
EOF
  sysctl --system

  systemctl enable --now fstrim.timer
}

configure_time() {
  log "[5/7] 配置时间同步..."
  if [[ -n "${CFG_TIMEZONE}" ]]; then
    timedatectl set-timezone "${CFG_TIMEZONE}"
  fi

  local chrony_conf="/etc/chrony/chrony.conf"
  if ! grep -q '^# BEGIN VPS_INIT$' "${chrony_conf}"; then
    cat <<EOF >> "${chrony_conf}"
# BEGIN VPS_INIT
server time.cloudflare.com iburst
server time.google.com iburst
server time.facebook.com iburst
# END VPS_INIT
EOF
  fi
  systemctl mask systemd-timesyncd.service >/dev/null 2>&1 || true
  systemctl enable --now chrony
}

install_docker() {
  if [[ "${CFG_INSTALL_DOCKER}" != "yes" ]]; then
    return 0
  fi

  log "安装 Docker (官方脚本)..."
  if command -v docker >/dev/null 2>&1; then
    echo "Docker 已安装，跳过。"
    return 0
  fi

  curl -fsSL https://get.docker.com | sh

  if [[ "${CFG_DOCKER_GROUP}" == "yes" ]]; then
    usermod -aG docker "${CFG_USER}"
  fi
}

configure_firewall() {
  log "[6/7] 配置 nftables 防火墙..."

  if command -v ufw >/dev/null 2>&1; then
    ufw disable || true
  fi

  local ports=()
  if [[ "${CFG_KEEP_SSH22}" == "yes" ]]; then
    ports+=(22)
  fi
  ports+=("${CFG_SSH_PORT}")
  if [[ "${CFG_ALLOW_HTTP}" == "yes" ]]; then
    ports+=(80 443)
  fi
  if [[ -n "${CFG_EXTRA_TCP_PORTS}" ]]; then
    IFS=',' read -r -a extra_ports <<< "${CFG_EXTRA_TCP_PORTS}"
    for p in "${extra_ports[@]}"; do
      p="${p//[[:space:]]/}"
      [[ -n "${p}" ]] || continue
      if [[ ! "${p}" =~ ^[0-9]+$ || "${p}" -lt 1 || "${p}" -gt 65535 ]]; then
        die "额外端口不合法: ${p}"
      fi
      ports+=("${p}")
    done
  fi

  local port_list=""
  port_list=$(printf '%s\n' "${ports[@]}" | awk '!seen[$0]++' | paste -sd', ' -)

  if [[ -f /etc/nftables.conf ]]; then
    cp -a /etc/nftables.conf /etc/nftables.conf.bak.$(date +%F_%H%M%S)
  fi

  cat <<EOF > /etc/nftables.conf
#!/usr/sbin/nft -f
flush ruleset
table inet filter {
    chain input {
        type filter hook input priority filter; policy drop;
        ct state established, related accept
        ct state invalid drop
        iif "lo" accept
        ip protocol icmp limit rate 4/second accept
        ip6 nexthdr icmpv6 icmpv6 type { nd-neighbor-solicit, nd-neighbor-advert, nd-router-advert } accept
        ip6 nexthdr icmpv6 icmpv6 type echo-request limit rate 4/second accept

        tcp dport { ${port_list} } accept
    }

    chain forward {
        type filter hook forward priority filter; policy drop;
        ct state established, related accept
        iifname "docker0" accept
        iifname "br-*" accept
    }

    chain output {
        type filter hook output priority filter; policy accept;
    }
}
EOF

  nft -c -f /etc/nftables.conf
  systemctl enable --now nftables
  nft -f /etc/nftables.conf
}

configure_fail2ban() {
  log "[7/7] 配置 Fail2ban..."
  local ports=("${CFG_SSH_PORT}")
  if [[ "${CFG_KEEP_SSH22}" == "yes" && "${CFG_SSH_PORT}" != "22" ]]; then
    ports+=(22)
  fi
  local port_list=""
  port_list=$(printf '%s\n' "${ports[@]}" | awk '!seen[$0]++' | paste -sd', ' -)

  cat <<EOF > /etc/fail2ban/jail.d/99-sshd.local
[DEFAULT]
ignoreip = 127.0.0.1/8 ::1
bantime  = 1d
findtime = 10m
maxretry = 3
banaction = nftables-multiport
banaction_allports = nftables-allports

[sshd]
enabled = true
port    = ${port_list}
backend = systemd
mode    = aggressive
EOF

  systemctl enable --now fail2ban
  systemctl restart fail2ban
}

interactive_config() {
  if [[ ! -t 0 ]]; then
    NON_INTERACTIVE=1
  fi

  if [[ ${NON_INTERACTIVE} -eq 1 ]]; then
    return 0
  fi

  log ">>> 初始化配置向导"

  prompt_value CFG_USER "请输入用户名 [默认: ${CYAN}${CFG_USER}${NC}]: "
  prompt_value CFG_SSH_PORT "请输入 SSH 端口 [默认: ${CYAN}${CFG_SSH_PORT}${NC}]: "
  prompt_value CFG_TIMEZONE "请输入时区 (推荐 UTC) [默认: ${CYAN}${CFG_TIMEZONE}${NC}]: "
  prompt_value CFG_SWAP_SIZE_MB "请输入 Swap 大小(MB, 0=跳过) [默认: ${CYAN}${CFG_SWAP_SIZE_MB}${NC}]: "
  prompt_value CFG_ZRAM_PERCENT "请输入 ZRAM 百分比(0-100) [默认: ${CYAN}${CFG_ZRAM_PERCENT}${NC}]: "

  if ask_yes_no "是否保留 22 端口(避免锁死)?" "yes"; then
    CFG_KEEP_SSH22="yes"
  else
    CFG_KEEP_SSH22="no"
  fi

  if ask_yes_no "是否执行 apt upgrade?" "no"; then
    CFG_FULL_UPGRADE="yes"
  else
    CFG_FULL_UPGRADE="no"
  fi

  if ask_yes_no "是否安装 Docker?" "no"; then
    CFG_INSTALL_DOCKER="yes"
  else
    CFG_INSTALL_DOCKER="no"
  fi

  if ask_yes_no "是否为用户配置免密 sudo?" "no"; then
    CFG_SUDO_NOPASSWD="yes"
  else
    CFG_SUDO_NOPASSWD="no"
  fi

  if ask_yes_no "是否开放 80/443 端口?" "yes"; then
    CFG_ALLOW_HTTP="yes"
  else
    CFG_ALLOW_HTTP="no"
  fi

  prompt_value CFG_EXTRA_TCP_PORTS "请输入额外开放端口(逗号分隔, 可留空): "

  if [[ -z "${CFG_GITHUB_USER}" && -z "${CFG_PUBKEY}" ]]; then
    echo -e "${CYAN}公钥导入方式:${NC}"
    echo "  1) GitHub 用户名"
    echo "  2) 直接粘贴公钥"
    echo "  3) 跳过(不推荐)"
    printf "请选择 [1/2/3]: "
    local choice=""
    read -r choice
    case "${choice}" in
      1) prompt_value CFG_GITHUB_USER "请输入 GitHub 用户名: " ;;
      2) prompt_value CFG_PUBKEY "请粘贴公钥: " ;;
      *) ;;
    esac
  fi

  echo ""
  log ">>> 配置确认"
  echo "用户名称: ${CFG_USER}"
  echo "SSH 端口: ${CFG_SSH_PORT} (保留22: ${CFG_KEEP_SSH22})"
  echo "时区设置: ${CFG_TIMEZONE}"
  echo "Swap: ${CFG_SWAP_SIZE_MB} MB"
  echo "ZRAM: ${CFG_ZRAM_PERCENT}%"
  echo "apt upgrade: ${CFG_FULL_UPGRADE}"
  echo "Docker: ${CFG_INSTALL_DOCKER}"
  echo "免密 sudo: ${CFG_SUDO_NOPASSWD}"
  echo "开放 80/443: ${CFG_ALLOW_HTTP}"
  echo "额外端口: ${CFG_EXTRA_TCP_PORTS:-无}"
  if [[ -n "${CFG_GITHUB_USER}" ]]; then
    echo "公钥来源: https://github.com/${CFG_GITHUB_USER}.keys"
  elif [[ -n "${CFG_PUBKEY}" ]]; then
    echo "公钥来源: 手动粘贴"
  else
    echo "公钥来源: 未提供"
  fi

  if ! ask_yes_no "配置是否正确，继续执行?" "yes"; then
    die "已取消。"
  fi
}

main() {
  require_root
  check_platform
  init_defaults
  parse_args "$@"
  interactive_config
  validate_config

  install_packages
  configure_user
  configure_ssh
  configure_zram_swap_sysctl
  configure_time
  install_docker
  configure_firewall
  configure_fail2ban

  log "=============================================="
  log "初始化完成！"
  printf '用户: %s\n' "${CFG_USER}"
  printf 'SSH 端口: %s\n' "${CFG_SSH_PORT}"
  printf '建议新开终端测试: ssh -p %s %s@<服务器IP>\n' "${CFG_SSH_PORT}" "${CFG_USER}"
  if [[ "${CFG_KEEP_SSH22}" == "yes" && "${CFG_SSH_PORT}" != "22" ]]; then
    warn "提示：当前仍保留 22 端口，确认新端口可用后再关闭。"
  fi
  if [[ "${SSH_HAS_KEYS}" != "yes" ]]; then
    warn "提示：未配置公钥，已保持密码登录启用。请尽快添加公钥后再关闭密码登录。"
  fi
  log "=============================================="
}

main "$@"

