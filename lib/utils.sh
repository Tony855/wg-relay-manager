#!/bin/bash

# ===========================================
# 公共工具函数库
# ===========================================

# 防止重复加载
[ -n "${UTILS_LOADED:-}" ] && return
UTILS_LOADED=1

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
NC='\033[0m' # No Color

# 全局配置
CONFIG_DIR="/etc/wg-relay"
RULES_DIR="$CONFIG_DIR/rules"
LOCK_FILE="$CONFIG_DIR/.lock"
WEB_DIR="/etc/wg-relay-web"
NGINX_CONF_DIR="/etc/nginx/conf.d"
CERT_DIR="/etc/ssl/wg-relay"
LOG_FILE="/var/log/wg-relay.log"
SERVICE_NAME="wg-relay"
WEB_SERVICE_NAME="wg-relay-web"
RULE_MANAGER_NAME="wg-rule-manager"
SCRIPT_VERSION="1.1.0"
WEB_PORT="8080"
NGINX_PORT="80"
SSL_PORT="443"
IPTABLES_CHAIN="WG_RELAY"
IPTABLES_CHAIN_NAT="WG_RELAY_NAT"
RULE_COMMENT_PREFIX="WG_RELAY_RULE"

# 全局变量 (在主脚本中初始化，这里只声明)
WEB_USER="admin"
WEB_PASS=""
WEB_PASS_HASH=""
DOMAIN_NAME=""
ENABLE_SSL=false
ENABLE_HTTPS_REDIRECT=true
NON_INTERACTIVE=false
SKIP_SSL=false
PUBLIC_INTERFACE=""
PUBLIC_IP=""
RELAY_NAME="流量转发中继管理系统"
MASTER_IP=""
MASTER_PORT=""
RELAY_PORT=""
EMAIL_ADDRESS="v2wallid@gmail.com"
OS=""
VER=""
CODENAME=""

# ============================ 锁管理函数 ============================

acquire_lock() {
    local lock_timeout=${1:-30}
    mkdir -p "$(dirname "$LOCK_FILE")"
    
    exec 9>"$LOCK_FILE"
    if ! flock -w "$lock_timeout" 9; then
        warn "无法在 ${lock_timeout}s 内获取锁，请检查是否有其他实例在运行"
        exit 1
    fi
    trap 'release_lock' EXIT INT TERM
}

release_lock() {
    flock -u 9 2>/dev/null
    exec 9>&- 2>/dev/null
}

# ============================ 日志函数 ============================

log() {
    echo -e "${GREEN}[$(date '+%Y-%m-%d %H:%M:%S')]${NC} $1" | tee -a "$LOG_FILE"
}

error() {
    echo -e "${RED}[错误]${NC} $1" | tee -a "$LOG_FILE"
    release_lock
    exit 1
}

warn() {
    echo -e "${YELLOW}[警告]${NC} $1" | tee -a "$LOG_FILE"
}

info() {
    echo -e "${BLUE}[信息]${NC} $1" | tee -a "$LOG_FILE"
}

success() {
    echo -e "${GREEN}[成功]${NC} $1" | tee -a "$LOG_FILE"
}

generate_web_password_hash() {
    local password="${1:-}"
    printf '%s' "$password" | python3 -c '
import sys
from werkzeug.security import generate_password_hash

print(generate_password_hash(sys.stdin.read()))
'
}

# ============================ 系统检测函数 ============================

check_root() {
    if [[ $EUID -ne 0 ]]; then
        error "请使用 root 用户运行此脚本"
    fi
}

detect_os() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS=$ID
        VER=$VERSION_ID
        CODENAME=$VERSION_CODENAME
        
        [ -z "$CODENAME" ] && CODENAME=$(lsb_release -cs 2>/dev/null || echo "unknown")
        log "检测到系统: $OS $VER ($CODENAME)"
    elif [ -f /etc/redhat-release ]; then
        OS="centos"
        VER=$(rpm -q --qf "%{\VERSION}" centos-release)
        CODENAME=""
        log "检测到系统: CentOS $VER"
    else
        error "无法检测操作系统类型"
    fi
}

detect_network_interfaces() {
    info "检测网络接口..."
    
    PUBLIC_INTERFACE=$(ip route | grep default | awk '{print $5}' | head -1)
    [ -z "$PUBLIC_INTERFACE" ] && \
        PUBLIC_INTERFACE=$(ls /sys/class/net/ | grep -E "^(eth|ens|enp|eno)" | head -1)
    [ -z "$PUBLIC_INTERFACE" ] && error "无法检测到公网接口"
    
    info "检测到公网接口: $PUBLIC_INTERFACE"
    
    # 获取公网IP
    local ip_services=(
        "https://api.ipify.org"
        "https://ifconfig.me"
        "https://icanhazip.com"
    )
    
    for service in "${ip_services[@]}"; do
        local retries=3
        while [ $retries -gt 0 ]; do
            PUBLIC_IP=$(curl -s --connect-timeout 5 --max-time 8 "$service" 2>/dev/null || true)
            [ -n "$PUBLIC_IP" ] && break 2
            retries=$((retries - 1))
            sleep 1
        done
    done
    
    [ -z "$PUBLIC_IP" ] && \
        PUBLIC_IP=$(ip addr show $PUBLIC_INTERFACE | grep 'inet ' | awk '{print $2}' | cut -d'/' -f1 | head -1)
    
    info "公网IP地址: $PUBLIC_IP"
}

# ============================ 安装完成函数 ============================

show_completion() {
    echo -e "\n${GREEN}===========================================${NC}"
    echo -e "${GREEN}  流量转发中继管理系统安装完成         ${NC}"
    echo -e "${GREEN}          统一架构版本: $SCRIPT_VERSION                 ${NC}"
    echo -e "${GREEN}===========================================${NC}"
    echo -e "\n${CYAN}配置信息:${NC}"
    echo -e "  中继名称: $RELAY_NAME"
    echo -e "  公网IP: $PUBLIC_IP"
    echo -e "${CYAN}Web管理界面:${NC}"

    if [ "$ENABLE_SSL" = true ]; then
        echo -e "  协议: HTTPS (SSL已启用)"
        if [ -n "$DOMAIN_NAME" ] && [ "$DOMAIN_NAME" != "localhost" ]; then
            echo -e "  访问地址: https://$DOMAIN_NAME"
        else
            echo -e "  访问地址: https://$PUBLIC_IP:$SSL_PORT"
        fi
    else
        echo -e "  协议: HTTP (SSL未启用)"
        echo -e "  访问地址: http://$PUBLIC_IP:$NGINX_PORT"
    fi

    echo -e "\n  用户名: $WEB_USER"
    echo -e "  密码: 查看 /etc/wg-relay/.credentials (权限600)"
    echo -e "\n${CYAN}服务状态:${NC}"
    echo -e "  Web服务: $(systemctl is-active $WEB_SERVICE_NAME 2>/dev/null && echo '运行中' || echo '未运行')"
    echo -e "  Nginx服务: $(systemctl is-active nginx 2>/dev/null && echo '运行中' || echo '未运行')"
    echo -e "  规则管理器: $(command -v wg-rule-manager >/dev/null && echo '已安装' || echo '未安装')"
    echo -e "  统计收集器: $(command -v wg-relay-stats >/dev/null && echo '已安装' || echo '未安装')"
    echo -e "\n${CYAN}管理命令:${NC}"
    echo -e "  wg-relay status          # 查看状态"
    echo -e "  wg-relay reload          # 重新加载规则"
    echo -e "  wg-relay rules list      # 列出所有规则"
    echo -e "  wg-rule-manager          # 统一规则管理器"
    echo -e "  wg-relay-stats           # 查看统计"
    echo -e "\n${CYAN}配置文件位置:${NC}"
    echo -e "  主配置: $CONFIG_DIR/config.json"
    echo -e "  规则目录: $RULES_DIR/"
    echo -e "  Web界面: $WEB_DIR/"
    echo -e "\n${YELLOW}注意: 安装完成后，请通过Web管理界面添加转发规则。${NC}"
    echo -e ""
}

show_welcome_message() {
    echo -e "${GREEN}======================================================${NC}"
    echo -e "${GREEN}  欢迎使用 WireGuard 多中继增强管理系统${NC}"
    echo -e "${GREEN}======================================================${NC}"
}

print_color() {
    local color=$1
    local text=$2
    echo -e "${color}${text}${NC}"
}

# ============================ 卸载辅助函数 ============================

cleanup_iptables_rules() {
    info "清理iptables规则..."
    while iptables -t nat -C PREROUTING -j WG_RELAY_NAT 2>/dev/null; do
        iptables -t nat -D PREROUTING -j WG_RELAY_NAT
    done

    mapfile -t lines < <(
        iptables -t nat -L POSTROUTING -n --line-numbers | \
        grep "WG_RELAY_RULE" | awk '{print $1}' | sort -r
    )

    for line_num in "${lines[@]}"; do
        iptables -t nat -D POSTROUTING "$line_num" 2>/dev/null
    done

    iptables -t nat -F WG_RELAY_NAT 2>/dev/null
    iptables -t nat -X WG_RELAY_NAT 2>/dev/null
    while iptables -C FORWARD -j WG_RELAY 2>/dev/null; do
        iptables -D FORWARD -j WG_RELAY
    done
    iptables -F WG_RELAY 2>/dev/null
    iptables -X WG_RELAY 2>/dev/null
}

remove_files_and_dirs() {
    info "移除项目文件和目录..."
    for dir in /etc/wg-relay /etc/wg-relay-web /etc/ssl/wg-relay; do
        [ -d "$dir" ] && rm -rf "$dir"
    done
    for script in /usr/local/bin/wg-relay /usr/local/bin/wg-relay-stats /usr/local/bin/wg-rule-manager; do
        [ -f "$script" ] && rm -f "$script"
    done
    rm -f /etc/nginx/conf.d/wg-relay.conf
    rm -f /var/log/wg-relay*.log
    (crontab -l 2>/dev/null | grep -v "wg-relay\|renew-wg-relay-cert") | crontab - 2>/dev/null || true
}

# ============================ 卸载主函数 ============================

uninstall() {
    clear
    echo -e "${RED}===========================================${NC}"
    echo -e "${RED}  流量转发中继管理系统 - 卸载脚本         ${NC}"
    echo -e "${RED}===========================================${NC}"
    echo ""

    read -p "确定要卸载流量转发中继管理系统吗？(y/N): " confirm_uninstall
    [[ "$confirm_uninstall" != "y" && "$confirm_uninstall" != "Y" ]] && {
        echo "卸载已取消"
        exit 0
    }

    info "开始卸载..."
    stop_web_app 2>/dev/null
    disable_nginx_proxy 2>/dev/null
    cleanup_iptables_rules
    remove_systemd_services 2>/dev/null
    remove_files_and_dirs
    
    echo ""
    echo "=========================================="
    echo "卸载完成！建议重启系统以确保所有更改生效。"
    echo "=========================================="
}
