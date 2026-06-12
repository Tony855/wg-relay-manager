#!/bin/bash

# ===========================================
# 公共工具函数库
# ===========================================

# 颜色定义
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly CYAN='\033[0;36m'
readonly MAGENTA='\033[0;35m'
readonly NC='\033[0m' # No Color

# 全局配置
readonly CONFIG_DIR="/etc/wg-relay"
readonly RULES_DIR="$CONFIG_DIR/rules"
readonly LOCK_FILE="$CONFIG_DIR/.lock"
readonly WEB_DIR="/etc/wg-relay-web"
readonly NGINX_CONF_DIR="/etc/nginx/conf.d"
readonly CERT_DIR="/etc/ssl/wg-relay"
readonly LOG_FILE="/var/log/wg-relay.log"
readonly SERVICE_NAME="wg-relay"
readonly WEB_SERVICE_NAME="wg-relay-web"
readonly RULE_MANAGER_NAME="wg-rule-manager"
readonly SCRIPT_VERSION="1.1.0"
readonly WEB_PORT="8080"
readonly NGINX_PORT="80"
readonly SSL_PORT="443"
readonly IPTABLES_CHAIN="WG_RELAY"
readonly IPTABLES_CHAIN_NAT="WG_RELAY_NAT"
readonly RULE_COMMENT_PREFIX="WG_RELAY_RULE"

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

# ============================ 卸载函数 ============================

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

    systemctl stop "$WEB_SERVICE_NAME" 2>/dev/null && echo "已停止服务: $WEB_SERVICE_NAME"
    systemctl disable "$WEB_SERVICE_NAME" 2>/dev/null && echo "已禁用服务: $WEB_SERVICE_NAME"
    systemctl stop "$SERVICE_NAME" 2>/dev/null && echo "已停止服务: $SERVICE_NAME"
    systemctl disable "$SERVICE_NAME" 2>/dev/null && echo "已禁用服务: $SERVICE_NAME"
    systemctl stop nginx 2>/dev/null && echo "已停止服务: nginx"
    systemctl disable nginx 2>/dev/null && echo "已禁用服务: nginx"

    echo "清理iptables规则..."

    while iptables -t nat -C PREROUTING -j WG_RELAY_NAT 2>/dev/null; do
        iptables -t nat -D PREROUTING -j WG_RELAY_NAT
    done

    echo "清理POSTROUTING中的WG_RELAY_RULE MASQUERADE规则..."
    mapfile -t lines < <(
        iptables -t nat -L POSTROUTING -n --line-numbers | \
        grep "WG_RELAY_RULE" | awk '{print $1}' | sort -r
    )

    for line_num in "${lines[@]}"; do
        iptables -t nat -D POSTROUTING "$line_num" 2>/dev/null && \
            echo "已删除 POSTROUTING 规则行号: $line_num"
    done

    iptables -t nat -F WG_RELAY_NAT 2>/dev/null && echo "已清空NAT链: WG_RELAY_NAT"
    iptables -t nat -X WG_RELAY_NAT 2>/dev/null && echo "已删除NAT链: WG_RELAY_NAT"

    while iptables -C FORWARD -j WG_RELAY 2>/dev/null; do
        iptables -D FORWARD -j WG_RELAY
    done

    iptables -F WG_RELAY 2>/dev/null && echo "已清空链: WG_RELAY"
    iptables -X WG_RELAY 2>/dev/null && echo "已删除链: WG_RELAY"

    for dir in /etc/wg-relay /etc/wg-relay-web /etc/ssl/wg-relay; do
        [ -d "$dir" ] && rm -rf "$dir" && echo "已删除目录: $dir"
    done

    for service_file in /etc/systemd/system/wg-relay*.service; do
        [ -f "$service_file" ] && rm -f "$service_file" && echo "已删除服务文件: $service_file"
    done

    for script in /usr/local/bin/wg-relay /usr/local/bin/wg-relay-stats /usr/local/bin/wg-rule-manager; do
        [ -f "$script" ] && rm -f "$script" && echo "已删除脚本: $script"
    done

    [ -f "/etc/nginx/conf.d/wg-relay.conf" ] && \
        rm -f "/etc/nginx/conf.d/wg-relay.conf" && \
        echo "已删除Nginx配置"

    for log_file in /var/log/wg-relay*.log; do
        [ -f "$log_file" ] && rm -f "$log_file" && echo "已删除日志文件: $log_file"
    done

    (crontab -l 2>/dev/null | grep -v "wg-relay\|renew-wg-relay-cert") | crontab - 2>/dev/null && \
        echo "已清理定时任务"

    systemctl daemon-reload
    echo ""
    echo "=========================================="
    echo "卸载完成！建议重启系统以确保所有更改生效。"
    echo "=========================================="
}
