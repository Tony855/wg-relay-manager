#!/bin/bash

# ===========================================
# 配置创建和管理函数库
# ===========================================

# 自动检测 lib 目录位置
LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$LIB_DIR/utils.sh"

# ============================ 系统配置函数 ============================

configure_kernel() {
    info "正在配置内核参数..."
    
    cat > /etc/sysctl.d/99-wg-relay.conf << EOF
net.ipv4.ip_forward = 1
net.ipv6.conf.all.forwarding = 1
net.ipv4.conf.all.rp_filter = 0
net.ipv4.conf.default.rp_filter = 0
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
EOF
    
    sysctl -p /etc/sysctl.d/99-wg-relay.conf >/dev/null 2>&1 || true
    log "内核参数配置完成"
}

# ============================ 配置创建函数 ============================

create_forward_config() {
    info "创建流量转发配置..."
    
    create_directories
    create_main_config
    save_credentials
    # 不再创建默认规则，让用户通过Web界面添加
    # create_default_rule  已移除
    info "配置已创建，未添加任何默认规则，请通过Web界面添加转发规则"
}

save_credentials() {
    local cred_file="$CONFIG_DIR/.credentials"
    cat > "$cred_file" << EOF
# 流量转发中继管理系统 管理凭据
# 生成时间: $(date -Iseconds)
WEB_USER=$WEB_USER
WEB_PASS=$WEB_PASS
EOF
    chmod 600 "$cred_file"
    log "管理密码已保存至 $cred_file (权限600)"
}

create_directories() {
    mkdir -p $CONFIG_DIR $RULES_DIR $WEB_DIR $CERT_DIR
}

create_main_config() {
    cat > $CONFIG_DIR/config.json << EOF
{
    "relay_name": "$RELAY_NAME",
    "public_ip": "$PUBLIC_IP",
    "public_interface": "$PUBLIC_INTERFACE",
    "relay_port": ${RELAY_PORT:-null},
    "master_ip": ${MASTER_IP:+\"$MASTER_IP\"}${MASTER_IP:-null},
    "master_port": ${MASTER_PORT:-null},
    "web_port": $WEB_PORT,
    "web_user": "$WEB_USER",
    "web_pass_hash": "$WEB_PASS_HASH",
    "domain_name": "$DOMAIN_NAME",
    "email_address": "$EMAIL_ADDRESS",
    "enable_ssl": $ENABLE_SSL,
    "enable_https_redirect": $ENABLE_HTTPS_REDIRECT,
    "nginx_port": $NGINX_PORT,
    "ssl_port": $SSL_PORT,
    "created_at": "$(date -Iseconds)",
    "status": "active",
    "version": "$SCRIPT_VERSION",
    "iptables_chain": "$IPTABLES_CHAIN",
    "next_rule_id": 1
}
EOF
}

load_config_from_file() {
    if [ -f "$CONFIG_FILE" ]; then
        RELAY_NAME=$(jq -r ".relay_name" "$CONFIG_FILE")
        PUBLIC_IP=$(jq -r ".public_ip" "$CONFIG_FILE")
        PUBLIC_INTERFACE=$(jq -r ".public_interface" "$CONFIG_FILE")
    fi
}

update_config_file() {
    local updates=$1
    if [ -f "$CONFIG_FILE" ]; then
        local tmp_file=$(mktemp)
        jq ". + $updates" "$CONFIG_FILE" > "$tmp_file" && mv "$tmp_file" "$CONFIG_FILE"
    fi
}

get_next_rule_id_from_config() {
    local next_id=$(jq -r ".next_rule_id" "$CONFIG_FILE")
    local new_next_id=$((next_id + 1))
    local tmp_file=$(mktemp)
    jq ".next_rule_id = $new_next_id" "$CONFIG_FILE" > "$tmp_file" && mv "$tmp_file" "$CONFIG_FILE"
    echo "$next_id"
}

setup_sysctl() {
    configure_kernel
}
