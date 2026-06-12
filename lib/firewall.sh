#!/bin/bash

# ===========================================
# 防火墙配置函数库
# ===========================================

source "$(dirname "$0")"/utils.sh

# ============================ iptables统一管理 ============================

init_iptables_chain() {
    info "正在初始化iptables链..."
    
    iptables -N $IPTABLES_CHAIN 2>/dev/null || true
    iptables -F $IPTABLES_CHAIN 2>/dev/null || true
    iptables -t nat -N $IPTABLES_CHAIN_NAT 2>/dev/null || true
    iptables -t nat -F $IPTABLES_CHAIN_NAT 2>/dev/null || true
    
    while iptables -t nat -C PREROUTING -j $IPTABLES_CHAIN_NAT 2>/dev/null; do
        iptables -t nat -D PREROUTING -j $IPTABLES_CHAIN_NAT
    done
    
    while iptables -C FORWARD -j $IPTABLES_CHAIN 2>/dev/null; do
        iptables -D FORWARD -j $IPTABLES_CHAIN
    done
    
    iptables -t nat -I PREROUTING 1 -j $IPTABLES_CHAIN_NAT
    iptables -I FORWARD 1 -j $IPTABLES_CHAIN
    
    if command -v ip6tables >/dev/null 2>&1; then
        ip6tables -N ${IPTABLES_CHAIN}_V6 2>/dev/null || true
        ip6tables -F ${IPTABLES_CHAIN}_V6 2>/dev/null || true
        while ip6tables -C FORWARD -j ${IPTABLES_CHAIN}_V6 2>/dev/null; do
            ip6tables -D FORWARD -j ${IPTABLES_CHAIN}_V6
        done
        ip6tables -I FORWARD 1 -j ${IPTABLES_CHAIN}_V6
        if ! ip6tables -C ${IPTABLES_CHAIN}_V6 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null; then
            ip6tables -A ${IPTABLES_CHAIN}_V6 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
        fi
        log "IPv6 iptables链初始化完成"
    fi
    
    configure_base_firewall_rules
    log "iptables链初始化完成"
}

configure_base_firewall_rules() {
    if ! iptables -C INPUT -i lo -j ACCEPT 2>/dev/null; then
        iptables -A INPUT -i lo -j ACCEPT
    fi
    
    if ! iptables -C INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null; then
        iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    fi
    
    if ! iptables -C INPUT -p icmp -j ACCEPT 2>/dev/null; then
        iptables -A INPUT -p icmp -j ACCEPT
    fi
    
    if ! iptables -C INPUT -p tcp --dport 22 -j ACCEPT 2>/dev/null; then
        iptables -A INPUT -p tcp --dport 22 -j ACCEPT
    fi
    
    # 仅当 RELAY_PORT 有值时添加防火墙规则
    if [ -n "$RELAY_PORT" ]; then
        if ! iptables -C INPUT -p udp --dport $RELAY_PORT -j ACCEPT 2>/dev/null; then
            iptables -A INPUT -p udp --dport $RELAY_PORT -j ACCEPT
        fi
    fi
    
    if ! iptables -C FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null; then
        iptables -A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    fi
    
    if $ENABLE_SSL; then
        if ! iptables -C INPUT -p tcp --dport $SSL_PORT -j ACCEPT 2>/dev/null; then
            iptables -A INPUT -p tcp --dport $SSL_PORT -j ACCEPT
        fi
        if ! iptables -C INPUT -p tcp --dport $NGINX_PORT -j ACCEPT 2>/dev/null; then
            iptables -A INPUT -p tcp --dport $NGINX_PORT -j ACCEPT
        fi
    else
        if ! iptables -C INPUT -p tcp --dport $NGINX_PORT -j ACCEPT 2>/dev/null; then
            iptables -A INPUT -p tcp --dport $NGINX_PORT -j ACCEPT
        fi
    fi
}

add_iptables_rule() {
    local rule_id=$1 
    local protocol=$2 
    local listen_ip=$3 
    local listen_port=$4 
    local target_ip=$5 
    local target_port=$6
    
    delete_iptables_rule $rule_id
    
    local comment="${RULE_COMMENT_PREFIX}_${rule_id}"
    
    if echo "$listen_ip" | grep -qE "^0\\.0\\.0\\.0"; then
        iptables -t nat -A $IPTABLES_CHAIN_NAT \
            -p $protocol -m $protocol --dport $listen_port \
            -m comment --comment "$comment" \
            -j DNAT --to-destination $target_ip:$target_port
    else
        iptables -t nat -A $IPTABLES_CHAIN_NAT \
            -d "$listen_ip" -p $protocol -m $protocol --dport $listen_port \
            -m comment --comment "$comment" \
            -j DNAT --to-destination $target_ip:$target_port
    fi
    
    iptables -A $IPTABLES_CHAIN \
        -p $protocol -m $protocol -d $target_ip --dport $target_port \
        -m conntrack --ctstate NEW,ESTABLISHED,RELATED \
        -m comment --comment "$comment" \
        -j ACCEPT
    
    if ! iptables -t nat -C POSTROUTING \
        -p $protocol -d $target_ip --dport $target_port \
        -m conntrack --ctstate NEW,ESTABLISHED,RELATED \
        -m comment --comment "$comment" \
        -j MASQUERADE 2>/dev/null; then
        iptables -t nat -A POSTROUTING \
            -p $protocol -d $target_ip --dport $target_port \
            -m conntrack --ctstate NEW,ESTABLISHED,RELATED \
            -m comment --comment "$comment" \
            -j MASQUERADE
    fi
}

delete_iptables_rule() {
    local rule_id=$1
    local comment="${RULE_COMMENT_PREFIX}_${rule_id}"
    
    while true; do
        local post_line_num=$(iptables -t nat -L POSTROUTING -n --line-numbers | \
                           grep "$comment" | head -1 | awk \'{print $1}\' 2>/dev/null)
        [ -z "$post_line_num" ] && break
        iptables -t nat -D POSTROUTING $post_line_num 2>/dev/null
    done
    
    while true; do
        local nat_line_num=$(iptables -t nat -L $IPTABLES_CHAIN_NAT -n --line-numbers | \
                           grep "$comment" | head -1 | awk \'{print $1}\' 2>/dev/null)
        [ -z "$nat_line_num" ] && break
        iptables -t nat -D $IPTABLES_CHAIN_NAT $nat_line_num 2>/dev/null
    done
    
    while true; do
        local fwd_line_num=$(iptables -L $IPTABLES_CHAIN -n --line-numbers | \
                           grep "$comment" | head -1 | awk \'{print $1}\' 2>/dev/null)
        [ -z "$fwd_line_num" ] && break
        iptables -D $IPTABLES_CHAIN $fwd_line_num 2>/dev/null
    done
    
    log "已删除iptables规则 #$rule_id"
}

check_port_conflict() {
    local port=$1
    local rule_name=$2
    local exclude_rule_id=${3:-0}
    
    local existing_rules=$(iptables -t nat -L ${IPTABLES_CHAIN_NAT} -n | \
                          grep "dpt:$port" | grep -v "${RULE_COMMENT_PREFIX}_${exclude_rule_id}" | wc -l)
    
    [ $existing_rules -gt 0 ] && {
        warn "端口 $port 已被其他规则使用"
        return 1
    }
    
    local listeners=$(ss -ulpn -tlpn 2>/dev/null | grep ":$port " | grep -v "wg-relay-web" | wc -l)
    [ $listeners -gt 0 ] && {
        warn "端口 $port 已被系统进程监听"
        return 1
    }
    
    return 0
}

save_iptables_rules() {
    case "$(grep '^ID=' /etc/os-release | cut -d= -f2 | tr -d '"\')" in
        ubuntu|debian)
            mkdir -p /etc/iptables
            /sbin/iptables-save > /etc/iptables/rules.v4
            /sbin/ip6tables-save > /etc/iptables/rules.v6 2>/dev/null || true
            if command -v netfilter-persistent >/dev/null 2>&1; then
                netfilter-persistent save >/dev/null 2>&1 || true
            fi
            ;;
        centos|rhel|fedora|almalinux|rocky)
            /sbin/iptables-save > /etc/sysconfig/iptables
            /sbin/ip6tables-save > /etc/sysconfig/ip6tables 2>/dev/null || true
            ;;
        *)
            /sbin/iptables-save > /etc/iptables.rules
            ;;
    esac
}
