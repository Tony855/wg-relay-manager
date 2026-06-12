#!/bin/bash
set -e
set -o pipefail

# ===========================================
# 流量转发规则管理器
# ===========================================

CONFIG_DIR="/etc/wg-relay"
RULES_DIR="$CONFIG_DIR/rules"
LOCK_FILE="$CONFIG_DIR/.lock"
LOG_FILE="/var/log/wg-relay.log"
IPTABLES_CHAIN="WG_RELAY"
IPTABLES_CHAIN_NAT="WG_RELAY_NAT"
RULE_COMMENT_PREFIX="WG_RELAY_RULE"

# 简化的日志函数，避免循环依赖
log() { echo "[$(date "+%Y-%m-%d %H:%M:%S")] $1" | tee -a "$LOG_FILE"; }
info() { echo "[信息] $1" | tee -a "$LOG_FILE"; }
error() { echo "[错误] $1" | tee -a "$LOG_FILE"; exit 1; }
warn() { echo "[警告] $1" | tee -a "$LOG_FILE"; }

acquire_lock() {
    mkdir -p "$(dirname "$LOCK_FILE")"
    exec 9>"$LOCK_FILE"
    if ! flock -w 30 9; then
        warn "无法在30秒内获取锁"
        exit 1
    fi
    trap 'release_lock' EXIT INT TERM
}
release_lock() {
    flock -u 9 2>/dev/null || true
    exec 9>&- 2>/dev/null || true
}

delete_iptables_rule() {
    local rule_id=$1
    local comment="${RULE_COMMENT_PREFIX}_${rule_id}"
    
    while true; do
        local post_line_num=$(iptables -t nat -L POSTROUTING -n --line-numbers 2>/dev/null | grep "$comment" | head -1 | awk '{print $1}')
        [ -z "$post_line_num" ] && break
        iptables -t nat -D POSTROUTING $post_line_num 2>/dev/null || true
    done
    
    while true; do
        local nat_line_num=$(iptables -t nat -L $IPTABLES_CHAIN_NAT -n --line-numbers 2>/dev/null | grep "$comment" | head -1 | awk '{print $1}')
        [ -z "$nat_line_num" ] && break
        iptables -t nat -D $IPTABLES_CHAIN_NAT $nat_line_num 2>/dev/null || true
    done
    
    while true; do
        local fwd_line_num=$(iptables -L $IPTABLES_CHAIN -n --line-numbers 2>/dev/null | grep "$comment" | head -1 | awk '{print $1}')
        [ -z "$fwd_line_num" ] && break
        iptables -D $IPTABLES_CHAIN $fwd_line_num 2>/dev/null || true
    done
    
    log "已删除iptables规则 #$rule_id"
}

add_iptables_rule() {
    local rule_id=$1 protocol=$2 listen_ip=$3 listen_port=$4 target_ip=$5 target_port=$6
    delete_iptables_rule $rule_id
    local comment="${RULE_COMMENT_PREFIX}_${rule_id}"
    listen_port=$(echo "$listen_port" | tr -d ' ')
    target_port=$(echo "$target_port" | tr -d ' ')
    
    if ! [[ "$listen_port" =~ ^[0-9]+$ ]] || [ "$listen_port" -lt 1 ] || [ "$listen_port" -gt 65535 ]; then
        error "无效的监听端口: $listen_port"
    fi
    if ! [[ "$target_port" =~ ^[0-9]+$ ]] || [ "$target_port" -lt 1 ] || [ "$target_port" -gt 65535 ]; then
        error "无效的目标端口: $target_port"
    fi
    
    if echo "$listen_ip" | grep -qE '^0\.0\.0\.0'; then
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
    
    log "应用规则 #$rule_id: $listen_ip:$listen_port -> $target_ip:$target_port ($protocol)"
}

get_rule_file() { echo "$RULES_DIR/rule_${1}.json"; }

create_rule() {
    local rule_id=$1 name="$2" protocol="$3" listen_ip="$4" listen_port=$5 target_ip="$6" target_port=$7 enabled="$8" description="$9"
    local rule_file=$(get_rule_file $rule_id)
    local enabled_py=$( [ "$enabled" = "true" ] && echo "True" || echo "False" )
    python3 - "$rule_file" <<PYEOF
import json, sys
rule_file = sys.argv[1]
rule = {
    "id": ${rule_id},
    "name": """${name}""",
    "protocol": """${protocol}""",
    "listen_ip": """${listen_ip}""",
    "listen_port": ${listen_port},
    "target_ip": """${target_ip}""",
    "target_port": ${target_port},
    "enabled": ${enabled_py},
    "description": """${description}""",
    "created_at": "$(date -Iseconds)",
    "updated_at": "$(date -Iseconds)",
    "comment": "${RULE_COMMENT_PREFIX}_${rule_id}"
}
with open(rule_file, "w", encoding="utf-8") as f:
    json.dump(rule, f, indent=4, ensure_ascii=False)
PYEOF
    chmod 600 "$rule_file"
    log "创建规则文件: $rule_file"
}

update_rule() {
    local rule_id=$1 updates="$2"
    local rule_file=$(get_rule_file $rule_id)
    [ ! -f "$rule_file" ] && error "规则不存在: $rule_id"
    if command -v jq >/dev/null 2>&1; then
        local current_rule=$(cat "$rule_file")
        local updated_rule=$(echo "$current_rule" | jq ". + $updates + {updated_at: \"$(date -Iseconds)\"}")
        echo "$updated_rule" > "$rule_file"
    else
        error "jq 未安装，无法更新规则。请手动安装 jq 或更新脚本。"
    fi
    chmod 600 "$rule_file"
    log "更新规则文件: $rule_file"
}

delete_rule() {
    local rule_id=$1
    local rule_file=$(get_rule_file $rule_id)
    if [ -f "$rule_file" ]; then
        rm -f "$rule_file"
        log "删除规则文件: $rule_file"
    fi
}

apply_rule() {
    local rule_file=$1
    if [ ! -f "$rule_file" ]; then
        warn "规则文件不存在: $rule_file"
        return
    fi
    
    if command -v jq >/dev/null 2>&1; then
        local rule_json=$(cat "$rule_file")
        local rule_id=$(echo "$rule_json" | jq -r ".id")
        local enabled=$(echo "$rule_json" | jq -r ".enabled")
        
        delete_iptables_rule $rule_id
        
        if [ "$enabled" = "true" ]; then
            local protocol=$(echo "$rule_json" | jq -r ".protocol")
            local listen_ip=$(echo "$rule_json" | jq -r ".listen_ip")
            local listen_port=$(echo "$rule_json" | jq -r ".listen_port")
            local target_ip=$(echo "$rule_json" | jq -r ".target_ip")
            local target_port=$(echo "$rule_json" | jq -r ".target_port")
            
            add_iptables_rule "$rule_id" "$protocol" "$listen_ip" "$listen_port" "$target_ip" "$target_port"
            log "已启用规则 #$rule_id"
        else
            log "规则 #$rule_id 已禁用"
        fi
    else
        error "jq 未安装，无法应用规则。请手动安装 jq 或更新脚本。"
    fi
}

reload_all_rules() {
    info "重新加载所有规则..."
    init_iptables_chain # 重新初始化链，清除旧规则
    for rule_file in "$RULES_DIR"/rule_*.json; do
        [ -f "$rule_file" ] || continue
        apply_rule "$rule_file"
    done
    save_iptables_rules
    log "所有规则重新加载完成"
}

get_traffic_stats() {
    local rule_id=$1
    local stats=""
    
    local rule_file
    rule_file=$(get_rule_file "$rule_id")
    if [ -f "$rule_file" ] && command -v jq >/dev/null 2>&1; then
        local target_port proto
        target_port=$(jq -r ".target_port" "$rule_file" 2>/dev/null)
        proto=$(jq -r ".protocol" "$rule_file" 2>/dev/null)
        if [ -n "$target_port" ] && [ -n "$proto" ] && [ -f /proc/net/nf_conntrack ]; then
            local ct_bytes ct_packets
            ct_bytes=$(awk -v proto="$proto" -v dport="$target_port" '\
                BEGIN { total=0 }\
                $3 == proto || $4 == proto {\
                    for(i=1;i<=NF;i++){\
                        if($i ~ /^dport=/ && $i == "dport="dport) {\
                            for(j=1;j<=NF;j++){\
                                if($j ~ /^bytes=/){\
                                    split($j,a,"="); total+=a[2]\
                                }\
                            }\
                        }\
                    }\
                }\
                END { print total }\
            ' /proc/net/nf_conntrack 2>/dev/null || echo 0)
            ct_packets=$(awk -v proto="$proto" -v dport="$target_port" '\
                BEGIN { total=0 }\
                $3 == proto || $4 == proto {\
                    for(i=1;i<=NF;i++){\
                        if($i ~ /^dport=/ && $i == "dport="dport) {\
                            for(j=1;j<=NF;j++){\
                                if($j ~ /^packets=/){\
                                    split($j,a,"="); total+=a[2]\
                                }\
                            }\
                        }\
                    }\
                }\
                END { print total }\
            ' /proc/net/nf_conntrack 2>/dev/null || echo 0)
            if [ "${ct_bytes:-0}" -gt 0 ] 2>/dev/null; then
                if [ -n "$stats" ]; then stats="$stats;conntrack:${ct_packets:-0}:${ct_bytes}"
                else stats="conntrack:${ct_packets:-0}:${ct_bytes}"; fi
            fi
        fi
    fi

    echo "$stats"
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

case "$1" in
    add)
        acquire_lock; shift
        rule_id=$1; name=$2; protocol=$3; listen_ip=$4; listen_port=$5
        target_ip=$6; target_port=$7; enabled=$8; description=${9:-""}
        create_rule "$rule_id" "$name" "$protocol" "$listen_ip" "$listen_port" "$target_ip" "$target_port" "$enabled" "$description"
        apply_rule "$(get_rule_file $rule_id)"
        release_lock
        ;;
    update)
        acquire_lock; shift
        rule_id=$1; updates=$2
        update_rule "$rule_id" "$updates"
        apply_rule "$(get_rule_file $rule_id)"
        release_lock
        ;;
    delete)
        acquire_lock; shift
        rule_id=$1
        delete_iptables_rule "$rule_id"
        delete_rule "$rule_id"
        release_lock
        ;;
    toggle)
        acquire_lock; shift
        rule_id=$1; enabled=$2
        updates="{\"enabled\": $enabled}"
        update_rule "$rule_id" "$updates"
        apply_rule "$(get_rule_file $rule_id)"
        release_lock
        ;;
    reload)
        acquire_lock
        reload_all_rules
        save_iptables_rules
        release_lock
        exit 0
        ;;
    stats)
        shift
        rule_id=${1:-""}
        if [ -n "$rule_id" ]; then
            get_traffic_stats "$rule_id"
        else
            for rule_file in "$RULES_DIR"/rule_*.json; do
                [ -f "$rule_file" ] || continue
                r_id=$(basename "$rule_file" | sed 's/rule_//' | sed 's/.json//')
                stats_out=$(get_traffic_stats "$r_id")
                echo "$r_id:$stats_out"
            done
        fi
        ;;
    list)
        for rule_file in "$RULES_DIR"/rule_*.json; do
            [ -f "$rule_file" ] || continue
            cat "$rule_file"
            echo ""
        done
        ;;
    *)
        echo "流量转发中继管理系统"
        echo "用法: wg-rule-manager <命令> [参数]"
        echo "命令: add|update|delete|toggle|reload|stats|list"
        exit 1
        ;;
esac
