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
log()  { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"; }
info() { echo "[信息] $1" | tee -a "$LOG_FILE"; }
error(){ echo "[错误] $1" | tee -a "$LOG_FILE"; exit 1; }
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

# ============================ iptables 操作 ============================

delete_iptables_rule() {
    local rule_id=$1
    local comment="${RULE_COMMENT_PREFIX}_${rule_id}"

    while true; do
        local post_line_num
        post_line_num=$(iptables -t nat -L POSTROUTING -n --line-numbers 2>/dev/null | grep "$comment" | head -1 | awk '{print $1}')
        [ -z "$post_line_num" ] && break
        iptables -t nat -D POSTROUTING "$post_line_num" 2>/dev/null || true
    done

    while true; do
        local nat_line_num
        nat_line_num=$(iptables -t nat -L "$IPTABLES_CHAIN_NAT" -n --line-numbers 2>/dev/null | grep "$comment" | head -1 | awk '{print $1}')
        [ -z "$nat_line_num" ] && break
        iptables -t nat -D "$IPTABLES_CHAIN_NAT" "$nat_line_num" 2>/dev/null || true
    done

    while true; do
        local fwd_line_num
        fwd_line_num=$(iptables -L "$IPTABLES_CHAIN" -n --line-numbers 2>/dev/null | grep "$comment" | head -1 | awk '{print $1}')
        [ -z "$fwd_line_num" ] && break
        iptables -D "$IPTABLES_CHAIN" "$fwd_line_num" 2>/dev/null || true
    done

    log "已删除iptables规则 #$rule_id"
}

add_iptables_rule() {
    local rule_id=$1 protocol=$2 listen_ip=$3 listen_port=$4 target_ip=$5 target_port=$6
    delete_iptables_rule "$rule_id"
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
        iptables -t nat -A "$IPTABLES_CHAIN_NAT" \
            -p "$protocol" -m "$protocol" --dport "$listen_port" \
            -m comment --comment "$comment" \
            -j DNAT --to-destination "$target_ip:$target_port"
    else
        iptables -t nat -A "$IPTABLES_CHAIN_NAT" \
            -d "$listen_ip" -p "$protocol" -m "$protocol" --dport "$listen_port" \
            -m comment --comment "$comment" \
            -j DNAT --to-destination "$target_ip:$target_port"
    fi

    iptables -A "$IPTABLES_CHAIN" \
        -p "$protocol" -m "$protocol" -d "$target_ip" --dport "$target_port" \
        -m conntrack --ctstate NEW,ESTABLISHED,RELATED \
        -m comment --comment "$comment" \
        -j ACCEPT

    if ! iptables -t nat -C POSTROUTING \
        -p "$protocol" -d "$target_ip" --dport "$target_port" \
        -m conntrack --ctstate NEW,ESTABLISHED,RELATED \
        -m comment --comment "$comment" \
        -j MASQUERADE 2>/dev/null; then
        iptables -t nat -A POSTROUTING \
            -p "$protocol" -d "$target_ip" --dport "$target_port" \
            -m conntrack --ctstate NEW,ESTABLISHED,RELATED \
            -m comment --comment "$comment" \
            -j MASQUERADE
    fi

    log "应用规则 #$rule_id: $listen_ip:$listen_port -> $target_ip:$target_port ($protocol)"
}

# BUG FIX: 原代码 reload_all_rules 调用 init_iptables_chain 和 save_iptables_rules，
# 但这两个函数定义在 lib/firewall.sh 中，此脚本未 source 该文件，导致函数未定义。
# 解决方案：在此脚本中内联实现这两个函数，避免对外部文件的隐式依赖。

init_iptables_chain() {
    iptables -N "$IPTABLES_CHAIN" 2>/dev/null || true
    iptables -F "$IPTABLES_CHAIN" 2>/dev/null || true
    iptables -t nat -N "$IPTABLES_CHAIN_NAT" 2>/dev/null || true
    iptables -t nat -F "$IPTABLES_CHAIN_NAT" 2>/dev/null || true

    while iptables -t nat -C PREROUTING -j "$IPTABLES_CHAIN_NAT" 2>/dev/null; do
        iptables -t nat -D PREROUTING -j "$IPTABLES_CHAIN_NAT"
    done
    while iptables -C FORWARD -j "$IPTABLES_CHAIN" 2>/dev/null; do
        iptables -D FORWARD -j "$IPTABLES_CHAIN"
    done

    iptables -t nat -I PREROUTING 1 -j "$IPTABLES_CHAIN_NAT"
    iptables -I FORWARD 1 -j "$IPTABLES_CHAIN"

    # 允许已建立连接通过
    if ! iptables -C FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null; then
        iptables -A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    fi

    log "iptables链初始化完成"
}

save_iptables_rules() {
    local os_id
    os_id=$(grep '^ID=' /etc/os-release 2>/dev/null | cut -d= -f2 | tr -d '"' || echo "unknown")
    case "$os_id" in
        ubuntu|debian)
            mkdir -p /etc/iptables
            /sbin/iptables-save  > /etc/iptables/rules.v4
            /sbin/ip6tables-save > /etc/iptables/rules.v6 2>/dev/null || true
            if command -v netfilter-persistent >/dev/null 2>&1; then
                netfilter-persistent save >/dev/null 2>&1 || true
            fi
            ;;
        centos|rhel|fedora|almalinux|rocky)
            /sbin/iptables-save  > /etc/sysconfig/iptables
            /sbin/ip6tables-save > /etc/sysconfig/ip6tables 2>/dev/null || true
            ;;
        *)
            /sbin/iptables-save > /etc/iptables.rules
            ;;
    esac
    log "iptables规则已保存"
}

# ============================ 规则文件操作 ============================

get_rule_file() { echo "$RULES_DIR/rule_${1}.json"; }

create_rule() {
    local rule_id=$1 name="$2" protocol="$3" listen_ip="$4" listen_port=$5
    local target_ip="$6" target_port=$7 enabled="$8" description="${9:-}"
    local rule_file
    rule_file=$(get_rule_file "$rule_id")
    local enabled_py
    enabled_py=$([ "$enabled" = "true" ] && echo "True" || echo "False")

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
    local rule_file
    rule_file=$(get_rule_file "$rule_id")
    [ ! -f "$rule_file" ] && error "规则不存在: $rule_id"
    if command -v jq >/dev/null 2>&1; then
        local tmp_file
        tmp_file=$(mktemp)
        jq ". + $updates + {updated_at: \"$(date -Iseconds)\"}" "$rule_file" > "$tmp_file" \
            && mv "$tmp_file" "$rule_file"
    else
        error "jq 未安装，无法更新规则。请手动安装 jq。"
    fi
    chmod 600 "$rule_file"
    log "更新规则文件: $rule_file"
}

delete_rule() {
    local rule_id=$1
    local rule_file
    rule_file=$(get_rule_file "$rule_id")
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

    if ! command -v jq >/dev/null 2>&1; then
        error "jq 未安装，无法应用规则。请手动安装 jq。"
    fi

    local rule_json
    rule_json=$(cat "$rule_file")
    local rule_id enabled protocol listen_ip listen_port target_ip target_port
    rule_id=$(echo "$rule_json"    | jq -r ".id")
    enabled=$(echo "$rule_json"    | jq -r ".enabled")

    delete_iptables_rule "$rule_id"

    if [ "$enabled" = "true" ]; then
        protocol=$(echo "$rule_json"   | jq -r ".protocol")
        listen_ip=$(echo "$rule_json"  | jq -r ".listen_ip")
        listen_port=$(echo "$rule_json"| jq -r ".listen_port")
        target_ip=$(echo "$rule_json"  | jq -r ".target_ip")
        target_port=$(echo "$rule_json"| jq -r ".target_port")

        add_iptables_rule "$rule_id" "$protocol" "$listen_ip" "$listen_port" "$target_ip" "$target_port"
        log "已启用规则 #$rule_id"
    else
        log "规则 #$rule_id 已禁用"
    fi
}

reload_all_rules() {
    info "重新加载所有规则..."
    init_iptables_chain
    for rule_file in "$RULES_DIR"/rule_*.json; do
        [ -f "$rule_file" ] || continue
        apply_rule "$rule_file"
    done
    save_iptables_rules
    log "所有规则重新加载完成"
}

# ============================ 流量统计 ============================

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
            ct_bytes=$(awk -v proto="$proto" -v dport="$target_port" '
                BEGIN { total=0 }
                $3 == proto || $4 == proto {
                    for(i=1;i<=NF;i++){
                        if($i ~ /^dport=/ && $i == "dport="dport) {
                            for(j=1;j<=NF;j++){
                                if($j ~ /^bytes=/){
                                    split($j,a,"="); total+=a[2]
                                }
                            }
                        }
                    }
                }
                END { print total }
            ' /proc/net/nf_conntrack 2>/dev/null || echo 0)

            ct_packets=$(awk -v proto="$proto" -v dport="$target_port" '
                BEGIN { total=0 }
                $3 == proto || $4 == proto {
                    for(i=1;i<=NF;i++){
                        if($i ~ /^dport=/ && $i == "dport="dport) {
                            for(j=1;j<=NF;j++){
                                if($j ~ /^packets=/){
                                    split($j,a,"="); total+=a[2]
                                }
                            }
                        }
                    }
                }
                END { print total }
            ' /proc/net/nf_conntrack 2>/dev/null || echo 0)

            if [ "${ct_bytes:-0}" -gt 0 ] 2>/dev/null; then
                stats="conntrack:${ct_packets:-0}:${ct_bytes}"
            fi
        fi
    fi

    echo "$stats"
}

# ============================ 端口冲突检测 ============================

check_port_conflict() {
    local port=$1
    local rule_name=$2
    local exclude_rule_id=${3:-0}

    local existing_rules
    existing_rules=$(iptables -t nat -L "$IPTABLES_CHAIN_NAT" -n 2>/dev/null | \
                    grep "dpt:$port" | grep -v "${RULE_COMMENT_PREFIX}_${exclude_rule_id}" | wc -l)

    if [ "$existing_rules" -gt 0 ]; then
        warn "端口 $port 已被其他规则使用" >&2
        return 1
    fi

    local listeners
    listeners=$(ss -ulpn -tlpn 2>/dev/null | grep ":$port " | grep -v "wg-relay-web" | wc -l)
    if [ "$listeners" -gt 0 ]; then
        warn "端口 $port 已被系统进程监听" >&2
        return 1
    fi

    return 0
}

# ============================ 主入口 ============================

case "$1" in
    add)
        acquire_lock; shift
        rule_id=$1; name=$2; protocol=$3; listen_ip=$4; listen_port=$5
        target_ip=$6; target_port=$7; enabled=$8; description=${9:-""}
        create_rule "$rule_id" "$name" "$protocol" "$listen_ip" "$listen_port" \
                    "$target_ip" "$target_port" "$enabled" "$description"
        apply_rule "$(get_rule_file "$rule_id")"
        release_lock
        ;;
    update)
        acquire_lock; shift
        rule_id=$1; updates=$2
        update_rule "$rule_id" "$updates"
        apply_rule "$(get_rule_file "$rule_id")"
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
        update_rule "$rule_id" "{\"enabled\": $enabled}"
        apply_rule "$(get_rule_file "$rule_id")"
        release_lock
        ;;
    reload)
        acquire_lock
        reload_all_rules
        release_lock
        ;;
    stats)
        shift
        rule_id=${1:-""}
        if [ -n "$rule_id" ]; then
            get_traffic_stats "$rule_id"
        else
            for rule_file in "$RULES_DIR"/rule_*.json; do
                [ -f "$rule_file" ] || continue
                r_id=$(basename "$rule_file" | sed 's/rule_//' | sed 's/\.json//')
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
    # BUG FIX: 原代码缺少 check_port_conflict 的 case 入口，
    # 导致 Web 应用调用 `wg-rule-manager check_port_conflict ...` 时走到 *) 分支报错。
    check_port_conflict)
        shift
        port=$1; rule_name=${2:-""}; exclude_id=${3:-0}
        if check_port_conflict "$port" "$rule_name" "$exclude_id"; then
            exit 0
        else
            exit 1
        fi
        ;;
    *)
        echo "流量转发中继管理系统"
        echo "用法: wg-rule-manager <命令> [参数]"
        echo "命令: add|update|delete|toggle|reload|stats|list|check_port_conflict"
        exit 1
        ;;
esac
