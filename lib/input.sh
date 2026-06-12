#!/bin/bash

# ===========================================
# 用户输入和参数解析函数库
# ===========================================

LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$LIB_DIR/utils.sh"

# ============================ 参数解析函数 ============================

parse_arguments() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            --name) RELAY_NAME="$2"; shift 2 ;;
            --master-ip) MASTER_IP="$2"; shift 2 ;;
            --master-port) MASTER_PORT="$2"; shift 2 ;;
            --relay-port) RELAY_PORT="$2"; shift 2 ;;
            --domain) DOMAIN_NAME="$2"; ENABLE_SSL=true; shift 2 ;;
            --email) EMAIL_ADDRESS="$2"; shift 2 ;;
            --web-user) WEB_USER="$2"; shift 2 ;;
            --web-pass) WEB_PASS="$2"; shift 2 ;;
            --no-ssl) SKIP_SSL=true; shift ;;
            --non-interactive|-n) NON_INTERACTIVE=true; shift ;;
            --help|-h) show_help; exit 0 ;;
            *) error "未知参数: $1" ;;
        esac
    done
}

show_help() {
    cat << EOF
流量转发中继管理系统安装脚本 v$SCRIPT_VERSION

用法: $0 [选项]

选项:
  --name NAME             中继服务器名称 (默认: 流量转发中继管理系统)
  --master-ip IP          主服务器IP地址 (可选，安装后可在Web界面添加)
  --master-port PORT      主服务器端口 (可选)
  --relay-port PORT       中继服务器端口 (可选)
  --domain DOMAIN         域名 (启用SSL)
  --email EMAIL           邮箱地址 (用于SSL证书)
  --web-user USER         Web管理员用户名 (默认: admin)
  --web-pass PASS         Web管理员密码 (默认: 自动生成)
  --no-ssl                禁用SSL
  --non-interactive, -n   非交互模式
  --help, -h              显示此帮助信息

示例:
  $0 --name relay-hk-01
  $0 --name relay-us-01 --domain relay.example.com --email admin@example.com
  $0 --no-ssl --non-interactive
EOF
}

# ============================ 输入验证函数 ============================

validate_port() {
    local port=$1
    local name=$2
    
    if ! [[ "$port" =~ ^[0-9]+$ ]] || [ "$port" -lt 1 ] || [ "$port" -gt 65535 ]; then
        error "${name:-端口号}无效: $port，请输入1-65535之间的数字"
    fi
}

validate_ip() {
    local ip="$1"
    [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || return 1
    IFS=. read -r a b c d <<< "$ip"
    for i in $a $b $c $d; do
        ((i>=0 && i<=255)) || return 1
    done
    return 0
}

validate_inputs() {
    # 仅当参数非空时才验证格式
    if [ -n "$MASTER_PORT" ]; then
        validate_port "$MASTER_PORT" "主服务器端口"
    fi
    if [ -n "$RELAY_PORT" ]; then
        validate_port "$RELAY_PORT" "中继服务器端口"
    fi
    if [ -n "$MASTER_IP" ]; then
        if ! validate_ip "$MASTER_IP"; then
            error "主服务器IP地址格式无效: $MASTER_IP"
        fi
    fi
}

# ============================ 用户输入函数 ============================

get_user_input() {
    echo -e "${CYAN}================================"
    echo "流量转发中继管理系统配置"
    echo -e "================================${NC}"
    
    # 确保WEB_PASS不为空
    if [ -z "$WEB_PASS" ]; then
        WEB_PASS=$(openssl rand -base64 16 2>/dev/null | tr -dc 'A-Za-z0-9!@#$%^&*()_+-=' | head -c16 || echo "Admin123!@#456789")
        info "已自动生成Web管理员密码"
    fi
    
    [ -z "$RELAY_NAME" ] && {
        read -p "请输入中继服务器名称（默认: relay-server）: " RELAY_NAME
        [ -z "$RELAY_NAME" ] && RELAY_NAME="relay-server"
    }
    
    # 以下参数不再强制输入，留空即可
    echo -e "${YELLOW}提示: 主服务器和目标转发规则可在安装后通过Web管理界面添加，此处可留空${NC}"
    read -p "请输入主服务器IP地址（可选，留空则后续添加）: " input_master_ip
    if [ -n "$input_master_ip" ]; then
        MASTER_IP="$input_master_ip"
        # 如果输入了主服务器IP，再询问端口
        read -p "请输入主服务器端口（可选）: " input_master_port
        if [[ "$input_master_port" =~ ^[0-9]+$ ]] && [ "$input_master_port" -ge 1 ] && [ "$input_master_port" -le 65535 ]; then
            MASTER_PORT="$input_master_port"
        elif [ -n "$input_master_port" ]; then
            echo -e "${RED}端口无效，已忽略${NC}"
        fi
        
        read -p "请输入中继服务器端口（可选，用于接收客户端流量）: " input_relay_port
        if [[ "$input_relay_port" =~ ^[0-9]+$ ]] && [ "$input_relay_port" -ge 1 ] && [ "$input_relay_port" -le 65535 ]; then
            RELAY_PORT="$input_relay_port"
        elif [ -n "$input_relay_port" ]; then
            echo -e "${RED}端口无效，已忽略${NC}"
        fi
    fi
    
    [ -z "$WEB_USER" ] && WEB_USER="admin"
    
    # 显示生成的密码
    info "Web管理员密码: $WEB_PASS"
    
    # 生成密码哈希
    WEB_PASS_HASH=$(python3 -c "from werkzeug.security import generate_password_hash; print(generate_password_hash(\'$WEB_PASS\'))" 2>/dev/null || echo "")
    
    configure_ssl_options
    validate_inputs
    show_config_summary
}

configure_ssl_options() {
    echo -e "${MAGENTA}=== Nginx配置 ===${NC}"
    
    local system_fqdn=$(hostname -f 2>/dev/null)
    local system_hostname=$(hostname 2>/dev/null)
    local detected_domain=""
    
    if [[ "$system_fqdn" =~ \. ]]; then
        detected_domain="$system_fqdn"
    elif [[ "$system_hostname" =~ \. ]]; then
        detected_domain="$system_hostname"
    fi
    
    local invalid_hostnames=("localhost" "localhost.localdomain" "ip6-localhost" "ip6-loopback")
    for invalid in "${invalid_hostnames[@]}"; do
        if [[ "$detected_domain" == "$invalid" ]]; then
            detected_domain=""
            break
        fi
    done
    
    if [ -z "$WEB_PASS" ]; then
        WEB_PASS=$(openssl rand -base64 16 2>/dev/null | tr -dc 'A-Za-z0-9!@#$%^&*()_+-=' | head -c16 || echo "Admin123!@#456789")
        info "已自动生成Web管理员密码: $WEB_PASS"
    fi
    
    WEB_PASS_HASH=$(python3 -c "from werkzeug.security import generate_password_hash; print(generate_password_hash(\'$WEB_PASS\'))" 2>/dev/null || echo "")
    
    if $SKIP_SSL; then
        ENABLE_SSL=false
        info "SSL已被禁用"
    elif [ -n "$DOMAIN_NAME" ]; then
        ENABLE_SSL=true
        info "将使用域名: $DOMAIN_NAME"
    elif [ "$NON_INTERACTIVE" = false ]; then
        local prompt_text="请输入访问域名（用于SSL证书"
        if [ -n "$detected_domain" ]; then
            prompt_text="$prompt_text，留空使用 \"$detected_domain\""
        else
            prompt_text="$prompt_text，留空跳过SSL"
        fi
        prompt_text="$prompt_text）: "
        
        read -p "$prompt_text" DOMAIN_NAME
        
        if [ -n "$DOMAIN_NAME" ]; then
            ENABLE_SSL=true
            read -p "是否启用HTTP到HTTPS重定向？（默认: y）[y/N]: " https_redirect
            [ -z "$https_redirect" ] && https_redirect="y"
            [[ "$https_redirect" == "n" || "$https_redirect" == "N" ]] && \
                ENABLE_HTTPS_REDIRECT=false
            
            read -p "请输入邮箱地址（用于SSL证书，可选，默认: $EMAIL_ADDRESS）: " input_email
            if [ -n "$input_email" ]; then
                EMAIL_ADDRESS="$input_email"
            fi
        else
            if [ -n "$detected_domain" ]; then
                DOMAIN_NAME="$detected_domain"
                ENABLE_SSL=true
                echo ""
                info "检测到有效域名，自动使用: $DOMAIN_NAME"
                
                read -p "是否启用HTTP到HTTPS重定向？（默认: y）[y/N]: " https_redirect
                [ -z "$https_redirect" ] && https_redirect="y"
                [[ "$https_redirect" == "n" || "$https_redirect" == "N" ]] && \
                    ENABLE_HTTPS_REDIRECT=false
                    
                read -p "请输入邮箱地址（用于SSL证书，可选，默认: $EMAIL_ADDRESS）: " input_email
                if [ -n "$input_email" ]; then
                    EMAIL_ADDRESS="$input_email"
                fi
            else
                echo ""
                read -p "未检测到有效域名，是否使用自签名SSL证书？（默认: n）[y/N]: " self_signed
                if [[ "$self_signed" == "y" || "$self_signed" == "Y" ]]; then
                    ENABLE_SSL=true
                    DOMAIN_NAME="localhost"
                    warn "将使用自签名SSL证书，浏览器会显示安全警告"
                fi
            fi
        fi
    else
        if [ -z "$DOMAIN_NAME" ] && [ -n "$detected_domain" ]; then
            DOMAIN_NAME="$detected_domain"
            ENABLE_SSL=true
            info "非交互模式：使用检测到的域名: $DOMAIN_NAME"
        fi
    fi
}

show_config_summary() {
    echo -e "\n${CYAN}配置摘要:${NC}"
    cat << EOF
  中继名称: $RELAY_NAME
  主服务器: ${MASTER_IP:-未配置}${MASTER_PORT:+:$MASTER_PORT}
  转发端口: ${RELAY_PORT:-未配置}
  Web用户: $WEB_USER
  Web密码: [已保存至 /etc/wg-relay/.credentials，权限600]
  SSL状态: $([ "$ENABLE_SSL" = true ] && echo "启用" || echo "禁用")
EOF
    
    [ "$ENABLE_SSL" = true ] && {
        echo "  域名: ${DOMAIN_NAME:-无}"
        echo "  HTTPS重定向: $([ "$ENABLE_HTTPS_REDIRECT" = true ] && echo "启用" || echo "禁用")"
    }
    echo ""
    
    echo -e "${YELLOW}端口使用情况:${NC}"
    [ -n "$RELAY_PORT" ] && echo "  中继端口 ($RELAY_PORT): 用于接收客户端流量"
    [ -n "$MASTER_PORT" ] && echo "  主服务器端口 ($MASTER_PORT): 目标服务器端口"
    [ "$ENABLE_SSL" = false ] && echo "  Web端口 ($NGINX_PORT): Web管理界面"
    [ "$ENABLE_SSL" = true ] && echo "  HTTPS端口 ($SSL_PORT): Web管理界面(SSL)"
    echo ""
    
    echo -e "${YELLOW}注意: 主服务器信息和转发规则请在安装完成后通过Web管理后台添加${NC}"
    echo ""
    
    [ "$NON_INTERACTIVE" = false ] && {
        read -p "确认配置是否正确？(y/N): " confirm
        [[ "$confirm" != "y" && "$confirm" != "Y" ]] && {
            echo "安装已取消"
            exit 0
        }
    }
}

read_input() {
    local prompt=$1
    local var_name=$2
    local default_val=$3
    local input_val
    
    if [ -n "$default_val" ]; then
        read -p "$prompt [$default_val]: " input_val
        [ -z "$input_val" ] && eval "$var_name=\"$default_val\"" || eval "$var_name=\"$input_val\""
    else
        read -p "$prompt: " input_val
        eval "$var_name=\"$input_val\""
    fi
}

confirm_action() {
    local prompt=$1
    local confirm
    read -p "$prompt" confirm
    [[ "$confirm" == "y" || "$confirm" == "Y" ]]
}
