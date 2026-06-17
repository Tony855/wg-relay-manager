#!/bin/bash
set -e
set -o pipefail

# ===========================================
# WireGuard 多中继增强脚本 - 主入口
# ===========================================

# 定义项目根目录
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# 导入所有库文件
source "$PROJECT_ROOT/lib/utils.sh"
source "$PROJECT_ROOT/lib/input.sh"
source "$PROJECT_ROOT/lib/dependencies.sh"
source "$PROJECT_ROOT/lib/firewall.sh"
source "$PROJECT_ROOT/lib/config.sh"
source "$PROJECT_ROOT/lib/nginx.sh"
source "$PROJECT_ROOT/lib/web_app.sh"

# 定义配置目录和文件
CONFIG_DIR="/etc/wg-relay"
CONFIG_FILE="$CONFIG_DIR/config.json"
RULES_DIR="$CONFIG_DIR/rules"
LOG_FILE="/var/log/wg-relay.log"

# 确保配置目录存在
mkdir -p "$CONFIG_DIR"
mkdir -p "$RULES_DIR"
touch "$LOG_FILE"

# 检查并加载配置
load_config_from_file # 加载配置到全局变量

# 检查 root 权限
check_root

# 自动检测系统环境
detect_os
detect_network_interfaces

# 显示欢迎信息
show_welcome_message

# 主菜单
main_menu() {
    while true; do
        clear
        print_color "${GREEN}" "======================================================"
        print_color "${GREEN}" "  WireGuard 多中继增强脚本 - 主菜单"
        print_color "${GREEN}" "======================================================"
        print_color "${YELLOW}" "  当前中继名称: ${RELAY_NAME}"
        print_color "${YELLOW}" "  Web 管理地址: https://${PUBLIC_IP}"
        print_color "${GREEN}" "------------------------------------------------------"
        print_color "${BLUE}" "  1. 安装/更新 WireGuard 中继环境"
        print_color "${BLUE}" "  2. 管理转发规则 (命令行)"
        print_color "${BLUE}" "  3. 启动/停止/重启 Web 管理界面"
        print_color "${BLUE}" "  4. 配置系统参数"
        print_color "${BLUE}" "  5. 查看系统状态和日志"
        print_color "${BLUE}" "  6. 卸载脚本"
        print_color "${RED}" "  0. 退出"
        print_color "${GREEN}" "======================================================"

        read_input "请选择操作 [0-6]: " choice

        case "$choice" in
            1) install_update_environment ;;
            2) manage_rules_cli ;;
            3) manage_web_interface ;;
            4) configure_system_params ;;
            5) view_system_status_and_logs ;;
            6) uninstall_script ;;
            0) print_color "${GREEN}" "感谢使用，再见！"; exit 0 ;;
            *) print_color "${RED}" "无效选择，请重新输入。" ; sleep 1 ;;
        esac
        read -n 1 -s -r -p "按任意键继续..."
    done
}

# 安装/更新环境
install_update_environment() {
    info "开始安装/更新 WireGuard 中继环境..."
    install_dependencies
    setup_sysctl
    init_iptables_chain
    save_iptables_rules
    info "WireGuard 中继环境安装/更新完成。"
}

# 管理转发规则 (命令行)
manage_rules_cli() {
    while true; do
        clear
        print_color "${GREEN}" "======================================================"
        print_color "${GREEN}" "  转发规则管理 (命令行)"
        print_color "${GREEN}" "======================================================"
        print_color "${BLUE}" "  1. 列出所有规则"
        print_color "${BLUE}" "  2. 添加新规则"
        print_color "${BLUE}" "  3. 编辑规则"
        print_color "${BLUE}" "  4. 启用/禁用规则"
        print_color "${BLUE}" "  5. 删除规则"
        print_color "${BLUE}" "  6. 重新加载所有规则"
        print_color "${BLUE}" "  7. 查看规则流量统计"
        print_color "${RED}" "  0. 返回主菜单"
        print_color "${GREEN}" "======================================================"

        read_input "请选择操作 [0-7]: " choice

        case "$choice" in
            1) "$PROJECT_ROOT/scripts/rule_manager.sh" list ;;
            2) add_rule_interactive ;;
            3) edit_rule_interactive ;;
            4) toggle_rule_interactive ;;
            5) delete_rule_interactive ;;
            6) "$PROJECT_ROOT/scripts/rule_manager.sh" reload ;;
            7) "$PROJECT_ROOT/scripts/stats_collector.py" ;;
            0) break ;;
            *) print_color "${RED}" "无效选择，请重新输入。" ; sleep 1 ;;
        esac
        read -n 1 -s -r -p "按任意键继续..."
    done
}

add_rule_interactive() {
    info "添加新规则:"
    local name protocol listen_ip listen_port target_ip target_port enabled description
    read_input "规则名称: " name
    read_input "协议 (tcp/udp): " protocol
    read_input "监听IP (例如: 0.0.0.0 或 特定IP): " listen_ip
    read_input "监听端口: " listen_port
    read_input "目标IP: " target_ip
    read_input "目标端口: " target_port
    read_input "是否启用 (true/false): " enabled "true"
    read_input "描述 (可选): " description ""

    local next_id=$(get_next_rule_id_from_config)
    "$PROJECT_ROOT/scripts/rule_manager.sh" add "$next_id" "$name" "$protocol" "$listen_ip" "$listen_port" "$target_ip" "$target_port" "$enabled" "$description"
    info "规则添加成功。"
}

edit_rule_interactive() {
    info "编辑规则:"
    local rule_id
    read_input "请输入要编辑的规则ID: " rule_id
    
    local current_rule_json=$("$PROJECT_ROOT/scripts/rule_manager.sh" list | jq -c ".[] | select(.id == $rule_id)")
    if [ -z "$current_rule_json" ]; then
        error "规则ID $rule_id 不存在。"
        return 1
    fi

    local name protocol listen_ip listen_port target_ip target_port enabled description
    name=$(echo "$current_rule_json" | jq -r ".name")
    protocol=$(echo "$current_rule_json" | jq -r ".protocol")
    listen_ip=$(echo "$current_rule_json" | jq -r ".listen_ip")
    listen_port=$(echo "$current_rule_json" | jq -r ".listen_port")
    target_ip=$(echo "$current_rule_json" | jq -r ".target_ip")
    target_port=$(echo "$current_rule_json" | jq -r ".target_port")
    enabled=$(echo "$current_rule_json" | jq -r ".enabled")
    description=$(echo "$current_rule_json" | jq -r ".description")

    print_color "${CYAN}" "当前规则信息:"
    print_color "${CYAN}" "  名称: $name"
    print_color "${CYAN}" "  协议: $protocol"
    print_color "${CYAN}" "  监听: $listen_ip:$listen_port"
    print_color "${CYAN}" "  目标: $target_ip:$target_port"
    print_color "${CYAN}" "  启用: $enabled"
    print_color "${CYAN}" "  描述: $description"

    read_input "新规则名称 (留空则不修改): " new_name "$name"
    read_input "新协议 (tcp/udp, 留空则不修改): " new_protocol "$protocol"
    read_input "新监听IP (留空则不修改): " new_listen_ip "$listen_ip"
    read_input "新监听端口 (留空则不修改): " new_listen_port "$listen_port"
    read_input "新目标IP (留空则不修改): " new_target_ip "$target_ip"
    read_input "新目标端口 (留空则不修改): " new_target_port "$target_port"
    read_input "是否启用 (true/false, 留空则不修改): " new_enabled "$enabled"
    read_input "新描述 (留空则不修改): " new_description "$description"

    local updates="{}"
    [ "$new_name" != "$name" ] && updates=$(echo "$updates" | jq ".name = \"$new_name\"")
    [ "$new_protocol" != "$protocol" ] && updates=$(echo "$updates" | jq ".protocol = \"$new_protocol\"")
    [ "$new_listen_ip" != "$listen_ip" ] && updates=$(echo "$updates" | jq ".listen_ip = \"$new_listen_ip\"")
    [ "$new_listen_port" != "$listen_port" ] && updates=$(echo "$updates" | jq ".listen_port = $new_listen_port")
    [ "$new_target_ip" != "$target_ip" ] && updates=$(echo "$updates" | jq ".target_ip = \"$new_target_ip\"")
    [ "$new_target_port" != "$target_port" ] && updates=$(echo "$updates" | jq ".target_port = $new_target_port")
    [ "$new_enabled" != "$enabled" ] && updates=$(echo "$updates" | jq ".enabled = ($new_enabled | test(\"true\"))")
    [ "$new_description" != "$description" ] && updates=$(echo "$updates" | jq ".description = \"$new_description\"")

    if [ "$updates" = "{}" ]; then
        info "没有检测到修改，取消更新。"
        return 0
    fi

    "$PROJECT_ROOT/scripts/rule_manager.sh" update "$rule_id" "$updates"
    info "规则 $rule_id 更新成功。"
}

toggle_rule_interactive() {
    info "启用/禁用规则:"
    local rule_id
    read_input "请输入要启用/禁用的规则ID: " rule_id
    
    local current_enabled=$("$PROJECT_ROOT/scripts/rule_manager.sh" list | jq -r ".[] | select(.id == $rule_id) | .enabled")
    if [ -z "$current_enabled" ]; then
        error "规则ID $rule_id 不存在。"
        return 1
    fi

    local new_enabled
    if [ "$current_enabled" = "true" ]; then
        read_input "当前规则已启用。是否禁用？ (true/false): " new_enabled "false"
    else
        read_input "当前规则已禁用。是否启用？ (true/false): " new_enabled "true"
    fi

    "$PROJECT_ROOT/scripts/rule_manager.sh" toggle "$rule_id" "$new_enabled"
    info "规则 $rule_id 状态已切换。"
}

delete_rule_interactive() {
    info "删除规则:"
    local rule_id
    read_input "请输入要删除的规则ID: " rule_id
    confirm_action "确定要删除规则 $rule_id 吗？ (y/N): " || return 1
    "$PROJECT_ROOT/scripts/rule_manager.sh" delete "$rule_id"
    info "规则 $rule_id 删除成功。"
}

# 管理 Web 界面
manage_web_interface() {
    while true; do
        clear
        print_color "${GREEN}" "======================================================"
        print_color "${GREEN}" "  Web 管理界面操作"
        print_color "${GREEN}" "======================================================"
        print_color "${BLUE}" "  1. 启动 Web 管理界面"
        print_color "${BLUE}" "  2. 停止 Web 管理界面"
        print_color "${BLUE}" "  3. 重启 Web 管理界面"
        print_color "${BLUE}" "  4. 重新配置 Nginx 和 SSL"
        print_color "${RED}" "  0. 返回主菜单"
        print_color "${GREEN}" "======================================================"

        read_input "请选择操作 [0-4]: " choice

        case "$choice" in
            1) start_web_app ;;
            2) stop_web_app ;;
            3) restart_web_app ;;
            4) setup_nginx_and_ssl ;;
            0) break ;;
            *) print_color "${RED}" "无效选择，请重新输入。" ; sleep 1 ;;
        esac
        read -n 1 -s -r -p "按任意键继续..."
    done
}

# 配置系统参数
configure_system_params() {
    info "配置系统参数:"
    local current_config_json=$(cat "$CONFIG_FILE")
    local current_relay_name=$(echo "$current_config_json" | jq -r ".relay_name")
    local current_web_user=$(echo "$current_config_json" | jq -r ".web_user")
    local current_public_interface=$(echo "$current_config_json" | jq -r ".public_interface")

    print_color "${CYAN}" "当前配置信息:"
    print_color "${CYAN}" "  中继名称: $current_relay_name"
    print_color "${CYAN}" "  Web 用户名: $current_web_user"
    print_color "${CYAN}" "  公网接口: $current_public_interface"

    read_input "新中继名称 (留空则不修改): " new_relay_name "$current_relay_name"
    read_input "新Web管理员用户名 (留空则不修改): " new_web_user "$current_web_user"
    read_input "新Web管理员密码 (留空则不修改): " new_web_pass ""
    read_input "新公网接口 (例如: eth0, 留空则不修改): " new_public_interface "$current_public_interface"

    local updates="{}"
    [ "$new_relay_name" != "$current_relay_name" ] && updates=$(echo "$updates" | jq ".relay_name = \"$new_relay_name\"")
    [ "$new_web_user" != "$current_web_user" ] && updates=$(echo "$updates" | jq ".web_user = \"$new_web_user\"")
    [ -n "$new_web_pass" ] && updates=$(echo "$updates" | jq --arg web_pass_hash "$(generate_web_password_hash "$new_web_pass")" '.web_pass_hash = $web_pass_hash')
    [ "$new_public_interface" != "$current_public_interface" ] && updates=$(echo "$updates" | jq ".public_interface = \"$new_public_interface\"")

    if [ "$updates" = "{}" ]; then
        info "没有检测到修改，取消更新。"
        return 0
    fi

    update_config_file "$updates"
    info "系统参数更新成功。"
    load_config_from_file # 重新加载配置到全局变量
}

# 查看系统状态和日志
view_system_status_and_logs() {
    while true; do
        clear
        print_color "${GREEN}" "======================================================"
        print_color "${GREEN}" "  系统状态和日志"
        print_color "${GREEN}" "======================================================"
        print_color "${BLUE}" "  1. 查看实时系统状态 (CPU, 内存, 磁盘, 流量等)"
        print_color "${BLUE}" "  2. 查看脚本运行日志"
        print_color "${RED}" "  0. 返回主菜单"
        print_color "${GREEN}" "======================================================"

        read_input "请选择操作 [0-2]: " choice

        case "$choice" in
            1) view_realtime_status ;;
            2) view_script_logs ;;
            0) break ;;
            *) print_color "${RED}" "无效选择，请重新输入。" ; sleep 1 ;;
        esac
        read -n 1 -s -r -p "按任意键继续..."
    done
}

view_realtime_status() {
    info "正在获取实时系统状态..."
    python3 "$PROJECT_ROOT/scripts/stats_collector.py"
}

view_script_logs() {
    info "正在查看脚本运行日志 (最近50行)..."
    tail -n 50 "$LOG_FILE" || warn "日志文件不存在或为空。"
}

# 卸载脚本
uninstall_script() {
    confirm_action "确定要卸载 WireGuard 多中继增强脚本吗？这将删除所有相关文件和配置。 (y/N): " || return 1
    info "开始卸载脚本..."
    stop_web_app # 停止 Web 服务
    disable_nginx_proxy # 禁用 Nginx 代理
    cleanup_iptables_rules # 清理 iptables 规则
    remove_systemd_services # 移除 systemd 服务
    remove_files_and_dirs # 移除文件和目录
    info "脚本卸载完成。"
}

# 运行主菜单
main_menu
