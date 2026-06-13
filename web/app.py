#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# ===========================================
# Flask Web 应用 (web/ 目录独立版本)
# 注意：生产部署版本由 lib/web_app.sh 生成至 /etc/wg-relay-web/app.py
#       本文件为开发参考版本，两者逻辑保持一致。
# ===========================================

import os
import json
import time
import subprocess
from datetime import datetime, timedelta
from functools import wraps

from flask import Flask, render_template, request, redirect, url_for, session, jsonify
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = os.urandom(24)
app.permanent_session_lifetime = timedelta(days=7)

CONFIG_FILE = "/etc/wg-relay/config.json"
LOG_FILE    = "/var/log/wg-relay.log"


# ============================ 工具函数 ============================

def load_config():
    if not os.path.exists(CONFIG_FILE):
        return {
            "relay_name":     "WG Relay Manager",
            "web_user":       "admin",
            # BUG FIX: 原代码用 sha256 哈希密码，但 lib/web_app.sh 部署版使用 werkzeug。
            # 统一改用 werkzeug，保持两个版本一致，避免登录失败。
            "web_pass_hash":  generate_password_hash("admin"),
            "public_interface": "eth0",
            "public_ip":      "127.0.0.1",
            "next_rule_id":   1,
        }
    with open(CONFIG_FILE, "r", encoding="utf-8") as f:
        return json.load(f)


def save_config(config):
    os.makedirs(os.path.dirname(CONFIG_FILE), exist_ok=True)
    with open(CONFIG_FILE, "w", encoding="utf-8") as f:
        json.dump(config, f, indent=4, ensure_ascii=False)


def log_event(level, message):
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    log_message = f"[{timestamp}] [{level.upper()}] {message}"
    print(log_message)
    try:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(log_message + "\n")
    except OSError:
        pass


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "logged_in" not in session:
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated_function


# BUG FIX: 原代码 run_shell_command 总是使用 shell=True 并期待字符串命令，
# 但调用方有时传入 list（如 add_rule 中的 command 列表）。
# 修复：接受 list 或 str，分别用不同方式执行。
def run_shell_command(command, check=True):
    """执行 shell 命令，command 可以是字符串或列表。"""
    try:
        if isinstance(command, list):
            result = subprocess.run(command, capture_output=True, text=True, check=check)
        else:
            result = subprocess.run(command, capture_output=True, text=True,
                                    check=check, shell=True)
        return result.stdout.strip(), result.stderr.strip()
    except subprocess.CalledProcessError as e:
        log_event("error", f"命令执行失败: {command} -> {e.stderr}")
        raise


def get_next_rule_id():
    config = load_config()
    next_id = config.get("next_rule_id", 1)
    config["next_rule_id"] = next_id + 1
    save_config(config)
    return next_id


def format_bytes(bytes_count):
    if bytes_count is None:
        return "0 B"
    for unit in ["B", "KB", "MB", "GB", "TB", "PB"]:
        if bytes_count < 1024:
            return f"{bytes_count:.2f} {unit}"
        bytes_count /= 1024
    return f"{bytes_count:.2f} PB"


def format_bits(bits_count):
    if bits_count is None:
        return "0 bps"
    for unit in ["bps", "Kbps", "Mbps", "Gbps", "Tbps", "Pbps"]:
        if bits_count < 1000:
            return f"{bits_count:.2f} {unit}"
        bits_count /= 1000
    return f"{bits_count:.2f} Pbps"


# 存储网络接口历史流量数据（进程生命周期内有效）
_traffic_history = {}


def _get_interface_speeds(interface):
    """从 /proc/net/dev 计算瞬时上下行速度（bps）。"""
    current_time = time.time()
    net_dev_output, _ = run_shell_command(f"grep '{interface}:' /proc/net/dev", check=False)
    if net_dev_output:
        parts = net_dev_output.split()
        current_rx = int(parts[1])
        current_tx = int(parts[9])
    else:
        current_rx = current_tx = 0

    hist = _traffic_history.get(interface, {})
    last_time = hist.get("timestamp", current_time)
    last_rx   = hist.get("rx_bytes",  current_rx)
    last_tx   = hist.get("tx_bytes",  current_tx)

    time_diff = max(current_time - last_time, 1)
    download_speed_bps = (current_rx - last_rx) / time_diff * 8
    upload_speed_bps   = (current_tx - last_tx) / time_diff * 8

    _traffic_history[interface] = {
        "timestamp": current_time,
        "rx_bytes":  current_rx,
        "tx_bytes":  current_tx,
    }

    return {
        "upload_speed":            upload_speed_bps,
        "download_speed":          download_speed_bps,
        "upload_speed_formatted":  format_bits(upload_speed_bps),
        "download_speed_formatted":format_bits(download_speed_bps),
        "total_upload":            current_tx,
        "total_download":          current_rx,
        "total_upload_formatted":  format_bytes(current_tx),
        "total_download_formatted":format_bytes(current_rx),
    }


def _load_forward_rules_with_stats():
    """调用 wg-rule-manager list 并附加流量统计。"""
    stdout, _ = run_shell_command("wg-rule-manager list", check=False)
    rules_raw = stdout.strip().split("\n\n")
    rules = []
    for rule_json_str in rules_raw:
        rule_json_str = rule_json_str.strip()
        if not rule_json_str:
            continue
        try:
            rule = json.loads(rule_json_str)
        except json.JSONDecodeError:
            log_event("warn", f"无法解析规则JSON: {rule_json_str[:80]}")
            continue

        # 附加流量统计
        stats_output, _ = run_shell_command(
            ["wg-rule-manager", "stats", str(rule["id"])], check=False
        )
        total_bytes = 0
        for part in stats_output.split(";"):
            if part.startswith("conntrack:"):
                segs = part.split(":")
                if len(segs) == 3:
                    try:
                        total_bytes += int(segs[2])
                    except ValueError:
                        pass

        rule["rule_id"] = rule.get("id")
        rule["traffic_stats"] = {
            "total_bytes":             total_bytes,
            "total_bytes_formatted":   format_bytes(total_bytes),
            "current_speed":           0,
            "current_speed_formatted": "0 bps",
            "instant_speed":           0,
            "max_speed_10s":           1,
        }
        rules.append(rule)

    rules.sort(key=lambda x: x.get("id", 0))
    return rules


# ============================ 路由 ============================

@app.route("/")
@login_required
def index():
    config = load_config()
    rules  = {"forward_rules": _load_forward_rules_with_stats()}
    return render_template("rules.html", config=config, rules=rules, now=datetime.now())


@app.route("/rules")
@login_required
def rules_management():
    return index()


@app.route("/login", methods=["GET", "POST"])
def login():
    config = load_config()
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        remember = bool(request.form.get("remember"))

        # BUG FIX: 统一使用 werkzeug check_password_hash 验证
        if username == config.get("web_user") and \
                check_password_hash(config.get("web_pass_hash", ""), password):
            session["logged_in"] = True
            session["username"]  = username
            session.permanent    = remember
            log_event("info", f"用户 {username} 登录成功")
            return redirect(url_for("index"))
        else:
            log_event("warn", f"用户 {username} 登录失败")
            return render_template("login.html", error="用户名或密码错误", config=config)

    return render_template("login.html", config=config)


@app.route("/logout")
@login_required
def logout():
    username = session.get("username", "未知用户")
    session.clear()
    log_event("info", f"用户 {username} 已登出")
    return redirect(url_for("login"))


# ============================ API ============================

@app.route("/api/status")
@login_required
def api_status():
    try:
        cpu_percent, _ = run_shell_command(
            "grep 'cpu ' /proc/stat | awk '{usage=($2+$4)*100/($2+$4+$5)} END {print usage}'",
            check=False
        )
        cpu_percent = float(cpu_percent) if cpu_percent else 0.0

        mem_info, _ = run_shell_command("free | grep Mem", check=False)
        mem_parts   = mem_info.split()
        total_mem   = int(mem_parts[1])
        used_mem    = int(mem_parts[2])
        memory_percent = (used_mem / total_mem * 100) if total_mem > 0 else 0.0

        disk_info, _ = run_shell_command(
            "df -h / | awk 'NR==2 {print $5}' | sed 's/%//'", check=False
        )
        disk_percent = float(disk_info) if disk_info else 0.0

        conn_count, _ = run_shell_command(
            "wc -l /proc/net/nf_conntrack 2>/dev/null || echo 0", check=False
        )
        connection_stats = int(conn_count) if conn_count else 0

        uptime_raw, _ = run_shell_command(
            "cat /proc/uptime | awk -F. '{print $1}'", check=False
        )
        uptime_seconds = int(uptime_raw) if uptime_raw else 0
        uptime_str = (
            f"{uptime_seconds // 86400}天 "
            f"{(uptime_seconds % 86400) // 3600}小时 "
            f"{(uptime_seconds % 3600) // 60}分钟"
        )

        web_status,   _ = run_shell_command("systemctl is-active wg-relay-web", check=False)
        nginx_status, _ = run_shell_command("systemctl is-active nginx",        check=False)

        config    = load_config()
        interface = config.get("public_interface", "eth0")
        speeds    = _get_interface_speeds(interface)

        return jsonify({
            "status": "success",
            "data": {
                "cpu_percent":             round(cpu_percent, 2),
                "memory_percent":          round(memory_percent, 2),
                "disk_percent":            round(disk_percent, 2),
                "connection_stats":        connection_stats,
                "uptime":                  uptime_str,
                "web_status":              web_status.strip(),
                "nginx_status":            nginx_status.strip(),
                "public_interface":        interface,
                "public_ip":               config.get("public_ip", "未知"),
                **speeds,
            }
        })
    except Exception as e:
        log_event("error", f"获取系统状态失败: {e}")
        return jsonify({"status": "error", "message": str(e)}), 500


# BUG FIX: 原代码将路由 `/api/rules` 绑定到名为 get_forward_rules 的函数，
# 同时其他函数（delete_rule 等）与 Flask 内置或其他路由函数同名，
# 导致路由注册冲突或函数被覆盖。统一以 api_ 前缀命名所有 API 路由函数。

@app.route("/api/rules")
@login_required
def api_get_rules():
    try:
        rules = _load_forward_rules_with_stats()
        return jsonify({"status": "success", "data": rules})
    except Exception as e:
        log_event("error", f"获取转发规则失败: {e}")
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route("/api/rules/add", methods=["POST"])
@login_required
def api_add_rule():
    try:
        data        = request.get_json()
        name        = data["name"]
        protocol    = data["protocol"]
        listen_ip   = data["listen_ip"]
        listen_port = data["listen_port"]
        target_ip   = data["target_ip"]
        target_port = data["target_port"]
        enabled     = str(data.get("enabled", True)).lower()
        description = data.get("description", "")

        # 检查端口冲突（通过 wg-rule-manager check_port_conflict 子命令）
        _, stderr = run_shell_command(
            ["wg-rule-manager", "check_port_conflict", str(listen_port), name, "0"],
            check=False
        )
        if stderr:
            return jsonify({"status": "error", "message": stderr}), 400

        rule_id = get_next_rule_id()
        # BUG FIX: 使用列表传参，避免 shell=True 下空格分词问题
        run_shell_command([
            "wg-rule-manager", "add",
            str(rule_id), name, protocol, listen_ip, str(listen_port),
            target_ip, str(target_port), enabled, description
        ])
        log_event("info", f"添加规则 {rule_id}: {name}")
        return jsonify({"status": "success", "message": "规则添加成功", "rule_id": rule_id})
    except Exception as e:
        log_event("error", f"添加规则失败: {e}")
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route("/api/rules/update/<int:rule_id>", methods=["POST"])
@login_required
def api_update_rule(rule_id):
    try:
        data    = request.get_json()
        updates = {}
        for field in ("name", "protocol", "listen_ip", "listen_port",
                      "target_ip", "target_port", "enabled", "description"):
            if field in data:
                updates[field] = data[field]

        if "listen_port" in updates:
            _, stderr = run_shell_command(
                ["wg-rule-manager", "check_port_conflict",
                 str(updates["listen_port"]), updates.get("name", ""), str(rule_id)],
                check=False
            )
            if stderr:
                return jsonify({"status": "error", "message": stderr}), 400

        updates_json = json.dumps(updates, ensure_ascii=False)
        run_shell_command(["wg-rule-manager", "update", str(rule_id), updates_json])
        log_event("info", f"更新规则 {rule_id}")
        return jsonify({"status": "success", "message": "规则更新成功"})
    except Exception as e:
        log_event("error", f"更新规则失败: {e}")
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route("/api/rules/delete/<int:rule_id>", methods=["POST"])
@login_required
def api_delete_rule(rule_id):
    try:
        run_shell_command(["wg-rule-manager", "delete", str(rule_id)])
        log_event("info", f"删除规则 {rule_id}")
        return jsonify({"status": "success", "message": "规则删除成功"})
    except Exception as e:
        log_event("error", f"删除规则失败: {e}")
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route("/api/rules/toggle/<int:rule_id>", methods=["POST"])
@login_required
def api_toggle_rule(rule_id):
    try:
        data    = request.get_json()
        enabled = str(data["enabled"]).lower()
        run_shell_command(["wg-rule-manager", "toggle", str(rule_id), enabled])
        log_event("info", f"切换规则 {rule_id} 状态为 {enabled}")
        return jsonify({"status": "success", "message": "规则状态切换成功"})
    except Exception as e:
        log_event("error", f"切换规则状态失败: {e}")
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route("/api/rules/reload", methods=["POST"])
@login_required
def api_reload_rules():
    try:
        run_shell_command(["wg-rule-manager", "reload"])
        log_event("info", "所有规则已重新加载")
        return jsonify({"status": "success", "message": "所有规则已重新加载"})
    except Exception as e:
        log_event("error", f"重新加载规则失败: {e}")
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route("/api/config", methods=["GET", "POST"])
@login_required
def api_config():
    config = load_config()
    if request.method == "POST":
        try:
            data = request.get_json()
            if "relay_name" in data:
                config["relay_name"] = data["relay_name"]
            if "web_user" in data:
                config["web_user"] = data["web_user"]
            if data.get("new_web_pass"):
                config["web_pass_hash"] = generate_password_hash(data["new_web_pass"])
            save_config(config)
            log_event("info", "系统配置已更新")
            return jsonify({"status": "success", "message": "配置更新成功"})
        except Exception as e:
            log_event("error", f"更新系统配置失败: {e}")
            return jsonify({"status": "error", "message": str(e)}), 500
    else:
        display = {k: v for k, v in config.items() if k != "web_pass_hash"}
        return jsonify({"status": "success", "data": display})


@app.route("/api/logs")
@login_required
def api_logs():
    try:
        if not os.path.exists(LOG_FILE):
            return jsonify({"status": "success", "data": ["日志文件不存在"]})
        with open(LOG_FILE, "r", encoding="utf-8") as f:
            logs = f.readlines()[-500:]
        return jsonify({"status": "success", "data": logs})
    except Exception as e:
        log_event("error", f"读取日志失败: {e}")
        return jsonify({"status": "error", "message": str(e)}), 500


if __name__ == "__main__":
    if not os.path.exists(CONFIG_FILE):
        save_config(load_config())
    config = load_config()
    app.run(host="0.0.0.0", port=config.get("web_port", 8080), debug=False)
