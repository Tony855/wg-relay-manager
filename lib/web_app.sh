#!/bin/bash

# ===========================================
# Web 应用部署函数库
# ===========================================

LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$LIB_DIR/utils.sh"

# ============================ Web管理界面 ============================

create_web_interface() {
    info "创建Web管理界面..."

    create_web_app_files
    create_web_service
    start_web_service
}

# BUG FIX: 原代码 create_web_app_files 末尾重复写了一次 systemd 服务文件
# （create_web_service 已经负责写该文件），此处已移除重复部分。
# 同时修正了 app.py heredoc 结尾的 \'EOF\' → EOF（单引号导致 heredoc 不展开，
# 但真正的问题是结尾标记被错误地写成了 \'EOF\'，shell 无法识别）。
create_web_app_files() {
    mkdir -p "$WEB_DIR/templates" "$WEB_DIR/static/css" "$WEB_DIR/static/js" "$WEB_DIR/static/img"

    # ---------- app.py ----------
    cat > "$WEB_DIR/app.py" << 'PYEOF'
import os
import json
import time
import subprocess
import threading
import copy
from datetime import datetime, timedelta
from collections import deque
from functools import wraps

import psutil
from flask import Flask, render_template, request, redirect, url_for, session, jsonify
from werkzeug.security import generate_password_hash, check_password_hash

# ============================ 配置 ============================
CONFIG_DIR  = "/etc/wg-relay"
RULES_DIR   = os.path.join(CONFIG_DIR, "rules")
LOG_FILE    = "/var/log/wg-relay.log"
CREDENTIALS_FILE = os.path.join(CONFIG_DIR, ".credentials")

app = Flask(__name__)
app.secret_key = os.urandom(24)
app.permanent_session_lifetime = timedelta(days=7)

# 全局流量统计变量
app.rule_traffic_stats = {}
app.interface_speeds   = {}
traffic_stats_lock     = threading.Lock()

# ============================ 辅助函数 ============================

def log_event(level, message, username=None):
    timestamp  = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    user_info  = f"[User: {username}] " if username else ""
    log_message = f"[{timestamp}] [{level.upper()}] {user_info}{message}"
    print(log_message)
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(log_message + "\n")

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get("logged_in"):
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated_function

def handle_errors(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        try:
            return f(*args, **kwargs)
        except Exception as e:
            log_event("error", f"API错误: {request.path} - {str(e)}", session.get("username"))
            return jsonify({"status": "error", "message": str(e)}), 500
    return decorated_function

def load_config():
    config_path = os.path.join(CONFIG_DIR, "config.json")
    if os.path.exists(config_path):
        with open(config_path, "r", encoding="utf-8") as f:
            return json.load(f)
    return {}

def save_config(config):
    config_path = os.path.join(CONFIG_DIR, "config.json")
    with open(config_path, "w", encoding="utf-8") as f:
        json.dump(config, f, indent=4, ensure_ascii=False)

def load_forward_rules():
    rules = []
    os.makedirs(RULES_DIR, exist_ok=True)
    for filename in os.listdir(RULES_DIR):
        if filename.startswith("rule_") and filename.endswith(".json"):
            filepath = os.path.join(RULES_DIR, filename)
            try:
                with open(filepath, "r", encoding="utf-8") as f:
                    rule = json.load(f)
                    rules.append(rule)
            except json.JSONDecodeError as e:
                log_event("error", f"解析规则文件失败 {filepath}: {e}")
            except Exception as e:
                log_event("error", f"读取规则文件失败 {filepath}: {e}")
    rules.sort(key=lambda x: x.get("id", 0))
    return {"forward_rules": rules}

def format_bytes(bytes_count):
    if bytes_count is None:
        return "0 B"
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if bytes_count < 1024:
            return f"{bytes_count:.2f} {unit}"
        bytes_count /= 1024
    return f"{bytes_count:.2f} PB"

def format_bits(bits_count):
    if bits_count is None:
        return "0 bps"
    for unit in ["bps", "Kbps", "Mbps", "Gbps", "Tbps"]:
        if bits_count < 1000:
            return f"{bits_count:.2f} {unit}"
        bits_count /= 1000
    return f"{bits_count:.2f} Pbps"

def get_system_uptime():
    try:
        uptime_seconds = time.monotonic()
        days    = int(uptime_seconds // 86400)
        hours   = int((uptime_seconds % 86400) // 3600)
        minutes = int((uptime_seconds % 3600) // 60)
        seconds = int(uptime_seconds % 60)
        return f"{days}天 {hours}小时 {minutes}分钟 {seconds}秒", uptime_seconds
    except Exception:
        return "未知", 0

def get_active_connections():
    try:
        output = subprocess.check_output(["ss", "-tunap"]).decode("utf-8")
        return len([l for l in output.splitlines() if "ESTAB" in l or "LISTEN" in l])
    except Exception:
        return 0

def get_traffic_stats_from_manager():
    try:
        result = subprocess.run(
            ["wg-rule-manager", "stats"], capture_output=True, text=True, check=True
        )
        stats_data = {}
        for line in result.stdout.strip().split("\n"):
            if ":" not in line:
                continue
            rule_id_str, stats_str = line.split(":", 1)
            total_packets = total_bytes = 0
            for part in stats_str.split(";"):
                if part.startswith("conntrack:"):
                    segs = part.split(":")
                    if len(segs) == 3:
                        total_packets += int(segs[1])
                        total_bytes   += int(segs[2])
            stats_data[int(rule_id_str)] = {"packets": total_packets, "bytes": total_bytes}
        return stats_data
    except Exception as e:
        log_event("error", f"获取流量统计失败: {e}")
        return {}

def calculate_traffic_stats():
    with traffic_stats_lock:
        current_time = time.time()
        all_stats    = get_traffic_stats_from_manager()
        for rule_id, counter in all_stats.items():
            bytes_count   = counter["bytes"]
            packets_count = counter["packets"]
            if rule_id not in app.rule_traffic_stats:
                app.rule_traffic_stats[rule_id] = {
                    "last_bytes": bytes_count, "last_packets": packets_count,
                    "last_time": current_time, "current_speed": 0, "instant_speed": 0,
                    "total_bytes": bytes_count, "total_packets": packets_count,
                    "history": deque(maxlen=10), "max_speed_10s": 0,
                }
                continue
            stats     = app.rule_traffic_stats[rule_id]
            time_diff = current_time - stats["last_time"]
            if time_diff > 0:
                bytes_diff    = bytes_count - stats["last_bytes"]
                instant_bps   = bytes_diff / time_diff * 8
                stats["history"].append(instant_bps)
                avg_speed = sum(stats["history"]) / len(stats["history"]) if stats["history"] else 0
                stats["max_speed_10s"] = max(stats["max_speed_10s"] * 0.9, instant_bps)
                stats.update({
                    "last_bytes": bytes_count, "last_packets": packets_count,
                    "last_time": current_time, "current_speed": avg_speed,
                    "instant_speed": instant_bps, "total_bytes": bytes_count,
                    "total_packets": packets_count,
                })
        return app.rule_traffic_stats

def get_safe_traffic_stats():
    with traffic_stats_lock:
        return copy.deepcopy(app.rule_traffic_stats)

def get_network_interface_speed(interface=None):
    try:
        current_time = time.time()
        net_io       = psutil.net_io_counters(pernic=True)
        interfaces   = {interface: net_io[interface]} if interface and interface in net_io else net_io
        result       = {}
        for iface_name, io_stats in interfaces.items():
            if iface_name.startswith(("lo", "docker", "br-", "veth", "virbr")):
                continue
            if iface_name not in app.interface_speeds:
                app.interface_speeds[iface_name] = {
                    "last_bytes_sent": io_stats.bytes_sent,
                    "last_bytes_recv": io_stats.bytes_recv,
                    "last_time": current_time, "upload_speed": 0, "download_speed": 0,
                    "upload_history": deque(maxlen=10), "download_history": deque(maxlen=10),
                }
                result[iface_name] = {
                    "name": iface_name, "upload_speed": 0, "download_speed": 0,
                    "upload_speed_formatted": "0 bps", "download_speed_formatted": "0 bps",
                    "total_upload": io_stats.bytes_sent, "total_download": io_stats.bytes_recv,
                    "total_upload_formatted": format_bytes(io_stats.bytes_sent),
                    "total_download_formatted": format_bytes(io_stats.bytes_recv), "is_up": True,
                }
                continue
            sp        = app.interface_speeds[iface_name]
            time_diff = current_time - sp["last_time"]
            if time_diff > 0:
                up_bps  = (io_stats.bytes_sent - sp["last_bytes_sent"]) / time_diff * 8
                dn_bps  = (io_stats.bytes_recv - sp["last_bytes_recv"]) / time_diff * 8
                sp["upload_history"].append(up_bps)
                sp["download_history"].append(dn_bps)
                up_avg  = sum(sp["upload_history"])   / len(sp["upload_history"])
                dn_avg  = sum(sp["download_history"]) / len(sp["download_history"])
                sp.update({
                    "last_bytes_sent": io_stats.bytes_sent, "last_bytes_recv": io_stats.bytes_recv,
                    "last_time": current_time, "upload_speed": up_avg, "download_speed": dn_avg,
                })
                result[iface_name] = {
                    "name": iface_name, "upload_speed": up_avg, "download_speed": dn_avg,
                    "upload_speed_formatted":   format_bits(up_avg),
                    "download_speed_formatted":  format_bits(dn_avg),
                    "total_upload":   io_stats.bytes_sent, "total_download": io_stats.bytes_recv,
                    "total_upload_formatted":   format_bytes(io_stats.bytes_sent),
                    "total_download_formatted":  format_bytes(io_stats.bytes_recv), "is_up": True,
                }
        return result
    except Exception as e:
        log_event("error", f"获取网口带宽失败: {str(e)}")
        return {}

# ============================ 路由 ============================

@app.route("/login", methods=["GET", "POST"])
def login():
    if session.get("logged_in"):
        return redirect(url_for("rules_management"))
    error  = None
    config = load_config()
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        remember = bool(request.form.get("remember"))
        if username == config.get("web_user") and \
                check_password_hash(config.get("web_pass_hash", ""), password):
            session["logged_in"] = True
            session["username"]  = username
            session["login_time"]= datetime.now().isoformat()
            session.permanent    = remember
            log_event("login", "用户登录成功", username)
            return redirect(url_for("rules_management"))
        else:
            error = "用户名或密码错误"
            log_event("login_failed", error, username)
    return render_template("login.html", error=error, config=config)

@app.route("/logout")
@login_required
def logout():
    username = session.get("username")
    session.clear()
    log_event("logout", "用户注销登录", username)
    return redirect(url_for("login"))

@app.route("/")
def index():
    if session.get("logged_in"):
        return redirect(url_for("rules_management"))
    return redirect(url_for("login"))

@app.route("/rules")
@login_required
def rules_management():
    config = load_config()
    rules  = load_forward_rules()
    calculate_traffic_stats()
    rule_stats = get_safe_traffic_stats()
    for rule in rules.get("forward_rules", []):
        rule_id = rule.get("id")
        stats   = rule_stats.get(rule_id, {})
        rule["traffic_stats"] = {
            "current_speed":           stats.get("current_speed", 0),
            "current_speed_formatted": format_bits(stats.get("current_speed", 0)),
            "instant_speed":           stats.get("instant_speed", 0),
            "instant_speed_formatted": format_bits(stats.get("instant_speed", 0)),
            "total_bytes":             stats.get("total_bytes", 0),
            "total_packets":           stats.get("total_packets", 0),
            "total_bytes_formatted":   format_bytes(stats.get("total_bytes", 0)),
            "max_speed_10s":           stats.get("max_speed_10s", 0),
        }
    return render_template("rules.html", config=config, rules=rules, now=datetime.now())

_status_cache      = {}
_status_cache_time = 0
_STATUS_CACHE_TTL  = 2

@app.route("/api/status")
@login_required
@handle_errors
def api_status():
    global _status_cache, _status_cache_time
    now = time.time()
    if _status_cache and (now - _status_cache_time) < _STATUS_CACHE_TTL:
        return jsonify({"status": "success", "data": _status_cache})

    cpu_percent = psutil.cpu_percent(interval=0.3, percpu=False)
    memory      = psutil.virtual_memory()
    disk_usage  = psutil.disk_usage("/")

    services = {}
    for svc in ["nginx", "wg-relay-web"]:
        try:
            r = subprocess.run(["systemctl", "is-active", svc],
                               capture_output=True, text=True, timeout=2)
            services[svc] = "active" if r.stdout.strip() == "active" else "inactive"
        except Exception:
            services[svc] = "inactive"

    config    = load_config()
    main_iface = config.get("public_interface", "eth0")
    iface_data = get_network_interface_speed(main_iface)

    if iface_data and main_iface in iface_data:
        d = iface_data[main_iface]
    else:
        net_io = psutil.net_io_counters()
        d = {
            "upload_speed": 0, "download_speed": 0,
            "upload_speed_formatted": "0 bps", "download_speed_formatted": "0 bps",
            "total_upload": net_io.bytes_sent,  "total_download": net_io.bytes_recv,
            "total_upload_formatted":  format_bytes(net_io.bytes_sent),
            "total_download_formatted":format_bytes(net_io.bytes_recv),
        }

    uptime_str, uptime_seconds = get_system_uptime()

    return_data = {
        "cpu_percent":    round(cpu_percent, 1),
        "memory_percent": round(memory.percent, 1),
        "memory_total":   round(memory.total  / 1024**3, 2),
        "memory_used":    round(memory.used   / 1024**3, 2),
        "disk_percent":   round(disk_usage.percent, 1),
        "disk_total":     round(disk_usage.total / 1024**3, 2),
        "disk_used":      round(disk_usage.used  / 1024**3, 2),
        "nginx_status":   services.get("nginx",       "inactive"),
        "web_status":     services.get("wg-relay-web","inactive"),
        "uptime":         uptime_str,
        "uptime_seconds": uptime_seconds,
        "connection_stats": get_active_connections(),
        **{k: d[k] for k in ("upload_speed","download_speed",
                              "upload_speed_formatted","download_speed_formatted",
                              "total_upload","total_download",
                              "total_upload_formatted","total_download_formatted")},
    }
    _status_cache.update(return_data)
    _status_cache_time = now
    return jsonify({"status": "success", "data": return_data})

@app.route("/api/rules")
@login_required
@handle_errors
def api_rules():
    rules      = load_forward_rules()
    calculate_traffic_stats()
    rule_stats = get_safe_traffic_stats()
    formatted  = []
    for rule in rules.get("forward_rules", []):
        rule_id = rule.get("id")
        stats   = rule_stats.get(rule_id, {})
        formatted.append({
            "rule_id":     rule_id,
            "name":        rule.get("name"),
            "protocol":    rule.get("protocol"),
            "listen_ip":   rule.get("listen_ip"),
            "listen_port": rule.get("listen_port"),
            "target_ip":   rule.get("target_ip"),
            "target_port": rule.get("target_port"),
            "enabled":     rule.get("enabled"),
            "description": rule.get("description"),
            "traffic_stats": {
                "current_speed":           stats.get("current_speed", 0),
                "current_speed_formatted": format_bits(stats.get("current_speed", 0)),
                "instant_speed":           stats.get("instant_speed", 0),
                "instant_speed_formatted": format_bits(stats.get("instant_speed", 0)),
                "total_bytes":             stats.get("total_bytes", 0),
                "total_packets":           stats.get("total_packets", 0),
                "total_bytes_formatted":   format_bytes(stats.get("total_bytes", 0)),
                "max_speed_10s":           stats.get("max_speed_10s", 0),
            },
        })
    return jsonify({"status": "success", "data": formatted})

@app.route("/api/rules/add", methods=["POST"])
@login_required
@handle_errors
def api_add_rule():
    data = request.get_json()
    if not data:
        return jsonify({"status": "error", "message": "无效的请求数据"}), 400
    for field in ("name", "protocol", "listen_ip", "listen_port", "target_ip", "target_port"):
        if field not in data:
            return jsonify({"status": "error", "message": f"缺少字段: {field}"}), 400

    existing_rules = load_forward_rules().get("forward_rules", [])
    new_rule_id    = max([r.get("id", 0) for r in existing_rules], default=0) + 1

    listen_port = int(data["listen_port"])
    target_port = int(data["target_port"])
    enabled     = data.get("enabled", True)
    description = data.get("description", "")

    result = subprocess.run(
        ["wg-rule-manager", "check_port_conflict", str(listen_port), data["name"], "0"],
        capture_output=True, text=True
    )
    if result.returncode != 0:
        return jsonify({"status": "error", "message": result.stderr.strip()}), 400

    subprocess.run([
        "wg-rule-manager", "add",
        str(new_rule_id), data["name"], data["protocol"].lower(),
        data["listen_ip"], str(listen_port),
        data["target_ip"], str(target_port),
        str(enabled).lower(), description,
    ], check=True)
    log_event("info", f"添加规则: {data['name']} (ID: {new_rule_id})", session.get("username"))
    return jsonify({"status": "success", "message": "规则添加成功", "rule_id": new_rule_id})

@app.route("/api/rules/update/<int:rule_id>", methods=["POST"])
@login_required
@handle_errors
def api_update_rule(rule_id):
    data = request.get_json()
    if not data:
        return jsonify({"status": "error", "message": "无效的请求数据"}), 400
    updates = {}
    for field in ("name","protocol","listen_ip","listen_port","target_ip","target_port","enabled","description"):
        if field in data:
            updates[field] = data[field]
    if not updates:
        return jsonify({"status": "error", "message": "没有提供更新字段"}), 400

    if "listen_port" in updates:
        result = subprocess.run(
            ["wg-rule-manager", "check_port_conflict",
             str(updates["listen_port"]), updates.get("name", ""), str(rule_id)],
            capture_output=True, text=True
        )
        if result.returncode != 0:
            return jsonify({"status": "error", "message": result.stderr.strip()}), 400

    subprocess.run(
        ["wg-rule-manager", "update", str(rule_id), json.dumps(updates, ensure_ascii=False)],
        check=True
    )
    log_event("info", f"更新规则: ID {rule_id}", session.get("username"))
    return jsonify({"status": "success", "message": "规则更新成功"})

@app.route("/api/rules/delete/<int:rule_id>", methods=["POST"])
@login_required
@handle_errors
def api_delete_rule(rule_id):
    subprocess.run(["wg-rule-manager", "delete", str(rule_id)], check=True)
    log_event("info", f"删除规则: ID {rule_id}", session.get("username"))
    return jsonify({"status": "success", "message": "规则删除成功"})

@app.route("/api/rules/toggle/<int:rule_id>", methods=["POST"])
@login_required
@handle_errors
def api_toggle_rule(rule_id):
    data = request.get_json()
    if not data or "enabled" not in data:
        return jsonify({"status": "error", "message": "缺少 'enabled' 字段"}), 400
    subprocess.run(
        ["wg-rule-manager", "toggle", str(rule_id), str(data["enabled"]).lower()],
        check=True
    )
    log_event("info", f"切换规则: ID {rule_id}, Enabled: {data['enabled']}", session.get("username"))
    return jsonify({"status": "success", "message": "规则状态切换成功"})

@app.route("/api/rules/reload", methods=["POST"])
@login_required
@handle_errors
def api_reload_rules():
    subprocess.run(["wg-rule-manager", "reload"], check=True)
    log_event("info", "所有规则已重新加载", session.get("username"))
    return jsonify({"status": "success", "message": "所有规则已重新加载"})

@app.route("/api/config", methods=["GET", "POST"])
@login_required
@handle_errors
def api_config():
    if request.method == "GET":
        config = load_config()
        config.pop("web_pass_hash", None)
        return jsonify({"status": "success", "data": config})

    data = request.get_json()
    if not data:
        return jsonify({"status": "error", "message": "无效的请求数据"}), 400
    config  = load_config()
    updated = False
    if "relay_name" in data and data["relay_name"] != config.get("relay_name"):
        config["relay_name"] = data["relay_name"];  updated = True
    if "web_user" in data and data["web_user"] != config.get("web_user"):
        config["web_user"] = data["web_user"];      updated = True
    if data.get("new_web_pass"):
        config["web_pass_hash"] = generate_password_hash(data["new_web_pass"])
        with open(CREDENTIALS_FILE, "w", encoding="utf-8") as f:
            f.write(f"# 流量转发中继管理系统 管理凭据\n")
            f.write(f"# 生成时间: {datetime.now().isoformat()}\n")
            f.write(f"WEB_USER={config['web_user']}\n")
            f.write(f"WEB_PASS={data['new_web_pass']}\n")
        os.chmod(CREDENTIALS_FILE, 0o600)
        updated = True

    if updated:
        save_config(config)
        log_event("info", "配置已更新", session.get("username"))
        return jsonify({"status": "success", "message": "配置更新成功"})
    return jsonify({"status": "success", "message": "没有配置更改"})

@app.route("/api/logs")
@login_required
@handle_errors
def api_logs():
    with open(LOG_FILE, "r", encoding="utf-8") as f:
        logs = f.readlines()[-500:]
    return jsonify({"status": "success", "data": logs})

if __name__ == "__main__":
    def traffic_stats_updater():
        while True:
            calculate_traffic_stats()
            get_network_interface_speed()
            time.sleep(1)

    threading.Thread(target=traffic_stats_updater, daemon=True).start()
    app.run(host="127.0.0.1", port=load_config().get("web_port", 8080), debug=False)
PYEOF

    chmod 755 "$WEB_DIR/app.py"

    # ---------- login.html ----------
    cat > "$WEB_DIR/templates/login.html" << 'HTMLEOF'
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>登录 - 流量转发中继管理系统</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.10.0/font/bootstrap-icons.css" rel="stylesheet">
    <style>
        body { background-color:#f8f9fa; display:flex; justify-content:center; align-items:center; min-height:100vh; }
        .login-container { max-width:400px; width:100%; padding:30px; border-radius:8px; box-shadow:0 0 20px rgba(0,0,0,.1); background:#fff; }
        .logo-text { font-size:1.8rem; font-weight:bold; color:#007bff; text-align:center; margin-bottom:20px; }
        .form-control:focus { box-shadow:none; border-color:#007bff; }
        .btn-primary { background-color:#007bff; border-color:#007bff; }
        .btn-primary:hover { background-color:#0056b3; border-color:#0056b3; }
    </style>
</head>
<body>
    <div class="login-container">
        <div class="logo-text mb-4"><i class="bi bi-diagram-3-fill me-2"></i>流量转发中继管理系统</div>
        <h5 class="text-center mb-4">请登录</h5>
        {% if error %}
        <div class="alert alert-danger alert-dismissible fade show" role="alert">
            {{ error }}
            <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
        </div>
        {% endif %}
        <form method="POST">
            <div class="mb-3">
                <label for="username" class="form-label">用户名</label>
                <input type="text" class="form-control" id="username" name="username" value="{{ config.web_user if config else 'admin' }}" required>
            </div>
            <div class="mb-3">
                <label for="password" class="form-label">密码</label>
                <input type="password" class="form-control" id="password" name="password" required>
            </div>
            <div class="mb-3 form-check">
                <input type="checkbox" class="form-check-input" id="remember" name="remember" checked>
                <label class="form-check-label" for="remember">记住我</label>
            </div>
            <button type="submit" class="btn btn-primary w-100">登录</button>
        </form>
    </div>
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
HTMLEOF

    # ---------- rules.html (内容与 web/templates/rules.html 一致，从外部文件复制) ----------
    # 为保持可维护性，rules.html 较大，直接复制源目录文件
    local SCRIPT_DIR
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
    if [ -f "$SCRIPT_DIR/web/templates/rules.html" ]; then
        cp "$SCRIPT_DIR/web/templates/rules.html" "$WEB_DIR/templates/rules.html"
        log "rules.html 已从源目录复制"
    else
        warn "未找到 web/templates/rules.html，请手动复制到 $WEB_DIR/templates/"
    fi
}

# BUG FIX: 原代码 create_web_service 和 start_web_service 各被定义了两次，
# 导致后一个定义覆盖前一个（虽然内容相同，但重复定义是代码异味且易出错）。
# 此处每个函数只定义一次。

create_web_service() {
    info "创建Web管理界面Systemd服务..."
    cat > /etc/systemd/system/wg-relay-web.service << EOF
[Unit]
Description=WireGuard Relay Web Management Interface
After=network.target

[Service]
User=root
WorkingDirectory=$WEB_DIR
ExecStart=/usr/bin/python3 $WEB_DIR/app.py
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable wg-relay-web
    success "Web管理界面服务创建完成"
}

start_web_service() {
    info "启动Web管理界面服务..."
    systemctl enable wg-relay-web
    systemctl start wg-relay-web
    sleep 2
    if systemctl is-active --quiet wg-relay-web; then
        success "Web管理界面服务启动成功"
    else
        error "Web管理界面服务启动失败，请检查日志: journalctl -u wg-relay-web -n 20"
    fi
}

start_web_app() {
    start_web_service
}

stop_web_app() {
    info "停止 Web 管理界面服务..."
    systemctl stop wg-relay-web || true
}

restart_web_app() {
    info "重启 Web 管理界面服务..."
    systemctl restart wg-relay-web
}

remove_systemd_services() {
    info "移除 systemd 服务..."
    systemctl stop    wg-relay-web || true
    systemctl disable wg-relay-web || true
    rm -f /etc/systemd/system/wg-relay-web.service
    systemctl daemon-reload
}

create_management_scripts() {
    info "创建管理脚本..."

    # wg-relay 主管理脚本
    cat > /usr/local/bin/wg-relay << 'EOF'
#!/bin/bash
CONFIG_DIR="/etc/wg-relay"
LOG_FILE="/var/log/wg-relay.log"
WEB_SERVICE_NAME="wg-relay-web"
RULE_MANAGER_NAME="wg-rule-manager"

log()     { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"; }
info()    { echo "[信息] $1" | tee -a "$LOG_FILE"; }
error()   { echo "[错误] $1" | tee -a "$LOG_FILE"; exit 1; }
success() { echo "[成功] $1" | tee -a "$LOG_FILE"; }

show_status() {
    echo "服务状态:"
    systemctl status $WEB_SERVICE_NAME --no-pager || true
    systemctl status nginx --no-pager || true
    echo ""
    echo "最近日志:"
    tail -n 20 "$LOG_FILE" || true
}

reload_rules() {
    info "正在重新加载所有转发规则..."
    if command -v $RULE_MANAGER_NAME >/dev/null 2>&1; then
        $RULE_MANAGER_NAME reload
        success "规则重新加载成功"
    else
        error "规则管理器 ($RULE_MANAGER_NAME) 未找到，请检查安装"
    fi
}

list_rules() {
    info "列出所有转发规则..."
    if command -v $RULE_MANAGER_NAME >/dev/null 2>&1; then
        $RULE_MANAGER_NAME list | jq .
    else
        error "规则管理器 ($RULE_MANAGER_NAME) 未找到，请检查安装"
    fi
}

case "$1" in
    status) show_status ;;
    reload) reload_rules ;;
    rules)
        shift
        case "$1" in
            list) list_rules ;;
            *) echo "用法: wg-relay rules {list}"; exit 1 ;;
        esac
        ;;
    *) echo "用法: wg-relay {status|reload|rules}"; exit 1 ;;
esac
EOF
    chmod +x /usr/local/bin/wg-relay

    # wg-relay-stats 统计脚本
    local SCRIPT_DIR
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
    if [ -f "$SCRIPT_DIR/scripts/stats_collector.py" ]; then
        install -m 755 "$SCRIPT_DIR/scripts/stats_collector.py" /usr/local/bin/wg-relay-stats
        log "wg-relay-stats 已安装"
    else
        warn "未找到 scripts/stats_collector.py，请手动安装 wg-relay-stats"
    fi

    # wg-rule-manager 规则管理器
    if [ -f "$SCRIPT_DIR/scripts/rule_manager.sh" ]; then
        install -m 755 "$SCRIPT_DIR/scripts/rule_manager.sh" /usr/local/bin/wg-rule-manager
        log "wg-rule-manager 已安装"
    else
        warn "未找到 scripts/rule_manager.sh，请手动安装 wg-rule-manager"
    fi
}
