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

create_web_app_files() {
    mkdir -p $WEB_DIR/templates $WEB_DIR/static/css $WEB_DIR/static/js $WEB_DIR/static/img
    
    # 创建 app.py
    cat > $WEB_DIR/app.py << 'EOF'
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
CONFIG_DIR = "/etc/wg-relay"
RULES_DIR = os.path.join(CONFIG_DIR, "rules")
LOG_FILE = "/var/log/wg-relay.log"
CREDENTIALS_FILE = os.path.join(CONFIG_DIR, ".credentials")

app = Flask(__name__)
app.secret_key = os.urandom(24)
app.permanent_session_lifetime = timedelta(days=7)

# 全局流量统计变量
app.rule_traffic_stats = {}
app.interface_speeds = {}
traffic_stats_lock = threading.Lock()

# ============================ 辅助函数 ============================

def log_event(level, message, username=None):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    user_info = f"[User: {username}] " if username else ""
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
    if bytes_count is None: return "0 B"
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if bytes_count < 1024:
            return f"{bytes_count:.2f} {unit}"
        bytes_count /= 1024
    return f"{bytes_count:.2f} PB"

def format_bits(bits_count):
    if bits_count is None: return "0 bps"
    for unit in ["bps", "Kbps", "Mbps", "Gbps", "Tbps"]:
        if bits_count < 1000:
            return f"{bits_count:.2f} {unit}"
        bits_count /= 1000
    return f"{bits_count:.2f} Pbps"

def get_system_uptime():
    try:
        uptime_seconds = time.monotonic()
        days = int(uptime_seconds // (24 * 3600))
        hours = int((uptime_seconds % (24 * 3600)) // 3600)
        minutes = int((uptime_seconds % 3600) // 60)
        seconds = int(uptime_seconds % 60)
        return f"{days}天 {hours}小时 {minutes}分钟 {seconds}秒", uptime_seconds
    except Exception:
        return "未知", 0

def get_active_connections():
    try:
        output = subprocess.check_output(["ss", "-tunap"]).decode("utf-8")
        connections = len([line for line in output.splitlines() if "ESTAB" in line or "LISTEN" in line])
        return connections
    except Exception:
        return 0

def get_traffic_stats_from_manager():
    try:
        result = subprocess.run(["wg-rule-manager", "stats"], capture_output=True, text=True, check=True)
        output_lines = result.stdout.strip().split("\n")
        stats_data = {}
        for line in output_lines:
            if ":" in line:
                rule_id_str, stats_str = line.split(":", 1)
                rule_id = int(rule_id_str)
                
                total_packets = 0
                total_bytes = 0
                
                parts = stats_str.split(";")
                for part in parts:
                    if part.startswith("conntrack:"):
                        _, packets, bytes_val = part.split(":")
                        total_packets += int(packets)
                        total_bytes += int(bytes_val)
                
                stats_data[rule_id] = {
                    "packets": total_packets,
                    "bytes": total_bytes
                }
        
        return stats_data
        
    except Exception as e:
        log_event("error", f"获取流量统计失败: {e}")
        return {}

def calculate_traffic_stats():
    """计算流量统计（线程安全）"""
    with traffic_stats_lock:
        current_time = time.time()
        
        all_stats = get_traffic_stats_from_manager()
        
        for rule_id_str, counter in all_stats.items():
            try:
                rule_id = int(rule_id_str)
                bytes_count = counter["bytes"]
                packets_count = counter["packets"]
                
                if rule_id not in app.rule_traffic_stats:
                    app.rule_traffic_stats[rule_id] = {
                        "last_bytes": bytes_count,
                        "last_packets": packets_count,
                        "last_time": current_time,
                        "current_speed": 0,
                        "instant_speed": 0,
                        "total_bytes": bytes_count,
                        "total_packets": packets_count,
                        "history": deque(maxlen=10),
                        "max_speed_10s": 0
                    }
                    continue
                
                stats = app.rule_traffic_stats[rule_id]
                time_diff = current_time - stats["last_time"]
                
                if time_diff > 0:
                    bytes_diff = bytes_count - stats["last_bytes"]
                    packets_diff = packets_count - stats["last_packets"]
                    
                    instant_speed = bytes_diff / time_diff if time_diff > 0 else 0
                    instant_speed_bps = instant_speed * 8
                    
                    stats["history"].append(instant_speed_bps)
                    
                    if len(stats["history"]) > 0:
                        avg_speed = sum(stats["history"]) / len(stats["history"])
                    else:
                        avg_speed = 0
                    
                    stats["max_speed_10s"] = max(
                        stats["max_speed_10s"] * 0.9,
                        instant_speed_bps
                    )
                    
                    stats.update({
                        "last_bytes": bytes_count,
                        "last_packets": packets_count,
                        "last_time": current_time,
                        "current_speed": avg_speed,
                        "instant_speed": instant_speed_bps,
                        "total_bytes": bytes_count,
                        "total_packets": packets_count
                    })
            except (ValueError, KeyError) as e:
                continue
        
        return app.rule_traffic_stats

def get_safe_traffic_stats():
    """线程安全获取流量统计"""
    with traffic_stats_lock:
        return copy.deepcopy(app.rule_traffic_stats)

def get_network_interface_speed(interface=None):
    """获取指定网口的实时带宽数据"""
    try:
        current_time = time.time()
        net_io = psutil.net_io_counters(pernic=True)
        
        result = {}
        
        if interface and interface in net_io:
            interfaces = {interface: net_io[interface]}
        else:
            interfaces = net_io
        
        for iface_name, io_stats in interfaces.items():
            if iface_name.startswith(("lo", "docker", "br-", "veth", "virbr")):
                continue
                
            if iface_name not in app.interface_speeds:
                app.interface_speeds[iface_name] = {
                    "last_bytes_sent": io_stats.bytes_sent,
                    "last_bytes_recv": io_stats.bytes_recv,
                    "last_time": current_time,
                    "upload_speed": 0,
                    "download_speed": 0,
                    "total_upload": io_stats.bytes_sent,
                    "total_download": io_stats.bytes_recv,
                    "upload_history": deque(maxlen=10),
                    "download_history": deque(maxlen=10)
                }
                result[iface_name] = {
                    "name": iface_name,
                    "upload_speed": 0,
                    "download_speed": 0,
                    "upload_speed_formatted": "0 bps",
                    "download_speed_formatted": "0 bps",
                    "total_upload": io_stats.bytes_sent,
                    "total_download": io_stats.bytes_recv,
                    "total_upload_formatted": format_bytes(io_stats.bytes_sent),
                    "total_download_formatted": format_bytes(io_stats.bytes_recv),
                    "is_up": True
                }
                continue
            
            time_diff = current_time - app.interface_speeds[iface_name]["last_time"]
            if time_diff > 0:
                bytes_sent_diff = io_stats.bytes_sent - app.interface_speeds[iface_name]["last_bytes_sent"]
                bytes_recv_diff = io_stats.bytes_recv - app.interface_speeds[iface_name]["last_bytes_recv"]
                
                upload_speed = (bytes_sent_diff * 8) / time_diff
                download_speed = (bytes_recv_diff * 8) / time_diff
                
                app.interface_speeds[iface_name]["upload_history"].append(upload_speed)
                app.interface_speeds[iface_name]["download_history"].append(download_speed)
                
                if len(app.interface_speeds[iface_name]["upload_history"]) > 0:
                    upload_speed = sum(app.interface_speeds[iface_name]["upload_history"]) / len(app.interface_speeds[iface_name]["upload_history"])
                    download_speed = sum(app.interface_speeds[iface_name]["download_history"]) / len(app.interface_speeds[iface_name]["download_history"])
                
                app.interface_speeds[iface_name].update({
                    "last_bytes_sent": io_stats.bytes_sent,
                    "last_bytes_recv": io_stats.bytes_recv,
                    "last_time": current_time,
                    "upload_speed": upload_speed,
                    "download_speed": download_speed,
                    "total_upload": io_stats.bytes_sent,
                    "total_download": io_stats.bytes_recv
                })
                
                result[iface_name] = {
                    "name": iface_name,
                    "upload_speed": upload_speed,
                    "download_speed": download_speed,
                    "upload_speed_formatted": format_bits(upload_speed),
                    "download_speed_formatted": format_bits(download_speed),
                    "total_upload": io_stats.bytes_sent,
                    "total_download": io_stats.bytes_recv,
                    "total_upload_formatted": format_bytes(io_stats.bytes_sent),
                    "total_download_formatted": format_bytes(io_stats.bytes_recv),
                    "is_up": True
                }
        
        return result
        
    except Exception as e:
        log_event("error", f"获取网口带宽失败: {str(e)}", session.get("username"))
        return {}

# 路由函数
@app.route("/login", methods=["GET", "POST"])
def login():
    """登录页面"""
    if session.get("logged_in"):
        return redirect(url_for("rules_management"))

    error = None
    config = load_config()

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        remember = bool(request.form.get("remember"))

        if username == config.get("web_user") and \
           check_password_hash(config.get("web_pass_hash"), password):

            session["logged_in"] = True
            session["username"] = username
            session["login_time"] = datetime.now().isoformat()
            session.permanent = remember

            log_event("login", "用户登录成功", username)
            return redirect(url_for("rules_management"))
        else:
            error = "用户名或密码错误"
            log_event("login_failed", error, username)

    return render_template("login.html", error=error, config=config)

@app.route("/logout")
@login_required
def logout():
    """注销登录"""
    username = session.get("username")
    session.clear()
    log_event("logout", "用户注销登录", username)
    return redirect(url_for("login"))

@app.route("/")
def index():
    """首页重定向"""
    if session.get("logged_in"):
        return redirect(url_for("rules_management"))
    return redirect(url_for("login"))

@app.route("/rules")
@login_required
def rules_management():
    """规则管理页面（主管面板）"""
    config = load_config()
    rules = load_forward_rules()
    
    calculate_traffic_stats()
    rule_stats = get_safe_traffic_stats()
    
    for rule in rules.get("forward_rules", []):
        rule_id = rule.get("id")
        stats = rule_stats.get(rule_id, {})
        rule["traffic_stats"] = {
            "current_speed": stats.get("current_speed", 0),
            "current_speed_formatted": format_bits(stats.get("current_speed", 0)),
            "instant_speed": stats.get("instant_speed", 0),
            "instant_speed_formatted": format_bits(stats.get("instant_speed", 0)),
            "total_bytes": stats.get("total_bytes", 0),
            "total_packets": stats.get("total_packets", 0),
            "total_bytes_formatted": format_bytes(stats.get("total_bytes", 0)),
            "max_speed_10s": stats.get("max_speed_10s", 0)
        }
    
    return render_template("rules.html", config=config, rules=rules, now=datetime.now())

_status_cache = {}
_status_cache_time = 0
_STATUS_CACHE_TTL = 2

@app.route("/api/status")
@login_required
@handle_errors
def api_status():
    """获取系统状态（带缓存，2秒TTL）"""
    global _status_cache, _status_cache_time
    now = time.time()
    if _status_cache and (now - _status_cache_time) < _STATUS_CACHE_TTL:
        return jsonify({"status": "success", "data": _status_cache})
    try:
        cpu_percent = psutil.cpu_percent(interval=0.3, percpu=False)
        memory = psutil.virtual_memory()
        disk_usage = psutil.disk_usage("/")
        
        services = {}
        for service_name in ["nginx", "wg-relay-web"]:
            try:
                result = subprocess.run(
                    ["systemctl", "is-active", service_name], 
                    capture_output=True, 
                    text=True, 
                    timeout=1
                )
                services[service_name] = "active" if result.stdout.strip() == "active" else "inactive"
            except Exception as e:
                print(f"检查服务状态失败 {service_name}: {e}")
                services[service_name] = "inactive"
        
        config = load_config()
        main_interface = config.get("public_interface", "eth0")
        interface_data = get_network_interface_speed(main_interface)
        
        if interface_data and main_interface in interface_data:
            iface_data = interface_data[main_interface]
            upload_speed = iface_data["upload_speed"]
            download_speed = iface_data["download_speed"]
            upload_speed_formatted = iface_data["upload_speed_formatted"]
            download_speed_formatted = iface_data["download_speed_formatted"]
            total_upload = iface_data["total_upload"]
            total_download = iface_data["total_download"]
            total_upload_formatted = iface_data["total_upload_formatted"]
            total_download_formatted = iface_data["total_download_formatted"]
        else:
            net_io = psutil.net_io_counters()
            upload_speed = 0
            download_speed = 0
            upload_speed_formatted = "0 bps"
            download_speed_formatted = "0 bps"
            total_upload_formatted = format_bytes(net_io.bytes_sent)
            total_download_formatted = format_bytes(net_io.bytes_recv)
            total_upload = net_io.bytes_sent
            total_download = net_io.bytes_recv
        
        uptime_str, uptime_seconds = get_system_uptime()
        
        connection_stats = get_active_connections()
        
        return_data = {
                "cpu_percent": round(cpu_percent, 1),
                "memory_percent": round(memory.percent, 1),
                "memory_total": round(memory.total / (1024**3), 2),
                "memory_used": round(memory.used / (1024**3), 2),
                "disk_percent": round(disk_usage.percent, 1),
                "disk_total": round(disk_usage.total / (1024**3), 2),
                "disk_used": round(disk_usage.used / (1024**3), 2),
                "upload_speed": upload_speed,
                "download_speed": download_speed,
                "upload_speed_formatted": upload_speed_formatted,
                "download_speed_formatted": download_speed_formatted,
                "total_upload": total_upload,
                "total_download": total_download,
                "total_upload_formatted": total_upload_formatted,
                "total_download_formatted": total_download_formatted,
                "nginx_status": services.get("nginx", "inactive"),
                "web_status": services.get("wg-relay-web", "inactive"),
                "uptime": uptime_str,
                "uptime_seconds": uptime_seconds,
                "connection_stats": connection_stats
            }
        _status_cache.update(return_data)
        _status_cache_time = now
        return jsonify({
            "status": "success",
            "data": return_data
        })
    except Exception as e:
        log_event("error", f"获取系统状态失败: {str(e)}", session.get("username"))
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route("/api/rules")
@login_required
@handle_errors
def api_rules():
    """获取转发规则"""
    try:
        rules = load_forward_rules()
        
        calculate_traffic_stats()
        rule_stats = get_safe_traffic_stats()
        
        formatted_rules = []
        for rule in rules.get("forward_rules", []):
            rule_id = rule.get("id")
            stats = rule_stats.get(rule_id, {})
            
            formatted_rules.append({
                "rule_id": rule_id,
                "name": rule.get("name"),
                "protocol": rule.get("protocol"),
                "listen_ip": rule.get("listen_ip"),
                "listen_port": rule.get("listen_port"),
                "target_ip": rule.get("target_ip"),
                "target_port": rule.get("target_port"),
                "enabled": rule.get("enabled"),
                "description": rule.get("description"),
                "traffic_stats": {
                    "current_speed": stats.get("current_speed", 0),
                    "current_speed_formatted": format_bits(stats.get("current_speed", 0)),
                    "instant_speed": stats.get("instant_speed", 0),
                    "instant_speed_formatted": format_bits(stats.get("instant_speed", 0)),
                    "total_bytes": stats.get("total_bytes", 0),
                    "total_packets": stats.get("total_packets", 0),
                    "total_bytes_formatted": format_bytes(stats.get("total_bytes", 0)),
                    "max_speed_10s": stats.get("max_speed_10s", 0)
                }
            })
        
        return jsonify({"status": "success", "data": formatted_rules})
    except Exception as e:
        log_event("error", f"获取规则失败: {str(e)}", session.get("username"))
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route("/api/rules/add", methods=["POST"])
@login_required
@handle_errors
def api_add_rule():
    """添加转发规则"""
    data = request.get_json()
    if not data:
        return jsonify({"status": "error", "message": "无效的请求数据"}), 400
    
    required_fields = ["name", "protocol", "listen_ip", "listen_port", "target_ip", "target_port"]
    for field in required_fields:
        if field not in data:
            return jsonify({"status": "error", "message": f"缺少字段: {field}"}), 400

    try:
        # 查找最大的 rule_id 并加1
        existing_rules = load_forward_rules().get("forward_rules", [])
        new_rule_id = 1
        if existing_rules:
            new_rule_id = max([rule.get("id", 0) for rule in existing_rules]) + 1

        name = data["name"]
        protocol = data["protocol"].lower()
        listen_ip = data["listen_ip"]
        listen_port = int(data["listen_port"])
        target_ip = data["target_ip"]
        target_port = int(data["target_port"])
        enabled = data.get("enabled", True)
        description = data.get("description", "")

        # 检查端口冲突
        cmd = ["wg-rule-manager", "check_port_conflict", str(listen_port), name, "0"]
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode != 0:
            return jsonify({"status": "error", "message": result.stderr.strip()}), 400

        cmd = ["wg-rule-manager", "add", str(new_rule_id), name, protocol, listen_ip, str(listen_port), target_ip, str(target_port), str(enabled).lower(), description]
        subprocess.run(cmd, check=True)
        log_event("info", f"添加规则: {name} (ID: {new_rule_id})", session.get("username"))
        return jsonify({"status": "success", "message": "规则添加成功", "rule_id": new_rule_id})
    except subprocess.CalledProcessError as e:
        log_event("error", f"添加规则失败: {e.stderr}", session.get("username"))
        return jsonify({"status": "error", "message": e.stderr.strip()}), 500
    except Exception as e:
        log_event("error", f"添加规则失败: {str(e)}", session.get("username"))
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route("/api/rules/update/<int:rule_id>", methods=["POST"])
@login_required
@handle_errors
def api_update_rule(rule_id):
    """更新转发规则"""
    data = request.get_json()
    if not data:
        return jsonify({"status": "error", "message": "无效的请求数据"}), 400
    
    updates = {}
    if "name" in data: updates["name"] = data["name"]
    if "protocol" in data: updates["protocol"] = data["protocol"].lower()
    if "listen_ip" in data: updates["listen_ip"] = data["listen_ip"]
    if "listen_port" in data: updates["listen_port"] = int(data["listen_port"])
    if "target_ip" in data: updates["target_ip"] = data["target_ip"]
    if "target_port" in data: updates["target_port"] = int(data["target_port"])
    if "enabled" in data: updates["enabled"] = data["enabled"]
    if "description" in data: updates["description"] = data["description"]

    if not updates:
        return jsonify({"status": "error", "message": "没有提供更新字段"}), 400

    try:
        # 检查端口冲突 (如果端口有更新)
        if "listen_port" in updates:
            cmd = ["wg-rule-manager", "check_port_conflict", str(updates["listen_port"]), updates.get("name", ""), str(rule_id)]
            result = subprocess.run(cmd, capture_output=True, text=True)
            if result.returncode != 0:
                return jsonify({"status": "error", "message": result.stderr.strip()}), 400

        updates_json = json.dumps(updates, ensure_ascii=False)
        cmd = ["wg-rule-manager", "update", str(rule_id), updates_json]
        subprocess.run(cmd, check=True)
        log_event("info", f"更新规则: ID {rule_id}", session.get("username"))
        return jsonify({"status": "success", "message": "规则更新成功"})
    except subprocess.CalledProcessError as e:
        log_event("error", f"更新规则失败: {e.stderr}", session.get("username"))
        return jsonify({"status": "error", "message": e.stderr.strip()}), 500
    except Exception as e:
        log_event("error", f"更新规则失败: {str(e)}", session.get("username"))
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route("/api/rules/delete/<int:rule_id>", methods=["POST"])
@login_required
@handle_errors
def api_delete_rule(rule_id):
    """删除转发规则"""
    try:
        cmd = ["wg-rule-manager", "delete", str(rule_id)]
        subprocess.run(cmd, check=True)
        log_event("info", f"删除规则: ID {rule_id}", session.get("username"))
        return jsonify({"status": "success", "message": "规则删除成功"})
    except subprocess.CalledProcessError as e:
        log_event("error", f"删除规则失败: {e.stderr}", session.get("username"))
        return jsonify({"status": "error", "message": e.stderr.strip()}), 500
    except Exception as e:
        log_event("error", f"删除规则失败: {str(e)}", session.get("username"))
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route("/api/rules/toggle/<int:rule_id>", methods=["POST"])
@login_required
@handle_errors
def api_toggle_rule(rule_id):
    """切换规则启用/禁用状态"""
    data = request.get_json()
    if not data or "enabled" not in data:
        return jsonify({"status": "error", "message": "无效的请求数据或缺少 'enabled' 字段"}), 400
    
    enabled = data["enabled"]
    try:
        cmd = ["wg-rule-manager", "toggle", str(rule_id), str(enabled).lower()]
        subprocess.run(cmd, check=True)
        log_event("info", f"切换规则状态: ID {rule_id}, Enabled: {enabled}", session.get("username"))
        return jsonify({"status": "success", "message": "规则状态切换成功"})
    except subprocess.CalledProcessError as e:
        log_event("error", f"切换规则状态失败: {e.stderr}", session.get("username"))
        return jsonify({"status": "error", "message": e.stderr.strip()}), 500
    except Exception as e:
        log_event("error", f"切换规则状态失败: {str(e)}", session.get("username"))
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route("/api/rules/reload", methods=["POST"])
@login_required
@handle_errors
def api_reload_rules():
    """重新加载所有规则"""
    try:
        subprocess.run(["wg-rule-manager", "reload"], check=True)
        log_event("info", "所有规则已重新加载", session.get("username"))
        return jsonify({"status": "success", "message": "所有规则已重新加载"})
    except subprocess.CalledProcessError as e:
        log_event("error", f"重新加载规则失败: {e.stderr}", session.get("username"))
        return jsonify({"status": "error", "message": e.stderr.strip()}), 500
    except Exception as e:
        log_event("error", f"重新加载规则失败: {str(e)}", session.get("username"))
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route("/api/config", methods=["GET", "POST"])
@login_required
@handle_errors
def api_config():
    """获取或更新配置"""
    if request.method == "GET":
        config = load_config()
        # 移除敏感信息
        config.pop("web_pass_hash", None)
        return jsonify({"status": "success", "data": config})
    elif request.method == "POST":
        data = request.get_json()
        if not data:
            return jsonify({"status": "error", "message": "无效的请求数据"}), 400
        
        config = load_config()
        updated = False
        
        if "relay_name" in data and data["relay_name"] != config.get("relay_name"):
            config["relay_name"] = data["relay_name"]
            updated = True
        if "web_user" in data and data["web_user"] != config.get("web_user"):
            config["web_user"] = data["web_user"]
            updated = True
        if "new_web_pass" in data and data["new_web_pass"]:
            config["web_pass_hash"] = generate_password_hash(data["new_web_pass"])
            # 更新凭据文件
            with open(CREDENTIALS_FILE, "w", encoding="utf-8") as f:
                f.write(f"# 流量转发中继管理系统 管理凭据\n")
                f.write(f"# 生成时间: {datetime.now().isoformat()}\n")
                f.write(f"WEB_USER={config["web_user"]}\n")
                f.write(f"WEB_PASS={data["new_web_pass"]}\n")
            os.chmod(CREDENTIALS_FILE, 0o600)
            updated = True

        if updated:
            save_config(config)
            log_event("info", "配置已更新", session.get("username"))
            return jsonify({"status": "success", "message": "配置更新成功"})
        else:
            return jsonify({"status": "success", "message": "没有配置更改"})

@app.route("/api/logs")
@login_required
@handle_errors
def api_logs():
    """获取日志"""
    try:
        with open(LOG_FILE, "r", encoding="utf-8") as f:
            logs = f.readlines()[-500:] # 获取最新的500行日志
        return jsonify({"status": "success", "data": logs})
    except Exception as e:
        log_event("error", f"获取日志失败: {str(e)}", session.get("username"))
        return jsonify({"status": "error", "message": str(e)}), 500

if __name__ == "__main__":
    # 启动流量统计更新的后台线程
    def traffic_stats_updater():
        while True:
            calculate_traffic_stats()
            get_network_interface_speed()
            time.sleep(1) # 每秒更新一次

    updater_thread = threading.Thread(target=traffic_stats_updater, daemon=True)
    updater_thread.start()

    app.run(host="127.0.0.1", port=load_config().get("web_port", 8080), debug=False)
\'EOF\'
    chmod 755 $WEB_DIR/app.py
    
    # 创建 templates/login.html
    cat > $WEB_DIR/templates/login.html << \'EOF\'
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>登录 - 流量转发中继管理系统</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.10.0/font/bootstrap-icons.css" rel="stylesheet">
    <style>
        body {
            background-color: #f8f9fa;
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
        }
        .login-container {
            max-width: 400px;
            width: 100%;
            padding: 30px;
            border-radius: 8px;
            box-shadow: 0 0 20px rgba(0, 0, 0, 0.1);
            background-color: #fff;
        }
        .logo-text {
            font-size: 1.8rem;
            font-weight: bold;
            color: #007bff;
            text-align: center;
            margin-bottom: 20px;
        }
        .form-control:focus {
            box-shadow: none;
            border-color: #007bff;
        }
        .btn-primary {
            background-color: #007bff;
            border-color: #007bff;
        }
        .btn-primary:hover {
            background-color: #0056b3;
            border-color: #0056b3;
        }
    </style>
</head>
<body>
    <div class="login-container">
        <div class="logo-text mb-4">
            <i class="bi bi-diagram-3-fill me-2"></i>流量转发中继管理系统
        </div>
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
\'EOF\'

    # 创建 templates/rules.html
    cat > $WEB_DIR/templates/rules.html << \'EOF\'
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>规则管理 - 流量转发中继管理系统</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.10.0/font/bootstrap-icons.css" rel="stylesheet">
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        body {
            font-family: "Segoe UI", Roboto, "Helvetica Neue", Arial, "Noto Sans", sans-serif, "Apple Color Emoji", "Segoe UI Emoji", "Segoe UI Symbol", "Noto Color Emoji";
            background-color: #f0f2f5;
            color: #333;
        }
        .navbar {
            background-color: #fff;
            border-bottom: 1px solid #dee2e6;
        }
        .sidebar {
            width: 250px;
            background-color: #fff;
            padding: 20px;
            border-right: 1px solid #dee2e6;
            height: 100vh;
            position: fixed;
            top: 0;
            left: 0;
            overflow-y: auto;
        }
        .content {
            margin-left: 250px;
            padding: 20px;
        }
        .stat-card {
            border-radius: 8px;
            overflow: hidden;
            box-shadow: 0 2px 10px rgba(0, 0, 0, 0.05);
            margin-bottom: 20px;
        }
        .stat-card .card-body {
            padding: 20px;
        }
        .stats-number {
            font-size: 1.8rem;
            font-weight: bold;
            color: #333;
        }
        .stats-label {
            font-size: 0.9rem;
            color: #6c757d;
        }
        .bandwidth-value {
            font-size: 1.5rem;
            font-weight: bold;
            color: #fff;
        }
        .bandwidth-label {
            font-size: 0.8rem;
            color: rgba(255, 255, 255, 0.8);
        }
        .table-container {
            background-color: #fff;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0, 0, 0, 0.05);
            overflow: hidden;
        }
        .table th, .table td {
            vertical-align: middle;
        }
        .table thead th {
            background-color: #f8f9fa;
            font-weight: bold;
            color: #555;
        }
        .rule-row:hover {
            background-color: #f5f5f5;
        }
        .modal-dialog-centered {
            display: flex;
            align-items: center;
            min-height: calc(100% - 1rem);
        }
        .modal-body code {
            background-color: #e9ecef;
            padding: 2px 4px;
            border-radius: 4px;
        }
        .form-check-input:checked {
            background-color: #0d6efd;
            border-color: #0d6efd;
        }
        .form-check-input:focus {
            box-shadow: 0 0 0 0.25rem rgba(13, 110, 253, 0.25);
        }
        .sidebar .nav-link {
            color: #333;
            padding: 10px 15px;
            border-radius: 5px;
            margin-bottom: 5px;
        }
        .sidebar .nav-link.active {
            background-color: #007bff;
            color: #fff;
        }
        .sidebar .nav-link:hover {
            background-color: #e9ecef;
        }
        .sidebar .nav-link.active:hover {
            background-color: #0056b3;
        }
        .sidebar .logo {
            font-size: 1.5rem;
            font-weight: bold;
            color: #007bff;
            text-align: center;
            margin-bottom: 30px;
        }
        .sidebar .logo i {
            vertical-align: middle;
        }
        .navbar-brand {
            font-weight: bold;
        }
        .navbar-nav .nav-link {
            color: #333;
        }
        .navbar-nav .nav-link:hover {
            color: #007bff;
        }
        .chart-container {
            position: relative;
            height: 200px;
            width: 100%;
        }
        .progress-bar {
            transition: width 0.5s ease-in-out;
        }
    </style>
</head>
<body>
    <div class="sidebar d-flex flex-column">
        <div class="logo">
            <i class="bi bi-diagram-3-fill me-2"></i>{{ config.relay_name if config else '管理系统' }}
        </div>
        <ul class="nav nav-pills flex-column mb-auto">
            <li class="nav-item">
                <a href="/rules" class="nav-link active">
                    <i class="bi bi-diagram-3 me-2"></i>规则管理
                </a>
            </li>
            <li class="nav-item">
                <a href="#" class="nav-link" onclick="showConfigModal()">
                    <i class="bi bi-gear me-2"></i>系统设置
                </a>
            </li>
            <li class="nav-item">
                <a href="#" class="nav-link" onclick="showLogsModal()">
                    <i class="bi bi-file-text me-2"></i>系统日志
                </a>
            </li>
        </ul>
        <div class="mt-auto">
            <hr>
            <div class="dropdown">
                <a href="#" class="d-flex align-items-center text-decoration-none dropdown-toggle" id="dropdownUser2" data-bs-toggle="dropdown" aria-expanded="false">
                    <img src="https://avatars.githubusercontent.com/u/9919?s=200&v=4" alt="" width="32" height="32" class="rounded-circle me-2">
                    <strong>{{ session.username if session.username else 'Guest' }}</strong>
                </a>
                <ul class="dropdown-menu text-small shadow" aria-labelledby="dropdownUser2">
                    <li><a class="dropdown-item" href="/logout">登出</a></li>
                </ul>
            </div>
        </div>
    </div>

    <div class="content">
        <nav class="navbar navbar-expand-lg mb-4">
            <div class="container-fluid">
                <a class="navbar-brand" href="#">仪表盘</a>
                <div class="collapse navbar-collapse" id="navbarNav">
                    <ul class="navbar-nav ms-auto">
                        <li class="nav-item">
                            <span class="nav-link text-muted">
                                <i class="bi bi-calendar me-1"></i>{{ now.strftime('%Y年%m月%d日 %H:%M:%S') }}
                            </span>
                        </li>
                    </ul>
                </div>
            </div>
        </nav>

        <main>
            <div class="container-fluid pt-4 px-4">
                <div class="row g-4">
                    <div class="col-xl-2 col-md-4 col-sm-6">
                        <div class="stat-card card border-0">
                            <div class="card-body d-flex align-items-center">
                                <div class="text-white rounded-3 p-3 me-3" style="background: linear-gradient(135deg, #84fab0 0%, #8fd3f4 100%);">
                                    <i class="bi bi-cpu fs-4"></i>
                                </div>
                                <div class="flex-grow-1">
                                    <div class="stats-number" id="cpuUsage">0%</div>
                                    <div class="stats-label">CPU使用率</div>
                                </div>
                            </div>
                        </div>
                    </div>
                    <div class="col-xl-2 col-md-4 col-sm-6">
                        <div class="stat-card card border-0">
                            <div class="card-body d-flex align-items-center">
                                <div class="text-white rounded-3 p-3 me-3" style="background: linear-gradient(135deg, #a1c4fd 0%, #c2e9fb 100%);">
                                    <i class="bi bi-memory fs-4"></i>
                                </div>
                                <div class="flex-grow-1">
                                    <div class="stats-number" id="memoryUsage">0%</div>
                                    <div class="stats-label">内存使用率</div>
                                </div>
                            </div>
                        </div>
                    </div>
                    <div class="col-xl-2 col-md-4 col-sm-6">
                        <div class="stat-card card border-0">
                            <div class="card-body d-flex align-items-center">
                                <div class="text-white rounded-3 p-3 me-3" style="background: linear-gradient(135deg, #ffecd2 0%, #fcb69f 100%);">
                                    <i class="bi bi-hdd fs-4"></i>
                                </div>
                                <div class="flex-grow-1">
                                    <div class="stats-number" id="diskUsage">0%</div>
                                    <div class="stats-label">磁盘使用率</div>
                                </div>
                            </div>
                        </div>
                    </div>
                    <div class="col-xl-2 col-md-4 col-sm-6">
                        <div class="stat-card card border-0">
                            <div class="card-body d-flex align-items-center">
                                <div class="text-white rounded-3 p-3 me-3" style="background: linear-gradient(135deg, #f6d365 0%, #fda085 100%);">
                                    <i class="bi bi-diagram-3 fs-4"></i>
                                </div>
                                <div class="flex-grow-1">
                                    <div class="stats-number" id="connectionCount">0</div>
                                    <div class="stats-label">规则连接数</div>
                                </div>
                            </div>
                        </div>
                    </div>
                    
                    <div class="col-xl-2 col-md-4 col-sm-6">
                        <div class="stat-card card border-0">
                            <div class="card-body d-flex align-items-center">
                                <div class="text-white rounded-3 p-3 me-3" style="background: linear-gradient(135deg, #a6c1ee 0%, #fbc2eb 100%);">
                                    <i class="bi bi-clock-history fs-4"></i>
                                </div>
                                <div class="flex-grow-1">
                                    <div class="stats-number" id="uptimeValue">0天</div>
                                    <div class="stats-label">运行时间</div>
                                </div>
                            </div>
                        </div>
                    </div>
                    
                    <div class="col-xl-2 col-md-4 col-sm-6">
                        <div class="stat-card card border-0">
                            <div class="card-body">
                                <div class="mb-3">
                                    <div class="d-flex justify-content-between align-items-center mb-2">
                                        <span class="fw-bold">服务状态</span>
                                    </div>
                                    <div class="d-flex flex-column gap-2">
                                        <div class="d-flex justify-content-between">
                                            <span><i class="bi bi-globe me-1"></i>Web服务</span>
                                            <span class="badge bg-success" id="webStatus">运行中</span>
                                        </div>
                                        <div class="d-flex justify-content-between">
                                            <span><i class="bi bi-hdd-network me-1"></i>Nginx服务</span>
                                            <span class="badge bg-success" id="nginxStatus">运行中</span>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
            
            <div class="container-fluid pt-2 px-4">
                <div class="card bg-primary text-white">
                    <div class="card-body">
                        <h6 class="mb-3">
                            <i class="bi bi-speedometer2 me-2"></i>网络带宽监控
                            <small class="ms-2 opacity-75">
                                {{ config.public_interface if config else 'eth0' }} (公网IP: {{ config.public_ip if config and config.public_ip else '未知' }})
                            </small>
                        </h6>
                        <div class="row">
                            <div class="col-md-6 mb-3">
                                <div class="bandwidth-value" id="uploadSpeed">0 bps</div>
                                <div class="bandwidth-label">上传速度</div>
                                <div class="progress mt-2" style="height: 6px;">
                                    <div id="uploadProgress" class="progress-bar bg-info" style="width: 0%;"></div>
                                </div>
                                <small class="mt-2 d-block">累计: <span id="totalUpload">0 B</span></small>
                            </div>
                            <div class="col-md-6 mb-3">
                                <div class="bandwidth-value" id="downloadSpeed">0 bps</div>
                                <div class="bandwidth-label">下载速度</div>
                                <div class="progress mt-2" style="height: 6px;">
                                    <div id="downloadProgress" class="progress-bar bg-success" style="width: 0%;"></div>
                                </div>
                                <small class="mt-2 d-block">累计: <span id="totalDownload">0 B</span></small>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
            
            <div class="container-fluid px-4 pb-4">
                <div class="row">
                    <div class="col-12">
                        <div class="table-container">
                            <div class="d-flex justify-content-between align-items-center p-3 border-bottom">
                                <h5 class="mb-0 fw-bold">
                                    <i class="bi bi-funnel me-2"></i>端口转发规则
                                </h5>
                                <div class="d-flex gap-2">
                                    <button class="btn btn-outline-primary btn-sm" onclick="showRulesJson()">
                                        <i class="bi bi-code-slash me-1"></i>规则配置
                                    </button>
                                    <button class="btn btn-primary btn-sm" onclick="showAddRuleModal()">
                                        <i class="bi bi-plus-circle me-1"></i>添加规则
                                    </button>
                                    <button class="btn btn-success btn-sm" onclick="reloadAllRules()">
                                        <i class="bi bi-arrow-repeat me-1"></i>重新加载
                                    </button>
                                </div>
                            </div>
                            
                            <div class="table-responsive">
                                <table class="table table-hover mb-0">
                                    <thead class="table-light">
                                        <tr>
                                            <th style="width: 60px;">ID</th>
                                            <th style="width: 180px;">规则信息</th>
                                            <th style="width: 160px;">监听地址</th>
                                            <th style="width: 160px;">目标地址</th>
                                            <th style="width: 100px;">协议</th>
                                            <th style="width: 120px;">实时速率</th>
                                            <th style="width: 100px;">状态</th>
                                            <th style="width: 140px;">操作</th>
                                        </tr>
                                    </thead>
                                    <tbody id="rulesTableBody">
                                        {% if rules and rules.forward_rules %}
                                            {% for rule in rules.forward_rules %}
                                            <tr id="rule-row-{{ rule.id }}" class="align-middle rule-row">
                                                <td class="fw-bold">#{{ rule.id }}</td>
                                                <td>
                                                    <div class="fw-semibold">{{ rule.name }}</div>
                                                    {% if rule.description %}
                                                    <small class="text-muted d-block mt-1">{{ rule.description }}</small>
                                                    {% endif %}
                                                </td>
                                                <td>
                                                    <code class="bg-light p-1 rounded">{{ rule.listen_ip }}:{{ rule.listen_port }}</code>
                                                </td>
                                                <td>
                                                    <code class="bg-light p-1 rounded">{{ rule.target_ip }}:{{ rule.target_port }}</code>
                                                </td>
                                                <td>
                                                    <span class="badge {% if rule.protocol == 'udp' %}bg-info{% else %}bg-secondary{% endif %}">
                                                        {{ rule.protocol|upper }}
                                                    </span>
                                                </td>
                                                <td id="rule-speed-{{ rule.id }}" style="width: 120px;">
                                                    <div class="d-flex flex-column">
                                                        <span class="speed-value fw-bold">
                                                            {{ rule.traffic_stats.current_speed_formatted if rule.traffic_stats else '0 bps' }}
                                                        </span>
                                                        <small class="text-muted" id="rule-total-{{ rule.id }}">
                                                            {{ rule.traffic_stats.total_bytes_formatted if rule.traffic_stats else '0 B' }}
                                                        </small>
                                                        <div class="progress mt-1" style="height: 3px;">
                                                            <div id="rule-progress-{{ rule.id }}" class="progress-bar bg-success" style="width: 0%;"></div>
                                                        </div>
                                                    </div>
                                                </td>
                                                <td id="rule-status-{{ rule.id }}">
                                                    {% if rule.enabled %}
                                                    <span class="badge bg-success">启用</span>
                                                    {% else %}
                                                    <span class="badge bg-danger">禁用</span>
                                                    {% endif %}
                                                </td>
                                                <td>
                                                    <div class="btn-group">
                                                        <button class="btn btn-sm btn-outline-primary" onclick="editRule({{ rule.id }})">
                                                            <i class="bi bi-pencil"></i>
                                                        </button>
                                                        <button class="btn btn-sm btn-outline-{% if rule.enabled %}warning{% else %}success{% endif %}" 
                                                                onclick="toggleRule({{ rule.id }})">
                                                            {% if rule.enabled %}
                                                            <i class="bi bi-pause"></i>
                                                            {% else %}
                                                            <i class="bi bi-play"></i>
                                                            {% endif %}
                                                        </button>
                                                        <button class="btn btn-sm btn-outline-danger" onclick="deleteRule({{ rule.id }})">
                                                            <i class="bi bi-trash"></i>
                                                        </button>
                                                    </div>
                                                </td>
                                            </tr>
                                            {% endfor %}
                                        {% else %}
                                        <tr>
                                            <td colspan="8" class="text-center py-5">
                                                <div class="text-muted">
                                                    <i class="bi bi-funnel display-4 mb-3"></i>
                                                    <h5>暂无转发规则</h5>
                                                    <p class="mb-4">开始创建您的第一个端口转发规则</p>
                                                    <button class="btn btn-primary" onclick="showAddRuleModal()">
                                                        <i class="bi bi-plus-circle me-1"></i>创建第一个规则
                                                    </button>
                                                </div>
                                            </td>
                                        </tr>
                                        {% endif %}
                                    </tbody>
                                </table>
                            </div>
                            
                            {% if rules and rules.forward_rules %}
                            <div class="p-3 border-top bg-light">
                                <div class="row align-items-center">
                                    <div class="col-md-6">
                                        <div class="d-flex gap-3">
                                            <small>启用: <span class="fw-bold" id="enabledCount">{{ rules.forward_rules|selectattr('enabled')|list|length }}</span></small>
                                            <small>禁用: <span class="fw-bold" id="disabledCount">{{ rules.forward_rules|rejectattr('enabled')|list|length }}</span></small>
                                            <small>总计: <span class="fw-bold">{{ rules.forward_rules|length }}</span></small>
                                        </div>
                                    </div>
                                    <div class="col-md-6 text-end">
                                        <button class="btn btn-outline-primary btn-sm" onclick="refreshRules()">
                                            <i class="bi bi-arrow-clockwise me-1"></i>刷新列表
                                        </button>
                                    </div>
                                </div>
                            </div>
                            {% endif %}
                        </div>
                    </div>
                </div>
            </div>

            <!-- Add/Edit Rule Modal -->
            <div class="modal fade" id="ruleModal" tabindex="-1" aria-labelledby="ruleModalLabel" aria-hidden="true">
                <div class="modal-dialog modal-dialog-centered">
                    <div class="modal-content">
                        <div class="modal-header">
                            <h5 class="modal-title" id="ruleModalLabel">添加新规则</h5>
                            <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                        </div>
                        <div class="modal-body">
                            <form id="ruleForm">
                                <input type="hidden" id="ruleId">
                                <div class="mb-3">
                                    <label for="ruleName" class="form-label">规则名称</label>
                                    <input type="text" class="form-control" id="ruleName" required>
                                </div>
                                <div class="mb-3">
                                    <label for="ruleDescription" class="form-label">描述 (可选)</label>
                                    <textarea class="form-control" id="ruleDescription" rows="2"></textarea>
                                </div>
                                <div class="row">
                                    <div class="col-md-6 mb-3">
                                        <label for="listenIp" class="form-label">监听IP</label>
                                        <input type="text" class="form-control" id="listenIp" value="0.0.0.0" required>
                                        <small class="form-text text-muted">0.0.0.0 表示监听所有IP</small>
                                    </div>
                                    <div class="col-md-6 mb-3">
                                        <label for="listenPort" class="form-label">监听端口</label>
                                        <input type="number" class="form-control" id="listenPort" min="1" max="65535" required>
                                    </div>
                                </div>
                                <div class="row">
                                    <div class="col-md-6 mb-3">
                                        <label for="targetIp" class="form-label">目标IP</label>
                                        <input type="text" class="form-control" id="targetIp" required>
                                    </div>
                                    <div class="col-md-6 mb-3">
                                        <label for="targetPort" class="form-label">目标端口</label>
                                        <input type="number" class="form-control" id="targetPort" min="1" max="65535" required>
                                    </div>
                                </div>
                                <div class="mb-3">
                                    <label for="protocol" class="form-label">协议</label>
                                    <select class="form-select" id="protocol" required>
                                        <option value="tcp">TCP</option>
                                        <option value="udp">UDP</option>
                                    </select>
                                </div>
                                <div class="form-check mb-3">
                                    <input class="form-check-input" type="checkbox" id="ruleEnabled" checked>
                                    <label class="form-check-label" for="ruleEnabled">启用规则</label>
                                </div>
                                <div class="alert alert-danger d-none" id="ruleErrorAlert" role="alert"></div>
                            </form>
                        </div>
                        <div class="modal-footer">
                            <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">取消</button>
                            <button type="button" class="btn btn-primary" id="saveRuleBtn">保存</button>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Rules JSON Modal -->
            <div class="modal fade" id="rulesJsonModal" tabindex="-1" aria-labelledby="rulesJsonModalLabel" aria-hidden="true">
                <div class="modal-dialog modal-lg modal-dialog-centered">
                    <div class="modal-content">
                        <div class="modal-header">
                            <h5 class="modal-title" id="rulesJsonModalLabel">规则配置 (JSON)</h5>
                            <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                        </div>
                        <div class="modal-body">
                            <pre><code id="rulesJsonContent" class="language-json"></code></pre>
                        </div>
                        <div class="modal-footer">
                            <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">关闭</button>
                        </div>
                    </div>
                </div>
            </div>

            <!-- System Config Modal -->
            <div class="modal fade" id="configModal" tabindex="-1" aria-labelledby="configModalLabel" aria-hidden="true">
                <div class="modal-dialog modal-dialog-centered">
                    <div class="modal-content">
                        <div class="modal-header">
                            <h5 class="modal-title" id="configModalLabel">系统设置</h5>
                            <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                        </div>
                        <div class="modal-body">
                            <form id="configForm">
                                <div class="mb-3">
                                    <label for="relayNameConfig" class="form-label">中继名称</label>
                                    <input type="text" class="form-control" id="relayNameConfig" required>
                                </div>
                                <div class="mb-3">
                                    <label for="webUserConfig" class="form-label">Web管理员用户名</label>
                                    <input type="text" class="form-control" id="webUserConfig" required>
                                </div>
                                <div class="mb-3">
                                    <label for="newWebPassConfig" class="form-label">新密码 (留空则不修改)</label>
                                    <input type="password" class="form-control" id="newWebPassConfig">
                                </div>
                                <div class="alert alert-danger d-none" id="configErrorAlert" role="alert"></div>
                            </form>
                        </div>
                        <div class="modal-footer">
                            <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">取消</button>
                            <button type="button" class="btn btn-primary" id="saveConfigBtn">保存</button>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Logs Modal -->
            <div class="modal fade" id="logsModal" tabindex="-1" aria-labelledby="logsModalLabel" aria-hidden="true">
                <div class="modal-dialog modal-xl modal-dialog-centered">
                    <div class="modal-content">
                        <div class="modal-header">
                            <h5 class="modal-title" id="logsModalLabel">系统日志</h5>
                            <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                        </div>
                        <div class="modal-body">
                            <pre><code id="logsContent" class="language-bash" style="max-height: 60vh; overflow-y: scroll;"></code></pre>
                        </div>
                        <div class="modal-footer">
                            <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">关闭</button>
                        </div>
                    </div>
                </div>
            </div>

        </main>

        <footer class="footer mt-auto py-3 bg-light">
            <div class="container-fluid text-center">
                <span class="text-muted">© {{ now.year }} {{ config.relay_name if config else '流量转发中继管理系统' }}. All rights reserved.</span>
            </div>
        </footer>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/jquery@3.6.0/dist/jquery.min.js"></script>
    <script>
        let systemStatusInterval;
        let rulesRefreshInterval;

        function formatBytes(bytes) {
            if (bytes === 0) return '0 B';
            const k = 1024;
            const sizes = ['B', 'KB', 'MB', 'GB', 'TB', 'PB'];
            const i = Math.floor(Math.log(bytes) / Math.log(k));
            return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
        }

        function formatBits(bits) {
            if (bits === 0) return '0 bps';
            const k = 1000; // For bits, usually 1000 is used
            const sizes = ['bps', 'Kbps', 'Mbps', 'Gbps', 'Tbps', 'Pbps'];
            const i = Math.floor(Math.log(bits) / Math.log(k));
            return parseFloat((bits / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
        }

        function updateSystemStatus() {
            $.getJSON('/api/status', function(data) {
                if (data.status === 'success') {
                    const status = data.data;
                    $('#cpuUsage').text(status.cpu_percent + '%');
                    $('#memoryUsage').text(status.memory_percent + '%');
                    $('#diskUsage').text(status.disk_percent + '%');
                    $('#connectionCount').text(status.connection_stats);
                    $('#uptimeValue').text(status.uptime);

                    $('#webStatus').text(status.web_status === 'active' ? '运行中' : '未运行').removeClass('bg-success bg-danger').addClass(status.web_status === 'active' ? 'bg-success' : 'bg-danger');
                    $('#nginxStatus').text(status.nginx_status === 'active' ? '运行中' : '未运行').removeClass('bg-success bg-danger').addClass(status.nginx_status === 'active' ? 'bg-success' : 'bg-danger');

                    $('#uploadSpeed').text(status.upload_speed_formatted);
                    $('#downloadSpeed').text(status.download_speed_formatted);
                    $('#totalUpload').text(status.total_upload_formatted);
                    $('#totalDownload').text(status.total_download_formatted);

                    const maxSpeed = Math.max(status.upload_speed, status.download_speed, 1);
                    $('#uploadProgress').css('width', (status.upload_speed / maxSpeed * 100) + '%');
                    $('#downloadProgress').css('width', (status.download_speed / maxSpeed * 100) + '%');
                }
            });
        }

        function refreshRules() {
            $.getJSON('/api/rules', function(data) {
                if (data.status === 'success') {
                    const rules = data.data;
                    let rulesTableBody = $('#rulesTableBody');
                    rulesTableBody.empty();

                    if (rules.length === 0) {
                        rulesTableBody.append(`
                            <tr>
                                <td colspan="8" class="text-center py-5">
                                    <div class="text-muted">
                                        <i class="bi bi-funnel display-4 mb-3"></i>
                                        <h5>暂无转发规则</h5>
                                        <p class="mb-4">开始创建您的第一个端口转发规则</p>
                                        <button class="btn btn-primary" onclick="showAddRuleModal()">
                                            <i class="bi bi-plus-circle me-1"></i>创建第一个规则
                                        </button>
                                    </div>
                                </td>
                            </tr>
                        `);
                        $('.p-3.border-top.bg-light').hide();
                    } else {
                        rules.forEach(function(rule) {
                            const statusBadge = rule.enabled ? '<span class="badge bg-success">启用</span>' : '<span class="badge bg-danger">禁用</span>';
                            const toggleButton = rule.enabled ? 
                                `<button class="btn btn-sm btn-outline-warning" onclick="toggleRule(${rule.rule_id})"><i class="bi bi-pause"></i></button>` :
                                `<button class="btn btn-sm btn-outline-success" onclick="toggleRule(${rule.rule_id})"><i class="bi bi-play"></i></button>`;
                            
                            const speedValue = rule.traffic_stats ? rule.traffic_stats.current_speed_formatted : '0 bps';
                            const totalTraffic = rule.traffic_stats ? rule.traffic_stats.total_bytes_formatted : '0 B';
                            const maxSpeed10s = rule.traffic_stats ? rule.traffic_stats.max_speed_10s : 1; // Prevent division by zero
                            const progressWidth = rule.traffic_stats ? (rule.traffic_stats.instant_speed / maxSpeed10s * 100) : 0;

                            rulesTableBody.append(`
                                <tr id="rule-row-${rule.rule_id}" class="align-middle rule-row">
                                    <td class="fw-bold">#${rule.rule_id}</td>
                                    <td>
                                        <div class="fw-semibold">${rule.name}</div>
                                        ${rule.description ? `<small class="text-muted d-block mt-1">${rule.description}</small>` : ''}
                                    </td>
                                    <td>
                                        <code class="bg-light p-1 rounded">${rule.listen_ip}:${rule.listen_port}</code>
                                    </td>
                                    <td>
                                        <code class="bg-light p-1 rounded">${rule.target_ip}:${rule.target_port}</code>
                                    </td>
                                    <td>
                                        <span class="badge ${rule.protocol === 'udp' ? 'bg-info' : 'bg-secondary'}">
                                            ${rule.protocol.toUpperCase()}
                                        </span>
                                    </td>
                                    <td id="rule-speed-${rule.rule_id}" style="width: 120px;">
                                        <div class="d-flex flex-column">
                                            <span class="speed-value fw-bold">${speedValue}</span>
                                            <small class="text-muted" id="rule-total-${rule.rule_id}">${totalTraffic}</small>
                                            <div class="progress mt-1" style="height: 3px;">
                                                <div id="rule-progress-${rule.rule_id}" class="progress-bar bg-success" style="width: ${progressWidth}%;"></div>
                                            </div>
                                        </div>
                                    </td>
                                    <td id="rule-status-${rule.rule_id}">${statusBadge}</td>
                                    <td>
                                        <div class="btn-group">
                                            <button class="btn btn-sm btn-outline-primary" onclick="editRule(${rule.rule_id})">
                                                <i class="bi bi-pencil"></i>
                                            </button>
                                            ${toggleButton}
                                            <button class="btn btn-sm btn-outline-danger" onclick="deleteRule(${rule.rule_id})">
                                                <i class="bi bi-trash"></i>
                                            </button>
                                        </div>
                                    </td>
                                </tr>
                            `);
                        });
                        $('.p-3.border-top.bg-light').show();
                        $('#enabledCount').text(rules.filter(r => r.enabled).length);
                        $('#disabledCount').text(rules.filter(r => !r.enabled).length);
                    }
                }
            });
        }

        function showAddRuleModal() {
            $('#ruleModalLabel').text('添加新规则');
            $('#ruleId').val('');
            $('#ruleForm')[0].reset();
            $('#ruleEnabled').prop('checked', true);
            $('#ruleErrorAlert').addClass('d-none').text('');
            $('#ruleModal').modal('show');
            $('#saveRuleBtn').off('click').on('click', addRule);
        }

        function editRule(ruleId) {
            $.getJSON('/api/rules', function(data) {
                if (data.status === 'success') {
                    const rule = data.data.find(r => r.rule_id === ruleId);
                    if (rule) {
                        $('#ruleModalLabel').text('编辑规则 #' + ruleId);
                        $('#ruleId').val(rule.rule_id);
                        $('#ruleName').val(rule.name);
                        $('#ruleDescription').val(rule.description);
                        $('#listenIp').val(rule.listen_ip);
                        $('#listenPort').val(rule.listen_port);
                        $('#targetIp').val(rule.target_ip);
                        $('#targetPort').val(rule.target_port);
                        $('#protocol').val(rule.protocol);
                        $('#ruleEnabled').prop('checked', rule.enabled);
                        $('#ruleErrorAlert').addClass('d-none').text('');
                        $('#ruleModal').modal('show');
                        $('#saveRuleBtn').off('click').on('click', function() { updateRule(ruleId); });
                    }
                }
            });
        }

        function addRule() {
            const ruleData = {
                name: $('#ruleName').val(),
                description: $('#ruleDescription').val(),
                listen_ip: $('#listenIp').val(),
                listen_port: parseInt($('#listenPort').val()),
                target_ip: $('#targetIp').val(),
                target_port: parseInt($('#targetPort').val()),
                protocol: $('#protocol').val(),
                enabled: $('#ruleEnabled').is(':checked')
            };

            $.ajax({
                url: '/api/rules/add',
                type: 'POST',
                contentType: 'application/json',
                data: JSON.stringify(ruleData),
                success: function(response) {
                    if (response.status === 'success') {
                        $('#ruleModal').modal('hide');
                        refreshRules();
                    } else {
                        $('#ruleErrorAlert').text(response.message).removeClass('d-none');
                    }
                },
                error: function(xhr) {
                    const errorMsg = xhr.responseJSON && xhr.responseJSON.message ? xhr.responseJSON.message : '请求失败';
                    $('#ruleErrorAlert').text(errorMsg).removeClass('d-none');
                }
            });
        }

        function updateRule(ruleId) {
            const ruleData = {
                name: $('#ruleName').val(),
                description: $('#ruleDescription').val(),
                listen_ip: $('#listenIp').val(),
                listen_port: parseInt($('#listenPort').val()),
                target_ip: $('#targetIp').val(),
                target_port: parseInt($('#targetPort').val()),
                protocol: $('#protocol').val(),
                enabled: $('#ruleEnabled').is(':checked')
            };

            $.ajax({
                url: '/api/rules/update/' + ruleId,
                type: 'POST',
                contentType: 'application/json',
                data: JSON.stringify(ruleData),
                success: function(response) {
                    if (response.status === 'success') {
                        $('#ruleModal').modal('hide');
                        refreshRules();
                    } else {
                        $('#ruleErrorAlert').text(response.message).removeClass('d-none');
                    }
                },
                error: function(xhr) {
                    const errorMsg = xhr.responseJSON && xhr.responseJSON.message ? xhr.responseJSON.message : '请求失败';
                    $('#ruleErrorAlert').text(errorMsg).removeClass('d-none');
                }
            });
        }

        function deleteRule(ruleId) {
            if (confirm('确定要删除这条规则吗？')) {
                $.ajax({
                    url: '/api/rules/delete/' + ruleId,
                    type: 'POST',
                    contentType: 'application/json',
                    success: function(response) {
                        if (response.status === 'success') {
                            refreshRules();
                        } else {
                            alert('删除失败: ' + response.message);
                        }
                    },
                    error: function(xhr) {
                        const errorMsg = xhr.responseJSON && xhr.responseJSON.message ? xhr.responseJSON.message : '请求失败';
                        alert('删除失败: ' + errorMsg);
                    }
                });
            }
        }

        function toggleRule(ruleId) {
            $.getJSON('/api/rules', function(data) {
                if (data.status === 'success') {
                    const rule = data.data.find(r => r.rule_id === ruleId);
                    if (rule) {
                        const newStatus = !rule.enabled;
                        $.ajax({
                            url: '/api/rules/toggle/' + ruleId,
                            type: 'POST',
                            contentType: 'application/json',
                            data: JSON.stringify({ enabled: newStatus }),
                            success: function(response) {
                                if (response.status === 'success') {
                                    refreshRules();
                                } else {
                                    alert('切换状态失败: ' + response.message);
                                }
                            },
                            error: function(xhr) {
                                const errorMsg = xhr.responseJSON && xhr.responseJSON.message ? xhr.responseJSON.message : '请求失败';
                                alert('切换状态失败: ' + errorMsg);
                            }
                        });
                    }
                }
            });
        }

        function reloadAllRules() {
            if (confirm('确定要重新加载所有规则吗？这会重新应用所有防火墙规则。')) {
                $.ajax({
                    url: '/api/rules/reload',
                    type: 'POST',
                    contentType: 'application/json',
                    success: function(response) {
                        if (response.status === 'success') {
                            alert('所有规则已重新加载！');
                            refreshRules();
                        } else {
                            alert('重新加载失败: ' + response.message);
                        }
                    },
                    error: function(xhr) {
                        const errorMsg = xhr.responseJSON && xhr.responseJSON.message ? xhr.responseJSON.message : '请求失败';
                        alert('重新加载失败: ' + errorMsg);
                    }
                });
            }
        }

        function showRulesJson() {
            $.getJSON('/api/rules', function(data) {
                if (data.status === 'success') {
                    $('#rulesJsonContent').text(JSON.stringify(data.data, null, 4));
                    $('#rulesJsonModal').modal('show');
                } else {
                    alert('获取规则配置失败: ' + data.message);
                }
            });
        }

        function showConfigModal() {
            $.getJSON('/api/config', function(data) {
                if (data.status === 'success') {
                    const config = data.data;
                    $('#relayNameConfig').val(config.relay_name);
                    $('#webUserConfig').val(config.web_user);
                    $('#newWebPassConfig').val(''); // Clear password field
                    $('#configErrorAlert').addClass('d-none').text('');
                    $('#configModal').modal('show');
                } else {
                    alert('获取系统配置失败: ' + data.message);
                }
            });
            $('#saveConfigBtn').off('click').on('click', saveConfig);
        }

        function saveConfig() {
            const configData = {
                relay_name: $('#relayNameConfig').val(),
                web_user: $('#webUserConfig').val(),
                new_web_pass: $('#newWebPassConfig').val()
            };

            $.ajax({
                url: '/api/config',
                type: 'POST',
                contentType: 'application/json',
                data: JSON.stringify(configData),
                success: function(response) {
                    if (response.status === 'success') {
                        $('#configModal').modal('hide');
                        alert('配置更新成功！');
                        // Optionally refresh page or parts of it
                        location.reload(); 
                    } else {
                        $('#configErrorAlert').text(response.message).removeClass('d-none');
                    }
                },
                error: function(xhr) {
                    const errorMsg = xhr.responseJSON && xhr.responseJSON.message ? xhr.responseJSON.message : '请求失败';
                    $('#configErrorAlert').text(errorMsg).removeClass('d-none');
                }
            });
        }

        function showLogsModal() {
            $.getJSON('/api/logs', function(data) {
                if (data.status === 'success') {
                    $('#logsContent').text(data.data.join(''));
                    $('#logsModal').modal('show');
                } else {
                    alert('获取日志失败: ' + data.message);
                }
            });
        }

        $(document).ready(function() {
            updateSystemStatus();
            refreshRules();
            systemStatusInterval = setInterval(updateSystemStatus, 2000); // 每2秒更新一次系统状态
            rulesRefreshInterval = setInterval(refreshRules, 5000); // 每5秒更新一次规则列表和流量
        });

        // Clear intervals on page unload to prevent memory leaks
        $(window).on('beforeunload', function() {
            clearInterval(systemStatusInterval);
            clearInterval(rulesRefreshInterval);
        });
    </script>
</body>
</html>
\'EOF\'

    # 创建 systemd 服务文件
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
}

create_web_service() {
    info "创建Web管理界面服务..."
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
    systemctl stop wg-relay-web || true
    systemctl disable wg-relay-web || true
    rm -f /etc/systemd/system/wg-relay-web.service
    systemctl daemon-reload
}

create_management_scripts() {
    info "创建管理脚本..."
    # 创建 wg-relay 主管理脚本
    cat > /usr/local/bin/wg-relay << 'EOF'
#!/bin/bash

# ===========================================
# 流量转发中继管理系统 - 命令行管理工具
# ===========================================

CONFIG_DIR="/etc/wg-relay"
LOG_FILE="/var/log/wg-relay.log"
WEB_SERVICE_NAME="wg-relay-web"
RULE_MANAGER_NAME="wg-rule-manager"

log() { echo "[$(date "+%Y-%m-%d %H:%M:%S")] $1" | tee -a "$LOG_FILE"; }
info() { echo "[信息] $1" | tee -a "$LOG_FILE"; }
error() { echo "[错误] $1" | tee -a "$LOG_FILE"; exit 1; }
success() { echo "[成功] $1" | tee -a "$LOG_FILE"; }

show_status() {
    echo "服务状态:"
    systemctl status $WEB_SERVICE_NAME --no-pager || true
    systemctl status nginx --no-pager || true
    echo "\n最近日志:"
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
    status)
        show_status
        ;;
    reload)
        reload_rules
        ;;
    rules)
        shift
        case "$1" in
            list)
                list_rules
                ;;
            *)
                echo "用法: wg-relay rules {list}"
                exit 1
                ;;
        esac
        ;;
    *)
        echo "用法: wg-relay {status|reload|rules}"
        exit 1
        ;;
esac
EOF
    chmod +x /usr/local/bin/wg-relay

    # 创建 wg-relay-stats 脚本
    cat > /usr/local/bin/wg-relay-stats << 'EOF'
#!/usr/bin/python3

import json
import time
import subprocess
import os

CONFIG_DIR = "/etc/wg-relay"
LOG_FILE = "/var/log/wg-relay.log"

def log_event(level, message):
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    log_message = f"[{timestamp}] [{level.upper()}] {message}"
    print(log_message)
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(log_message + "\n")

def format_bytes(bytes_count):
    if bytes_count is None: return "0 B"
    for unit in ["B", "KB", "MB", "GB", "TB", "PB"]:
        if bytes_count < 1024:
            return f"{bytes_count:.2f} {unit}"
        bytes_count /= 1024
    return f"{bytes_count:.2f} PB"

def format_bits(bits_count):
    if bits_count is None: return "0 bps"
    for unit in ["bps", "Kbps", "Mbps", "Gbps", "Tbps", "Pbps"]:
        if bits_count < 1000:
            return f"{bits_count:.2f} {unit}"
        bits_count /= 1000
    return f"{bits_count:.2f} Pbps"

def get_traffic_stats_from_manager():
    try:
        result = subprocess.run(["wg-rule-manager", "stats"], capture_output=True, text=True, check=True)
        output_lines = result.stdout.strip().split("\n")
        stats_data = {}
        for line in output_lines:
            if ":" in line:
                rule_id_str, stats_str = line.split(":", 1)
                rule_id = int(rule_id_str)
                
                total_packets = 0
                total_bytes = 0
                
                parts = stats_str.split(";")
                for part in parts:
                    if part.startswith("conntrack:"):
                        _, packets, bytes_val = part.split(":")
                        total_packets += int(packets)
                        total_bytes += int(bytes_val)
                
                stats_data[rule_id] = {
                    "packets": total_packets,
                    "bytes": total_bytes
                }
        
        return stats_data
        
    except Exception as e:
        log_event("error", f"获取流量统计失败: {e}")
        return {}

def load_forward_rules():
    rules = []
    rules_dir = os.path.join(CONFIG_DIR, "rules")
    os.makedirs(rules_dir, exist_ok=True)
    for filename in os.listdir(rules_dir):
        if filename.startswith("rule_") and filename.endswith(".json"):
            filepath = os.path.join(rules_dir, filename)
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

def main():
    print("\n===========================================")
    print("  流量转发中继管理系统 - 实时统计")
    print("===========================================\n")

    rules_data = load_forward_rules()
    if not rules_data.get("forward_rules"):
        print("暂无转发规则。")
        return

    print(f"{{\n  \"timestamp\": \"{time.strftime('%Y-%m-%d %H:%M:%S')}\",")
    print(f"  \"rules_stats\": [")

    all_stats = get_traffic_stats_from_manager()
    
    for i, rule in enumerate(rules_data["forward_rules"]):
        rule_id = rule.get("id")
        stats = all_stats.get(rule_id, {"bytes": 0, "packets": 0})
        
        print(f"    {{")
        print(f"      \"rule_id\": {rule_id},")
        print(f"      \"name\": \"{rule.get('name', '未知')}\",")
        print(f"      \"protocol\": \"{rule.get('protocol', '未知').upper()}\",")
        print(f"      \"listen_ip\": \"{rule.get('listen_ip', '未知')}\",")
        print(f"      \"listen_port\": {rule.get('listen_port', 0)},")
        print(f"      \"target_ip\": \"{rule.get('target_ip', '未知')}\",")
        print(f"      \"target_port\": {rule.get('target_port', 0)},")
        print(f"      \"enabled\": {str(rule.get('enabled', False)).lower()},")
        print(f"      \"total_bytes\": {stats['bytes']},")
        print(f"      \"total_bytes_formatted\": \"{format_bytes(stats['bytes'])}\",")
        print(f"      \"total_packets\": {stats['packets']}")
        print(f"    }}{',' if i < len(rules_data['forward_rules']) - 1 else ''}")
    print(f"  ]\n}}")

if __name__ == "__main__":
    main()
EOF
    chmod +x /usr/local/bin/wg-relay-stats
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
    systemctl stop wg-relay-web || true
    systemctl disable wg-relay-web || true
    rm -f /etc/systemd/system/wg-relay-web.service
    systemctl daemon-reload
}
