import os
import json
import time
import subprocess
import hashlib
from datetime import datetime, timedelta
from functools import wraps

from flask import Flask, render_template, request, redirect, url_for, session, jsonify

# ===========================================
# Flask Web 应用
# ===========================================

app = Flask(__name__)
app.secret_key = os.urandom(24) # 用于会话管理，生产环境应使用更安全的密钥
app.permanent_session_lifetime = timedelta(days=7) # 设置会话有效期为7天

CONFIG_FILE = "/etc/wg-relay/config.json"
LOG_FILE = "/var/log/wg-relay.log"

def load_config():
    if not os.path.exists(CONFIG_FILE):
        return {
            "relay_name": "WG Relay Manager",
            "web_user": "admin",
            "web_pass_hash": hashlib.sha256("admin".encode()).hexdigest(),
            "public_interface": "eth0",
            "public_ip": "127.0.0.1",
            "next_rule_id": 1
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
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(log_message + "\n")

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'logged_in' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def run_shell_command(command, check=True):
    try:
        result = subprocess.run(command, capture_output=True, text=True, check=check, shell=True)
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

# 路由
@app.route('/')
@login_required
def index():
    config = load_config()
    rules_data = get_forward_rules()
    return render_template('rules.html', config=config, rules=rules_data, now=datetime.now())

@app.route('/login', methods=['GET', 'POST'])
def login():
    config = load_config()
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        remember = request.form.get('remember')

        if username == config["web_user"] and hashlib.sha256(password.encode()).hexdigest() == config["web_pass_hash"]:
            session['logged_in'] = True
            session['username'] = username
            if remember:
                session.permanent = True
            else:
                session.permanent = False
            log_event("info", f"用户 {username} 登录成功")
            return redirect(url_for('index'))
        else:
            log_event("warn", f"用户 {username} 登录失败 (密码错误或用户不存在)")
            return render_template('login.html', error='用户名或密码错误', config=config)
    return render_template('login.html', config=config)

@app.route('/logout')
@login_required
def logout():
    username = session.get('username', '未知用户')
    session.pop('logged_in', None)
    session.pop('username', None)
    session.permanent = False
    log_event("info", f"用户 {username} 已登出")
    return redirect(url_for('login'))

# API 接口
@app.route('/api/status')
@login_required
def api_status():
    try:
        # CPU 使用率
        cpu_percent, _ = run_shell_command("grep 'cpu ' /proc/stat | awk '{usage=($2+$4)*100/($2+$4+$5)} END {print usage}'", check=False)
        cpu_percent = float(cpu_percent) if cpu_percent else 0.0

        # 内存使用率
        mem_info, _ = run_shell_command("free | grep Mem", check=False)
        total_mem = int(mem_info.split()[1])
        used_mem = int(mem_info.split()[2])
        memory_percent = (used_mem / total_mem) * 100 if total_mem > 0 else 0.0

        # 磁盘使用率
        disk_info, _ = run_shell_command("df -h / | awk 'NR==2 {print $5}' | sed 's/%//'", check=False)
        disk_percent = float(disk_info) if disk_info else 0.0

        # 规则连接数 (通过 conntrack 统计)
        connection_stats, _ = run_shell_command("wc -l /proc/net/nf_conntrack 2>/dev/null || echo 0", check=False)
        connection_stats = int(connection_stats) if connection_stats else 0

        # 运行时间
        uptime_seconds, _ = run_shell_command("cat /proc/uptime | awk -F. '{print $1}'", check=False)
        uptime_seconds = int(uptime_seconds) if uptime_seconds else 0
        uptime_days = uptime_seconds // (24 * 3600)
        uptime_hours = (uptime_seconds % (24 * 3600)) // 3600
        uptime_minutes = (uptime_seconds % 3600) // 60
        uptime_str = f"{uptime_days}天 {uptime_hours}小时 {uptime_minutes}分钟"

        # 服务状态
        web_status, _ = run_shell_command("systemctl is-active wg-relay-web", check=False)
        nginx_status, _ = run_shell_command("systemctl is-active nginx", check=False)

        # 带宽监控
        config = load_config()
        interface = config.get("public_interface", "eth0")
        public_ip = config.get("public_ip", "未知")

        # 获取当前时间戳
        current_timestamp = time.time()
        # 定义存储历史数据的字典
        if 'traffic_history' not in app.__dict__:
            app.traffic_history = {}

        # 从 /proc/net/dev 获取流量数据
        net_dev_output, _ = run_shell_command(f"grep {interface}: /proc/net/dev", check=False)
        if net_dev_output:
            parts = net_dev_output.split()
            # RX bytes (received bytes) is the second column (index 1)
            # TX bytes (transmitted bytes) is the tenth column (index 9)
            current_rx_bytes = int(parts[1])
            current_tx_bytes = int(parts[9])
        else:
            current_rx_bytes = 0
            current_tx_bytes = 0

        # 获取历史数据
        last_timestamp = app.traffic_history.get(interface, {}).get('timestamp', current_timestamp)
        last_rx_bytes = app.traffic_history.get(interface, {}).get('rx_bytes', current_rx_bytes)
        last_tx_bytes = app.traffic_history.get(interface, {}).get('tx_bytes', current_tx_bytes)
        total_rx_bytes = app.traffic_history.get(interface, {}).get('total_rx_bytes', 0)
        total_tx_bytes = app.traffic_history.get(interface, {}).get('total_tx_bytes', 0)

        # 计算时间差
        time_diff = current_timestamp - last_timestamp
        if time_diff <= 0: # 避免除以零或负数
            time_diff = 1 # 至少为1秒

        # 计算瞬时速度 (bytes/second)
        download_speed_bytes = (current_rx_bytes - last_rx_bytes) / time_diff
        upload_speed_bytes = (current_tx_bytes - last_tx_bytes) / time_diff

        # 更新总流量
        total_rx_bytes += (current_rx_bytes - last_rx_bytes)
        total_tx_bytes += (current_tx_bytes - last_tx_bytes)

        # 更新历史数据
        app.traffic_history[interface] = {
            'timestamp': current_timestamp,
            'rx_bytes': current_rx_bytes,
            'tx_bytes': current_tx_bytes,
            'total_rx_bytes': total_rx_bytes,
            'total_tx_bytes': total_tx_bytes
        }

        # 转换为 bits/second
        download_speed_bits = download_speed_bytes * 8
        upload_speed_bits = upload_speed_bytes * 8

        response_data = {
            "status": "success",
            "data": {
                "cpu_percent": round(cpu_percent, 2),
                "memory_percent": round(memory_percent, 2),
                "disk_percent": round(disk_percent, 2),
                "connection_stats": connection_stats,
                "uptime": uptime_str,
                "web_status": web_status.strip(),
                "nginx_status": nginx_status.strip(),
                "public_interface": interface,
                "public_ip": public_ip,
                "upload_speed": upload_speed_bits,
                "download_speed": download_speed_bits,
                "upload_speed_formatted": format_bits(upload_speed_bits),
                "download_speed_formatted": format_bits(download_speed_bits),
                "total_upload": total_tx_bytes,
                "total_download": total_rx_bytes,
                "total_upload_formatted": format_bytes(total_tx_bytes),
                "total_download_formatted": format_bytes(total_rx_bytes)
            }
        }
        return jsonify(response_data)
    except Exception as e:
        log_event("error", f"获取系统状态失败: {e}")
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/api/rules')
@login_required
def get_forward_rules():
    try:
        stdout, stderr = run_shell_command("wg-rule-manager list", check=False)
        rules_raw = stdout.strip().split("\n\n")
        rules = []
        for rule_json_str in rules_raw:
            if rule_json_str:
                try:
                    rule = json.loads(rule_json_str)
                    # 获取流量统计
                    stats_output, _ = run_shell_command(f"wg-rule-manager stats {rule['id']}", check=False)
                    stats_parts = stats_output.split(';')
                    total_bytes = 0
                    for part in stats_parts:
                        if part.startswith("conntrack:"):
                            _, packets, bytes_val = part.split(":")
                            total_bytes += int(bytes_val)
                    
                    # 瞬时速度计算 (这里需要更复杂的逻辑来存储历史数据并计算差值)
                    # 暂时简化处理，Web前端会自己计算瞬时速度
                    rule["traffic_stats"] = {
                        "total_bytes": total_bytes,
                        "total_bytes_formatted": format_bytes(total_bytes),
                        "current_speed": 0, # 待前端计算
                        "current_speed_formatted": "0 bps", # 待前端计算
                        "instant_speed": 0, # 待前端计算
                        "max_speed_10s": 1 # 待前端计算
                    }
                    rules.append(rule)
                except json.JSONDecodeError:
                    log_event("warn", f"无法解析规则JSON: {rule_json_str}")
        
        # 对规则进行排序，确保ID递增
        rules.sort(key=lambda x: x.get('id', 0))

        return jsonify({"status": "success", "data": rules})
    except Exception as e:
        log_event("error", f"获取转发规则失败: {e}")
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/api/rules/add', methods=['POST'])
@login_required
def add_rule():
    try:
        data = request.get_json()
        name = data['name']
        protocol = data['protocol']
        listen_ip = data['listen_ip']
        listen_port = data['listen_port']
        target_ip = data['target_ip']
        target_port = data['target_port']
        enabled = str(data.get('enabled', True)).lower()
        description = data.get('description', '')

        # 检查端口冲突
        check_conflict_cmd = f"wg-rule-manager check_port_conflict {listen_port} \"{name}\""
        stdout, stderr = run_shell_command(check_conflict_cmd, check=False)
        if "warn" in stderr.lower() or "error" in stderr.lower():
            return jsonify({"status": "error", "message": stderr.strip()}), 400

        rule_id = get_next_rule_id()
        command = [
            "wg-rule-manager", "add",
            str(rule_id), name, protocol, listen_ip, str(listen_port),
            target_ip, str(target_port), enabled, description
        ]
        stdout, stderr = run_shell_command(command)
        if stderr:
            return jsonify({"status": "error", "message": stderr}), 500
        log_event("info", f"添加规则 {rule_id}: {name}")
        return jsonify({"status": "success", "message": "规则添加成功", "rule_id": rule_id})
    except Exception as e:
        log_event("error", f"添加规则失败: {e}")
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/api/rules/update/<int:rule_id>', methods=['POST'])
@login_required
def update_rule(rule_id):
    try:
        data = request.get_json()
        updates = {}
        if 'name' in data: updates['name'] = data['name']
        if 'protocol' in data: updates['protocol'] = data['protocol']
        if 'listen_ip' in data: updates['listen_ip'] = data['listen_ip']
        if 'listen_port' in data: updates['listen_port'] = data['listen_port']
        if 'target_ip' in data: updates['target_ip'] = data['target_ip']
        if 'target_port' in data: updates['target_port'] = data['target_port']
        if 'enabled' in data: updates['enabled'] = data['enabled']
        if 'description' in data: updates['description'] = data['description']

        # 检查端口冲突，排除当前规则
        if 'listen_port' in data:
            check_conflict_cmd = f"wg-rule-manager check_port_conflict {data['listen_port']} \"\" {rule_id}"
            stdout, stderr = run_shell_command(check_conflict_cmd, check=False)
            if "warn" in stderr.lower() or "error" in stderr.lower():
                return jsonify({"status": "error", "message": stderr.strip()}), 400

        updates_json = json.dumps(updates, ensure_ascii=False)
        command = ["wg-rule-manager", "update", str(rule_id), updates_json]
        stdout, stderr = run_shell_command(command)
        if stderr:
            return jsonify({"status": "error", "message": stderr}), 500
        log_event("info", f"更新规则 {rule_id}")
        return jsonify({"status": "success", "message": "规则更新成功"})
    except Exception as e:
        log_event("error", f"更新规则失败: {e}")
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/api/rules/delete/<int:rule_id>', methods=['POST'])
@login_required
def delete_rule(rule_id):
    try:
        command = ["wg-rule-manager", "delete", str(rule_id)]
        stdout, stderr = run_shell_command(command)
        if stderr:
            return jsonify({"status": "error", "message": stderr}), 500
        log_event("info", f"删除规则 {rule_id}")
        return jsonify({"status": "success", "message": "规则删除成功"})
    except Exception as e:
        log_event("error", f"删除规则失败: {e}")
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/api/rules/toggle/<int:rule_id>', methods=['POST'])
@login_required
def toggle_rule(rule_id):
    try:
        data = request.get_json()
        enabled = str(data['enabled']).lower()
        command = ["wg-rule-manager", "toggle", str(rule_id), enabled]
        stdout, stderr = run_shell_command(command)
        if stderr:
            return jsonify({"status": "error", "message": stderr}), 500
        log_event("info", f"切换规则 {rule_id} 状态为 {enabled}")
        return jsonify({"status": "success", "message": "规则状态切换成功"})
    except Exception as e:
        log_event("error", f"切换规则状态失败: {e}")
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/api/rules/reload', methods=['POST'])
@login_required
def reload_rules():
    try:
        command = ["wg-rule-manager", "reload"]
        stdout, stderr = run_shell_command(command)
        if stderr:
            return jsonify({"status": "error", "message": stderr}), 500
        log_event("info", "所有规则已重新加载")
        return jsonify({"status": "success", "message": "所有规则已重新加载"})
    except Exception as e:
        log_event("error", f"重新加载规则失败: {e}")
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/api/config', methods=['GET', 'POST'])
@login_required
def api_config():
    config = load_config()
    if request.method == 'POST':
        try:
            data = request.get_json()
            if 'relay_name' in data: config['relay_name'] = data['relay_name']
            if 'web_user' in data: config['web_user'] = data['web_user']
            if 'new_web_pass' in data and data['new_web_pass']:
                config['web_pass_hash'] = hashlib.sha256(data['new_web_pass'].encode()).hexdigest()
            save_config(config)
            log_event("info", "系统配置已更新")
            return jsonify({"status": "success", "message": "配置更新成功"})
        except Exception as e:
            log_event("error", f"更新系统配置失败: {e}")
            return jsonify({"status": "error", "message": str(e)}), 500
    else:
        # GET 请求返回当前配置，不包含密码哈希
        display_config = config.copy()
        display_config.pop('web_pass_hash', None)
        return jsonify({"status": "success", "data": display_config})

@app.route('/api/logs')
@login_required
def api_logs():
    try:
        if not os.path.exists(LOG_FILE):
            return jsonify({"status": "success", "data": ["日志文件不存在"]})
        with open(LOG_FILE, "r", encoding="utf-8") as f:
            logs = f.readlines()[-500:] # 只读取最新的500行
        return jsonify({"status": "success", "data": logs})
    except Exception as e:
        log_event("error", f"读取日志失败: {e}")
        return jsonify({"status": "error", "message": str(e)}), 500

if __name__ == '__main__':
    # 确保配置文件存在
    if not os.path.exists(CONFIG_FILE):
        save_config(load_config())
    app.run(host='0.0.0.0', port=5000)
