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

    print(f"{{\n  \"timestamp\": \"{time.strftime("%Y-%m-%d %H:%M:%S")}\",")
    print(f"  \"rules_stats\": [")

    all_stats = get_traffic_stats_from_manager()
    
    for i, rule in enumerate(rules_data["forward_rules"]):
        rule_id = rule.get("id")
        stats = all_stats.get(rule_id, {"bytes": 0, "packets": 0})
        
        print(f"    {{")
        print(f"      \"rule_id\": {rule_id},")
        print(f"      \"name\": \"{rule.get("name", "未知")}\",")
        print(f"      \"protocol\": \"{rule.get("protocol", "未知").upper()}\",")
        print(f"      \"listen_ip\": \"{rule.get("listen_ip", "未知")}\",")
        print(f"      \"listen_port\": {rule.get("listen_port", 0)},")
        print(f"      \"target_ip\": \"{rule.get("target_ip", "未知")}\",")
        print(f"      \"target_port\": {rule.get("target_port", 0)},")
        print(f"      \"enabled\": {str(rule.get("enabled", False)).lower()},")
        print(f"      \"total_bytes\": {stats["bytes"]},")
        print(f"      \"total_bytes_formatted\": \"{format_bytes(stats["bytes"]) }\",")
        print(f"      \"total_packets\": {stats["packets"]}")
        print(f"    }}{"," if i < len(rules_data["forward_rules"]) - 1 else ""}")
    print(f"  ]\n}}")

if __name__ == "__main__":
    main()
