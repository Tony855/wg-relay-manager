#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# ===========================================
# 流量统计收集脚本
# ===========================================

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


def get_traffic_stats_from_manager():
    try:
        result = subprocess.run(
            ["wg-rule-manager", "stats"],
            capture_output=True, text=True, check=True
        )
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

    all_stats = get_traffic_stats_from_manager()
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")

    # BUG FIX: 原代码在 f-string 中使用与外层相同的双引号，例如：
    #   f"\"name\": \"{rule.get("name", "未知")}\""
    # 在 Python 3.12 以下会导致 SyntaxError。
    # 修复方案：先将所有变量提取到局部变量中，再在 f-string 中引用，
    # 完全避免 f-string 内嵌引号问题。

    output_lines = []
    output_lines.append("{")
    output_lines.append(f'  "timestamp": "{timestamp}",')
    output_lines.append('  "rules_stats": [')

    forward_rules = rules_data["forward_rules"]
    total = len(forward_rules)

    for i, rule in enumerate(forward_rules):
        rule_id      = rule.get("id")
        rule_name    = rule.get("name", "未知")
        rule_proto   = rule.get("protocol", "未知").upper()
        rule_lip     = rule.get("listen_ip", "未知")
        rule_lport   = rule.get("listen_port", 0)
        rule_tip     = rule.get("target_ip", "未知")
        rule_tport   = rule.get("target_port", 0)
        rule_enabled = str(rule.get("enabled", False)).lower()

        stats        = all_stats.get(rule_id, {"bytes": 0, "packets": 0})
        total_bytes  = stats["bytes"]
        total_pkts   = stats["packets"]
        bytes_fmt    = format_bytes(total_bytes)

        comma = "," if i < total - 1 else ""
        output_lines.append("    {")
        output_lines.append(f'      "rule_id": {rule_id},')
        output_lines.append(f'      "name": "{rule_name}",')
        output_lines.append(f'      "protocol": "{rule_proto}",')
        output_lines.append(f'      "listen_ip": "{rule_lip}",')
        output_lines.append(f'      "listen_port": {rule_lport},')
        output_lines.append(f'      "target_ip": "{rule_tip}",')
        output_lines.append(f'      "target_port": {rule_tport},')
        output_lines.append(f'      "enabled": {rule_enabled},')
        output_lines.append(f'      "total_bytes": {total_bytes},')
        output_lines.append(f'      "total_bytes_formatted": "{bytes_fmt}",')
        output_lines.append(f'      "total_packets": {total_pkts}')
        output_lines.append(f'    }}{comma}')

    output_lines.append("  ]")
    output_lines.append("}")

    print("\n".join(output_lines))


if __name__ == "__main__":
    main()
