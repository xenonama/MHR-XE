#!/usr/bin/env python3
"""
MHR-XE Monitor - Full Feature with Group Shortcuts
"""

import json
import threading
import time
import os
import re
from datetime import datetime
from http.server import HTTPServer, SimpleHTTPRequestHandler
from pathlib import Path

WEB_PORT = 8888
DAILY_LIMIT = 20000
LOG_FILE = "logs/proxy.log"
RULES_FILE = "monitor_rules.json"
CONFIG_FILE = "config.json"
USAGE_LOG_FILE = "logs/usage.log"

# ============ بارگذاری و ذخیره قوانین ============

def load_rules():
    default_rules = {
        "mode": "normal",
        "whitelist": [],
        "blacklist": [],
        "auto_apply": True
    }
    if os.path.exists(RULES_FILE):
        try:
            with open(RULES_FILE, 'r', encoding='utf-8') as f:
                rules = json.load(f)
                for key in default_rules:
                    if key not in rules:
                        rules[key] = default_rules[key]
                return rules
        except Exception:
            return default_rules
    return default_rules

def save_rules(rules):
    try:
        with open(RULES_FILE, 'w', encoding='utf-8') as f:
            json.dump(rules, f, indent=2, ensure_ascii=False)
        return True
    except Exception:
        return False

def apply_rules_to_config(rules):
    if not os.path.exists(CONFIG_FILE):
        return False
    try:
        with open(CONFIG_FILE, 'r', encoding='utf-8') as f:
            config = json.load(f)
        
        if rules["mode"] == "whitelist":
            config["bypass_hosts"] = list(rules["whitelist"])
            config["block_hosts"] = []
        elif rules["mode"] == "blacklist":
            config["block_hosts"] = list(rules["blacklist"])
            config["bypass_hosts"] = []
        else:
            config["block_hosts"] = []
            config["bypass_hosts"] = []
        
        with open(CONFIG_FILE, 'w', encoding='utf-8') as f:
            json.dump(config, f, indent=2, ensure_ascii=False)
        return True
    except Exception:
        return False

def write_usage_log():
    try:
        Path("logs").mkdir(exist_ok=True)
        with open(USAGE_LOG_FILE, "a", encoding='utf-8') as f:
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            f.write(f"[{timestamp}] Total: {stats['total_requests']} | "
                    f"Errors: {stats['errors_count']} | "
                    f"Blocked: {stats['blocked_count']} | "
                    f"Rate: {stats['rate_per_minute']}/min | "
                    f"Remaining: {stats['remaining']}\n")
    except Exception:
        pass

# ============ آمار ============

stats = {
    "total_requests": 0,
    "daily_limit": DAILY_LIMIT,
    "remaining": DAILY_LIMIT,
    "percent_used": 0,
    "rate_per_minute": 0,
    "minutes_left": 0,
    "hours_left": 0,
    "top_hosts": {},
    "errors_count": 0,
    "top_errors": {},
    "last_update": datetime.now().strftime("%H:%M:%S"),
    "running_time": "0:00:00",
    "start_time": datetime.now(),
    "blocked_count": 0,
    "blocked_hosts": {}
}

current_rules = load_rules()
last_position = 0
last_usage_log_time = 0

PATTERNS = {
    "HTTP_POST": re.compile(r"HTTP → POST http://([^/:]+)(?::\d+)?/api"),
    "CONNECT": re.compile(r"CONNECT → ([^\s:]+)"),
    "MITM": re.compile(r"MITM → (?:GET|POST) https?://([^/]+)"),
    "SOCKS5": re.compile(r"SOCKS5 CONNECT → ([^\s:]+)"),
    "ERROR_502": re.compile(r"RESP ← ([^\s]+) status=502"),
    "ERROR_403": re.compile(r"RESP ← ([^\s]+) status=403"),
    "RELAY_ERROR": re.compile(r"ERROR.*Relay error.*\((?:https?://)?([^/:]+)"),
}

def is_host_in_whitelist(host):
    if not host:
        return False
    host_lower = host.lower()
    for pattern in current_rules["whitelist"]:
        p_lower = pattern.lower()
        if p_lower.startswith('.'):
            if host_lower.endswith(p_lower) or host_lower == p_lower[1:]:
                return True
        elif host_lower == p_lower or host_lower.endswith('.' + p_lower):
            return True
    return False

def is_host_in_blacklist(host):
    if not host:
        return False
    host_lower = host.lower()
    for pattern in current_rules["blacklist"]:
        p_lower = pattern.lower()
        if p_lower.startswith('.'):
            if host_lower.endswith(p_lower) or host_lower == p_lower[1:]:
                return True
        elif host_lower == p_lower or host_lower.endswith('.' + p_lower):
            return True
    return False

def is_host_blocked(host):
    if current_rules["mode"] == "normal":
        return False
    if not host:
        return False
    
    host_lower = host.lower()
    
    if current_rules["mode"] == "whitelist":
        allowed = False
        for pattern in current_rules["whitelist"]:
            p_lower = pattern.lower()
            if p_lower.startswith('.'):
                if host_lower.endswith(p_lower) or host_lower == p_lower[1:]:
                    allowed = True
                    break
            elif host_lower == p_lower or host_lower.endswith('.' + p_lower):
                allowed = True
                break
        return not allowed
    else:
        for pattern in current_rules["blacklist"]:
            p_lower = pattern.lower()
            if p_lower.startswith('.'):
                if host_lower.endswith(p_lower) or host_lower == p_lower[1:]:
                    return True
            elif host_lower == p_lower or host_lower.endswith('.' + p_lower):
                return True
        return False

def parse_line(line):
    host = None
    if "HTTP → POST http://" in line:
        match = PATTERNS["HTTP_POST"].search(line)
        if match:
            host = match.group(1)
    elif "CONNECT →" in line and "api" not in line:
        match = PATTERNS["CONNECT"].search(line)
        if match:
            host = match.group(1)
    elif "MITM →" in line:
        match = PATTERNS["MITM"].search(line)
        if match:
            host = match.group(1)
    elif "SOCKS5 CONNECT →" in line:
        match = PATTERNS["SOCKS5"].search(line)
        if match:
            host = match.group(1)
    elif "status=502" in line or "status=403" in line:
        match = PATTERNS["ERROR_502"].search(line) or PATTERNS["ERROR_403"].search(line)
        if match:
            stats["errors_count"] += 1
            stats["top_errors"][match.group(1)] = stats["top_errors"].get(match.group(1), 0) + 1
            return True
    elif "Relay error" in line:
        match = PATTERNS["RELAY_ERROR"].search(line)
        if match:
            host = match.group(1)
            stats["errors_count"] += 1
            stats["top_errors"][host] = stats["top_errors"].get(host, 0) + 1
            return True
    
    if host:
        if is_host_blocked(host):
            stats["blocked_count"] += 1
            stats["blocked_hosts"][host] = stats["blocked_hosts"].get(host, 0) + 1
            return True
        
        stats["total_requests"] += 1
        stats["top_hosts"][host] = stats["top_hosts"].get(host, 0) + 1
        return True
    
    return False

def update_stats():
    elapsed = datetime.now() - stats["start_time"]
    stats["running_time"] = str(elapsed).split('.')[0]
    stats["last_update"] = datetime.now().strftime("%H:%M:%S")
    stats["percent_used"] = round((stats["total_requests"] / DAILY_LIMIT) * 100, 1) if DAILY_LIMIT > 0 else 0
    stats["remaining"] = max(0, DAILY_LIMIT - stats["total_requests"])
    
    minutes = elapsed.total_seconds() / 60
    if minutes > 0 and stats["total_requests"] > 0:
        rate = stats["total_requests"] / minutes
        stats["rate_per_minute"] = round(rate, 1)
        if rate > 0:
            stats["minutes_left"] = round(stats["remaining"] / rate, 0)
            stats["hours_left"] = round(stats["minutes_left"] / 60, 1)

def reset_stats():
    global stats, last_position, last_usage_log_time
    stats["total_requests"] = 0
    stats["errors_count"] = 0
    stats["blocked_count"] = 0
    stats["top_hosts"] = {}
    stats["top_errors"] = {}
    stats["blocked_hosts"] = {}
    stats["start_time"] = datetime.now()
    stats["running_time"] = "0:00:00"
    last_position = 0
    last_usage_log_time = 0
    return True

def read_log_file():
    global last_position, last_usage_log_time
    
    if not os.path.exists(LOG_FILE):
        return
    
    try:
        with open(LOG_FILE, 'r', encoding='utf-8', errors='ignore') as f:
            f.seek(last_position)
            new_lines = f.readlines()
            last_position = f.tell()
            
            for line in new_lines:
                if parse_line(line):
                    update_stats()
    except Exception:
        pass
    
    now = time.time()
    if now - last_usage_log_time >= 300:
        write_usage_log()
        last_usage_log_time = now

def monitor_loop():
    while True:
        try:
            read_log_file()
            time.sleep(1)
        except Exception:
            time.sleep(5)

# ============ HTML Dashboard ============

HTML_TEMPLATE = '''<!DOCTYPE html>
<html lang="fa" dir="rtl">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>MHR-XE Monitor</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #0a0a1a 0%, #0f0f23 50%, #1a1a3e 100%);
            min-height: 100vh;
            padding: 20px;
            color: #e0e0ff;
        }
        .container { max-width: 1600px; margin: 0 auto; }
        .header { text-align: center; margin-bottom: 20px; }
        
        /* Mode Bar */
        .mode-bar {
            display: flex;
            justify-content: center;
            gap: 10px;
            margin-bottom: 20px;
        }
        .mode-btn {
            padding: 8px 25px;
            border: none;
            border-radius: 40px;
            cursor: pointer;
            font-size: 0.85rem;
            font-weight: 600;
            background: rgba(255,255,255,0.1);
            color: #aaa;
        }
        .mode-btn.active { background: linear-gradient(135deg, #00d2ff, #3a7bd5); color: white; }
        .mode-desc { font-size:0.7rem; margin-bottom: 20px; color:#888; text-align:center; }
        
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(260px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        .stat-card {
            background: rgba(255,255,255,0.05);
            backdrop-filter: blur(12px);
            border-radius: 20px;
            padding: 22px;
        }
        .stat-title { font-size: 0.75rem; text-transform: uppercase; letter-spacing: 3px; color: #88aaff; }
        .stat-value { font-size: 2.2rem; font-weight: bold; background: linear-gradient(135deg, #fff, #88aaff); -webkit-background-clip: text; background-clip: text; color: transparent; }
        .progress-bar { background: rgba(255,255,255,0.1); border-radius: 20px; height: 6px; margin-top: 15px; }
        .progress-fill { background: linear-gradient(90deg, #00d2ff, #7b2f9d); height: 100%; border-radius: 20px; transition: width 0.5s; }
        .progress-fill.danger { background: linear-gradient(90deg, #ff4444, #cc0000); animation: pulse 0.8s infinite; }
        @keyframes pulse { 0%,100% { opacity: 1; } 50% { opacity: 0.6; } }
        
        .tables-container { display: grid; grid-template-columns: repeat(auto-fit, minmax(550px, 1fr)); gap: 20px; margin-bottom: 30px; }
        .table-card { background: rgba(15,15,35,0.6); border-radius: 20px; padding: 20px; overflow-x: auto; }
        .table-card h3 { margin-bottom: 15px; border-right: 3px solid #00d2ff; padding-right: 12px; }
        table { width: 100%; border-collapse: collapse; }
        th, td { padding: 10px; text-align: right; border-bottom: 1px solid rgba(255,255,255,0.05); }
        .host-cell { font-family: monospace; font-size: 0.8rem; word-break: break-all; max-width: 400px; }
        .count-cell { text-align: left; font-weight: bold; color: #00d2ff; }
        .error-cell { color: #ff6b6b; }
        .status-icon { display: inline-block; width: 20px; text-align: center; margin-left: 5px; }
        .status-ok { color: #0f0; }
        .status-blocked { color: #f44; }
        .status-none { color: #888; }
        .action-buttons { display: flex; gap: 5px; flex-wrap: wrap; }
        .btn-icon {
            background: rgba(255,255,255,0.08);
            border: none;
            border-radius: 6px;
            padding: 4px 10px;
            cursor: pointer;
            font-size: 11px;
        }
        .btn-whitelist { background: rgba(0,210,255,0.2); }
        .btn-whitelist:hover { background: rgba(0,210,255,0.5); }
        .btn-blacklist { background: rgba(244,67,54,0.2); }
        .btn-blacklist:hover { background: rgba(244,67,54,0.5); }
        
        /* Rule panels with inline shortcuts */
        .rule-panels { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; margin-bottom: 20px; }
        .rule-card { background: rgba(15,15,35,0.6); border-radius: 20px; padding: 20px; }
        .rule-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 15px;
            flex-wrap: wrap;
            gap: 10px;
        }
        .rule-header h3 { margin: 0; border-right: 3px solid #00d2ff; padding-right: 12px; }
        .group-shortcuts {
            display: flex;
            gap: 6px;
            flex-wrap: wrap;
        }
        .shortcut-btn {
            padding: 4px 10px;
            border: none;
            border-radius: 20px;
            cursor: pointer;
            font-size: 0.7rem;
            font-weight: bold;
            background: rgba(255,255,255,0.1);
            color: #ddd;
        }
        .shortcut-youtube { background: rgba(255,0,0,0.3); }
        .shortcut-instagram { background: rgba(225,48,108,0.3); }
        .shortcut-telegram { background: rgba(0,136,204,0.3); }
        .shortcut-github { background: rgba(255,255,255,0.2); }
        .shortcut-all { background: rgba(123,47,157,0.3); }
        
        .rule-list { background: rgba(0,0,0,0.3); border-radius: 12px; padding: 12px; min-height: 100px; max-height: 160px; overflow-y: auto; }
        .rule-item {
            display: inline-block;
            background: rgba(0,210,255,0.12);
            border-radius: 20px;
            padding: 5px 12px;
            margin: 4px;
            font-size: 12px;
            font-family: monospace;
        }
        .rule-item button { background: none; border: none; color: #ff8888; cursor: pointer; margin-left: 8px; }
        .add-rule { display: flex; gap: 10px; margin-top: 12px; }
        .add-rule input { flex: 1; padding: 8px; border-radius: 10px; background: rgba(255,255,255,0.08); color: white; border: none; }
        .add-rule button { padding: 8px 15px; background: linear-gradient(135deg, #00d2ff, #3a7bd5); border: none; border-radius: 10px; cursor: pointer; }
        
        .btn-apply { background: linear-gradient(135deg, #7b2f9d, #00d2ff); border: none; border-radius: 40px; padding: 12px 35px; color: white; font-weight: bold; margin: 10px; cursor: pointer; }
        .btn-reset { background: linear-gradient(135deg, #ff4444, #cc0000); border: none; border-radius: 40px; padding: 12px 25px; color: white; font-weight: bold; margin: 10px; cursor: pointer; }
        
        .footer { text-align: center; padding: 20px; border-top: 1px solid rgba(255,255,255,0.05); margin-top: 20px; }
        .credit { color: #555; font-size: 0.7rem; margin-top: 8px; }
        .update-time { position: fixed; bottom: 12px; left: 15px; font-size: 0.7rem; color: #444; background: rgba(0,0,0,0.5); padding: 4px 12px; border-radius: 20px; }
        
        @media (max-width: 900px) { .stats-grid { grid-template-columns: 1fr; } .rule-panels { grid-template-columns: 1fr; } .host-cell { max-width: 200px; font-size: 0.7rem; } }
    </style>
</head>
<body>
    <div class="container">
        <div class="mode-bar">
            <button class="mode-btn" data-mode="normal" id="modeNormal">🌐 Normal</button>
            <button class="mode-btn" data-mode="blacklist" id="modeBlacklist">🛡️ Blacklist</button>
            <button class="mode-btn" data-mode="whitelist" id="modeWhitelist">✨ Whitelist</button>
        </div>
        <div class="mode-desc" id="modeDesc"></div>
        
        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-title">📡 TOTAL REQUESTS</div>
                <div class="stat-value"><span id="totalRequests">0</span> <span class="stat-unit">/ <span id="dailyLimit">20000</span></span></div>
                <div class="progress-bar"><div class="progress-fill" id="progressFill" style="width: 0%"></div></div>
                <div><span id="percentUsed">0</span>% of daily quota</div>
            </div>
            <div class="stat-card">
                <div class="stat-title">⏱️ REQUEST RATE</div>
                <div class="stat-value"><span id="ratePerMinute">0</span> <span class="stat-unit">req/min</span></div>
                <div>Time left: <strong id="timeLeft" style="color:#00d2ff;">Unlimited</strong></div>
                <div>Uptime: <span id="runningTime">0</span></div>
            </div>
            <div class="stat-card">
                <div class="stat-title">⚠️ ERRORS / BLOCKED</div>
                <div class="stat-value"><span id="errorsCount" style="color:#ff6b6b;">0</span> / <span id="blockedCount" style="color:#ffaa44;">0</span></div>
                <div>✅ Success: <span id="successRate">100</span>%</div>
                <div>🚫 Blocked: <span id="blockedPercent">0</span>%</div>
            </div>
        </div>
        
        <div class="tables-container">
            <div class="table-card">
                <h3>📊 All Hosts <span style="font-size:11px;">(sorted by count)</span></h3>
                <div style="max-height: 500px; overflow-y: auto;">
                    <table style="width:100%">
                        <thead><tr><th>Host</th><th>Count</th><th>Actions</th></tr></thead>
                        <tbody id="allHostsBody"></tbody>
                    </table>
                </div>
            </div>
            <div class="table-card">
                <h3>⚠️ Top Errors</h3>
                <div style="max-height: 500px; overflow-y: auto;">
                    <table style="width:100%">
                        <thead><tr><th>Host</th><th>Count</th></tr></thead>
                        <tbody id="topErrorsBody"></tbody>
                    </table>
                </div>
            </div>
        </div>
        
        <div class="rule-panels">
            <div class="rule-card">
                <div class="rule-header">
                    <h3>✅ Whitelist</h3>
                    <div class="group-shortcuts">
                        <button class="shortcut-btn shortcut-youtube" onclick="toggleServiceGroup('youtube', 'whitelist')" oncontextmenu="event.preventDefault(); toggleServiceGroup('youtube', 'blacklist')">🎬 YT</button>
                        <button class="shortcut-btn shortcut-instagram" onclick="toggleServiceGroup('instagram', 'whitelist')" oncontextmenu="event.preventDefault(); toggleServiceGroup('instagram', 'blacklist')">📸 IG</button>
                        <button class="shortcut-btn shortcut-telegram" onclick="toggleServiceGroup('telegram', 'whitelist')" oncontextmenu="event.preventDefault(); toggleServiceGroup('telegram', 'blacklist')">💬 TG</button>
                        <button class="shortcut-btn shortcut-github" onclick="toggleServiceGroup('github', 'whitelist')" oncontextmenu="event.preventDefault(); toggleServiceGroup('github', 'blacklist')">🐙 GH</button>
                        <button class="shortcut-btn shortcut-all" onclick="toggleAllServices('whitelist')" oncontextmenu="event.preventDefault(); toggleAllServices('blacklist')">🌐 All</button>
                    </div>
                </div>
                <div class="rule-list" id="whitelistContainer"></div>
                <div class="add-rule"><input type="text" id="whitelistInput" placeholder="hostname or .suffix"><button onclick="addToWhitelist()">+ Add</button></div>
            </div>
            <div class="rule-card">
                <div class="rule-header">
                    <h3>🚫 Blacklist</h3>
                    <div class="group-shortcuts">
                        <button class="shortcut-btn shortcut-youtube" onclick="toggleServiceGroup('youtube', 'blacklist')" oncontextmenu="event.preventDefault(); toggleServiceGroup('youtube', 'whitelist')">🎬 YT</button>
                        <button class="shortcut-btn shortcut-instagram" onclick="toggleServiceGroup('instagram', 'blacklist')" oncontextmenu="event.preventDefault(); toggleServiceGroup('instagram', 'whitelist')">📸 IG</button>
                        <button class="shortcut-btn shortcut-telegram" onclick="toggleServiceGroup('telegram', 'blacklist')" oncontextmenu="event.preventDefault(); toggleServiceGroup('telegram', 'whitelist')">💬 TG</button>
                        <button class="shortcut-btn shortcut-github" onclick="toggleServiceGroup('github', 'blacklist')" oncontextmenu="event.preventDefault(); toggleServiceGroup('github', 'whitelist')">🐙 GH</button>
                        <button class="shortcut-btn shortcut-all" onclick="toggleAllServices('blacklist')" oncontextmenu="event.preventDefault(); toggleAllServices('whitelist')">🌐 All</button>
                    </div>
                </div>
                <div class="rule-list" id="blacklistContainer"></div>
                <div class="add-rule"><input type="text" id="blacklistInput" placeholder="hostname or .suffix"><button onclick="addToBlacklist()">+ Add</button></div>
            </div>
        </div>
        
        <div style="text-align:center;">
            <button class="btn-apply" onclick="applyRules()">🔄 Apply</button>
            <button class="btn-reset" onclick="resetStats()">🗑️ Reset</button>
        </div>
        
        <div class="footer">
            <div class="credit">اثر <strong>MasterKing32</strong> · ارتقا یافته توسط <strong>Xenon</strong> با کمک DeepSeek AI</div>
        </div>
        <div class="update-time" id="updateTime">Last update: --:--:--</div>
    </div>
    
    <script>
        let currentMode = 'normal', whitelist = [], blacklist = [];
        
        const SERVICE_HOSTS = {
            "youtube": [
                "youtube.com", "youtu.be", "youtube-nocookie.com",
                "googlevideo.com", "ytimg.com", "ggpht.com",
                "youtubei.googleapis.com", "youtube.googleapis.com"
            ],
            "instagram": [
                "instagram.com", "cdninstagram.com", "instagram.faia1-2.fna.fbcdn.net",
                "graphinstagram.com", "i.instagram.com"
            ],
            "telegram": [
                "telegram.org", "tdesktop.com", "t.me",
                "149.154.167.91", "149.154.167.43", "91.108.56.200",
                "149.154.167.41", "149.154.175.53", "149.154.175.100",
                "149.154.167.222"
            ],
            "github": [
                "github.com", "github.io", "githubassets.com",
                "githubcopilot.com", "githubstatus.com", "raw.githubusercontent.com",
                "gist.github.com", "api.github.com"
            ]
        };
        
        function isHostInWhitelist(host) {
            for(let w of whitelist) {
                if(w.startsWith('.')) {
                    if(host.endsWith(w) || host === w.substring(1)) return true;
                } else if(host === w || host.endsWith('.' + w)) return true;
            }
            return false;
        }
        
        function isHostInBlacklist(host) {
            for(let b of blacklist) {
                if(b.startsWith('.')) {
                    if(host.endsWith(b) || host === b.substring(1)) return true;
                } else if(host === b || host.endsWith('.' + b)) return true;
            }
            return false;
        }
        
        function getStatusIcon(host) {
            if(isHostInWhitelist(host)) return '<span class="status-icon status-ok">✓</span>';
            if(isHostInBlacklist(host)) return '<span class="status-icon status-blocked">✗</span>';
            return '<span class="status-icon status-none">○</span>';
        }
        
        async function toggleServiceGroup(service, listType) {
            const hosts = SERVICE_HOSTS[service];
            if(!hosts) return;
            
            let allExist = true;
            for(let h of hosts) {
                if(listType === 'whitelist') {
                    if(!whitelist.includes(h) && !whitelist.some(w => w.startsWith('.') && h.endsWith(w))) {
                        allExist = false;
                        break;
                    }
                } else {
                    if(!blacklist.includes(h) && !blacklist.some(b => b.startsWith('.') && h.endsWith(b))) {
                        allExist = false;
                        break;
                    }
                }
            }
            
            for(let h of hosts) {
                if(allExist) {
                    await removeFromList(listType, h);
                } else {
                    await addToList(listType, h);
                }
            }
            fetchRules();
        }
        
        async function toggleAllServices(listType) {
            let allHosts = [];
            for(let service in SERVICE_HOSTS) {
                allHosts = allHosts.concat(SERVICE_HOSTS[service]);
            }
            
            let allExist = true;
            for(let h of allHosts) {
                if(listType === 'whitelist') {
                    if(!whitelist.includes(h) && !whitelist.some(w => w.startsWith('.') && h.endsWith(w))) {
                        allExist = false;
                        break;
                    }
                } else {
                    if(!blacklist.includes(h) && !blacklist.some(b => b.startsWith('.') && h.endsWith(b))) {
                        allExist = false;
                        break;
                    }
                }
            }
            
            for(let h of allHosts) {
                if(allExist) {
                    await removeFromList(listType, h);
                } else {
                    await addToList(listType, h);
                }
            }
            fetchRules();
        }
        
        async function fetchStats() {
            try {
                const r = await fetch('/api/stats');
                const d = await r.json();
                document.getElementById('totalRequests').textContent = d.total_requests?.toLocaleString() || '0';
                document.getElementById('percentUsed').textContent = d.percent_used || '0';
                document.getElementById('ratePerMinute').textContent = d.rate_per_minute || '0';
                document.getElementById('errorsCount').textContent = d.errors_count || '0';
                document.getElementById('blockedCount').textContent = d.blocked_count || '0';
                document.getElementById('runningTime').textContent = d.running_time || '0';
                document.getElementById('updateTime').textContent = `Last update: ${d.last_update || '-'}`;
                document.getElementById('successRate').textContent = d.success_rate || '100';
                const total = d.total_requests || 1;
                document.getElementById('blockedPercent').textContent = ((d.blocked_count||0)/total*100).toFixed(1);
                const p = d.percent_used || 0;
                const f = document.getElementById('progressFill');
                f.style.width = `${p}%`;
                f.classList.toggle('danger', p>=90);
                const left = d.minutes_left || 0;
                document.getElementById('timeLeft').textContent = left>60 ? `${(left/60).toFixed(1)} hours` : (left>0 ? `${left.toFixed(0)} min` : 'Unlimited');
                
                const allHostsBody = document.getElementById('allHostsBody');
                if(d.all_hosts?.length) {
                    allHostsBody.innerHTML = d.all_hosts.map(h => `
                        <tr>
                            <td class="host-cell">${escapeHtml(h.host)} ${getStatusIcon(h.host)}</td>
                            <td class="count-cell">${h.count}</td>
                            <td class="action-buttons">
                                <button class="btn-icon btn-whitelist" onclick="addHostToWhitelist('${escapeHtml(h.host)}')">✨ WL</button>
                                <button class="btn-icon btn-blacklist" onclick="addHostToBlacklist('${escapeHtml(h.host)}')">🚫 BL</button>
                            </td>
                        </tr>
                    `).join('');
                } else {
                    allHostsBody.innerHTML = '<tr><td colspan="3" style="text-align:center;">No requests yet...</td></tr>';
                }
                
                const errBody = document.getElementById('topErrorsBody');
                if(d.top_errors?.length) {
                    errBody.innerHTML = d.top_errors.map(e => `
                        <tr>
                            <td class="host-cell">${escapeHtml(e.host)}</td>
                            <td class="count-cell error-cell">${e.count}</td>
                        </tr>
                    `).join('');
                } else {
                    errBody.innerHTML = '<tr><td colspan="2" style="text-align:center;">No errors...</td></tr>';
                }
            } catch(e) { console.error(e); }
        }
        
        async function fetchRules() {
            try {
                const r = await fetch('/api/rules');
                const data = await r.json();
                currentMode = data.mode;
                whitelist = data.whitelist || [];
                blacklist = data.blacklist || [];
                
                document.getElementById('modeNormal').classList.toggle('active', currentMode === 'normal');
                document.getElementById('modeBlacklist').classList.toggle('active', currentMode === 'blacklist');
                document.getElementById('modeWhitelist').classList.toggle('active', currentMode === 'whitelist');
                
                const desc = document.getElementById('modeDesc');
                if(currentMode === 'normal') desc.innerHTML = '🌐 Normal Mode: No filtering';
                else if(currentMode === 'whitelist') desc.innerHTML = '✨ Whitelist Mode: Only listed hosts work';
                else desc.innerHTML = '🛡️ Blacklist Mode: All except blocked hosts';
                
                const wlContainer = document.getElementById('whitelistContainer');
                if(whitelist.length) {
                    wlContainer.innerHTML = whitelist.map(i => `<div class="rule-item"><button onclick="removeFromList('whitelist','${escapeHtml(i)}')">✖</button>${escapeHtml(i)}</div>`).join('');
                } else {
                    wlContainer.innerHTML = '<div style="color:#555;padding:10px;">— empty —</div>';
                }
                
                const blContainer = document.getElementById('blacklistContainer');
                if(blacklist.length) {
                    blContainer.innerHTML = blacklist.map(i => `<div class="rule-item"><button onclick="removeFromList('blacklist','${escapeHtml(i)}')">✖</button>${escapeHtml(i)}</div>`).join('');
                } else {
                    blContainer.innerHTML = '<div style="color:#555;padding:10px;">— empty —</div>';
                }
                
                fetchStats();
            } catch(e) { console.error(e); }
        }
        
        async function addToList(type, value) {
            await fetch('/api/rules', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({action: 'add', type: type, value: value})
            });
        }
        
        async function removeFromList(type, value) {
            await fetch('/api/rules', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({action: 'remove', type: type, value: value})
            });
        }
        
        async function addToWhitelist() {
            const v = document.getElementById('whitelistInput').value.trim();
            if(v) { await addToList('whitelist', v); document.getElementById('whitelistInput').value = ''; fetchRules(); }
        }
        
        async function addToBlacklist() {
            const v = document.getElementById('blacklistInput').value.trim();
            if(v) { await addToList('blacklist', v); document.getElementById('blacklistInput').value = ''; fetchRules(); }
        }
        
        async function addHostToWhitelist(h) { await addToList('whitelist', h); fetchRules(); }
        async function addHostToBlacklist(h) { await addToList('blacklist', h); fetchRules(); }
        
        async function setMode(mode) {
            await fetch('/api/rules', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({action: 'set_mode', mode: mode})
            });
            fetchRules();
        }
        
        async function applyRules() {
            const btn = document.querySelector('.btn-apply');
            const orig = btn.innerHTML;
            btn.innerHTML = 'Applying...';
            await fetch('/api/apply', {method: 'POST'});
            btn.innerHTML = '✓ Done!';
            setTimeout(() => btn.innerHTML = orig, 1500);
        }
        
        async function resetStats() {
            if(confirm('Reset monitor display? (Proxy continues working)')) {
                await fetch('/api/reset', {method: 'POST'});
                fetchStats();
            }
        }
        
        document.getElementById('modeNormal').onclick = () => setMode('normal');
        document.getElementById('modeBlacklist').onclick = () => setMode('blacklist');
        document.getElementById('modeWhitelist').onclick = () => setMode('whitelist');
        
        function escapeHtml(t) {
            return t.replace(/[&<>]/g, function(m) {
                return m === '&' ? '&amp;' : (m === '<' ? '&lt;' : '&gt;');
            });
        }
        
        fetchStats();
        fetchRules();
        setInterval(fetchStats, 2000);
        setInterval(fetchRules, 5000);
    </script>
</body>
</html>
'''

# ============ HTTP Handler ============

class Handler(SimpleHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/api/stats':
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            success = 100
            if stats["total_requests"] > 0:
                success = round(((stats["total_requests"] - stats["errors_count"]) / stats["total_requests"]) * 100, 1)
            data = {
                "total_requests": stats["total_requests"],
                "percent_used": stats["percent_used"],
                "rate_per_minute": stats["rate_per_minute"],
                "minutes_left": stats["minutes_left"],
                "errors_count": stats["errors_count"],
                "blocked_count": stats["blocked_count"],
                "success_rate": success,
                "running_time": stats["running_time"],
                "last_update": stats["last_update"],
                "all_hosts": [{"host": h, "count": c} for h, c in sorted(stats["top_hosts"].items(), key=lambda x: x[1], reverse=True)],
                "top_errors": [{"host": h, "count": c} for h, c in sorted(stats["top_errors"].items(), key=lambda x: x[1], reverse=True)[:15]]
            }
            self.wfile.write(json.dumps(data).encode())
        elif self.path == '/api/rules':
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps(current_rules).encode())
        elif self.path in ('/', '/dashboard'):
            self.path = '/static/dashboard.html'
            super().do_GET()
        else:
            super().do_GET()
    
    def do_POST(self):
        if self.path == '/api/rules':
            length = int(self.headers.get('Content-Length', 0))
            body = self.rfile.read(length)
            try:
                data = json.loads(body)
                action = data.get('action')
                if action == 'add':
                    t, v = data.get('type'), data.get('value')
                    if t == 'whitelist' and v not in current_rules['whitelist']:
                        current_rules['whitelist'].append(v)
                        if v in current_rules['blacklist']:
                            current_rules['blacklist'].remove(v)
                    elif t == 'blacklist' and v not in current_rules['blacklist']:
                        current_rules['blacklist'].append(v)
                        if v in current_rules['whitelist']:
                            current_rules['whitelist'].remove(v)
                    save_rules(current_rules)
                elif action == 'remove':
                    t, v = data.get('type'), data.get('value')
                    if t == 'whitelist' and v in current_rules['whitelist']:
                        current_rules['whitelist'].remove(v)
                    elif t == 'blacklist' and v in current_rules['blacklist']:
                        current_rules['blacklist'].remove(v)
                    save_rules(current_rules)
                elif action == 'set_mode':
                    mode = data.get('mode')
                    if mode in ('normal', 'whitelist', 'blacklist'):
                        current_rules['mode'] = mode
                        save_rules(current_rules)
                self.send_response(200)
                self.end_headers()
                self.wfile.write(json.dumps({"success": True}).encode())
            except Exception as e:
                self.send_response(500)
                self.end_headers()
                self.wfile.write(json.dumps({"success": False}).encode())
        elif self.path == '/api/apply':
            success = apply_rules_to_config(current_rules)
            self.send_response(200)
            self.end_headers()
            self.wfile.write(json.dumps({"success": success}).encode())
        elif self.path == '/api/reset':
            reset_stats()
            self.send_response(200)
            self.end_headers()
            self.wfile.write(json.dumps({"success": True}).encode())
    
    def log_message(self, *args):
        pass

# ============ Main ============

def main():
    Path("static").mkdir(exist_ok=True)
    with open("static/dashboard.html", "w", encoding='utf-8') as f:
        f.write(HTML_TEMPLATE)
    
    server = HTTPServer(('0.0.0.0', WEB_PORT), Handler)
    
    print(f"""
{'='*50}
MHR-XE MONITOR
{'='*50}
🌐 Dashboard: http://localhost:{WEB_PORT}
📁 Log file: {LOG_FILE}
📊 Usage log: {USAGE_LOG_FILE}
📋 Rules: {RULES_FILE}
{'='*50}
Mode: {current_rules['mode']}
WL: {len(current_rules['whitelist'])}  |  BL: {len(current_rules['blacklist'])}
{'='*50}
Press Ctrl+C to stop
""")
    
    threading.Thread(target=monitor_loop, daemon=True).start()
    
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nMonitor stopped.")
        write_usage_log()

if __name__ == "__main__":
    main()