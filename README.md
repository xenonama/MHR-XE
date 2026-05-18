# MHR-XE (MasterHttpRelay - Xenon Edition)

**Domain-Fronted Tunnel via Google Apps Script**

A local HTTP/HTTPS proxy that bypasses DPI censorship by tunneling traffic through Google Apps Script with domain fronting (SNI shows www.google.com while Host header points to script.google.com).

## Features

- 🔒 **Domain Fronting** - SNI shows www.google.com, encrypted Host header targets script.google.com
- 🚀 **HTTP/2 Multiplexing** - Single TLS connection handles all requests
- 📊 **Real-time Monitor** - Web dashboard showing request counts, rates, and quotas
- 🎛️ **Whitelist/Blacklist Modes** - Control which hosts are allowed or blocked
- 💾 **Persistent Rules** - Settings saved automatically
- 🔄 **Auto Log Rotation** - Logs organized by date
- 📈 **Usage Tracking** - Daily quota monitoring (20,000 requests/day)

## Quick Start

### 1. Install dependencies

```bash
pip install -r requirements.txt