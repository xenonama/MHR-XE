#!/usr/bin/env python3
"""
Logging utilities for DomainFront Tunnel.
Configures colored console output and file logging.
"""

import logging
import sys
from pathlib import Path

# ANSI color codes for terminal output
COLORS = {
    'DEBUG': '\033[36m',     # Cyan
    'INFO': '\033[32m',      # Green
    'WARNING': '\033[33m',   # Yellow
    'ERROR': '\033[31m',     # Red
    'CRITICAL': '\033[35m',  # Magenta
    'RESET': '\033[0m',
}


class ColoredFormatter(logging.Formatter):
    """Custom formatter that adds colors to log levels in console output."""
    
    def format(self, record):
        original_levelname = record.levelname
        if hasattr(record, 'colored') and record.colored:
            color = COLORS.get(record.levelname, COLORS['RESET'])
            record.levelname = f"{color}{record.levelname}{COLORS['RESET']}"
        
        result = super().format(record)
        record.levelname = original_levelname
        return result


class SafeFileHandler(logging.FileHandler):
    """File handler that handles Unicode safely on Windows."""
    
    def __init__(self, filename, mode='a', encoding='utf-8', delay=False):
        super().__init__(filename, mode, encoding, delay)
    
    def emit(self, record):
        try:
            super().emit(record)
        except UnicodeEncodeError:
            # Replace problematic characters
            record.msg = record.msg.encode('ascii', 'ignore').decode('ascii')
            super().emit(record)


def configure(level_name: str = "INFO"):
    """
    Configure the root logger with console and file output.
    """
    level = getattr(logging, level_name.upper(), logging.INFO)
    
    root_logger = logging.getLogger()
    
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)
    
    root_logger.setLevel(level)
    
    # Console handler with UTF-8 safe wrapper
    try:
        # Force UTF-8 for console on Windows
        if sys.platform == 'win32':
            sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    except Exception:
        pass
    
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(level)
    
    # Create custom record factory for console coloring
    original_factory = logging.getLogRecordFactory()
    
    def record_factory(*args, **kwargs):
        record = original_factory(*args, **kwargs)
        record.colored = True
        return record
    
    logging.setLogRecordFactory(record_factory)
    
    console_formatter = ColoredFormatter(
        '%(asctime)s  • %(levelname)-8s [%(name)s] %(message)s',
        datefmt='%H:%M:%S'
    )
    console_handler.setFormatter(console_formatter)
    root_logger.addHandler(console_handler)
    
    # Reset record factory
    logging.setLogRecordFactory(original_factory)
    
    # File handler (NO EMOJIS - ASCII only)
    try:
        log_dir = Path("logs")
        log_dir.mkdir(exist_ok=True)
        
        log_file = log_dir / "proxy.log"
        file_handler = SafeFileHandler(log_file, encoding="utf-8")
        file_handler.setLevel(logging.DEBUG)
        
        file_formatter = logging.Formatter(
            '%(asctime)s  • %(levelname)-5s [%(name)s] %(message)s',
            datefmt='%H:%M:%S'
        )
        file_handler.setFormatter(file_formatter)
        root_logger.addHandler(file_handler)
        
        # NO EMOJI in log message - ASCII only
        root_logger.info(f"Logging to file: {log_file}")
        
    except Exception as e:
        root_logger.warning(f"Could not create file log: {e}")


def get_logger(name: str):
    return logging.getLogger(name)


def print_banner(version: str):
    """Print the startup banner (ASCII only)."""
    banner = f"""

╭────────────────────────────────────────────────────────────────────╮
│ MasterHttpRelayVPN     Domain-Fronted Apps Script Relay     v{version} │
╰────────────────────────────────────────────────────────────────────╯
"""
    print(banner, flush=True)