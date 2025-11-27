#!/usr/bin/env python3
import sys
import concurrent_monitor

if __name__ == "__main__":
    print("Starting Serial Monitor")
    
    if len(sys.argv) > 1:
        concurrent_monitor.offline_mode(sys.argv[1])
    else:
        concurrent_monitor.monitor_serial()