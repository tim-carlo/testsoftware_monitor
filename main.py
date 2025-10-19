#!/usr/bin/env python3
"""
Simplified main entry point
"""

def main():
    print("Starting CBOR Serial Monitor (Concurrent Version)...")
    
    # Use the concurrent monitor
    import concurrent_monitor
    concurrent_monitor.monitor_serial()

if __name__ == "__main__":
    main()