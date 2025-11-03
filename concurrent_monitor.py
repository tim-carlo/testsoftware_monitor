#!/usr/bin/env python3
"""
Concurrent CBOR Serial Monitor
"""

import serial
import cbor2
import crcmod
import time
import threading
import queue
from event_decoder import decode_result, format_event_list, merge_handshake_events
from data_storage import DeviceDataCollector

# Configuration
PORT = "/dev/tty.usbmodem11102"
BAUDRATE = 9600

# Protocol identifiers (4 bytes each, little endian)
HEADER_START = bytes([0x0C, 0x0B, 0x0A, 0x09])
HEADER_END = bytes([0x10, 0x0F, 0x0E, 0x0D])
CHUNK_START = bytes([0x04, 0x03, 0x02, 0x01])
CHUNK_END = bytes([0x08, 0x07, 0x06, 0x05])

# CRC calculation
calculate_crc = crcmod.predefined.mkPredefinedCrcFun('crc-32')

# ACK protocol
ACK_START = 0x191A1B1C
ACK_END = 0x1D1E1F20

ACK_REQUESTED = 8

def send_ack(ser, received_hash):
    """Send simple ACK with crc"""
    try:
        ack_data = bytearray()
        ack_data.extend(ACK_START.to_bytes(4, 'little'))
        ack_data.extend(received_hash.to_bytes(4, 'little'))
        ack_data.extend(ACK_END.to_bytes(4, 'little'))
        
        ser.write(ack_data)
        print(f"✅ ACK sent for crc: 0x{received_hash:08X}")
    except Exception as e:
        print(f"❌ ACK send failed: {e}")

def parse_header_packet(hex_data):
    """Parse CBOR header packet: [LENGTH][CBOR][CRC]"""
    try:
        # Extract length (2 bytes, little endian)
        length = int.from_bytes(bytes.fromhex(hex_data[:4]), "little")
        
        # Extract CBOR data
        cbor_hex = hex_data[4:4 + length * 2]
        cbor_bytes = bytes.fromhex(cbor_hex)
        
        # Extract hash (4 bytes at end)
        hash_hex = hex_data[4 + length * 2:4 + length * 2 + 8]
        received_hash = int.from_bytes(bytes.fromhex(hash_hex), "little")
        
        # Verify hash
        calculated_hash = calculate_crc(cbor_bytes)
        hash_valid = received_hash == calculated_hash
        
        # Decode CBOR
        try:
            decoded = cbor2.loads(cbor_bytes)
        except:
            decoded = {"error": "cbor decode failed"}
        
        return {
            "ack_requested": decoded.get(ACK_REQUESTED, 0),
            "data": decoded,
            "hash_valid": hash_valid,
            "received_hash": received_hash,
            "calculated_hash": calculated_hash   
        }
    except Exception as e:
        print(f"Parse header error: {e}")
        return None

def parse_chunk_packet(hex_data):
    """Parse CBOR chunk packet: [PACKET_ID][LENGTH][CBOR][CRC]"""
    try:
        # Extract packet ID (1 byte)
        packet_id = int.from_bytes(bytes.fromhex(hex_data[:2]), "little")
        
        # Extract length (2 bytes, little endian)
        length = int.from_bytes(bytes.fromhex(hex_data[2:6]), "little")
        
        # Extract CBOR data
        cbor_hex = hex_data[6:6 + length * 2]
        cbor_bytes = bytes.fromhex(cbor_hex)
        
        # Extract hash (4 bytes at end)
        hash_hex = hex_data[6 + length * 2:6 + length * 2 + 8]
        received_hash = int.from_bytes(bytes.fromhex(hash_hex), "little")
        
        # Verify hash
        calculated_hash = calculate_crc(cbor_bytes)
        hash_valid = received_hash == calculated_hash
        
        # Decode CBOR
        try:
            decoded = cbor2.loads(cbor_bytes)
        except:
            decoded = {"error": "cbor decode failed"}
        
        return {
            "ack_requested": decoded.get(ACK_REQUESTED, 0),
            "packet_id": packet_id,
            "data": decoded,
            "hash_valid": hash_valid,
            "received_hash": received_hash,
            "calculated_hash": calculated_hash
        }
    except Exception as e:
        print(f"Parse chunk error: {e}")
        return None

def serial_reader(ser, data_queue, stop_event):
    print("Serial reader thread started")
    
    while not stop_event.is_set():
        try:
            if ser.in_waiting:
                new_data = ser.read(ser.in_waiting)
                if new_data:
                    data_queue.put(new_data)
            else:
                time.sleep(0.001)  # Very small delay when no data
                
        except Exception as e:
            print(f"Reader error: {e}")
            break
    
    print("📡 Serial reader stopped")

def packet_processor(ser, data_queue, stop_event):
    """Process 2: Process incoming data and handle protocol"""
    print("Packet processor thread started")
    
    buffer = bytearray()
    packet_data = bytearray()
    debug_buffer = bytearray()  # Separate buffer for DEBUG messages
    receiving_header = False
    receiving_chunk = False
    
    # Initialize data collector
    collector = DeviceDataCollector()
    
    while not stop_event.is_set():
        try:
            # Get data from queue (non-blocking)
            try:
                new_data = data_queue.get_nowait()
                
                # Extract DEBUG messages
                for byte in new_data:
                    debug_buffer.append(byte)
                    
                    # Check if we have a complete line ending with \n
                    if byte == ord('\n'):
                        try:
                            line_text = debug_buffer.decode('utf-8', errors='ignore').strip()
                            # Only print if it starts with DEBUG:
                            if line_text.startswith("DEBUG:"):
                                print(f"🕹️ {line_text}")
                        except:
                            pass
                        debug_buffer.clear()  # Clear for next line
                    
                    # Prevent memory leak - clear if buffer gets too large
                    elif len(debug_buffer) > 1000:
                        debug_buffer.clear()
                
                # Add all data to binary protocol buffer (unmodified)
                buffer.extend(new_data)
                
            except queue.Empty:
                time.sleep(0.0001)
                continue
            
            # Look for protocol markers (binary protocol handling)
            while len(buffer) >= 4:
                if buffer[:4] == HEADER_START:
                    print("=== Header Start ===")
                    receiving_header = True
                    packet_data = bytearray()
                    buffer = buffer[4:]
                    
                elif buffer[:4] == HEADER_END:
                    print("=== Header End ===")
                    receiving_header = False
                    if packet_data:
                        result = parse_header_packet(packet_data.hex())
                        
                        # Debug: Print CBOR structure with keys
                        data = result.get('data', {})
                        print(f"CBOR Header:")
                        print(f"  [0] DEVICE_UUID: {data.get(0)}")
                        print(f"  [1] DEVICE_FAMILY: {data.get(1)}")
                        print(f"  [2] TOTAL_CHUNKS: {data.get(2)}")
                        print(f"  [3] TOTAL_PINS: {data.get(3)}")
                        print(f"  [4] ACTIVE_PINS: {data.get(4)}")
                        print(f"  [5] HEADER_HASH: {data.get(5)}")
                        print(f"  [6] NUMBER_SEEN_DEVICES: {data.get(6)}")
                        print(f"  [7] SEEN_DEVICE_IDS: {data.get(7)}")
                        print(f"  [8] ACK_REQUESTED: {data.get(8)}")
                        print(f"Hash valid: {result['hash_valid']}")
                        
                        # Process header in collector
                        collector.process_header(result)
                        
                        if result.get('ack_requested', 1):    
                            # Send ACK if hash is valid
                            if result['hash_valid']:
                                send_ack(ser, result['received_hash'])
                            else:
                                print("❌ Hash invalid, no ACK sent")
                        else:
                            print("❌ ACK not requested, no ACK sent")
                    packet_data = bytearray()
                    buffer = buffer[4:]
                    
                elif buffer[:4] == CHUNK_START:
                    print("=== Chunk Start ===")
                    receiving_chunk = True
                    packet_data = bytearray()
                    buffer = buffer[4:]
                    
                elif buffer[:4] == CHUNK_END:
                    print("=== Chunk End ===")
                    receiving_chunk = False
                    if packet_data:
                        result = parse_chunk_packet(packet_data.hex())
                        if result:
                            # Debug: Print CBOR structure with keys
                            data = result.get('data', {})
                            print(f"CBOR Chunk (Packet ID: {result['packet_id']}):")
                            print(f"  [0] CHUNK_ID: {data.get(0)}")
                            print(f"  [1] NUM_ENTRIES: {data.get(1)}")
                            print(f"  [3] CRC: {data.get(3)}")
                            
                            pins = data.get(2, [])
                            print(f"  [2] PINS ({len(pins)} entries):")
                            for i, pin in enumerate(pins):
                                if isinstance(pin, dict):
                                    print(f"    Pin {i}:")
                                    print(f"      [4] PIN: {pin.get(4)}")
                                    print(f"      [5] EVENTS: {pin.get(5, 0)} ({bin(pin.get(5, 0))})")
                                    print(f"      [8] DEVICE_ID: {pin.get(8)}")
                                    
                                    connections = pin.get(6, [])
                                    if connections:
                                        print(f"      [6] CONNECTIONS ({len(connections)} entries):")
                                        for j, conn in enumerate(connections):
                                            if isinstance(conn, dict):
                                                print(f"        Conn {j}: [7] OTHER_PIN={conn.get(7)}, [8] DEVICE_ID={conn.get(8)}")
                                    else:
                                        print(f"      [6] CONNECTIONS: []")
                                else:
                                    print(f"    Pin {i}: {pin} (unexpected type)")
                            
                            print(f"Hash valid: {result['hash_valid']}")
                            
                            # Process chunk in collector
                            collector.process_chunk(result)
                            
                            # Check if collection is complete and export CBOR
                            if collector.is_complete():
                                collector.print_connections_summary()
                                collector.to_cbor()
                            
                            if result.get('ack_requested', 1):
                                # Send ACK if hash is valid
                                if result['hash_valid']:
                                    send_ack(ser, result['received_hash'])
                                else:
                                    print("❌ Hash invalid, no ACK sent")
                            else:
                                print("❌ ACK not requested, no ACK sent")
                    packet_data = bytearray()
                    buffer = buffer[4:]
                    
                elif receiving_header or receiving_chunk:
                    # Collect packet data
                    packet_data.append(buffer[0])
                    buffer = buffer[1:]
                else:
                    # Skip unknown byte
                    buffer = buffer[1:]
                    
        except Exception as e:
            print(f"Processor error: {e}")
    
    print("Packet processor stopped")

def monitor_serial():
    """Concurrent serial monitor with two threads"""
    print(f"Opening {PORT} at {BAUDRATE} baud...")
    
    with serial.Serial(PORT, BAUDRATE, timeout=1) as ser:
        # Shared data structures
        data_queue = queue.Queue(maxsize=1000)  # Buffer for data transfer
        stop_event = threading.Event()
        
        print("Starting concurrent monitoring...")
        
        # Create and start threads
        reader_thread = threading.Thread(
            target=serial_reader,
            args=(ser, data_queue, stop_event),
            name="SerialReader"
        )
        
        processor_thread = threading.Thread(
            target=packet_processor,
            args=(ser, data_queue, stop_event),
            name="PacketProcessor"
        )
        
        reader_thread.daemon = True
        processor_thread.daemon = True
        
        reader_thread.start()
        processor_thread.start()
        
        try:
            # Main thread just waits for interruption
            while True:
                time.sleep(0.1)
                
                # Check if threads are still alive
                if not reader_thread.is_alive():
                    print("❌ Reader thread died")
                    break
                if not processor_thread.is_alive():
                    print("❌ Processor thread died")
                    break
                    
        except KeyboardInterrupt:
            print("\n🛑 Stopping monitor...")
            
        finally:
            # Stop threads gracefully
            stop_event.set()
            
            # Wait for threads to finish (with timeout)
            reader_thread.join(timeout=2)
            processor_thread.join(timeout=2)
            
            print("Monitor stopped")

if __name__ == "__main__":
    monitor_serial()