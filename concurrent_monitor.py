#!/usr/bin/env python3
"""
Concurrent CBOR Serial Monitor - Two-process implementation with proper DEBUG handling
"""

import serial
import cbor2
import crcmod
import time
import threading
import queue

# Configuration
PORT = "/dev/tty.usbmodem1302"
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

def send_ack(ser, received_hash):
    """Send simple ACK with hash"""
    try:
        ack_data = bytearray()
        ack_data.extend(ACK_START.to_bytes(4, 'little'))
        ack_data.extend(received_hash.to_bytes(4, 'little'))
        ack_data.extend(ACK_END.to_bytes(4, 'little'))
        
        ser.write(ack_data)
        print(f"✅ ACK sent for hash: 0x{received_hash:08X}")
    except Exception as e:
        print(f"❌ ACK send failed: {e}")

def parse_packet(hex_data):
    """Parse CBOR packet: [LENGTH][CBOR][HASH]"""
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
            "data": decoded,
            "hash_valid": hash_valid,
            "received_hash": received_hash,
            "calculated_hash": calculated_hash
        }
    except Exception as e:
        print(f"Parse error: {e}")
        return None

def serial_reader(ser, data_queue, stop_event):
    """Process 1: Read serial data continuously"""
    print("📡 Serial reader thread started")
    
    while not stop_event.is_set():
        try:
            if ser.in_waiting:
                new_data = ser.read(ser.in_waiting)
                if new_data:
                    data_queue.put(new_data)
            else:
                time.sleep(0.001)  # Very small delay when no data
                
        except Exception as e:
            print(f"📡 Reader error: {e}")
            break
    
    print("📡 Serial reader stopped")

def packet_processor(ser, data_queue, stop_event):
    """Process 2: Process incoming data and handle protocol"""
    print("🔄 Packet processor thread started")
    
    buffer = bytearray()
    packet_data = bytearray()
    debug_buffer = bytearray()  # Separate buffer for DEBUG messages
    receiving_header = False
    receiving_chunk = False
    
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
                        result = parse_packet(packet_data.hex())
                        if result:
                            print(f"Header data: {result['data']}")
                            print(f"Hash valid: {result['hash_valid']}")
                            
                            # Send ACK if hash is valid
                            if result['hash_valid']:
                                send_ack(ser, result['received_hash'])
                            else:
                                print("❌ Hash invalid, no ACK sent")
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
                        result = parse_packet(packet_data.hex())
                        if result:
                            print(f"Chunk data: {result['data']}")
                            print(f"Hash valid: {result['hash_valid']}")
                            
                            # Send ACK if hash is valid
                            if result['hash_valid']:
                                send_ack(ser, result['received_hash'])
                            else:
                                print("❌ Hash invalid, no ACK sent")
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
            print(f"🔄 Processor error: {e}")
    
    print("🔄 Packet processor stopped")

def monitor_serial():
    """Concurrent serial monitor with two threads"""
    print(f"Opening {PORT} at {BAUDRATE} baud...")
    
    with serial.Serial(PORT, BAUDRATE, timeout=1) as ser:
        # Shared data structures
        data_queue = queue.Queue(maxsize=1000)  # Buffer for data transfer
        stop_event = threading.Event()
        
        print("🚀 Starting concurrent monitoring...")
        
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
            
            print("✅ Monitor stopped")

if __name__ == "__main__":
    monitor_serial()