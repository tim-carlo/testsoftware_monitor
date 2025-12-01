#!/usr/bin/env python3
import serial
import cbor2
import crcmod
import time
import threading
import queue
import sys
import select
from event_decoder import decode_result, format_event_list, decode_event_type_one_hot
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
        print(f"ACK sent for crc: 0x{received_hash:08X}")
    except Exception as e:
        print(f"ACK send failed: {e}")

def parse_packet(hex_data, has_packet_id=False):
    """Parse CBOR packet: [PACKET_ID?][LENGTH][CBOR][CRC]"""
    try:
        offset = 0
        packet_id = -1
        
        if has_packet_id:
            packet_id = int.from_bytes(bytes.fromhex(hex_data[:8]), "little")
            offset = 4
            
        # Extract length (2 bytes, little endian)
        length = int.from_bytes(bytes.fromhex(hex_data[offset*2:offset*2+4]), "little")
        
        # Extract CBOR data
        cbor_start = offset*2 + 4
        cbor_end = cbor_start + length * 2
        cbor_hex = hex_data[cbor_start:cbor_end]
        cbor_bytes = bytes.fromhex(cbor_hex)
        
        # Extract hash (4 bytes at end)
        hash_hex = hex_data[cbor_end:cbor_end + 8]
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
            "calculated_hash": calculated_hash,
            "raw_bytes": cbor_bytes
        }
    except Exception as e:
        print(f"Parse packet error: {e}")
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
    
    print("Serial reader stopped")

def packet_processor(ser, data_queue, stop_event, collector):
    """Process 2: Process incoming data and handle protocol"""
    print("Packet processor thread started")
    
    buffer = bytearray()
    packet_data = bytearray()
    debug_buffer = bytearray()
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
                                print(f"{line_text}")
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
                        result = parse_packet(packet_data.hex(), has_packet_id=False)
                        
                        # Debug: Print CBOR structure with keys
                        data = result.get('data', {})
                        print(f"CBOR Header: Device Family {data.get(1)}, Total Chunks {data.get(2)}")
                        print(f"📦 CBOR Header Data: {data}")
                        
                        # Process header in collector
                        collector.process_header(result)
                        
                        if result.get('ack_requested', 1):    
                            # Send ACK if hash is valid
                            if result['hash_valid']:
                                send_ack(ser, result['received_hash'])
                            else:
                                print("Hash invalid, no ACK sent")
                        else:
                            print("ACK not requested, no ACK sent")
                    packet_data = bytearray()
                    buffer = buffer[4:]
                    
                elif buffer[:4] == CHUNK_START:
                    receiving_chunk = True
                    packet_data = bytearray()
                    buffer = buffer[4:]
                    
                elif buffer[:4] == CHUNK_END:
                    receiving_chunk = False
                    if packet_data:
                        result = parse_packet(packet_data.hex(), has_packet_id=True)
                        if result:
                            # Debug: Print CBOR structure with keys
                            data = result.get('data', {})
                            print(f"Received Chunk {data.get(0)} (Packet ID: {result['packet_id']})")
                            print(f"CBOR Data: {data}")
                            
                            # Process chunk in collector
                            collector.process_chunk(result)
                            
                            # Check if collection is complete and export CBOR
                            collector.is_complete()
                            
                            if result.get('ack_requested', 1):
                                # Send ACK if hash is valid
                                if result['hash_valid']:
                                    send_ack(ser, result['received_hash'])
                                else:
                                    print("Hash invalid, no ACK sent")
                            else:
                                print("ACK not requested, no ACK sent")
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

def offline_mode(filename):
    """Run in offline mode loading data from XML"""
    collector = DeviceDataCollector()
    if collector.load_from_xml(filename):
        print("Data loaded. Entering offline command mode.")
        print("Press 'v' to visualize, 's' to save report, 'q' to quit")
        
        while True:
            try:
                cmd = input("Command (v/s/q): ").strip().lower()
                if cmd == 'v':
                    collector.visualize_matrices()
                elif cmd == 's':
                    collector.manual_save()
                elif cmd == 'q':
                    break
            except KeyboardInterrupt:
                break
            except EOFError:
                break
    else:
        print("Failed to load data.")

def monitor_serial():
    """Concurrent serial monitor with two threads"""
    print(f"Opening {PORT} at {BAUDRATE} baud...")
    
    collector = DeviceDataCollector()
    
    with serial.Serial(PORT, BAUDRATE, timeout=1) as ser:
        data_queue = queue.Queue(maxsize=1000)
        stop_event = threading.Event()
        
        print("Starting concurrent monitoring...")
        print("Press 's' to save, 'r' to save raw XML, 'v' to visualize")
        
        reader_thread = threading.Thread(
            target=serial_reader,
            args=(ser, data_queue, stop_event),
            name="SerialReader"
        )
        
        processor_thread = threading.Thread(
            target=packet_processor,
            args=(ser, data_queue, stop_event, collector),
            name="PacketProcessor"
        )
        
        reader_thread.daemon = True
        processor_thread.daemon = True
        
        reader_thread.start()
        processor_thread.start()
        
        try:
            while True:
                if sys.stdin in select.select([sys.stdin], [], [], 0.1)[0]:
                    cmd = sys.stdin.read(1)
                    if cmd == 's':
                        collector.manual_save()
                    elif cmd == 'r':
                        collector.save_raw_xml()
                    elif cmd == 'v':
                        collector.visualize_matrices()
                    elif cmd == 'q':
                        break
                
                if not reader_thread.is_alive() or not processor_thread.is_alive():
                    print("Thread died")
                    break
                    
        except KeyboardInterrupt:
            print("\nStopping...")
            
        finally:
            # Stop threads gracefully
            stop_event.set()
            
            # Wait for threads to finish (with timeout)
            reader_thread.join(timeout=2)
            processor_thread.join(timeout=2)
            
            print("Monitor stopped")

if __name__ == "__main__":
    if len(sys.argv) > 1:
        offline_mode(sys.argv[1])
    else:
        monitor_serial()