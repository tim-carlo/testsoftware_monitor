import serial
import cbor2
import crcmod
import time

PORT = "/dev/cu.usbmodem0010502825871"
BAUDRATE = 9600

# Protocol identifiers
CHUNK_START = 0x01020304
CHUNK_END = 0x05060708
HEADER_START = 0x090A0B0C
HEADER_END = 0x0D0E0F10
TRANSMISSION_START = 0x11121314
TRANSMISSION_END = 0x15161718
ACK_START = 0x191A1B1C
ACK_END = 0x1D1E1F20
ERROR_WITH_ACK = 0x1D1E1F20
ERROR_ID = 0xE0E1E2E3

# Status codes
WAIT_FOR_ACK_RESULT = {
    0: "Success",
    1: "Timeout",
    2: "Missing start identifier",
    3: "Invalid hash",
    4: "Missing end identifier",
    5: "Null pointer",
}

UART_TRANSMISSION_RESULT = {
    0: "Transmission successful",
    1: "Initialization failed",
    2: "Send failed",
    3: "Acknowledgment failed",
    4: "Memory allocation failed",
    5: "Null pointer error",
}

# Byte representations of identifiers (little endian)
identifiers = {
    CHUNK_START.to_bytes(4, 'little'): CHUNK_START,
    CHUNK_END.to_bytes(4, 'little'): CHUNK_END,
    HEADER_START.to_bytes(4, 'little'): HEADER_START,
    HEADER_END.to_bytes(4, 'little'): HEADER_END,
    TRANSMISSION_START.to_bytes(4, 'little'): TRANSMISSION_START,
    TRANSMISSION_END.to_bytes(4, 'little'): TRANSMISSION_END,
    ACK_START.to_bytes(4, 'little'): ACK_START,
    ACK_END.to_bytes(4, 'little'): ACK_END,
    ERROR_WITH_ACK.to_bytes(4, 'little'): ERROR_WITH_ACK,
    ERROR_ID.to_bytes(4, 'little'): ERROR_ID,
}

# Data structure keys
DEVICE_UUID = 0
DEVICE_FAMILY = 1
TOTAL_CHUNKS = 2
TOTAL_PINS = 3
ACTIVE_PINS = 4
HEADER_CRC = 5

CHUNK_ID = 0
NUM_ENTRIES = 1
PINS = 2

PIN = 4
EVENTS = 5
CONNECTIONS = 6
OTHER_PIN = 7
DEVICE_ID = 8

# Global variables
packet_buffer = []
last_header_info = None


crc32_func = crcmod.predefined.mkPredefinedCrcFun('crc-32')

def calculate_hash(data):
    """Calculate CRC32 value for given binary data."""
    if not isinstance(data, bytes):
        raise TypeError(f"Expected bytes, got {type(data)}")
    
    # Use the exact CRC32 table from your C code
    # This matches the crcTable[] in your C implementation
    result = crc32_func(data)
    
    # Debug: Show what we're calculating CRC over
    print(f"Computing CRC over {len(data)} bytes: {data.hex()}")
    print(f"CRC result: 0x{result:08X}")
    
    return result


def send_ack(ser, packet_data):
    """Send acknowledgment to the device."""
    if packet_data and "_received_hash" in packet_data and packet_data.get("_hash_valid", False):
        time.sleep(0.05)
        
        ack_data = bytearray()
        ack_data.extend(ACK_START.to_bytes(4, 'little'))  # Little endian
        ack_data.extend(packet_data["_received_hash"].to_bytes(4, 'little'))  # Little endian
        ack_data.extend(ACK_END.to_bytes(4, 'little'))  # Little endian
        
        ser.write(ack_data)
        print(f"Sent ACK for hash: 0x{packet_data['_received_hash']:08X}")
    else:
        print("Invalid hash, sending error")
        send_error(ser)


def send_error(ser):
    """Send error message to the device."""
    error_data = ERROR_WITH_ACK.to_bytes(4, 'little')  # Little endian
    ser.write(error_data)
    print("Sent error response")


def parse_header_data(hex_data):
    """Process received header data."""
    try:
        # Header structure from C code:
        # [2 BYTE LENGTH][CBOR BYTES][4 BYTE CRC32] (no packet ID for header)
        
        if len(hex_data) < 12:  # Minimum: 2 + 0 + 4 = 6 bytes = 12 hex chars
            print("Header data too short for complete packet")
            return None
        
        # Extract CBOR data length (2 bytes, little endian)
        length_bytes = hex_data[:4]
        cbor_size = int.from_bytes(bytes.fromhex(length_bytes), "little")
        
        expected_length = (2 + cbor_size + 4) * 2  # Total header length in hex chars
        
        if len(hex_data) < expected_length:
            print(f"Not enough header data for expected packet size: got {len(hex_data)}, need {expected_length}")
            return None

        # Extract CBOR data
        cbor_start = 4  # After length (4)
        cbor_end = cbor_start + cbor_size * 2
        cbor_hex = hex_data[cbor_start:cbor_end]
        
        # Extract hash (4 bytes at the end)
        hash_hex = hex_data[cbor_end:cbor_end + 8]

        cbor_bytes = bytes.fromhex(cbor_hex)
        received_hash = int.from_bytes(bytes.fromhex(hash_hex), "little")
        calculated_hash = calculate_hash(cbor_bytes)

        decoded = cbor2.loads(cbor_bytes)
        decoded["_received_hash"] = received_hash
        decoded["_calculated_hash"] = calculated_hash
        decoded["_hash_valid"] = received_hash == calculated_hash

        # Debug information for hash comparison
        print(f"=== HEADER DEBUG ===")
        print(f"Total header: {len(hex_data)} hex chars ({len(hex_data)//2} bytes)")
        print(f"Length field: {length_bytes} -> CBOR size: {cbor_size}")
        print(f"CBOR hex: {cbor_hex}")
        print(f"Hash hex: {hash_hex}")
        print(f"CBOR bytes: {len(cbor_bytes)} bytes")
        print(f"Received hash: 0x{received_hash:08X}")
        print(f"Calculated hash: 0x{calculated_hash:08X}")
        print(f"Match: {received_hash == calculated_hash}")
        print("====================")
        
        return decoded
        
    except Exception as e:
        print(f"Error processing header data: {e}")
        return None


def parse_packet_data(hex_data):
    """Process received packet data."""
    try:
        # Packet structure from C code:
        # [1 BYTE PACKET_ID][2 BYTE LENGTH][CBOR BYTES][4 BYTE CRC32]
        
        if len(hex_data) < 14:  # Minimum: 1 + 2 + 0 + 4 = 7 bytes = 14 hex chars
            print("Data too short for complete packet")
            return None
        
        # Extract packet ID (1 byte)
        packet_id = int.from_bytes(bytes.fromhex(hex_data[:2]), "little")
        
        # Extract CBOR data length (2 bytes, little endian)
        length_bytes = hex_data[2:6]
        cbor_size = int.from_bytes(bytes.fromhex(length_bytes), "little")
        
        print (f" Length bytes: {length_bytes} -> CBOR size: {cbor_size}")
        
        print (f"Packet ID: {packet_id}, CBOR size from length field: {cbor_size}")
        
        expected_length = (1 + 2 + cbor_size + 4) * 2  # Total packet length in hex chars
        
        if len(hex_data) < expected_length:
            print(f"Not enough data for expected packet size: got {len(hex_data)}, need {expected_length}")
            return None

        # Extract CBOR data
        cbor_start = 6  # After packet ID (2) + length (4)
        cbor_end = cbor_start + cbor_size * 2
        cbor_hex = hex_data[cbor_start:cbor_end]
        
        # Extract hash (4 bytes at the end)
        hash_hex = hex_data[cbor_end:cbor_end + 8]

        cbor_bytes = bytes.fromhex(cbor_hex)
        received_hash = int.from_bytes(bytes.fromhex(hash_hex), "little")
        calculated_hash = calculate_hash(cbor_bytes)

        decoded = cbor2.loads(cbor_bytes)
        decoded["_packet_id"] = packet_id
        decoded["_received_hash"] = received_hash
        decoded["_calculated_hash"] = calculated_hash
        decoded["_hash_valid"] = received_hash == calculated_hash

        # Debug information for hash comparison
        print(f"=== PACKET DEBUG ===")
        print(f"Total packet: {len(hex_data)} hex chars ({len(hex_data)//2} bytes)")
        print(f"Packet ID: {packet_id}")
        print(f"Length field: {length_bytes} -> CBOR size: {cbor_size}")
        print(f"CBOR hex: {cbor_hex}")
        print(f"Hash hex: {hash_hex}")
        print(f"CBOR bytes: {len(cbor_bytes)} bytes")
        print(f"First 16 CBOR bytes: {cbor_bytes[:16].hex()}")
        print(f"Last 16 CBOR bytes: {cbor_bytes[-16:].hex()}")
        print(f"Received hash: 0x{received_hash:08X}")
        print(f"Calculated hash: 0x{calculated_hash:08X}")
        print(f"Match: {received_hash == calculated_hash}")
        
        # Test the raw packet structure to see if we extract correctly
        total_packet_bytes = bytes.fromhex(hex_data)
        print(f"Raw packet (first 32): {total_packet_bytes[:32].hex()}")
        print(f"Raw packet (last 8): {total_packet_bytes[-8:].hex()}")
        print("===================")
        
        return decoded
        
    except Exception as e:
        print(f"Error processing packet data: {e}")
        return None


def display_header(header):
    """Display header information."""
    if not header:
        return "Invalid header"

    names = {
        DEVICE_UUID: "Device UUID",
        DEVICE_FAMILY: "Device Family", 
        TOTAL_CHUNKS: "Total Chunks",
        TOTAL_PINS: "Total Pins",
        ACTIVE_PINS: "Active Pins"
    }

    output = []
    for key, value in header.items():
        if isinstance(key, str) and key.startswith("_"):
            continue
        
        label = names.get(key, f"Unknown field {key}")
        if key == DEVICE_UUID:
            output.append(f"{label}: 0x{value:016X}")
        else:
            output.append(f"{label}: {value}")

    if "_received_hash" in header:
        status = "Valid" if header["_hash_valid"] else "Invalid"
        output.append(f"Hash check: {status} (Received: 0x{header['_received_hash']:08X})")
    
    return "\n".join(output)


def process_transmission_end():
    """Process the end of transmission."""
    global packet_buffer, last_header_info
    
    if not packet_buffer:
        print("No packets received")
        return

    print("Transmission complete")
    
    # Check received quantities
    if last_header_info:
        expected_chunks = last_header_info.get(TOTAL_CHUNKS, 0)
        expected_pins = last_header_info.get(TOTAL_PINS, 0)
        received_chunks = len(packet_buffer)
        received_pins = sum(len(data.get(PINS, [])) for _, data in packet_buffer if isinstance(data, dict))

        print(f"Chunks: {received_chunks}/{expected_chunks}")
        print(f"Pins: {received_pins}/{expected_pins}")

    # Display received packets
    for packet_num, data in sorted(packet_buffer):
        print(f"Packet {packet_num}:")
        if isinstance(data, dict):
            print(f"  Chunk ID: {data.get(CHUNK_ID)}")
            print(f"  Entries: {data.get(NUM_ENTRIES)}")
            
            if "_received_hash" in data:
                status = "Valid" if data["_hash_valid"] else "Invalid"
                print(f"  Hash: 0x{data['_received_hash']:08X} ({status})")
            
            for pin in data.get(PINS, []):
                if isinstance(pin, dict):
                    pin_num = pin.get(PIN)
                    events = pin.get(EVENTS, [])
                    connections = pin.get(CONNECTIONS, [])
                    print(f"  Pin {pin_num}: Events {events}")
                    if connections:
                        for conn in connections:
                            if isinstance(conn, dict):
                                other_pin = conn.get(OTHER_PIN)
                                device_id = conn.get(DEVICE_ID)
                                print(f"    Connected to pin {other_pin}, device 0x{device_id:016X}")

    packet_buffer.clear()


if __name__ == "__main__":
    
    
    
    # Calculate CRC32 for the given hex string
    test_hex = "A5001B4B9BD4D1DC6F64A801684E52463532383430020A0318300400"
    test_bytes = bytes.fromhex(test_hex)
    crc_result = calculate_hash(test_bytes)
    print(f"CRC32 for {test_hex}: 0x{crc_result:08X}")
    
    print(f"Opening {PORT} at {BAUDRATE} baud")
    ser = serial.Serial(PORT, BAUDRATE, timeout=1)
    binary_buffer = bytearray()
    current_packet_data = bytearray()
    receiving_header = False
    receiving_chunk = False
    waiting_for_error_code = False
    
    try:
        while True:
            if ser.in_waiting:
                new_data = ser.read(ser.in_waiting)
                
                # Check for debug messages in text format
                try:
                    text_data = new_data.decode('utf-8', errors='ignore')
                    if "DEBUG:" in text_data:
                        lines = text_data.split('\n')
                        for line in lines:
                            if "DEBUG:" in line:
                                print(f"Device: {line.strip()}")
                except:
                    pass
                
                binary_buffer.extend(new_data)
                
                # Check for 4-byte identifiers
                while len(binary_buffer) >= 4:
                    found_identifier = False
                    for id_bytes, id_value in identifiers.items():
                        if binary_buffer[:4] == id_bytes:
                            # Process identifier
                            if id_value == HEADER_START:
                                receiving_header = True
                                current_packet_data = bytearray()
                                print("Header transmission started")
                                
                            elif id_value == HEADER_END:
                                receiving_header = False
                                if current_packet_data:
                                    print(f"Header data received: {len(current_packet_data)} bytes")
                                    print(f"Complete header hex data: {current_packet_data.hex()}")
                                    # Header has format: [2 BYTE LENGTH][CBOR BYTES][4 BYTE CRC32] (no packet ID)
                                    header = parse_header_data(current_packet_data.hex())
                                    if header:
                                        last_header_info = header
                                        print(display_header(header))
                                        send_ack(ser, header)
                                    else:
                                        send_error(ser)
                                else:
                                    print("No header data received")
                                print("Header transmission ended")
                                
                            elif id_value == CHUNK_START:
                                receiving_chunk = True
                                current_packet_data = bytearray()
                                print("Chunk transmission started")
                                
                            elif id_value == CHUNK_END:
                                receiving_chunk = False
                                if current_packet_data:
                                    print(f"Raw chunk data: {current_packet_data.hex()}")
                                    # The chunk data IS the complete packet: [1 BYTE PACKET_ID][2 BYTE LENGTH][CBOR BYTES][4 BYTE CRC32]
                                    chunk = parse_packet_data(current_packet_data.hex())
                                    if chunk:
                                        chunk_id = chunk.get("_packet_id", 0)
                                        chunk["_chunk_id"] = chunk_id
                                        packet_buffer.append((chunk_id, chunk))
                                        print(f"Chunk {chunk_id} stored")
                                        
                                        # Check if all expected chunks received
                                        if last_header_info:
                                            expected_chunks = last_header_info.get(TOTAL_CHUNKS, 0)
                                            received_chunks = len(packet_buffer)
                                            if received_chunks == expected_chunks:
                                                print(f"All {expected_chunks} chunks received")
                                        
                                        send_ack(ser, chunk)
                                    else:
                                        print("Failed to parse chunk data")
                                        send_error(ser)
                                else:
                                    print("No chunk data received")
                                    send_error(ser)
                                print("Chunk transmission ended")
                                
                            elif id_value == TRANSMISSION_START:
                                print("Transmission started")
                                
                            elif id_value == TRANSMISSION_END:
                                print("Transmission ended")
                                process_transmission_end()
                            
                            elif id_value == ERROR_WITH_ACK:
                                print("Error with ACK request received")
                                
                            elif id_value == ERROR_ID:
                                waiting_for_error_code = True
                                print("Error identifier received, waiting for error code")
                                
                            binary_buffer = binary_buffer[4:]
                            found_identifier = True
                            break
                    
                    if not found_identifier:
                        # Wait for error code
                        if waiting_for_error_code and len(binary_buffer) >= 4:
                            error_code = int.from_bytes(binary_buffer[:4], "little")  # Little endian
                            name = WAIT_FOR_ACK_RESULT.get(error_code) or UART_TRANSMISSION_RESULT.get(error_code)
                            if name:
                                print(f"Error code received: {error_code} ({name})")
                            else:
                                print(f"Unknown error code: {error_code}")
                            binary_buffer = binary_buffer[4:]
                            waiting_for_error_code = False
                        # Collect packet data
                        elif receiving_header:
                            current_packet_data.append(binary_buffer[0])
                            binary_buffer = binary_buffer[1:]
                        elif receiving_chunk:
                            current_packet_data.append(binary_buffer[0])
                            binary_buffer = binary_buffer[1:]
                        else:
                            binary_buffer = binary_buffer[1:]
                    
    except KeyboardInterrupt:
        print("Reception stopped")
    finally:
        ser.close()