import struct
import zlib

def parse_packet(packet: bytes):
    """
    Zerlegt ein Paket:
    [4-byte identifier][2-byte CBOR length][CBOR payload][4-byte CRC32]
    Alles Little Endian.
    """
    # Prüfen, dass wir mindestens 10 Byte haben (4+2+4 minimal)
    if len(packet) < 10:
        raise ValueError("Paket zu kurz")
    
    # 4-Byte Identifier (LE)
    identifier = struct.unpack_from('<I', packet, 0)[0]
    
    # 2-Byte CBOR Länge (LE)
    cbor_length = struct.unpack_from('<H', packet, 4)[0]
    
    # CBOR-Daten
    cbor_start = 6
    cbor_end = cbor_start + cbor_length
    cbor_data = packet[cbor_start:cbor_end]
    
    # CRC32 (LE)
    crc32_bytes = packet[cbor_end:cbor_end+4]
    crc32_value = struct.unpack('<I', crc32_bytes)[0]
    
    # Optional: CRC32 über CBOR-Daten prüfen
    crc_check = zlib.crc32(cbor_data) & 0xFFFFFFFF
    crc_ok = (crc32_value == crc_check)
    
    return {
        "identifier": identifier,
        "cbor_length": cbor_length,
        "cbor_data": cbor_data,
        "crc32": crc32_value,
        "crc_valid": crc_ok
    }

# ------------------------------
# Beispiel-Nutzung
# ------------------------------
if __name__ == "__main__":
    # Beispiel-Hexstring (wie von UART empfangen)
    hex_data = b'\x04\x03\x02\x01\x01(\0\xA2\x01\x05\x02\x85\xA3\x04\0\x05\x80\x06\x80\xA3\x04\x01\x05\x80\x06\x80\xA3\x04\x02\x05\x80\x06\x80\xA3\x04\x03\x05\x80\x06\x80\xA3\x04\x04\x05\x80\x06\x80\xC2\x91\xF9K\x08\x07\x06\x05W'
    
    packet_info = parse_packet(hex_data)
    
    print("Identifier:", hex(packet_info['identifier']))
    print("CBOR Length:", packet_info['cbor_length'])
    print("CBOR Data:", packet_info['cbor_data'].hex())
    print("CRC32:", hex(packet_info['crc32']))
    print("CRC valid:", packet_info['crc_valid'])