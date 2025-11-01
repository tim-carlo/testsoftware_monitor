#!/usr/bin/env python3

from event_decoder import decode_event_type_one_hot, merge_handshake_events
import base64
import hashlib
import cbor2

KEY_CHUNK_ID = 0
KEY_PINS = 2
KEY_PIN = 4
KEY_EVENTS = 5
KEY_CONNECTIONS = 6
KEY_OTHER_PIN = 7
KEY_DEVICE_ID = 8

HEADER_KEY_DEVICE_FAMILY = 1
HEADER_KEY_TOTAL_CHUNKS = 2

NUMBER_OF_EXPECTED_DEVICES_FOR_COMPLETION = 1


class DeviceDataCollector:
    
    def __init__(self):
        self.devices = {}
        self.current_device_family = None
        
    def process_header(self, header_result):
        if not header_result or not header_result.get('hash_valid'):
            return False
            
        header_data = header_result.get('data', {})
        device_family = header_data.get(HEADER_KEY_DEVICE_FAMILY)
        if device_family is None:
            return False
        
        self.current_device_family = device_family
        
        if device_family not in self.devices:
            self.devices[device_family] = {
                'total_chunks': header_data.get(HEADER_KEY_TOTAL_CHUNKS, 0),
                'pins': [],
                'chunks_received': set(),
                'complete': False
            }
        return True
    
    def process_chunk(self, chunk_result):
        if not chunk_result or not chunk_result.get('hash_valid') or not self.current_device_family:
            return False
        
        chunk_data = chunk_result.get('data', {})
        device = self.devices.get(self.current_device_family)
        if not device:
            return False
        
        chunk_id = chunk_data.get(KEY_CHUNK_ID, chunk_result.get('packet_id', -1))
        if chunk_id in device['chunks_received']:
            return False
        
        for pin_entry in chunk_data.get(KEY_PINS, []):
            events_raw = pin_entry.get(KEY_EVENTS, 0)
            events = merge_handshake_events(decode_event_type_one_hot(events_raw)) if events_raw else []
            
            device['pins'].append({
                'pin': pin_entry.get(KEY_PIN),
                'events': events,
                'connections': [{KEY_OTHER_PIN: c.get(KEY_OTHER_PIN), KEY_DEVICE_ID: c.get(KEY_DEVICE_ID)} 
                               for c in pin_entry.get(KEY_CONNECTIONS, [])]
            })
        
        device['chunks_received'].add(chunk_id)
        device['complete'] = len(device['chunks_received']) == device['total_chunks']
        return True
    
    def get_all_devices(self):
        return self.devices
    
    def is_complete(self):
        complete = sum(1 for d in self.devices.values() if d['complete']) >= NUMBER_OF_EXPECTED_DEVICES_FOR_COMPLETION
        if complete:
            print(f"✅ Collection complete")
        return complete
    
    def to_cbor(self):
        
        devices = [{HEADER_KEY_DEVICE_FAMILY: f, 2: [{KEY_PIN: p['pin'], KEY_EVENTS: p['events'], 
                    KEY_CONNECTIONS: p['connections']} for p in d['pins']]} 
                  for f, d in self.devices.items()]
        
        cbor_bytes = cbor2.dumps(devices)
        b64 = base64.b64encode(cbor_bytes).decode('utf-8')
        print(f"BASE64 of CBOR: {b64}")
        print(f"SHA256: {hashlib.sha256(cbor_bytes).hexdigest()}")
        return cbor_bytes

