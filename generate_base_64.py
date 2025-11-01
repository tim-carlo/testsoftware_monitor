#!/usr/bin/env python3

import cbor2
import base64
import hashlib
from data_storage import KEY_PIN, KEY_EVENTS, KEY_CONNECTIONS, KEY_OTHER_PIN, KEY_DEVICE_ID, HEADER_KEY_DEVICE_FAMILY


def export_cbor(collector):
    devices = []
    for family, data in collector.get_all_devices().items():
        pins = []
        for p in data.get('pins', []):
            pins.append({
                KEY_PIN: p.get('pin'),
                KEY_EVENTS: p.get('events', []),
                KEY_CONNECTIONS: [{KEY_OTHER_PIN: c.get('other_pin'), KEY_DEVICE_ID: c.get('device_id')} 
                                 for c in p.get('connections', [])]
            })
        devices.append({HEADER_KEY_DEVICE_FAMILY: family, 2: pins})
    
    cbor_bytes = cbor2.dumps(devices)
    b64 = base64.b64encode(cbor_bytes).decode('ascii')
    sha256_hash = hashlib.sha256(cbor_bytes).hexdigest()
    
    print(b64)
    print(f"SHA256: {sha256_hash}")
    
    return cbor_bytes