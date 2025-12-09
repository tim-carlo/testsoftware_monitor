import hashlib
import cbor2

EXCLUDED_EVENTS = {
    "STEP_1_A_HIGH",
    "STEP_1_A_LOW",
    "STEP_1_B_HIGH",
    "STEP_1_B_LOW",
    "STEP_2_A_HIGH"
}

def filter_connections_and_events(devices):
    filtered_devices = []
    for device in devices:
        filtered_pins = []
        for pin in device.get('pins', []):
            # Only keep connections that are not masked
            filtered_connections = [
                c for c in pin.get('connections', [])
                if not c.get('masked', False)
            ]
            # Only keep events not in EXCLUDED_EVENTS
            filtered_events = [
                e for e in pin.get('events', [])
                if e not in EXCLUDED_EVENTS
            ]
            filtered_pins.append({
                'pin': pin.get('pin'),
                'events': filtered_events,
                'connections': filtered_connections
            })
        filtered_devices.append({
            'device_family': device.get('device_family'),
            'pins': filtered_pins
        })
    return filtered_devices

def export_sha256(devices):
    filtered = filter_connections_and_events(devices)
    cbor_bytes = cbor2.dumps(filtered)
    sha256_hash = hashlib.sha256(cbor_bytes).hexdigest()
    return sha256_hash