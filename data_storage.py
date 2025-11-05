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
KEY_CONNECTION_PARAMETER = 8  # Device ID (external) or Phase (internal)
KEY_CONNECTION_TYPE = 9

# Connection Types
CONNECTION_TYPE_INTERNAL = 0
CONNECTION_TYPE_EXTERNAL = 1

# Internal Connection Phases (KEY_CONNECTION_PARAMETER values for internal connections)
PHASE_0_PULLDOWN_DRIVE_LOW = 0
PHASE_1_PULLUP_DRIVE_HIGH = 1
PHASE_2_NO_PULL_DRIVE_LOW = 2
PHASE_3_NO_PULL_DRIVE_HIGH = 3

PHASE_NAMES = {
    0: "PULLDOWN_DRIVE_LOW",
    1: "PULLUP_DRIVE_HIGH",
    2: "NO_PULL_DRIVE_LOW",
    3: "NO_PULL_DRIVE_HIGH"
}

HEADER_KEY_DEVICE_FAMILY = 1
HEADER_KEY_TOTAL_CHUNKS = 2

NUMBER_OF_EXPECTED_DEVICES_FOR_COMPLETION = 1

# Pin Name Mappings for NRF52840
NRF52840_PIN_NAMES = {
    21: "GPIO0_UART_RX",
    8: "GPIO1_UART_TX",
    4: "GPIO2",
    5: "GPIO3",
    41: "GPIO4",  # P1.09
    26: "GPIO5",
    35: "GPIO6",  # P1.03
    11: "GPIO7",
    13: "GPIO8",
    16: "GPIO9",
    12: "GPIO10",
    10: "GPIO11",
    19: "GPIO12",
    20: "GPIO13",
    24: "GPIO14",
    27: "GPIO15",
    23: "PWRGDL",
    7: "PWRGDH",
    45: "PIN_LED0",  # P1.13
    3: "PIN_LED2",
    40: "I2C_SCL",  # P1.08
    6: "I2C_SDA",
    30: "RTC_INT",
    25: "MAX_INT",
    18: "C2C_CLK",
    17: "C2C_CoPi",
    14: "C2C_CiPo",
    22: "C2C_PSel",
    15: "C2C_GPIO",
    9: "THRCTRL_H0",
    34: "THRCTRL_H1",  # P1.02
    39: "THRCTRL_L0",  # P1.07
    36: "THRCTRL_L1",  # P1.04
}

# Pin Name Mappings for MSP430FR5994
MSP430_PIN_NAMES = {
    22: "GPIO0_UART_RX",  # P2.6
    21: "GPIO1_UART_TX",  # P2.5
    19: "GPIO2",  # P2.3
    20: "GPIO3",  # P2.4
    38: "GPIO4",  # P4.6
    30: "GPIO5",  # P3.6
    6: "GPIO6",   # PJ.6
    43: "GPIO7",  # P5.3
    42: "GPIO8",  # P5.2
    41: "GPIO9",  # P5.1
    40: "GPIO10", # P5.0
    48: "GPIO11", # P6.0
    49: "GPIO12", # P6.1
    51: "GPIO13", # P6.3
    54: "GPIO14", # P6.6
    55: "GPIO15", # P6.7
    44: "PWRGDL",  # P5.4
    45: "PWRGDH",  # P5.5
    47: "PIN_LED0", # P5.7
    0: "PIN_LED2",  # PJ.0
    53: "I2C_SCL",  # P6.5
    52: "I2C_SDA",  # P6.4
    1: "MAX_INT",   # PJ.1
    13: "C2C_CLK",  # P1.5
    16: "C2C_CoPi", # P2.0
    17: "C2C_CiPo", # P2.1
    12: "C2C_PSel", # P1.4
    2: "C2C_GPIO",  # PJ.2
    11: "THRCTRL_H0", # P1.3
    27: "THRCTRL_H1", # P3.3
    50: "THRCTRL_L0", # P6.2
    56: "THRCTRL_L1", # P7.0
}

def get_pin_name(device_family, pin_num):
    """Get the pin name for a given device family and pin number"""
    if "NRF" in str(device_family).upper():
        return NRF52840_PIN_NAMES.get(pin_num, f"P{pin_num}")
    elif "MSP" in str(device_family).upper():
        return MSP430_PIN_NAMES.get(pin_num, f"P{pin_num}")
    else:
        return f"P{pin_num}"

def get_known_pins(device_family):
    """Get list of known pin numbers for a device family"""
    if "NRF" in str(device_family).upper():
        return list(NRF52840_PIN_NAMES.keys())
    elif "MSP" in str(device_family).upper():
        return list(MSP430_PIN_NAMES.keys())
    else:
        return []


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
        
        # Clear existing data for this device_family when new header received
        self.devices[device_family] = {
            'total_chunks': header_data.get(HEADER_KEY_TOTAL_CHUNKS, 0),
            'pins': [],
            'chunks_received': set(),
            'complete': False
        }
        print(f"🔄 Reset data for device_family {device_family}")
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
                'connections': [{KEY_OTHER_PIN: c.get(KEY_OTHER_PIN), 
                                KEY_CONNECTION_PARAMETER: c.get(KEY_CONNECTION_PARAMETER),
                                KEY_CONNECTION_TYPE: c.get(KEY_CONNECTION_TYPE, 0)} 
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
            
            # Ausgabe aller Matrizen für alle Devices
            for device_family in sorted(self.devices.keys()):
                # Connection Summary
                self.print_connections_summary()
                
                # Externe Connection Matrizen (zu anderen Devices)
                for other_device in sorted(self.devices.keys()):
                    if device_family != other_device:
                        matrix = self.create_connection_matrix(device_family, other_device)
                        if matrix and any(any(row) for row in matrix):  # Nur ausgeben wenn Verbindungen existieren
                            self.print_connection_matrix(device_family, other_device)
                
                # Alle 4 Phasen-Matrizen
                self.print_all_phase_matrices(device_family)
        
        return complete
    
    def print_connections_summary(self):
        print("\n=== Pin Connections ===")
        for device_family, device_data in sorted(self.devices.items()):
            print(f"Device {device_family}:")
            for pin in device_data['pins']:
                pin_name = get_pin_name(device_family, pin['pin'])
                for conn in pin['connections']:
                    conn_type = conn.get(KEY_CONNECTION_TYPE, 0)
                    param = conn.get(KEY_CONNECTION_PARAMETER, 0)
                    other_pin_name = get_pin_name(device_family, conn.get(KEY_OTHER_PIN))
                    
                    if conn_type == CONNECTION_TYPE_INTERNAL:
                        phase_name = PHASE_NAMES.get(param, f"PHASE_{param}")
                        print(f"  {pin_name} -> {other_pin_name} [{phase_name}]")
                    else:  # EXTERNAL
                        print(f"  {pin_name} -> Device{param}:{other_pin_name} [EXT]")
        print("="*23 + "\n")
            
    def create_connection_matrix(self, controller_a, controller_b):
        if controller_a not in self.devices or controller_b not in self.devices:
            print(f"❌ Controller {controller_a} oder {controller_b} nicht gefunden")
            return None
        
        device_a = self.devices[controller_a]
        device_b = self.devices[controller_b]
        
        num_pins_a = len(device_a['pins'])
        num_pins_b = len(device_b['pins'])
        
        matrix = [[0 for _ in range(num_pins_b)] for _ in range(num_pins_a)]
        
        pin_to_index_a = {pin['pin']: idx for idx, pin in enumerate(device_a['pins'])}
        pin_to_index_b = {pin['pin']: idx for idx, pin in enumerate(device_b['pins'])}
        
        for pin in device_a['pins']:
            pin_num_a = pin['pin']
            idx_a = pin_to_index_a[pin_num_a]
            
            for conn in pin['connections']:
                # Only external connections have device IDs
                conn_type = conn.get(KEY_CONNECTION_TYPE, 0)
                if conn_type == CONNECTION_TYPE_EXTERNAL:
                    device_id = conn.get(KEY_CONNECTION_PARAMETER, -1)
                    if device_id == controller_b:
                        pin_num_b = conn.get(KEY_OTHER_PIN)
                        if pin_num_b in pin_to_index_b:
                            idx_b = pin_to_index_b[pin_num_b]
                            matrix[idx_a][idx_b] = 1
        
        return matrix
    
    def print_connection_matrix(self, controller_a, controller_b):
        """
        Gibt die externe Connection Matrix formatiert aus
        """
        matrix = self.create_connection_matrix(controller_a, controller_b)
        if matrix is None:
            return
        
        device_a = self.devices[controller_a]
        device_b = self.devices[controller_b]
        
        # Filter nur bekannte Pins
        known_pins_a = get_known_pins(controller_a)
        known_pins_b = get_known_pins(controller_b)
        
        pin_nums_a = [pin['pin'] for pin in device_a['pins'] if pin['pin'] in known_pins_a]
        pin_nums_b = [pin['pin'] for pin in device_b['pins'] if pin['pin'] in known_pins_b]
        
        if not pin_nums_a or not pin_nums_b:
            return
        
        num_cols = 16 + 3 * len(pin_nums_b)
        print(f"\n{'='*num_cols}")
        print(f"External Connection Matrix: Device {controller_a} -> Device {controller_b}")
        print(f"{'='*num_cols}")
        
        # Zeilen mit Pin-Namen
        pin_to_idx_a = {pin['pin']: idx for idx, pin in enumerate(device_a['pins'])}
        pin_to_idx_b = {pin['pin']: idx for idx, pin in enumerate(device_b['pins'])}
        
        for pin_a in pin_nums_a:
            pin_name_a = get_pin_name(controller_a, pin_a)
            print(f"{pin_name_a[:15]:15}|", end="")
            idx_a = pin_to_idx_a[pin_a]
            for pin_b in pin_nums_b:
                idx_b = pin_to_idx_b[pin_b]
                print(f"{matrix[idx_a][idx_b]:2} ", end="")
            print()
        
        print("=" * num_cols + "\n")
    
    def create_phase_matrix(self, controller, phase):
        if controller not in self.devices:
            print(f"❌ Controller {controller} nicht gefunden")
            return None
        
        if not 0 <= phase <= 3:
            print(f"❌ Ungültige Phase {phase}. Muss zwischen 0 und 3 sein")
            return None
        
        device = self.devices[controller]
        num_pins = len(device['pins'])
        
        # Matrix erstellen (Pins x Pins)
        matrix = [[0 for _ in range(num_pins)] for _ in range(num_pins)]
        
        # Event-Namen zu Phase-Mapping
        phase_error_events = {
            0: "PIN_IS_NOT_LOW_WHEN_PULLED_DOWN",
            1: "PIN_IS_NOT_HIGH_WHEN_PULLED_UP",
            2: "PIN_IS_NOT_LOW_WHEN_DRIVEN_LOW",
            3: "PIN_IS_NOT_HIGH_WHEN_DRIVEN_HIGH"
        }
        
        pin_to_index = {pin['pin']: idx for idx, pin in enumerate(device['pins'])}
        
        for pin in device['pins']:
            pin_num_a = pin['pin']
            idx_a = pin_to_index[pin_num_a]
            
            error_event = phase_error_events.get(phase)
            pin_works = error_event and error_event not in pin['events']
            
            if pin_works:
                matrix[idx_a][idx_a] = 1
            
            # Prüfe alle Connections dieses Pins
            for conn in pin['connections']:
                conn_type = conn.get(KEY_CONNECTION_TYPE, 0)
                
                # Nur interne Connections berücksichtigen
                if conn_type == CONNECTION_TYPE_INTERNAL:
                    conn_phase = conn.get(KEY_CONNECTION_PARAMETER, -1)
                    pin_num_b = conn.get(KEY_OTHER_PIN)
                    
                    if conn_phase == phase and pin_num_b in pin_to_index:
                        idx_b = pin_to_index[pin_num_b]
                        
                        if pin_works:
                            matrix[idx_a][idx_b] = 1
        
        return matrix
    
    def print_phase_matrix(self, controller, phase):
        matrix = self.create_phase_matrix(controller, phase)
        if matrix is None:
            return
        
        device = self.devices[controller]
        
        known_pins = get_known_pins(controller)
        pin_nums = [pin['pin'] for pin in device['pins'] if pin['pin'] in known_pins]
        
        if not pin_nums:
            return
        
        phase_names = {
            0: "PULLDOWN_DRIVE_LOW",
            1: "PULLUP_DRIVE_HIGH",
            2: "NO_PULL_DRIVE_LOW",
            3: "NO_PULL_DRIVE_HIGH"
        }
        
        num_cols = 16 + 3 * len(pin_nums)
        print(f"\n{'='*num_cols}")
        print(f"Phase {phase}: {phase_names.get(phase, f'PHASE_{phase}')} (Device {controller})")
        print(f"{'='*num_cols}")
        
        pin_to_idx = {pin['pin']: idx for idx, pin in enumerate(device['pins'])}
        
        for pin_a in pin_nums:
            pin_name_a = get_pin_name(controller, pin_a)
            print(f"{pin_name_a[:15]:15}|", end="")
            idx_a = pin_to_idx[pin_a]
            for pin_b in pin_nums:
                idx_b = pin_to_idx[pin_b]
                print(f"{matrix[idx_a][idx_b]:2} ", end="")
            print()
        
        print("=" * num_cols + "\n")
    
    def print_all_phase_matrices(self, controller):
        print(f"\n{'='*50}")
        print(f"All Phase Matrices: Device {controller}")
        print(f"{'='*50}")
        
        for phase in range(4):
            self.print_phase_matrix(controller, phase)
    
    def to_cbor(self):
        
        devices = [{HEADER_KEY_DEVICE_FAMILY: f, 2: [{KEY_PIN: p['pin'], KEY_EVENTS: p['events'], 
                    KEY_CONNECTIONS: p['connections']} for p in d['pins']]} 
                  for f, d in self.devices.items()]
        
        cbor_bytes = cbor2.dumps(devices)
        b64 = base64.b64encode(cbor_bytes).decode('utf-8')
        print(f"SHA256: {hashlib.sha256(cbor_bytes).hexdigest()}")
        return cbor_bytes

