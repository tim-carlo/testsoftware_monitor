#!/usr/bin/env python3

from event_decoder import decode_event_type_one_hot, merge_handshake_events
from pin_analyzer import analyze_all_pins, analyze_pin
import base64
import hashlib
import cbor2
from datetime import datetime
import sys

KEY_CHUNK_ID = 0
KEY_PINS = 2
KEY_PIN = 4
KEY_EVENTS = 5
KEY_CONNECTIONS = 6
KEY_OTHER_PIN = 7
KEY_CONNECTION_PARAMETER = 8  # Device ID (external) or Phase (internal)
KEY_CONNECTION_TYPE = 9
KEY_DEVICE_UUID = 0  # UUID from header

# Connection Types
CONNECTION_TYPE_INTERNAL = 0
CONNECTION_TYPE_EXTERNAL = 1

# Internal Connection Phases (KEY_CONNECTION_PARAMETER values for internal connections)
PHASE_0_PULLDOWN = 0
PHASE_1_PULLUP = 1
PHASE_2_DRIVE_LOW = 2
PHASE_3_DRIVE_HIGH = 3

PHASE_NAMES = {
    0: "PULLDOWN",
    1: "PULLUP",
    2: "DRIVE_LOW",
    3: "DRIVE_HIGH"
}

HEADER_KEY_DEVICE_FAMILY = 1
HEADER_KEY_TOTAL_CHUNKS = 2
HEADER_KEY_NUMBER_SEEN_DEVICES = 6

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
        name = NRF52840_PIN_NAMES.get(pin_num)
        return f"{pin_num}: {name}" if name else str(pin_num)
    elif "MSP" in str(device_family).upper():
        name = MSP430_PIN_NAMES.get(pin_num)
        return f"{pin_num}: {name}" if name else str(pin_num)
    else:
        return str(pin_num)

def get_known_pins(device_family):
    """Get list of known pin numbers for a device family"""
    if "NRF" in str(device_family).upper():
        return list(NRF52840_PIN_NAMES.keys())
    elif "MSP" in str(device_family).upper():
        return list(MSP430_PIN_NAMES.keys())
    else:
        return []

def get_all_pins_sorted(device_family, device_data):
    """Get all pins from device data sorted by pin number"""
    all_pins = set()
    # Add all pins from device data
    for pin in device_data.get('pins', []):
        all_pins.add(pin['pin'])
    # Also add all known pins from mapping
    all_pins.update(get_known_pins(device_family))
    return sorted(all_pins)


class TeeOutput:
    """Helper class to write to both stdout and file"""
    def __init__(self, file_handle):
        self.terminal = sys.stdout
        self.log = file_handle
    
    def write(self, message):
        self.terminal.write(message)
        self.log.write(message)
    
    def flush(self):
        self.terminal.flush()
        self.log.flush()


class DeviceDataCollector:
    """Collects and processes device pin data from CBOR packets"""
    
    def __init__(self):
        self.devices = {}
        self.current_device_family = None
        self.output_file = None
        self.original_stdout = None
        self.device_uuid = None
        self.expected_devices = 1
        self.capture_started = False
    
    # ===== Data Processing Methods =====
    
    def process_header(self, header_result):
        if not header_result or not header_result.get('hash_valid'):
            return False
            
        header_data = header_result.get('data', {})
        device_family = header_data.get(HEADER_KEY_DEVICE_FAMILY)
        if device_family is None:
            return False
        
        # Get device UUID for filename
        self.device_uuid = header_data.get(KEY_DEVICE_UUID, "UNKNOWN")
        
        self.current_device_family = device_family
        self.expected_devices = header_data.get(HEADER_KEY_NUMBER_SEEN_DEVICES, 1)
        
        # Clear existing data for this device_family when new header received
        self.devices[device_family] = {
            'total_chunks': header_data.get(HEADER_KEY_TOTAL_CHUNKS, 0),
            'pins': [],
            'chunks_received': set(),
            'complete': False,
            'saved': False,
            'uuid': self.device_uuid
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
            
            if "EXCEEDS_CONNECTION_LIMIT" in events:
                pin_name = get_pin_name(self.current_device_family, pin_entry.get(KEY_PIN))
                print(f"⚠️ WARNING: Pin {pin_name} exceeded connection limit!")

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
        
        # Filter connections after all data is loaded
        if device['complete']:
            self._filter_weak_connections(self.current_device_family)
        
        return True
    
    def _filter_weak_connections(self, device_family):
        """Remove WEAK naturally driven connections after all pins are loaded"""
        device = self.devices.get(device_family)
        if not device:
            return
        
        # Create mapping of pin number to events
        pin_events = {pin['pin']: pin['events'] for pin in device['pins']}
        
        # Filter connections for each pin
        for pin in device['pins']:
            filtered_connections = []
            for conn in pin['connections']:
                conn_type = conn.get(KEY_CONNECTION_TYPE, 0)
                if conn_type == CONNECTION_TYPE_INTERNAL:
                    phase = conn.get(KEY_CONNECTION_PARAMETER, -1)
                    other_pin = conn.get(KEY_OTHER_PIN)
                    
                    # Check if source or target pin should be masked
                    source_masked = self._should_mask_connection(pin['events'], phase)
                    target_events = pin_events.get(other_pin, [])
                    target_masked = self._should_mask_connection(target_events, phase)
                    
                    # Keep connection only if neither is masked
                    if not source_masked and not target_masked:
                        filtered_connections.append(conn)
                else:
                    filtered_connections.append(conn)
            
            pin['connections'] = filtered_connections
    
    def get_all_devices(self):
        return self.devices
    
    
    def _start_output_capture(self, device_family=None, device_uuid=None):
        """Start capturing output to file"""
        if device_uuid is None:
            device_uuid = self.device_uuid if self.device_uuid else "UNKNOWN"
        
        if device_family is None:
            device_family = self.current_device_family if self.current_device_family is not None else "UNKNOWN"
        
        import os
        os.makedirs("logs", exist_ok=True)
        
        timestamp = datetime.now().strftime("%Y_%m_%d_%H_%M_%S")
        filename = f"logs/output_{device_family}_{device_uuid}_{timestamp}.txt"
        
        self.output_file = open(filename, 'w', encoding='utf-8')
        print(f"📝 Saving to: {filename}")
        
        self.original_stdout = sys.stdout
        sys.stdout = TeeOutput(self.output_file)
            
    def _stop_output_capture(self):
        """Stop capturing output to file"""
        if self.output_file:
            sys.stdout = self.original_stdout
            self.output_file.close()
            print(f"✅ File saved")
    
    def save_device_report(self, device_family):
        """Save report for a specific device"""
        device = self.devices.get(device_family)
        if not device:
            return
            
        self._start_output_capture(device_family, device.get('uuid'))
        
        if self.original_stdout:
            self.original_stdout.write(f"✅ Collection complete for Device {device_family}\n")
        
        # Print connections summary (filtered for this device)
        print("\n=== Pin Connections ===")
        print(f"Device {device_family}:")
        for pin in device['pins']:
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

        # Externe Connection Matrizen (zu anderen Devices)
        for other_device in sorted(self.devices.keys()):
            if device_family != other_device:
                self.print_connection_matrix(device_family, other_device)

        # Alle 4 Phasen-Matrizen
        self.print_all_phase_matrices(device_family)

        # After connections and matrices, print events for all pins
        self.print_all_pin_events(device_family)
        
        # Run pin force analysis for this device
        self.run_pin_analysis(device_family)
        
        self._stop_output_capture()

    def is_complete(self):
        # Check for any completed but unsaved devices
        for family, device in self.devices.items():
            if device['complete'] and not device.get('saved', False):
                self.save_device_report(family)
                device['saved'] = True
        
        # Return true if ALL expected devices are complete (for legacy check)
        return sum(1 for d in self.devices.values() if d['complete']) >= self.expected_devices
        
        return complete
    
    def manual_save(self):
        """Manual save triggered by 's' command"""
        self._start_output_capture()
        print(f"💾 Manual save")
        self.print_connections_summary()
        for device_family in sorted(self.devices.keys()):
            for other_device in sorted(self.devices.keys()):
                if device_family != other_device:
                    self.print_connection_matrix(device_family, other_device)
            self.print_all_phase_matrices(device_family)
        self.print_all_pin_events()
        self.run_pin_analysis()
        self._stop_output_capture()
    
    # ===== Output Display Methods =====
    
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

    def print_all_pin_events(self, device_family=None):
        """Print decoded events for all pins for all devices or a specific one."""
        print("\n=== Pin Events ===")
        
        devices_to_print = [device_family] if device_family is not None else sorted(self.devices.keys())
        
        for family in devices_to_print:
            if family not in self.devices:
                continue
                
            device_data = self.devices[family]
            print(f"Device {family}:")
            for pin in device_data['pins']:
                pin_name = get_pin_name(family, pin['pin'])
                events = pin.get('events', [])
                if events:
                    print(f"  {pin_name}: {', '.join(events)}")
                    if "EXCEEDS_CONNECTION_LIMIT" in events:
                        print(f"  ⚠️  WARNING: Connection limit exceeded for this pin!")
                else:
                    print(f"  {pin_name}: No events")
        print("="*23 + "\n")
    
    def run_pin_analysis(self, device_family=None):
        """Run pin force analysis for all devices or a specific one."""
        devices_to_analyze = [device_family] if device_family is not None else sorted(self.devices.keys())
        
        for family in devices_to_analyze:
            if family not in self.devices:
                continue
                
            device_data = self.devices[family]
            print(f"\n{'='*80}")
            print(f"Pin Force Analysis - Device {family}")
            print(f"{'='*80}")
            for pin_data in device_data['pins']:
                pin_num = pin_data.get('pin', 'UNKNOWN')
                pin_name = get_pin_name(family, pin_num)
                events = pin_data.get('events', [])
                from pin_analyzer import analyze_pin
                result = analyze_pin(pin_name, events)
                print(f"  {result}")
            print(f"{'='*80}\n")
    
    # ===== Matrix Generation Methods =====
    
    def _should_mask_connection(self, events, phase):
        """Mask connections for Strength 1 and -1 pins in specific phases"""
        analysis = analyze_pin("TEMP", events)
        
        # Mask if Strength 1 (Naturally High) and phase is PULLUP (1) or DRIVE_HIGH (3)
        if "Strength 1" in analysis and phase in (1, 3):
            return True
            
        # Mask if Strength -1 (Naturally Low) and phase is PULLDOWN (0) or DRIVE_LOW (2)
        if "Strength -1" in analysis and phase in (0, 2):
            return True
            
        return False
    
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
        matrix = self.create_connection_matrix(controller_a, controller_b)
        if matrix is None:
            return
        
        device_a = self.devices[controller_a]
        device_b = self.devices[controller_b]
        
        pin_nums_a = get_all_pins_sorted(controller_a, device_a)
        pin_nums_b = get_all_pins_sorted(controller_b, device_b)
        
        if not pin_nums_a or not pin_nums_b:
            return
        
        num_cols = 26 + 3 * len(pin_nums_b)
        print(f"\n{'='*num_cols}")
        print(f"External Connection Matrix: Device {controller_a} -> Device {controller_b}")
        print(f"{'='*num_cols}")
        
        pin_to_idx_a = {pin['pin']: idx for idx, pin in enumerate(device_a['pins'])}
        pin_to_idx_b = {pin['pin']: idx for idx, pin in enumerate(device_b['pins'])}
        
        for pin_a in pin_nums_a:
            pin_name_a = get_pin_name(controller_a, pin_a)
            print(f"{pin_name_a[:25]:25}|", end="")
            if pin_a in pin_to_idx_a:
                idx_a = pin_to_idx_a[pin_a]
                for pin_b in pin_nums_b:
                    if pin_b in pin_to_idx_b:
                        idx_b = pin_to_idx_b[pin_b]
                        print(f"{matrix[idx_a][idx_b]:2} ", end="")
                    else:
                        print(f" 0 ", end="")
            else:
                for pin_b in pin_nums_b:
                    print(f" 0 ", end="")
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
            
            # Check if connection should be masked for this pin
            should_mask = self._should_mask_connection(pin['events'], phase)
            
            if pin_works and not should_mask:
                matrix[idx_a][idx_a] = 1
            
            # Prüfe alle Connections dieses Pins (bereits gefiltert beim Laden)
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
        pin_nums = get_all_pins_sorted(controller, device)
        
        if not pin_nums:
            return
        
        phase_names = {
            0: "PULLDOWN",
            1: "PULLUP",
            2: "DRIVE_LOW",
            3: "DRIVE_HIGH"
        }
        
        num_cols = 26 + 3 * len(pin_nums)
        print(f"\n{'='*num_cols}")
        print(f"Phase {phase}: {phase_names.get(phase, f'PHASE_{phase}')} (Device {controller})")
        print(f"{'='*num_cols}")
        
        pin_to_idx = {pin['pin']: idx for idx, pin in enumerate(device['pins'])}
        
        for pin_a in pin_nums:
            pin_name_a = get_pin_name(controller, pin_a)
            print(f"{pin_name_a[:25]:25}|", end="")
            if pin_a in pin_to_idx:
                idx_a = pin_to_idx[pin_a]
                for pin_b in pin_nums:
                    if pin_b in pin_to_idx:
                        idx_b = pin_to_idx[pin_b]
                        print(f"{matrix[idx_a][idx_b]:2} ", end="")
                    else:
                        print(f" 0 ", end="")
            else:
                for pin_b in pin_nums:
                    print(f" 0 ", end="")
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
        print(f"SHA256: {hashlib.sha256(cbor_bytes).hexdigest()}")
        return cbor_bytes

    def save_raw_xml(self):
        """Save all collected data to an XML file with metadata"""
        import xml.etree.ElementTree as ET
        import socket
        import os
        
        os.makedirs("raw_data", exist_ok=True)
        
        root = ET.Element("ShepperdTest")
        
        # Metadata
        meta = ET.SubElement(root, "Metadata")
        ET.SubElement(meta, "Timestamp").text = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        ET.SubElement(meta, "Computer").text = socket.gethostname()
        try:
            ET.SubElement(meta, "User").text = os.getlogin()
        except:
            ET.SubElement(meta, "User").text = "unknown"
        
        # Devices
        devices_elem = ET.SubElement(root, "Devices")
        
        for family, device_data in self.devices.items():
            dev_elem = ET.SubElement(devices_elem, "Device")
            dev_elem.set("Family", str(family))
            dev_elem.set("UUID", str(device_data.get('uuid', 'UNKNOWN')))
            
            # Create CBOR for this specific device
            device_obj = {
                HEADER_KEY_DEVICE_FAMILY: family, 
                2: [{KEY_PIN: p['pin'], KEY_EVENTS: p['events'], 
                     KEY_CONNECTIONS: p['connections']} for p in device_data['pins']]
            }
            
            cbor_bytes = cbor2.dumps([device_obj])
            b64_cbor = base64.b64encode(cbor_bytes).decode('utf-8')
            
            data_elem = ET.SubElement(dev_elem, "RawData")
            data_elem.text = b64_cbor
            data_elem.set("Encoding", "base64")
            data_elem.set("Format", "CBOR")

        # Save to file
        timestamp = datetime.now().strftime("%Y_%m_%d_%H_%M_%S")
        filename = f"raw_data/raw_data_{timestamp}.xml"
        
        # Indent for pretty printing
        if hasattr(ET, 'indent'):
            ET.indent(root, space="  ", level=0)
            
        tree = ET.ElementTree(root)
        tree.write(filename, encoding="utf-8", xml_declaration=True)
        print(f"💾 Raw XML saved to: {filename}")

