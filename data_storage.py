#!/usr/bin/env python3
import pandas as pd

from event_decoder import decode_event_type_one_hot, PIN_EVENT_TYPES
from pin_analyzer import analyze_all_pins, analyze_pin
from phase_masking import PhaseMasking
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
KEY_STREAM_NUMBER = 10

# Header Keys
HEADER_KEY_DEVICE_UUID = 0
HEADER_KEY_DEVICE_FAMILY = 1
HEADER_KEY_TOTAL_CHUNKS = 2
HEADER_KEY_TOTAL_PINS = 3
HEADER_KEY_ACTIVE_PINS = 4
HEADER_KEY_HEADER_HASH = 5
HEADER_KEY_NUMBER_SEEN_DEVICES = 6
HEADER_KEY_SEEN_DEVICE_IDS = 7
HEADER_KEY_ACK_REQUESTED = 8
HEADER_KEY_VERSION = 9
HEADER_KEY_EXPECTED_SESSIONS = 10

# Connection Types
CONNECTION_TYPE_INTERNAL = 0
CONNECTION_TYPE_EXTERNAL = 1

# Internal Connection Phases
PHASE_0_PULLDOWN = 0
PHASE_1_PULLUP = 1
PHASE_2_DRIVE_LOW = 2
PHASE_3_DRIVE_HIGH = 3
PHASE_4_ALLPULLUP_LOW = 4
PHASE_5_ALLPULLDOWN_HIGH = 5

PHASE_NAMES = {
    0: "ONE_SET_PULLDOWN",
    1: "ONE_SET_PULLUP",
    2: "DRIVE_LOW",
    3: "DRIVE_HIGH",
    4: "ALLPULLUP_LOW",
    5: "ALLPULLDOWN_HIGH"
}

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
    59: "RTC_INT",    # P7.3
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
        self.capture_started = False

    # ===== Helper Methods =====
    def _save_matrix(self, df, title=None, filename=None):
        if title:
            print(f"\n=== {title} ===")
            # Print full matrix without column headers and without truncation/ellipsis
            with pd.option_context('display.max_rows', None,
                                   'display.max_columns', None,
                                   'display.width', None):
                print(df.to_string(header=False))
        if filename:
            df.to_csv(filename)
        return df
    
    def _save_heatmap(self, df, filename, cmap, xlabel, ylabel, annot=True, fmt='g', vmin=None, vmax=None, legend_handles=None, figsize=(12, 10)):
        import seaborn as sns
        import matplotlib.pyplot as plt
        
        plt.figure(figsize=figsize)
        sns.heatmap(df, annot=annot, cmap=cmap, cbar=False, fmt=fmt, vmin=vmin, vmax=vmax)
        plt.xlabel(xlabel)
        plt.ylabel(ylabel)
        
        if legend_handles:
             plt.legend(handles=legend_handles, loc='upper left', bbox_to_anchor=(0, -0.2))
             
        plt.tight_layout()
        plt.savefig(filename, format='pdf', bbox_inches='tight')
        plt.close()
        print(f"  Saved: {filename}")

    # ===== Data Processing Methods =====
    
    def process_header(self, header_result):
        if not header_result or not header_result.get('hash_valid'):
            return False

        header_data = header_result.get('data', {})
        device_family = header_data.get(HEADER_KEY_DEVICE_FAMILY)
        if device_family is None:
            return False

        # Print received hash (Device Version)
        git_commit_hash = header_data.get(HEADER_KEY_VERSION, None)

        self.current_device_family = device_family

        # Clear existing data for this device_family when new header received
        self.devices[device_family] = {
            'total_chunks': header_data.get(HEADER_KEY_TOTAL_CHUNKS, 0),
            'expected_sessions': header_data.get(HEADER_KEY_EXPECTED_SESSIONS, 1),
            'pins': [],
            'received_sessions': {}, 
            'raw_header': header_result.get('raw_bytes', b''),
            'raw_session_chunks': {}, 
            'complete': False,
            'saved': False,
            'uuid': header_data.get(HEADER_KEY_DEVICE_UUID, "UNKNOWN"),
            'git_commit': git_commit_hash
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
        session_id = chunk_data.get(KEY_STREAM_NUMBER, 0)
        
        if session_id not in device['received_sessions']:
            device['received_sessions'][session_id] = set()
            device['raw_session_chunks'][session_id] = {}
            
        if chunk_id in device['received_sessions'][session_id]:
            return False
        
        # Store raw chunk bytes
        device['raw_session_chunks'][session_id][chunk_id] = chunk_result.get('raw_bytes', b'')
        
        for pin_entry in chunk_data.get(KEY_PINS, []):
            events_raw = pin_entry.get(KEY_EVENTS, 0)
            events = decode_event_type_one_hot(events_raw) if events_raw else []
            
            if "EXCEEDS_CONNECTION_LIMIT" in events:
                pin_name = get_pin_name(self.current_device_family, pin_entry.get(KEY_PIN))
                print(f"WARNING: Pin {pin_name} exceeded connection limit!")

            pin_num = pin_entry.get(KEY_PIN)
            new_connections = [{KEY_OTHER_PIN: c.get(KEY_OTHER_PIN), 
                                KEY_CONNECTION_PARAMETER: c.get(KEY_CONNECTION_PARAMETER),
                                KEY_CONNECTION_TYPE: c.get(KEY_CONNECTION_TYPE, 0)} 
                               for c in pin_entry.get(KEY_CONNECTIONS, [])]


            strength = analyze_pin(events)
            # Find existing pin entry or create new one
            existing_pin = next((p for p in device['pins'] if p['pin'] == pin_num), None)
            
            if existing_pin:
                # Overwrite events and mask with latest session data
                existing_pin['events'] = events
                existing_pin['events_mask'] = events_raw
                existing_pin['strength'] = strength
                # Append new connections
                existing_pin['connections'].extend(new_connections)
            else:
                device['pins'].append({
                    'pin': pin_num,
                    'events': events,
                    'events_mask': events_raw,
                    'strength': strength,
                    'connections': new_connections
                })
        
        device['received_sessions'][session_id].add(chunk_id)
        
        # Check completion: All expected sessions must have all chunks
        sessions_done = 0
        for s_id in range(device['expected_sessions']):
            if s_id in device['received_sessions'] and len(device['received_sessions'][s_id]) == device['total_chunks']:
                sessions_done += 1
        
        device['complete'] = (sessions_done == device['expected_sessions'])
        
        # Filter connections after all data is loaded
        if device['complete']:
            self._filter_weak_connections(self.current_device_family)
        return True
    
    def _filter_weak_connections(self, device_family):
        """Mark connections that are disturbed and apply phase masking"""
        device = self.devices.get(device_family)
        if not device:
            return
        
        # Create mapping of pin number to events
        pin_events = {pin['pin']: pin['events'] for pin in device['pins']}
        
        # Filter connections for each pin
        for pin in device['pins']:
            for conn in pin['connections']:
                conn_type = conn.get(KEY_CONNECTION_TYPE, 0)
                if conn_type == CONNECTION_TYPE_INTERNAL:
                    phase = conn.get(KEY_CONNECTION_PARAMETER, -1)
                    other_pin = conn.get(KEY_OTHER_PIN)
                    
                    # Check if source or target pin should be masked
                    source_masked = self._should_mask_connection(pin['events'], phase)
                    target_events = pin_events.get(other_pin, [])
                    target_masked = self._should_mask_connection(target_events, phase)
                    
                    # Mark connection if either is masked
                    if source_masked or target_masked:
                        conn['masked'] = True
                    else:
                        conn['masked'] = False
                else:
                    conn['masked'] = False

    def _apply_phase_masking(self, device_family):
        """Apply phase masking per connection based on phases present for each specific directional connection"""
        device = self.devices.get(device_family)
        if not device:
            return
        
        # Collect connections grouped by directional pin pairs
        connection_pairs = {}
        
        # First pass: group connections by directional pin pairs
        for pin in device['pins']:
            for conn in pin['connections']:
                if conn.get(KEY_CONNECTION_TYPE, 0) == CONNECTION_TYPE_INTERNAL:
                    phase = conn.get(KEY_CONNECTION_PARAMETER, -1)
                    if 0 <= phase <= 5:
                        pin_pair = (pin['pin'], conn.get(KEY_OTHER_PIN))
                        if pin_pair not in connection_pairs:
                            connection_pairs[pin_pair] = {'phases': set(), 'connections': []}
                        connection_pairs[pin_pair]['phases'].add(phase)
                        connection_pairs[pin_pair]['connections'].append(conn)
        
        # Second pass: apply masking
        for pair_data in connection_pairs.values():
            for conn in pair_data['connections']:
                phase = conn.get(KEY_CONNECTION_PARAMETER, -1)
                conn['phase_masked'] = not PhaseMasking.should_keep_phase(phase, pair_data['phases'])
    
    def get_all_devices(self):
        return self.devices
    
    
    def _start_output_capture(self, device_family=None, device_uuid=None):
        """Start capturing output to file"""
        if device_family is None:
            device_family = self.current_device_family if self.current_device_family is not None else "UNKNOWN"

        if device_uuid is None:
            if device_family in self.devices:
                device_uuid = self.devices[device_family].get('uuid', "UNKNOWN")
            else:
                device_uuid = "UNKNOWN"
        
        import os
        os.makedirs("logs", exist_ok=True)
        
        timestamp = datetime.now().strftime("%Y_%m_%d_%H_%M_%S")
        filename = f"logs/output_{device_family}_{device_uuid}_{timestamp}.txt"
        
        self.output_file = open(filename, 'w', encoding='utf-8')
        print(f"Saving to: {filename}")
        
        self.original_stdout = sys.stdout
        sys.stdout = TeeOutput(self.output_file)
            
    def _stop_output_capture(self):
        """Stop capturing output to file"""
        if self.output_file:
            sys.stdout = self.original_stdout
            self.output_file.close()
            print(f"File saved")
    
    def save_device_report(self, device_family):
        """Save report for a specific device"""
        device = self.devices.get(device_family)
        if not device:
            return

        self._start_output_capture(device_family, device.get('uuid'))

        if self.original_stdout:
            self.original_stdout.write(f"Collection complete for Device {device_family}\n")

        # Print Git commit version
        print(f"Device Version: {device.get('git_commit', 'UNKNOWN')}")

        # --- Collect all matrix and force analysis binary data ---
        combined_bytes = bytearray()
        # External connection matrices
        for other_device in sorted(self.devices.keys()):
            if device_family != other_device:
                df = self.create_connection_matrix(device_family, other_device)
                if df is not None:
                    combined_bytes += df.values.tobytes()
        # All 6 phase matrices
        for phase in range(6):
            df = self.create_phase_matrix(device_family, phase)
            if df is not None:
                combined_bytes += df.values.tobytes()
        # Force analysis - use stored strengths if available
        strengths = []
        for pin_data in device['pins']:
            pin_num = pin_data.get('pin', 'UNKNOWN')
            pin_name = get_pin_name(device_family, pin_num)
            # Use stored strength if available, otherwise calculate
            strength = pin_data.get('strength')
            if strength is None:
                events = pin_data.get('events', [])
                strength = analyze_pin(events)
            strengths.append(strength)
        
        # Convert for hash (None -> 0)
        hash_strengths = [0 if s is None else int(s) for s in strengths]
        combined_bytes += bytearray([s & 0xFF for s in hash_strengths])
        combined_hash = hashlib.sha256(combined_bytes).hexdigest()
        print(f"HASH: {combined_hash}")

        # Print connections summary (filtered for this device)
        print("\n=== Pin Connections ===")
        print(f"Device {device_family}:")
        for pin in device['pins']:
            pin_name = get_pin_name(device_family, pin['pin'])
            for conn in pin['connections']:
                if conn.get('masked', False):
                    continue
                conn_type = conn.get(KEY_CONNECTION_TYPE, 0)
                param = conn.get(KEY_CONNECTION_PARAMETER, 0)
                other_pin_name = get_pin_name(device_family, conn.get(KEY_OTHER_PIN))

                if conn_type == CONNECTION_TYPE_INTERNAL:
                    phase_name = PHASE_NAMES.get(param, f"PHASE_{param}")
                    print(f"  {pin_name} -> {other_pin_name} [{phase_name}]")
                else:  # EXTERNAL
                    print(f"  {pin_name} -> Device{param}:{other_pin_name} [EXT]")
        print("="*23 + "\n")

        # External connection matrices (to other devices)
        for other_device in sorted(self.devices.keys()):
            if device_family != other_device:
                self.print_connection_matrix(device_family, other_device)

        # All 6 phase matrices
        self.print_all_phase_matrices(device_family)

        # After connections and matrices, print events for all pins
        self.print_all_pin_events(device_family)
        # Run pin force analysis for this device
        self.run_pin_analysis(device_family, precalculated_strengths=strengths)
        self._stop_output_capture()

    def is_complete(self):
        # Check for any completed but unsaved devices
        for family, device in self.devices.items():
            if device['complete'] and not device.get('saved', False):
                self.save_device_report(family)
                device['saved'] = True
        
        return False
        
    
    def manual_save(self):
        """Manual save triggered by 's' command"""
        self._start_output_capture("ALL", "DEVICES")
        print(f"Manual save")
        self.print_connections_summary()
        for device_family in sorted(self.devices.keys()):
            for other_device in sorted(self.devices.keys()):
                if device_family != other_device:
                    self.print_connection_matrix(device_family, other_device)
            self.print_all_phase_matrices(device_family)
        self.print_all_pin_events()
        self.run_pin_analysis()
        
        # Add simple vector analysis to text output
        from connection_analyzer import print_vectors
        print_vectors(self)
        
        self._stop_output_capture()
    
    
    def print_connections_summary(self):
        print("\n=== Pin Connections ===")
        for device_family, device_data in sorted(self.devices.items()):
            print(f"Device {device_family}:")
            for pin in device_data['pins']:
                pin_name = get_pin_name(device_family, pin['pin'])
                for conn in pin['connections']:
                    if conn.get('masked', False):
                        continue
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
                mask = pin.get('events_mask', 0)
                if events:
                    print(f"  {pin_name}: {', '.join(events)} (Mask: {mask})")
                    if "EXCEEDS_CONNECTION_LIMIT" in events:
                        print(f"  WARNING: Connection limit exceeded for this pin!")
                else:
                    print(f"  {pin_name}: No events (Mask: {mask})")
        print("="*23 + "\n")
    
    def run_pin_analysis(self, device_family=None, precalculated_strengths=None):
        """Run pin force analysis for all devices or a specific one."""
        devices_to_analyze = [device_family] if device_family is not None else sorted(self.devices.keys())
        for family in devices_to_analyze:
            if family not in self.devices:
                continue
            device_data = self.devices[family]
            
            if precalculated_strengths and family == device_family:
                strengths = precalculated_strengths
            else:
                strengths = []
                for pin_data in device_data['pins']:
                    pin_num = pin_data.get('pin', 'UNKNOWN')
                    pin_name = get_pin_name(family, pin_num)
                    # Use stored strength if available, otherwise calculate
                    strength = pin_data.get('strength')
                    if strength is None:
                        events = pin_data.get('events', [])
                        strength = analyze_pin(events)
                    strengths.append(strength)
            
            print(f"\n{'='*80}")
            print(f"Pin Force Analysis - Device {family}")
            print(f"{'='*80}")
            for pin_data, strength in zip(device_data['pins'], strengths):
                pin_num = pin_data.get('pin', 'UNKNOWN')
                pin_name = get_pin_name(family, pin_num)
                if strength is not None:
                    print(f"  {pin_name}: {strength}")
                else:
                    print(f"  {pin_name}: Undefined")
            print(f"{'='*80}\n")
    
    
    def _should_mask_connection(self, events, phase):
        # Use stored strength if available, otherwise calculate
        strength = None
        for pin in self.devices[self.current_device_family]['pins']:
            if pin['events'] == events:
                strength = pin.get('strength')
                break
        
        if strength is None:
            strength = analyze_pin(events)
            
        if strength is None or strength == 0:
            return False
        # Mask pins with strength >= 1 in phases 1 and 3
        if strength >= 1 and phase in (1, 3):
            return True
        # Mask pins with strength <= -1 in phases 0 and 2
        if strength <= -1 and phase in (0, 2):
            return True
        return False
    
    def create_connection_matrix(self, controller_a, controller_b):
        if controller_a not in self.devices or controller_b not in self.devices:
            print(f"Controller {controller_a} or {controller_b} not found")
            return None
        device_a = self.devices[controller_a]
        device_b = self.devices[controller_b]
        pins_a = [pin['pin'] for pin in device_a['pins']]
        pins_b = [pin['pin'] for pin in device_b['pins']]
        row_labels = [get_pin_name(controller_a, pin) for pin in pins_a]
        col_labels = [get_pin_name(controller_b, pin) for pin in pins_b]
        df = pd.DataFrame(0, index=row_labels, columns=col_labels)
        for pin in device_a['pins']:
            pin_name_a = get_pin_name(controller_a, pin['pin'])
            for conn in pin['connections']:
                conn_type = conn.get(KEY_CONNECTION_TYPE, 0)
                if conn_type == CONNECTION_TYPE_EXTERNAL:
                    device_id = conn.get(KEY_CONNECTION_PARAMETER, -1)
                    if device_id == controller_b:
                        pin_name_b = get_pin_name(controller_b, conn.get(KEY_OTHER_PIN))
                        if pin_name_b in col_labels:
                            df.at[pin_name_a, pin_name_b] = 1
        return df
    
    def print_connection_matrix(self, controller_a, controller_b, filename=None):
        df = self.create_connection_matrix(controller_a, controller_b)
        if df is None:
            return
        self._save_matrix(df, f"External Connection Matrix: Device {controller_a} -> Device {controller_b}", filename)
        
    def create_phase_matrix(self, controller, phase):
        if controller not in self.devices:
            print(f"Controller {controller} not found")
            return None
        if not 0 <= phase <= 5:
            print(f"Invalid phase {phase}. Must be between 0 and 5")
            return None
        device = self.devices[controller]
        pins = [pin['pin'] for pin in device['pins']]
        labels = [get_pin_name(controller, pin) for pin in pins]
        df = pd.DataFrame(0, index=labels, columns=labels)
        phase_error_events = {
            0: "PIN_IS_NOT_LOW_WHEN_ONE_SET_PULLDOWN",
            1: "PIN_IS_NOT_HIGH_WHEN_ONE_SET_PULLUP",
            2: "PIN_IS_NOT_LOW_WHEN_DRIVEN_LOW",
            3: "PIN_IS_NOT_HIGH_WHEN_DRIVEN_HIGH",
            4: "PIN_IS_NOT_LOW_WHEN_ALLPULLUP_LOW",
            5: "PIN_IS_NOT_HIGH_WHEN_ALLPULLDOWN_HIGH"
        }
        for pin in device['pins']:
            pin_name_a = get_pin_name(controller, pin['pin'])
            error_event = phase_error_events.get(phase)
            pin_works = error_event and error_event not in pin['events']
            
            # Diagonal elements (self-check) are never masked
            if pin_works:
                df.at[pin_name_a, pin_name_a] = 1

            for conn in pin['connections']:
                conn_type = conn.get(KEY_CONNECTION_TYPE, 0)
                if conn_type == CONNECTION_TYPE_INTERNAL:
                    conn_phase = conn.get(KEY_CONNECTION_PARAMETER, -1)
                    pin_name_b = get_pin_name(controller, conn.get(KEY_OTHER_PIN))
                                        
                    if conn_phase == phase and pin_name_b in labels:
                        if pin_works:
                            is_masked = conn.get('masked', False)
                            is_phase_masked = conn.get('phase_masked', False)
                            
                            if is_phase_masked:
                                # Phase masked connections show as 3
                                df.at[pin_name_a, pin_name_b] = 3
                            elif is_masked:
                                # Pin strength masked connections show as 2
                                df.at[pin_name_a, pin_name_b] = 2
                            else:
                                df.at[pin_name_a, pin_name_b] = 1
        return df

    def print_phase_matrix(self, controller, phase, filename=None):
        df = self.create_phase_matrix(controller, phase)
        if df is None:
            return
        phase_names = PHASE_NAMES
        self._save_matrix(df, f"Phase {phase}: {phase_names.get(phase, f'PHASE_{phase}')} (Device {controller})", filename)

    def print_all_phase_matrices(self, controller):
        for phase in range(6):
            self.print_phase_matrix(controller, phase)

    def save_raw_xml(self):
        """Save all collected data to an XML file with metadata (per device CBOR base64)"""
        import xml.etree.ElementTree as ET
        import socket
        import os
        os.makedirs("raw_data", exist_ok=True)
        root = ET.Element("ShepperdTest")
        meta = ET.SubElement(root, "Metadata")
        ET.SubElement(meta, "Timestamp").text = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        ET.SubElement(meta, "Computer").text = socket.gethostname()
        try:
            ET.SubElement(meta, "User").text = os.getlogin()
        except:
            ET.SubElement(meta, "User").text = "unknown"
        devices_elem = ET.SubElement(root, "Devices")
        for family, device_data in self.devices.items():
            dev_elem = ET.SubElement(devices_elem, "Device")
            dev_elem.set("Family", str(family))
            dev_elem.set("UUID", str(device_data.get('uuid', 'UNKNOWN')))
            dev_elem.set("GitCommit", str(device_data.get('git_commit', 'UNKNOWN')))

            # Global packet ID counter for this device
            packet_id = 0

            # Header
            if 'raw_header' in device_data and device_data['raw_header']:
                header_elem = ET.SubElement(dev_elem, "RawData")
                header_elem.set("Type", "Header")
                header_elem.set("Session", "0")
                header_elem.set("Id", str(packet_id))
                header_elem.set("Encoding", "base64")
                header_elem.text = base64.b64encode(device_data['raw_header']).decode('utf-8')
                packet_id += 1
            
            # Chunks
            if 'raw_session_chunks' in device_data:
                for session_id in sorted(device_data['raw_session_chunks'].keys()):
                    chunks = device_data['raw_session_chunks'][session_id]
                    for chunk_id in sorted(chunks.keys()):
                        chunk_elem = ET.SubElement(dev_elem, "RawData")
                        chunk_elem.set("Type", "Chunk")
                        chunk_elem.set("Session", str(session_id))
                        chunk_elem.set("Id", str(packet_id))
                        chunk_elem.set("ChunkId", str(chunk_id))
                        chunk_elem.set("Encoding", "base64")
                        chunk_elem.text = base64.b64encode(chunks[chunk_id]).decode('utf-8')
                        packet_id += 1

        timestamp = datetime.now().strftime("%Y_%m_%d_%H_%M_%S")
        filename = f"raw_data/raw_data_{timestamp}.xml"
        if hasattr(ET, 'indent'):
            ET.indent(root, space="  ", level=0)
        tree = ET.ElementTree(root)
        tree.write(filename, encoding="utf-8", xml_declaration=True)
        print(f"Raw XML saved to: {filename}")

    def visualize_matrices(self):
        """Visualize all matrices as heatmaps and save to PNG"""
        try:
            import seaborn as sns
            import matplotlib.pyplot as plt
            import matplotlib.ticker as ticker
            import matplotlib.patches as mpatches
        except ImportError:
            print("Visualization requires seaborn and matplotlib. Please install them: pip install seaborn matplotlib")
            return

        import os
        timestamp = datetime.now().strftime("%Y_%m_%d_%H_%M_%S")
        base_dir = f"visualization/viz_{timestamp}"
        os.makedirs(base_dir, exist_ok=True)
        print(f"Generating visualizations in: {base_dir}")

        # Apply phase masking before visualization
        for device_family in sorted(self.devices.keys()):
            self._apply_phase_masking(device_family)

        for device_family in sorted(self.devices.keys()):
            # External connection matrices
            for other_device in sorted(self.devices.keys()):
                if device_family != other_device:
                    df = self.create_connection_matrix(device_family, other_device)
                    if df is not None and not df.empty:
                        filename = f"{base_dir}/matrix_external_{device_family}_to_{other_device}.pdf"
                        self._save_heatmap(df, filename, "Blues", "Pin", "Pin")

            # Phase matrices
            for phase in range(6):
                df = self.create_phase_matrix(device_family, phase)
                if df is not None and not df.empty:
                    # Custom colormap: 0=White, 1=Green, 2=Red (pin masked), 3=Dark Red (phase masked)
                    from matplotlib.colors import ListedColormap
                    cmap = ListedColormap(['white', '#2ca02c', '#ff7f7f', '#d62728'])
                    
                    legend_handles = [
                        mpatches.Patch(facecolor='white', label='0: Unchanged', edgecolor='lightgray'),
                        mpatches.Patch(color='#2ca02c', label='1: Changed'),
                        mpatches.Patch(color='#ff7f7f', label='2: Pin Strength Masked'),
                        mpatches.Patch(color='#d62728', label='3: Phase Masked')
                    ]
                    
                    filename = f"{base_dir}/matrix_phase_{phase}_{device_family}.pdf"
                    self._save_heatmap(df, filename, cmap, "Measured Pin", "Changed Pin", 
                                     vmin=0, vmax=3, legend_handles=legend_handles)

            # Pin Strength Bar Chart
            pin_names = []
            pin_strengths = []
            device_data = self.devices[device_family]
            
            # Get all pins sorted
            sorted_pins = get_all_pins_sorted(device_family, device_data)
            
            for pin_num in sorted_pins:
                pin_name = get_pin_name(device_family, pin_num)
                # Find pin data
                pin_entry = next((p for p in device_data['pins'] if p['pin'] == pin_num), None)
                if pin_entry:
                    # Use stored strength if available, otherwise calculate
                    strength = pin_entry.get('strength')
                    if strength is None:
                        events = pin_entry.get('events', [])
                        strength = analyze_pin(events)
                    pin_names.append(pin_name)
                    pin_strengths.append(strength)
            
            if pin_names:
                plt.figure(figsize=(15, 8))
                
                # Plot bars manually
                x_pos = range(len(pin_names))
                for i, strength in enumerate(pin_strengths):
                    if strength is None:
                        # Undefined: Blue bar from -6 to 6
                        plt.bar(i, 12, bottom=-6, color='blue', alpha=0.3, width=0.8)
                    else:
                        # Defined: Red/Green bar from 0 to strength
                        color = 'red' if strength < 0 else 'green'
                        plt.bar(i, strength, color=color, width=0.8)
                
                plt.axhline(0, color='black', linewidth=0.8)
                plt.grid(axis='y', linestyle='--', alpha=0.7)
                plt.gca().yaxis.set_major_locator(ticker.MultipleLocator(1))
                plt.ylim(-6, 6)
                plt.xticks(x_pos, pin_names, rotation=90)
                plt.ylabel("Strength")
                plt.xlabel("Pin")
                # plt.title(f"Pin Strengths - Device {device_family}")

                # Legend for Strength
                legend_handles = [
                    mpatches.Patch(color='green', label='Positive Force'),
                    mpatches.Patch(color='red', label='Negative Force'),
                    mpatches.Patch(color='blue', alpha=0.3, label='Undefined')
                ]
                plt.legend(handles=legend_handles, loc='upper right')

                plt.tight_layout()
                filename = f"{base_dir}/strength_chart_{device_family}.pdf"
                plt.savefig(filename, format='pdf', bbox_inches='tight')
                plt.close()
                print(f"  Saved: {filename}")

            # Event Matrix
            df_events = self.create_event_matrix(device_family)
            if df_events is not None and not df_events.empty:
                width = max(12, len(df_events.columns) * 0.4)
                height = max(10, len(df_events.index) * 0.4)
                
                annot_df = df_events.map(lambda x: 'X' if x == 1 else '')
                
                from matplotlib.colors import ListedColormap
                cmap_events = ListedColormap(['white', '#ff7f0e'])
                
                legend_handles = [
                    mpatches.Patch(facecolor='white', label='Not Occurred', edgecolor='lightgray'),
                    mpatches.Patch(color='#ff7f0e', label='Occurred')
                ]
                
                filename = f"{base_dir}/matrix_events_{device_family}.pdf"
                self._save_heatmap(df_events, filename, cmap_events, "Event", "Pin", 
                                 annot=annot_df, fmt='', vmin=0, vmax=1, 
                                 legend_handles=legend_handles, figsize=(width, height))
        
        # Create connection vector plots
        from connection_analyzer import create_vector_plots
        create_vector_plots(self, base_dir)
        
        print(f"Visualization complete")

    def create_event_matrix(self, device_family):
        """Create a matrix of Pins vs Events"""
        if device_family not in self.devices:
            return None
        
        device_data = self.devices[device_family]
        sorted_pins = get_all_pins_sorted(device_family, device_data)
        
        # Get all possible events
        all_events = sorted(list(set(list(PIN_EVENT_TYPES.values()))))
        
        # Create DataFrame
        pin_labels = [get_pin_name(device_family, p) for p in sorted_pins]
        df = pd.DataFrame(0, index=pin_labels, columns=all_events)
        
        # Fill DataFrame
        for pin_num in sorted_pins:
            pin_name = get_pin_name(device_family, pin_num)
            pin_entry = next((p for p in device_data['pins'] if p['pin'] == pin_num), None)
            
            if pin_entry:
                events = pin_entry.get('events', [])
                for event in events:
                    if event in df.columns:
                        df.at[pin_name, event] = 1
        
        
        return df

    def load_from_xml(self, filename):
        """Load data from an XML file generated by save_raw_xml"""
        import xml.etree.ElementTree as ET
        import base64
        import cbor2
        
        try:
            tree = ET.parse(filename)
            root = tree.getroot()
        except Exception as e:
            print(f"Failed to parse XML file: {e}")
            return False

        print(f"Loading data from {filename}...")
        
        # Reset current state
        self.devices = {}
        self.current_device_family = None
        
        devices_elem = root.find("Devices")
        if devices_elem is None:
            print("No Devices found in XML")
            return False
            
        for device_elem in devices_elem.findall("Device"):
            family = device_elem.get("Family")
            uuid = device_elem.get("UUID")
            print(f"Found Device Family: {family}, UUID: {uuid}")
            
            # Process Header first
            header_elem = device_elem.find("RawData[@Type='Header']")
            if header_elem is not None:
                raw_bytes = base64.b64decode(header_elem.text)
                try:
                    data = cbor2.loads(raw_bytes)
                    header_result = {
                        'hash_valid': True,
                        'data': data,
                        'raw_bytes': raw_bytes
                    }
                    self.process_header(header_result)
                except Exception as e:
                    print(f"    Failed to decode header: {e}")
                    continue
            
            # Process Chunks
            for chunk_elem in device_elem.findall("RawData[@Type='Chunk']"):
                raw_bytes = base64.b64decode(chunk_elem.text)
                try:
                    data = cbor2.loads(raw_bytes)
                    chunk_result = {
                        'hash_valid': True,
                        'data': data,
                        'raw_bytes': raw_bytes,
                        'packet_id': int(chunk_elem.get("ChunkId", -1))
                    }
                    self.process_chunk(chunk_result)
                except Exception as e:
                    print(f"    Failed to decode chunk: {e}")
        
        print("Data loaded successfully")
        return True

