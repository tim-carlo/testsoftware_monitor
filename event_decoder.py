#!/usr/bin/env python3
"""Event Decoder for CBOR Serial Monitor
"""

# Pin Event Type definitions (indexes must match device enum)
PIN_EVENT_TYPES = {
    0: "HANDSHAKE_OK_INITIATOR",
    1: "HANDSHAKE_OK_RESPONDER",
    2: "HANDSHAKE_FAILURE",
    3: "DATA_HANDSHAKE_OK",
    4: "DATA_HANDSHAKE_FAILURE",
    5: "PIN_IS_CONNECTED_WITH_INTERNAL_PIN",
    6: "PIN_IS_NOT_LOW_WHEN_PULLED_DOWN",
    7: "PIN_IS_NOT_HIGH_WHEN_PULLED_UP",
    8: "PIN_IS_NOT_LOW_WHEN_DRIVEN_LOW",
    9: "PIN_IS_NOT_HIGH_WHEN_DRIVEN_HIGH",
    10: "UART_RX_IS_NOT_WORKING",
    11: "EXPECTS_TO_WORK_IN_ONE_DIRECTION",
    12: "EXCEEDS_CONNECTION_LIMIT",
    13: "STEP_1_A_HIGH",
    14: "STEP_1_A_LOW",
    15: "STEP_1_B_HIGH",
    16: "STEP_1_B_LOW",
    17: "STEP_2_A_HIGH",
    18: "STEP_2_A_LOW",
    19: "STEP_2_B_HIGH",
    20: "STEP_2_B_LOW",
    21: "STEP_3_A_HIGH",
    22: "STEP_3_A_LOW",
    23: "STEP_3_B_HIGH",
    24: "STEP_3_B_LOW",
    25: "PIN_IS_NATUTALLY_DISTURBED",
}


def decode_event_type_one_hot(event_bits):
    """Return list of event names for bits set in event_bits.
    """
    events = []
    for bit_position in range(32):
        if event_bits & (1 << bit_position):
            event_name = PIN_EVENT_TYPES.get(bit_position, f"UNKNOWN_EVENT_{bit_position}")
            events.append(event_name)
    return events

def encode_event_list(events):
    """Encode a list of event names back into one-hot encoded integer."""
    event_bits = 0
    reverse_event_map = {v: k for k, v in PIN_EVENT_TYPES.items()}
    
    for event in events:
        bit_position = reverse_event_map.get(event)
        if bit_position is not None:
            event_bits |= (1 << bit_position)
    
    return event_bits

def decode_result(result):
    if not result or not result.get('hash_valid'):
        print("Invalid or corrupted result")
        return []
    
    data = result.get('data', {})
    
    # Look for event_type field (adjust key name as needed)
    event_bits = data.get('event_type', 0)
    
    if event_bits == 0:
        return []
    
    # Decode one-hot encoded events
    events = decode_event_type_one_hot(event_bits)
    
    # Return raw events without merging handshakes
    return events


def format_event_list(events):
    """Format event list for pretty printing."""
    if not events:
        return "No events"
    
    return ", ".join(events)