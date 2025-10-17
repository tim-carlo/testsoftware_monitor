# Pin Event Type definitions
PIN_EVENT_TYPES = {
    0: "PIN_INITIALLY_LOW",
    1: "PIN_INITIALLY_HIGH", 
    2: "PIN_DISTURBED",
    3: "HANDSHAKE_OK_INITIATOR",
    4: "HANDSHAKE_OK_RESPONDER",
    5: "HANDSHAKE_FAILURE",
    6: "DATA_HANDSHAKE_OK",
    7: "DATA_HANDSHAKE_FAILURE",
    8: "PIN_IS_CONNECTED_WITH_INTERNAL_PIN",
    9: "PIN_IS_CONNECTED_WITH_EXTERNAL_PIN",
    10: "PIN_IS_NOT_LOW_WHEN_PULLED_DOWN",
    11: "PIN_IS_NOT_HIGH_WHEN_PULLED_UP",
    12: "PIN_IS_NOT_LOW_WHEN_DRIVEN_LOW",
    13: "PIN_IS_NOT_HIGH_WHEN_DRIVEN_HIGH"
}

def decode_pin_event_type(event_code):
    """Decode pin event type code to string."""
    return PIN_EVENT_TYPES.get(event_code, f"UNKNOWN_EVENT_{event_code}")

def decode_pin_events(event_list):
    """Decode a list of pin event codes to strings."""
    return [decode_pin_event_type(event) for event in event_list]