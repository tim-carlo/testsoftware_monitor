#!/usr/bin/env python3
"""
Pin Analyzer
"""

def analyze_pin(events):
    ev = set(events)
    # Order: Stage 1 N/P, Stage 2 N/P, Stage 3 N/P
    checks = [
        "STEP_1_A", "STEP_1_B", "STEP_2_A", "STEP_2_B", "STEP_3_A", "STEP_3_B"
    ]

    # Helper to get value for each stage: 1=HIGH, 0=LOW, 'U'=Undefined
    def get_val(stage, ev):
        if f"{stage}_HIGH" in ev:
            return 1
        if f"{stage}_LOW" in ev:
            return 0
        return 'U'

    patterns = {
        6:  (1, 1, 1, 1, 1, 1),
        5:  (1, 1, 1, 1, 'U', 1),
        4:  (1, 1, 1, 1, 0, 1),
        3:  (1, 1, 'U', 1, 0, 1),
        2:  (1, 1, 0, 1, 0, 1),
        1:  ('U', 1, 0, 1, 0, 1),
        0:  (0, 1, 0, 1, 0, 1),
        -1: (0, 'U', 0, 1, 0, 1),
        -2: (0, 0, 0, 1, 0, 1),
        -3: (0, 0, 'U', 1, 0, 1),
        -4: (0, 0, 0, 0, 0, 1),
        -5: (0, 0, 0, 0, 'U', 1),
        -6: (0, 0, 0, 0, 0, 0),
    }

    # Build actual values for this pin
    actual = tuple(get_val(stage, ev) for stage in checks)

    for strength, pattern in patterns.items():
        if actual == pattern:
            return strength
    return None

def analyze_all_pins(device_pins):
    return [analyze_pin(p.get('events', [])) for p in device_pins]

