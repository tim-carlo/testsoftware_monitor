#!/usr/bin/env python3
"""
Connection Analyzer - Analyzes pin connections and creates coordinate system vectors
"""

from data_storage import CONNECTION_TYPE_INTERNAL, KEY_CONNECTION_TYPE, KEY_CONNECTION_PARAMETER, KEY_OTHER_PIN, get_pin_name
import seaborn as sns
import matplotlib.pyplot as plt
from datetime import datetime

# Phase vector mappings (1D - only x-component)
PHASE_VECTORS = {
    0: {"A_to_B": -1,  "B_to_A": 1},
    1: {"A_to_B": 1,   "B_to_A": -1},
    2: {"A_to_B": -2,  "B_to_A": 2},
    3: {"A_to_B": 2,   "B_to_A": -2},
    4: {"A_to_B": -3,  "B_to_A": 3},
    5: {"A_to_B": 3,   "B_to_A": -3}
}

def should_keep_phase(phase, existing_phases):
    """Apply phase filtering rules based on existing phases"""
    # If phase 4 does not exist, remove phases 2 and 0
    if 4 not in existing_phases:
        if phase in (2, 0):
            return False
    
    # If phase 5 does not exist, remove phases 3 and 1
    if 5 not in existing_phases:
        if phase in (3, 1):
            return False
    
    # If phase 2 does not exist, remove phase 0
    if 2 not in existing_phases:
        if phase == 0:
            return False
    
    # If phase 3 does not exist, remove phase 1
    if 3 not in existing_phases:
        if phase == 1:
            return False
    
    return True

def analyze_connections(collector):
    """Analyze all connections and create coordinate vectors for pin pairs"""
    results = {}
    
    for device_family, device_data in collector.get_all_devices().items():
        summary_data = []
        
        # Track connections by pin pairs
        pair_connections = {}
        
        # Process all pins
        for pin in device_data['pins']:
            source_pin = pin['pin']
            
            # Process all connections of this pin
            for conn in pin['connections']:
                conn_type = conn.get(KEY_CONNECTION_TYPE, 0)
                
                # Skip masked connections
                if conn.get('masked', False):
                    continue
                
                # Only process internal connections
                if conn_type == CONNECTION_TYPE_INTERNAL:
                    target_pin = conn.get(KEY_OTHER_PIN)
                    phase = conn.get(KEY_CONNECTION_PARAMETER, -1)
                    
                    # Skip if phase is invalid
                    if phase not in PHASE_VECTORS:
                        continue
                    
                    # Determine Pin A (smaller number) and Pin B (larger number)
                    pin_a = min(source_pin, target_pin)
                    pin_b = max(source_pin, target_pin)
                    pair_key = f"{pin_a}-{pin_b}"
                    
                    if pair_key not in pair_connections:
                        pair_connections[pair_key] = {
                            'pin_a': pin_a,
                            'pin_b': pin_b,
                            'a_to_b_vectors': [],
                            'b_to_a_vectors': [],
                            'phases': set()
                        }
                    
                    # Track which phases exist for this pin pair
                    pair_connections[pair_key]['phases'].add(phase)
                    
                    # Determine direction and add vector
                    direction = "A_to_B" if source_pin == pin_a else "B_to_A"
                    vector = PHASE_VECTORS[phase][direction]
                    pair_connections[pair_key][f"{direction.lower()}_vectors"].append((vector, phase))
        
        # Store all individual phase vectors with filtering
        for pair_key, data in pair_connections.items():
            pin_a_name = get_pin_name(device_family, data['pin_a'])
            pin_b_name = get_pin_name(device_family, data['pin_b'])
            
            # Apply phase filtering rules and collect individual vectors
            phases = data['phases']
            individual_vectors = []
            
            # Process A_to_B vectors
            for vector, phase in data['a_to_b_vectors']:
                if should_keep_phase(phase, phases):
                    individual_vectors.append({
                        'value': vector,
                        'phase': phase,
                        'direction': 'A_to_B',
                        'label': f'Phase {phase} ({data["pin_a"]}→{data["pin_b"]})'
                    })
            
            # Process B_to_A vectors
            for vector, phase in data['b_to_a_vectors']:
                if should_keep_phase(phase, phases):
                    individual_vectors.append({
                        'value': vector,
                        'phase': phase,
                        'direction': 'B_to_A',
                        'label': f'Phase {phase} ({data["pin_b"]}→{data["pin_a"]})'
                    })
            
            # Sort vectors by phase for consistent display
            individual_vectors.sort(key=lambda x: x['phase'])
            
            # Only add to summary if there are vectors after filtering
            if individual_vectors:
                summary_data.append({
                    'pin_a': data['pin_a'],
                    'pin_b': data['pin_b'],
                    'pin_a_name': pin_a_name,
                    'pin_b_name': pin_b_name,
                    'individual_vectors': individual_vectors,
                    'total_count': len(individual_vectors)
                })
        
        results[device_family] = summary_data
    
    return results



def create_vector_plots(collector, base_dir):
    """Create connection vector plots in the given directory"""
    results = analyze_connections(collector)
    timestamp = datetime.now().strftime("%Y_%m_%d_%H_%M_%S")
    
    # Set seaborn style for better looking plots
    sns.set_style("whitegrid")
    sns.set_palette("husl")
    
    for device_family, summary_data in results.items():
        if not summary_data:
            continue
            
        # Calculate subplot grid dimensions
        n_pairs = len(summary_data)
        cols = min(4, n_pairs)  # Max 4 columns
        rows = (n_pairs + cols - 1) // cols  # Ceiling division
        
        # Create figure with subplots for each pin pair
        fig, axes = plt.subplots(rows, cols, figsize=(5*cols, 5*rows))
        
        # Handle case where there's only one subplot
        if n_pairs == 1:
            axes = [axes]
        elif rows == 1:
            axes = [axes] if n_pairs == 1 else list(axes)
        else:
            axes = axes.flatten()
        
        for i, data in enumerate(summary_data):
            ax = axes[i]
            pin_pair_label = f"{data['pin_a_name']} ↔ {data['pin_b_name']}"
            
            # Set up coordinate system with seaborn styling
            ax.set_title(pin_pair_label, fontsize=12, fontweight='bold', 
                        color='black')
            sns.despine(ax=ax, left=False, bottom=False)
            ax.axhline(y=0, color='black', linewidth=0.8, alpha=0.7)
            ax.axvline(x=0, color='black', linewidth=0.8, alpha=0.7)
            ax.set_aspect('equal', adjustable='box')
            
            # Use seaborn colors for vectors
            colors = sns.color_palette("Set1", 2)
            
            # Plot individual phase vectors and show largest absolute value
            if data['individual_vectors']:
                # Sort vectors by absolute value for plotting order (largest first = bottom layer)
                plot_order_vectors = sorted(data['individual_vectors'], 
                                          key=lambda x: abs(x['value']), reverse=True)
                
                # Sort vectors by phase number for consistent labeling
                phase_sorted_vectors = sorted(data['individual_vectors'], key=lambda x: x['phase'])
                
                # Find the vector with the largest absolute value for text display
                largest_vector = max(data['individual_vectors'], 
                                   key=lambda x: abs(x['value']))
                
                # Use different colors for each phase (change phase 5 to be more readable)
                phase_colors = sns.color_palette("Set1", 6)
                phase_colors[5] = (0.2, 0.2, 0.8)  # Change phase 5 from yellow to blue
                
                # Group vectors by phases: (0,2,4) and (1,3,5)
                group1_phases = {0, 2, 4}  # Bottom group
                group2_phases = {1, 3, 5}  # Top group
                
                y_pos_group1 = 1.0  # Bottom y-position for phases 0, 2, 4
                y_pos_group2 = 2.2  # Top y-position for phases 1, 3, 5 (with spacing)
                
                # Find largest negative and positive vectors for each group
                group1_vectors = [v for v in data['individual_vectors'] if v['phase'] in group1_phases]
                group2_vectors = [v for v in data['individual_vectors'] if v['phase'] in group2_phases]
                
                # Find largest vectors in each group for labeling
                group1_negative = max([v for v in group1_vectors if v['value'] < 0], 
                                    key=lambda x: abs(x['value'])) if [v for v in group1_vectors if v['value'] < 0] else None
                group1_positive = max([v for v in group1_vectors if v['value'] > 0], 
                                    key=lambda x: abs(x['value'])) if [v for v in group1_vectors if v['value'] > 0] else None
                group2_negative = max([v for v in group2_vectors if v['value'] < 0], 
                                    key=lambda x: abs(x['value'])) if [v for v in group2_vectors if v['value'] < 0] else None
                group2_positive = max([v for v in group2_vectors if v['value'] > 0], 
                                    key=lambda x: abs(x['value'])) if [v for v in group2_vectors if v['value'] > 0] else None
                
                # Plot in sorted order: largest first (bottom), smallest last (top)
                for i, vector_info in enumerate(plot_order_vectors):
                    vector_value = vector_info['value']
                    phase = vector_info['phase']
                    label = vector_info['label']
                    
                    # Determine y-position based on phase group
                    if phase in group1_phases:
                        y_pos = y_pos_group1
                    else:  # phase in group2_phases
                        y_pos = y_pos_group2
                    
                    # Plot arrow with full opacity
                    ax.arrow(0, y_pos, vector_value, 0, 
                             head_width=0.1, head_length=0.12, 
                             fc=phase_colors[phase % len(phase_colors)], 
                             ec=phase_colors[phase % len(phase_colors)], 
                             linewidth=2.5, alpha=1.0, label=label)
                    
                    # Show values for largest negative and positive vectors in each group
                    if vector_info == group1_negative or vector_info == group2_negative:
                        ax.text(vector_value - 0.8, y_pos, 
                                f"{vector_value}", 
                                fontsize=12, color='black', 
                                ha='center', va='center', fontweight='bold')
                    elif vector_info == group1_positive or vector_info == group2_positive:
                        ax.text(vector_value + 0.8, y_pos, 
                                f"{vector_value}", 
                                fontsize=12, color='black', 
                                ha='center', va='center', fontweight='bold')
            
            # Calculate limits for same-line vectors plot
            if data['individual_vectors']:
                vector_values = [v['value'] for v in data['individual_vectors']]
                max_x_coord = max(abs(x) for x in vector_values)
                x_limit = max(max_x_coord * 1.5, 2)  # Space for text labels
                ax.set_xlim(-x_limit, x_limit)
                
                # Fixed y-axis for grouped display with spacing
                ax.set_ylim(0.5, 2.7)
            else:
                ax.set_xlim(-2, 2)
                ax.set_ylim(0.5, 2.7)
            
            ax.set_xlabel('Flow Direction', fontsize=11, fontweight='medium')
            ax.set_ylabel('', fontsize=11, fontweight='medium')  # Remove y-label for 1D
            ax.tick_params(labelsize=9)
            
            # Add pin numbers on x-axis
            xlim = ax.get_xlim()
            ax.text(xlim[0], -0.3, f'Pin: {data["pin_a"]}', fontsize=10, fontweight='bold', 
                   ha='left', va='center', transform=ax.transData)
            ax.text(xlim[1], -0.3, f'Pin: {data["pin_b"]}', fontsize=10, fontweight='bold', 
                   ha='right', va='center', transform=ax.transData)
            
            if data['individual_vectors']:
                # Create legend with phase-sorted order
                legend_handles = []
                legend_labels = []
                for vector_info in phase_sorted_vectors:
                    phase = vector_info['phase']
                    label = vector_info['label']
                    color = phase_colors[phase % len(phase_colors)]
                    handle = plt.Line2D([0], [0], color=color, linewidth=3, label=label)
                    legend_handles.append(handle)
                    legend_labels.append(label)
                
                legend = ax.legend(legend_handles, legend_labels, fontsize=9, 
                                 bbox_to_anchor=(1.05, 1), loc='upper left', 
                                 frameon=True, fancybox=True, shadow=False)
                legend.get_frame().set_alpha(0.9)
        
        # Hide unused subplots
        for i in range(n_pairs, len(axes)):
            axes[i].set_visible(False)
        
        # Apply seaborn styling to the overall figure
        plt.tight_layout(pad=2.0)
        filename = f"{base_dir}/connection_vectors_{device_family}.pdf"
        plt.savefig(filename, format='pdf', bbox_inches='tight', dpi=300, 
                   facecolor='white', edgecolor='none')
        plt.close()
        print(f"  Saved: {filename}")
        
    sns.reset_defaults()

def print_vectors(collector):
    """Print simple vector summary"""
    results = analyze_connections(collector)
    
    for device_family, summary_data in results.items():
        print(f"\n=== Connection Vectors - Device {device_family} ===")
        
        if not summary_data:
            print("No internal connections found.")
            continue
        
        for data in summary_data:
            print(f"Pin Pair: {data['pin_a_name']} <-> {data['pin_b_name']}")
            for vector_info in data['individual_vectors']:
                print(f"  {vector_info['label']}: {vector_info['value']}")