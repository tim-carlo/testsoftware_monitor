#!/usr/bin/env python3
"""
Connection Analyzer - Analyzes pin connections and creates coordinate system vectors
"""

from data_storage import CONNECTION_TYPE_INTERNAL, KEY_CONNECTION_TYPE, KEY_CONNECTION_PARAMETER, KEY_OTHER_PIN, get_pin_name
import seaborn as sns
import matplotlib.pyplot as plt
from datetime import datetime


PHASE_VECTORS = {
    0: {"A_to_B": (-1, 1),   "B_to_A": (1, 1)},      
    1: {"A_to_B": (-1, -1),  "B_to_A": (1, -1)},     
    2: {"A_to_B": (-2, 2),   "B_to_A": (2, 2)},      
    3: {"A_to_B": (-2, -2),  "B_to_A": (2, -2)},     
    4: {"A_to_B": (-3, 3),   "B_to_A": (3, 3)},      
    5: {"A_to_B": (-3, -3),  "B_to_A": (3, -3)}      
}

# Phase masking is now handled in data_storage.py before vector analysis

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
                
                # Skip phase-masked connections  
                if conn.get('phase_masked', False):
                    continue
                # Get phase for this connection
                original_phase = conn.get(KEY_CONNECTION_PARAMETER, -1)
                
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
                    
                    # Determine direction and add vector (2D)
                    direction = "A_to_B" if source_pin == pin_a else "B_to_A"
                    vector_2d = PHASE_VECTORS[phase][direction]  # This is now a (x, y) tuple
                    pair_connections[pair_key][f"{direction.lower()}_vectors"].append((vector_2d, phase))
        
        # Store all individual phase vectors with filtering
        for pair_key, data in pair_connections.items():
            pin_a_name = get_pin_name(device_family, data['pin_a'])
            pin_b_name = get_pin_name(device_family, data['pin_b'])
            
            # Calculate grouped vectors (phase masking already applied at connection level)
            phases = data['phases']
            grouped_vectors = []
            
            # Group 1: Phases 0, 2, 4
            group1_phases = [0, 2, 4]
            # Group 2: Phases 1, 3, 5
            group2_phases = [1, 3, 5]
            
            # Use all vectors (phase masking already filtered out masked connections)
            a_to_b_vectors = data['a_to_b_vectors']
            b_to_a_vectors = data['b_to_a_vectors']
            
            
            # Calculate A_to_B Group 1 (phases 0+2+4) - 2D vector sum
            a_to_b_group1_vectors = [
                vector for vector, phase in a_to_b_vectors
                if phase in group1_phases
            ]
            if a_to_b_group1_vectors:
                sum_x = sum(v[0] for v in a_to_b_group1_vectors)
                sum_y = sum(v[1] for v in a_to_b_group1_vectors)
                if sum_x != 0 or sum_y != 0:
                    grouped_vectors.append({
                        'value': (sum_x, sum_y),
                        'group': 1,
                        'direction': 'A_to_B',
                        'label': f'Ph 0,2,4 - P{data["pin_a"]}→P{data["pin_b"]}'
                    })
            
            # Calculate A_to_B Group 2 (phases 1+3+5) - 2D vector sum
            a_to_b_group2_vectors = [
                vector for vector, phase in a_to_b_vectors
                if phase in group2_phases
            ]
            if a_to_b_group2_vectors:
                sum_x = sum(v[0] for v in a_to_b_group2_vectors)
                sum_y = sum(v[1] for v in a_to_b_group2_vectors)
                if sum_x != 0 or sum_y != 0:
                    grouped_vectors.append({
                        'value': (sum_x, sum_y),
                        'group': 2,
                        'direction': 'A_to_B',
                        'label': f'Ph 1,3,5 - P{data["pin_a"]}→P{data["pin_b"]}'
                    })
            
            # Calculate B_to_A Group 1 (phases 0+2+4) - 2D vector sum
            b_to_a_group1_vectors = [
                vector for vector, phase in b_to_a_vectors
                if phase in group1_phases
            ]
            if b_to_a_group1_vectors:
                sum_x = sum(v[0] for v in b_to_a_group1_vectors)
                sum_y = sum(v[1] for v in b_to_a_group1_vectors)
                if sum_x != 0 or sum_y != 0:
                    grouped_vectors.append({
                        'value': (sum_x, sum_y),
                        'group': 1,
                        'direction': 'B_to_A',
                        'label': f'Ph 0,2,4 - P{data["pin_b"]}→P{data["pin_a"]}'
                    })
            
            # Calculate B_to_A Group 2 (phases 1+3+5) - 2D vector sum
            b_to_a_group2_vectors = [
                vector for vector, phase in b_to_a_vectors
                if phase in group2_phases
            ]
            if b_to_a_group2_vectors:
                sum_x = sum(v[0] for v in b_to_a_group2_vectors)
                sum_y = sum(v[1] for v in b_to_a_group2_vectors)
                if sum_x != 0 or sum_y != 0:
                    grouped_vectors.append({
                        'value': (sum_x, sum_y),
                        'group': 2,
                        'direction': 'B_to_A',
                        'label': f'Ph 1,3,5 - P{data["pin_b"]}→P{data["pin_a"]}'
                    })
            
            # Only add to summary if there are vectors after filtering
            if grouped_vectors:
                # Get phases for each direction (phase masking already applied)
                a_to_b_phases = [phase for _, phase in a_to_b_vectors]
                b_to_a_phases = [phase for _, phase in b_to_a_vectors]
                
                # Only add if we have phases after masking
                if a_to_b_phases or b_to_a_phases:
                    summary_data.append({
                        'pin_a': data['pin_a'],
                        'pin_b': data['pin_b'],
                        'pin_a_name': pin_a_name,
                        'pin_b_name': pin_b_name,
                        'grouped_vectors': grouped_vectors,
                        'a_to_b_phases': sorted(set(a_to_b_phases)),
                        'b_to_a_phases': sorted(set(b_to_a_phases)),
                        'total_count': len(grouped_vectors)
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
            ax.set_title(pin_pair_label, fontsize=12, fontweight='medium', 
                        color='black')
            sns.despine(ax=ax, left=False, bottom=False)
            ax.axhline(y=0, color='black', linewidth=0.8, alpha=0.7)
            ax.axvline(x=0, color='black', linewidth=0.8, alpha=0.7)
            ax.set_aspect('equal', adjustable='box')
            
            # Use seaborn colors for vectors
            colors = sns.color_palette("Set1", 2)
            
            # Plot grouped vectors
            if data['grouped_vectors']:
                # Sort vectors by magnitude for plotting order (largest first = bottom layer)
                plot_order_vectors = sorted(data['grouped_vectors'], 
                                          key=lambda x: (x['value'][0]**2 + x['value'][1]**2)**0.5, reverse=True)
                
                # Sort vectors by group for consistent labeling
                group_sorted_vectors = sorted(data['grouped_vectors'], 
                                            key=lambda x: (x['group'], x['direction']))
                
                # Use different colors for each group and direction combination
                vector_colors = {
                    ('A_to_B', 1): (1.0, 0.0, 0.0),    # Red for Group 1 A→B
                    ('A_to_B', 2): (0.0, 1.0, 0.0),    # Green for Group 2 A→B
                    ('B_to_A', 1): (0.0, 0.0, 1.0),    # Blue for Group 1 B→A
                    ('B_to_A', 2): (1.0, 0.0, 1.0)     # Magenta for Group 2 B→A
                }
                
                # Define quadrant positions for 2D vectors
                quadrant_positions = {
                    # Group 1 B→A → Quadrant 3 (negative x, negative y)
                    ('B_to_A', 1): (-1, -1),
                    # Group 2 B→A → Quadrant 2 (negative x, positive y)  
                    ('B_to_A', 2): (-1, 1),
                    # Group 1 A→B → Quadrant 4 (positive x, negative y)
                    ('A_to_B', 1): (1, -1),
                    # Group 2 A→B → Quadrant 1 (positive x, positive y)
                    ('A_to_B', 2): (1, 1)
                }
                
                # Plot 2D vectors directly
                for v in plot_order_vectors:
                    dx, dy = v['value']
                    color = vector_colors[(v['direction'], v['group'])]
                    ax.arrow(0, 0, dx, dy, head_width=0.2, head_length=0.2, fc=color, ec=color, linewidth=2.5, alpha=1.0, label=v['label'])
                    mag = (dx**2 + dy**2)**0.5
                    lx = dx + (dx / mag if mag else 0)
                    ly = dy + (dy / mag if mag else 0)
                    dx_label = f"+{abs(dx):.0f}" if dy > 0 else f"-{abs(dx):.0f}"
                    ax.text(lx, ly, dx_label, fontsize=10, color='black', ha='center', va='center', fontweight='medium')
        
            # Calculate limits for 2D vector display
            if data['grouped_vectors']:
                all_x = [v['value'][0] for v in data['grouped_vectors']]
                all_y = [v['value'][1] for v in data['grouped_vectors']]
                max_x = max(abs(x) for x in all_x) if all_x else 2
                max_y = max(abs(y) for y in all_y) if all_y else 2
                axis_limit = max(max_x, max_y) * 1.5  # Space for text labels
                ax.set_xlim(-axis_limit, axis_limit)
                ax.set_ylim(-axis_limit, axis_limit)
            else:
                ax.set_xlim(-3, 3)
                ax.set_ylim(-3, 3)
            
            ax.set_xlabel('Response Direction', fontsize=11, fontweight='medium')
            ax.set_ylabel('Pin Level', fontsize=11, fontweight='medium')
            ax.tick_params(labelsize=9)
            
            # Add pin numbers on x-axis (deeper/lower position)
            xlim = ax.get_xlim()
            ax.text(xlim[0], -1.2, f'Pin: {data["pin_a"]}', fontsize=10, fontweight='medium', 
                   ha='left', va='center', transform=ax.transData)
            ax.text(xlim[1], -1.2, f'Pin: {data["pin_b"]}', fontsize=10, fontweight='medium', 
                   ha='right', va='center', transform=ax.transData)
            
            # Add Low/High labels for Pin Level (Y-axis) on the left side
            ylim = ax.get_ylim()
            xlim = ax.get_xlim()
            ax.text(xlim[0] - 0.5, ylim[0], 'Low', fontsize=10, fontweight='medium', 
                   ha='right', va='center', transform=ax.transData)
            ax.text(xlim[0] - 0.5, ylim[1], 'High', fontsize=10, fontweight='medium', 
                   ha='right', va='center', transform=ax.transData)
            
            if data['grouped_vectors']:
                # Create legend with group-sorted order
                legend_handles = []
                legend_labels = []
                for vector_info in group_sorted_vectors:
                    group = vector_info['group']
                    direction = vector_info['direction']
                    label = vector_info['label']
                    color = vector_colors[(direction, group)]
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
