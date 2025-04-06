from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QLabel, 
    QComboBox, QToolBar, QAction, QGraphicsView, QGraphicsScene,
    QGroupBox, QFormLayout, QSpinBox, QCheckBox, QSlider
)
from PyQt5.QtCore import Qt, QRectF, QPointF, QSizeF, pyqtSignal
from PyQt5.QtGui import QColor, QPen, QBrush, QPainter, QFont, QPixmap, QIcon

import math
import random
from typing import Dict, List, Any, Set, Tuple

from app.utils.logger import get_logger

# Module logger
logger = get_logger('components.network_topology')

class NetworkNode:
    """Represents a node in the network topology."""
    
    def __init__(self, node_id, name, ip, mac, is_gateway=False, vendor=None):
        """Initialize a network node.
        
        Args:
            node_id: Unique identifier for the node
            name: Display name for the node
            ip: IP address
            mac: MAC address
            is_gateway: Whether this node is a gateway
            vendor: Hardware vendor name
        """
        self.id = node_id
        self.name = name
        self.ip = ip
        self.mac = mac
        self.is_gateway = is_gateway
        self.vendor = vendor
        self.x = 0.0
        self.y = 0.0
        self.connected_to = set()  # Set of node IDs this node is connected to
        self.highlighted = False
        self.threat_level = 0  # 0: normal, 1: warning, 2: critical
        self.details = {}  # Additional details
    
    def add_connection(self, node_id):
        """Add a connection to another node.
        
        Args:
            node_id: ID of the node to connect to
        """
        self.connected_to.add(node_id)
    
    def remove_connection(self, node_id):
        """Remove a connection to another node.
        
        Args:
            node_id: ID of the node to disconnect from
        """
        if node_id in self.connected_to:
            self.connected_to.remove(node_id)

class NetworkTopologyView(QWidget):
    """Widget for displaying the network topology."""
    
    # Signals
    node_selected = pyqtSignal(str)  # Emitted when a node is selected, passes node_id
    node_double_clicked = pyqtSignal(str)  # Emitted when a node is double-clicked
    
    def __init__(self, parent=None):
        """Initialize the network topology view.
        
        Args:
            parent: Parent widget
        """
        super().__init__(parent)
        
        # Data
        self.nodes = {}  # Dict of nodes by ID
        self.selected_node_id = None
        self.layout_algorithm = "force-directed"  # Default layout algorithm
        self.show_labels = True
        self.show_ip_addresses = True
        self.show_vendors = True
        self.highlight_gateway = True
        self.highlight_threats = True
        
        # Layout parameters
        self.node_radius = 30
        self.gateway_radius = 40
        self.edge_length = 150
        self.repulsion_force = 10000
        self.attraction_force = 0.06
        self.damping = 0.85
        
        # Setup UI
        self.setup_ui()
    
    def setup_ui(self):
        """Set up the user interface."""
        main_layout = QVBoxLayout(self)
        
        # Top toolbar
        toolbar_layout = QHBoxLayout()
        
        # Layout algorithm selector
        layout_label = QLabel("Layout:")
        self.layout_combo = QComboBox()
        self.layout_combo.addItems(["Force-directed", "Circular", "Hierarchical"])
        self.layout_combo.setCurrentText("Force-directed")
        self.layout_combo.currentTextChanged.connect(self.change_layout_algorithm)
        
        # Apply layout button
        self.apply_layout_btn = QPushButton("Apply Layout")
        self.apply_layout_btn.clicked.connect(self.apply_layout)
        
        # Refresh button
        self.refresh_btn = QPushButton("Refresh")
        self.refresh_btn.clicked.connect(self.refresh_topology)
        
        # Add to toolbar
        toolbar_layout.addWidget(layout_label)
        toolbar_layout.addWidget(self.layout_combo)
        toolbar_layout.addWidget(self.apply_layout_btn)
        toolbar_layout.addStretch()
        toolbar_layout.addWidget(self.refresh_btn)
        
        # Graphics view and scene for the topology
        self.scene = QGraphicsScene(self)
        self.view = QGraphicsView(self.scene)
        self.view.setRenderHint(QPainter.Antialiasing)
        self.view.setDragMode(QGraphicsView.ScrollHandDrag)
        self.view.setTransformationAnchor(QGraphicsView.AnchorUnderMouse)
        self.view.setResizeAnchor(QGraphicsView.AnchorUnderMouse)
        self.view.setViewportUpdateMode(QGraphicsView.FullViewportUpdate)
        
        # Bottom controls
        controls_layout = QHBoxLayout()
        
        # Left group - Display options
        display_group = QGroupBox("Display Options")
        display_layout = QVBoxLayout(display_group)
        
        self.show_labels_cb = QCheckBox("Show Labels")
        self.show_labels_cb.setChecked(self.show_labels)
        self.show_labels_cb.toggled.connect(self.set_show_labels)
        
        self.show_ip_cb = QCheckBox("Show IP Addresses")
        self.show_ip_cb.setChecked(self.show_ip_addresses)
        self.show_ip_cb.toggled.connect(self.set_show_ip_addresses)
        
        self.show_vendors_cb = QCheckBox("Show Vendors")
        self.show_vendors_cb.setChecked(self.show_vendors)
        self.show_vendors_cb.toggled.connect(self.set_show_vendors)
        
        self.highlight_gateway_cb = QCheckBox("Highlight Gateway")
        self.highlight_gateway_cb.setChecked(self.highlight_gateway)
        self.highlight_gateway_cb.toggled.connect(self.set_highlight_gateway)
        
        self.highlight_threats_cb = QCheckBox("Highlight Threats")
        self.highlight_threats_cb.setChecked(self.highlight_threats)
        self.highlight_threats_cb.toggled.connect(self.set_highlight_threats)
        
        display_layout.addWidget(self.show_labels_cb)
        display_layout.addWidget(self.show_ip_cb)
        display_layout.addWidget(self.show_vendors_cb)
        display_layout.addWidget(self.highlight_gateway_cb)
        display_layout.addWidget(self.highlight_threats_cb)
        display_layout.addStretch()
        
        # Right group - Layout options
        layout_group = QGroupBox("Layout Settings")
        layout_settings = QFormLayout(layout_group)
        
        self.node_radius_spinner = QSpinBox()
        self.node_radius_spinner.setRange(10, 100)
        self.node_radius_spinner.setValue(self.node_radius)
        self.node_radius_spinner.valueChanged.connect(self.set_node_radius)
        
        self.edge_length_spinner = QSpinBox()
        self.edge_length_spinner.setRange(50, 400)
        self.edge_length_spinner.setValue(self.edge_length)
        self.edge_length_spinner.valueChanged.connect(self.set_edge_length)
        
        self.repulsion_slider = QSlider(Qt.Horizontal)
        self.repulsion_slider.setRange(1000, 20000)
        self.repulsion_slider.setValue(self.repulsion_force)
        self.repulsion_slider.valueChanged.connect(self.set_repulsion_force)
        
        self.attraction_slider = QSlider(Qt.Horizontal)
        self.attraction_slider.setRange(1, 100)
        self.attraction_slider.setValue(int(self.attraction_force * 1000))
        self.attraction_slider.valueChanged.connect(self.set_attraction_force)
        
        layout_settings.addRow("Node Size:", self.node_radius_spinner)
        layout_settings.addRow("Edge Length:", self.edge_length_spinner)
        layout_settings.addRow("Repulsion:", self.repulsion_slider)
        layout_settings.addRow("Attraction:", self.attraction_slider)
        
        # Add controls to the bottom layout
        controls_layout.addWidget(display_group)
        controls_layout.addWidget(layout_group)
        
        # Add all layouts to main layout
        main_layout.addLayout(toolbar_layout)
        main_layout.addWidget(self.view, 1)  # Give the view a stretch factor of 1
        main_layout.addLayout(controls_layout)
        
        # Initial setup
        self.refresh_topology()
    
    def change_layout_algorithm(self, algorithm):
        """Change the layout algorithm.
        
        Args:
            algorithm: The layout algorithm to use
        """
        self.layout_algorithm = algorithm.lower()
    
    def apply_layout(self):
        """Apply the current layout algorithm to the nodes."""
        if not self.nodes:
            return
            
        if self.layout_algorithm == "force-directed":
            self._apply_force_directed_layout()
        elif self.layout_algorithm == "circular":
            self._apply_circular_layout()
        elif self.layout_algorithm == "hierarchical":
            self._apply_hierarchical_layout()
            
        self._update_scene()
    
    def _apply_force_directed_layout(self):
        """Apply a force-directed layout algorithm."""
        if not self.nodes:
            return
            
        # Initialize with random positions if not set
        for node in self.nodes.values():
            if node.x == 0 and node.y == 0:
                node.x = random.uniform(-200, 200)
                node.y = random.uniform(-200, 200)
        
        # Perform iterations of force-directed layout
        iterations = 100
        temperature = 0.1
        cooling_factor = 0.99
        
        for i in range(iterations):
            # Calculate repulsive forces
            for node1_id, node1 in self.nodes.items():
                force_x = 0
                force_y = 0
                
                # Repulsive forces between all nodes
                for node2_id, node2 in self.nodes.items():
                    if node1_id != node2_id:
                        dx = node1.x - node2.x
                        dy = node1.y - node2.y
                        distance = max(1.0, math.sqrt(dx * dx + dy * dy))
                        
                        # Apply repulsive force
                        repulsive_force = self.repulsion_force / (distance * distance)
                        force_x += (dx / distance) * repulsive_force
                        force_y += (dy / distance) * repulsive_force
                
                # Attractive forces between connected nodes
                for connected_id in node1.connected_to:
                    if connected_id in self.nodes:
                        node2 = self.nodes[connected_id]
                        dx = node1.x - node2.x
                        dy = node1.y - node2.y
                        distance = max(1.0, math.sqrt(dx * dx + dy * dy))
                        
                        # Apply attractive force
                        attractive_force = -self.attraction_force * (distance - self.edge_length)
                        force_x += (dx / distance) * attractive_force
                        force_y += (dy / distance) * attractive_force
                
                # Apply forces with damping
                node1.x += force_x * temperature
                node1.y += force_y * temperature
            
            # Cool down the system
            temperature *= cooling_factor
    
    def _apply_circular_layout(self):
        """Apply a circular layout algorithm."""
        if not self.nodes:
            return
            
        # Find the center node (e.g., gateway or most connected)
        center_node_id = None
        max_connections = -1
        
        for node_id, node in self.nodes.items():
            if node.is_gateway:
                center_node_id = node_id
                break
            if len(node.connected_to) > max_connections:
                max_connections = len(node.connected_to)
                center_node_id = node_id
        
        if not center_node_id and self.nodes:
            # If no gateway or connections, just use the first node
            center_node_id = next(iter(self.nodes))
        
        # Place center node at the center
        if center_node_id and center_node_id in self.nodes:
            center_node = self.nodes[center_node_id]
            center_node.x = 0
            center_node.y = 0
            
            # Place other nodes in a circle around the center
            other_nodes = [node_id for node_id in self.nodes if node_id != center_node_id]
            node_count = len(other_nodes)
            
            if node_count > 0:
                radius = self.edge_length
                angle_step = 2 * math.pi / node_count
                
                for i, node_id in enumerate(other_nodes):
                    angle = i * angle_step
                    self.nodes[node_id].x = radius * math.cos(angle)
                    self.nodes[node_id].y = radius * math.sin(angle)
    
    def _apply_hierarchical_layout(self):
        """Apply a hierarchical layout algorithm."""
        if not self.nodes:
            return
            
        # Find the gateway(s)
        gateways = [node_id for node_id, node in self.nodes.items() if node.is_gateway]
        
        if not gateways and self.nodes:
            # If no gateway, find the most connected node
            max_connections = -1
            for node_id, node in self.nodes.items():
                if len(node.connected_to) > max_connections:
                    max_connections = len(node.connected_to)
                    gateways = [node_id]
        
        if not gateways and self.nodes:
            # If still no gateway, use the first node
            gateways = [next(iter(self.nodes))]
        
        # BFS to assign levels
        levels = {}
        visited = set()
        queue = [(gateway, 0) for gateway in gateways]  # (node_id, level)
        
        while queue:
            node_id, level = queue.pop(0)
            if node_id in visited:
                continue
                
            visited.add(node_id)
            levels[node_id] = level
            
            # Add all connected nodes
            node = self.nodes.get(node_id)
            if node:
                for connected_id in node.connected_to:
                    if connected_id not in visited and connected_id in self.nodes:
                        queue.append((connected_id, level + 1))
        
        # Group nodes by level
        nodes_by_level = {}
        for node_id, level in levels.items():
            if level not in nodes_by_level:
                nodes_by_level[level] = []
            nodes_by_level[level].append(node_id)
        
        # Position nodes by level
        level_height = self.edge_length
        
        for level, level_nodes in nodes_by_level.items():
            y = level * level_height
            node_count = len(level_nodes)
            
            if node_count > 0:
                level_width = (node_count - 1) * self.edge_length
                x_start = -level_width / 2
                
                for i, node_id in enumerate(level_nodes):
                    x = x_start + i * self.edge_length
                    self.nodes[node_id].x = x
                    self.nodes[node_id].y = y
    
    def refresh_topology(self):
        """Refresh the network topology display."""
        # Update the scene
        self._update_scene()
    
    def _update_scene(self):
        """Update the graphics scene with the current network topology."""
        self.scene.clear()
        
        if not self.nodes:
            # Display a message if no nodes
            text = self.scene.addText("No network topology available.\nRun a network scan to discover devices.")
            text.setDefaultTextColor(Qt.gray)
            font = QFont()
            font.setPointSize(12)
            text.setFont(font)
            return
        
        # Draw the edges (connections) first so they're behind the nodes
        for node_id, node in self.nodes.items():
            for connected_id in node.connected_to:
                if connected_id in self.nodes:
                    target_node = self.nodes[connected_id]
                    
                    # Don't draw the same connection twice
                    if node_id < connected_id:
                        # Draw the edge
                        pen = QPen(QColor(180, 180, 180))
                        pen.setWidth(2)
                        
                        # Use a different style for highlighted connections or threats
                        if node.highlighted and target_node.highlighted:
                            pen.setColor(QColor(100, 100, 255))
                            pen.setWidth(3)
                        
                        # If either node is a threat, use a warning color
                        if (node.threat_level > 0 or target_node.threat_level > 0) and self.highlight_threats:
                            pen.setColor(QColor(255, 150, 50))
                            pen.setWidth(3)
                        
                        self.scene.addLine(node.x, node.y, target_node.x, target_node.y, pen)
        
        # Draw the nodes
        for node_id, node in self.nodes.items():
            # Determine node appearance
            radius = self.node_radius
            
            # Use larger radius for gateway
            if node.is_gateway and self.highlight_gateway:
                radius = self.gateway_radius
            
            # Default colors
            border_color = QColor(100, 100, 100)
            fill_color = QColor(220, 220, 220)
            text_color = QColor(0, 0, 0)
            
            # Highlight gateway
            if node.is_gateway and self.highlight_gateway:
                border_color = QColor(0, 100, 200)
                fill_color = QColor(200, 230, 255)
            
            # Highlight selected node
            if node_id == self.selected_node_id:
                border_color = QColor(0, 150, 255)
                fill_color = QColor(210, 240, 255)
            
            # Highlight custom highlighting
            if node.highlighted:
                border_color = QColor(0, 0, 200)
                fill_color = QColor(200, 200, 255)
            
            # Highlight threats
            if node.threat_level > 0 and self.highlight_threats:
                if node.threat_level == 1:  # Warning
                    border_color = QColor(255, 150, 0)
                    fill_color = QColor(255, 240, 200)
                else:  # Critical
                    border_color = QColor(200, 0, 0)
                    fill_color = QColor(255, 200, 200)
            
            # Draw the node
            pen = QPen(border_color)
            pen.setWidth(2)
            brush = QBrush(fill_color)
            
            # Create a group for the node elements
            self.scene.addEllipse(node.x - radius, node.y - radius, 
                                  radius * 2, radius * 2, pen, brush)
            
            # Add labels
            if self.show_labels:
                # Node name/hostname
                text_item = self.scene.addText(node.name)
                text_item.setDefaultTextColor(text_color)
                text_font = QFont()
                text_font.setBold(True)
                text_item.setFont(text_font)
                text_rect = text_item.boundingRect()
                text_item.setPos(node.x - text_rect.width() / 2, 
                                node.y - text_rect.height() / 2)
                
                # Additional labels below the node
                label_y = node.y + radius + 5
                
                # IP address
                if self.show_ip_addresses:
                    ip_item = self.scene.addText(node.ip)
                    ip_item.setDefaultTextColor(QColor(80, 80, 80))
                    ip_rect = ip_item.boundingRect()
                    ip_item.setPos(node.x - ip_rect.width() / 2, label_y)
                    label_y += ip_rect.height()
                
                # Vendor
                if self.show_vendors and node.vendor:
                    vendor_item = self.scene.addText(node.vendor)
                    vendor_item.setDefaultTextColor(QColor(120, 120, 120))
                    vendor_font = QFont()
                    vendor_font.setItalic(True)
                    vendor_font.setPointSize(8)
                    vendor_item.setFont(vendor_font)
                    vendor_rect = vendor_item.boundingRect()
                    vendor_item.setPos(node.x - vendor_rect.width() / 2, label_y)
        
        # Set the scene rect to fit all items
        self.scene.setSceneRect(self.scene.itemsBoundingRect().adjusted(-100, -100, 100, 100))
    
    def set_nodes(self, nodes_data):
        """Set the network nodes data.
        
        Args:
            nodes_data: List of dictionaries with node data
        """
        # Clear existing nodes
        self.nodes = {}
        
        # Add new nodes
        for node_data in nodes_data:
            node_id = node_data.get('id')
            if not node_id:
                continue
                
            node = NetworkNode(
                node_id=node_id,
                name=node_data.get('name', f"Node {node_id}"),
                ip=node_data.get('ip', ''),
                mac=node_data.get('mac', ''),
                is_gateway=node_data.get('is_gateway', False),
                vendor=node_data.get('vendor', '')
            )
            
            # Add any additional details
            node.threat_level = node_data.get('threat_level', 0)
            node.highlighted = node_data.get('highlighted', False)
            node.details = node_data.get('details', {})
            
            # Add to nodes dictionary
            self.nodes[node_id] = node
        
        # Set up connections
        for node_data in nodes_data:
            node_id = node_data.get('id')
            connections = node_data.get('connections', [])
            
            if node_id in self.nodes:
                for conn_id in connections:
                    if conn_id in self.nodes:
                        self.nodes[node_id].add_connection(conn_id)
        
        # Apply layout and refresh
        self.apply_layout()
    
    def add_node(self, node_data):
        """Add a new node to the topology.
        
        Args:
            node_data: Dictionary with node data
        """
        node_id = node_data.get('id')
        if not node_id or node_id in self.nodes:
            return False
            
        node = NetworkNode(
            node_id=node_id,
            name=node_data.get('name', f"Node {node_id}"),
            ip=node_data.get('ip', ''),
            mac=node_data.get('mac', ''),
            is_gateway=node_data.get('is_gateway', False),
            vendor=node_data.get('vendor', '')
        )
        
        # Add any additional details
        node.threat_level = node_data.get('threat_level', 0)
        node.highlighted = node_data.get('highlighted', False)
        node.details = node_data.get('details', {})
        
        # Add to nodes dictionary
        self.nodes[node_id] = node
        
        # Add connections
        connections = node_data.get('connections', [])
        for conn_id in connections:
            if conn_id in self.nodes:
                node.add_connection(conn_id)
                # Add reverse connection
                self.nodes[conn_id].add_connection(node_id)
        
        # Refresh display
        self.apply_layout()
        return True
    
    def update_node(self, node_id, updates):
        """Update an existing node's properties.
        
        Args:
            node_id: ID of the node to update
            updates: Dictionary of properties to update
        """
        if node_id not in self.nodes:
            return False
            
        node = self.nodes[node_id]
        
        # Update basic properties
        if 'name' in updates:
            node.name = updates['name']
        if 'ip' in updates:
            node.ip = updates['ip']
        if 'mac' in updates:
            node.mac = updates['mac']
        if 'is_gateway' in updates:
            node.is_gateway = updates['is_gateway']
        if 'vendor' in updates:
            node.vendor = updates['vendor']
        if 'threat_level' in updates:
            node.threat_level = updates['threat_level']
        if 'highlighted' in updates:
            node.highlighted = updates['highlighted']
        
        # Update details
        if 'details' in updates:
            node.details.update(updates['details'])
        
        # Update connections
        if 'connections' in updates:
            # Clear existing connections
            node.connected_to.clear()
            
            # Add new connections
            for conn_id in updates['connections']:
                if conn_id in self.nodes:
                    node.add_connection(conn_id)
        
        # Refresh display
        self._update_scene()
        return True
    
    def remove_node(self, node_id):
        """Remove a node from the topology.
        
        Args:
            node_id: ID of the node to remove
        """
        if node_id not in self.nodes:
            return False
            
        # Remove all connections to this node
        for other_id, other_node in self.nodes.items():
            if node_id in other_node.connected_to:
                other_node.remove_connection(node_id)
        
        # Remove the node
        del self.nodes[node_id]
        
        # Clear selection if the selected node was removed
        if self.selected_node_id == node_id:
            self.selected_node_id = None
        
        # Refresh display
        self._update_scene()
        return True
    
    def select_node(self, node_id):
        """Select a node in the topology.
        
        Args:
            node_id: ID of the node to select
        """
        if node_id in self.nodes or node_id is None:
            self.selected_node_id = node_id
            self._update_scene()
            if node_id:
                self.node_selected.emit(node_id)
            return True
        return False
    
    def highlight_node(self, node_id, highlight=True):
        """Highlight a node in the topology.
        
        Args:
            node_id: ID of the node to highlight
            highlight: Whether to highlight or unhighlight
        """
        if node_id in self.nodes:
            self.nodes[node_id].highlighted = highlight
            self._update_scene()
            return True
        return False
    
    def set_node_threat_level(self, node_id, level):
        """Set the threat level of a node.
        
        Args:
            node_id: ID of the node
            level: Threat level (0: normal, 1: warning, 2: critical)
        """
        if node_id in self.nodes:
            self.nodes[node_id].threat_level = level
            self._update_scene()
            return True
        return False
    
    def auto_connect_nodes(self):
        """Automatically connect nodes based on network proximity."""
        # Simple implementation: connect all nodes to the gateway
        gateways = [node_id for node_id, node in self.nodes.items() if node.is_gateway]
        
        if not gateways:
            return
        
        for node_id, node in self.nodes.items():
            if not node.is_gateway:
                for gateway_id in gateways:
                    node.add_connection(gateway_id)
                    self.nodes[gateway_id].add_connection(node_id)
        
        self._update_scene()
    
    # Display setting methods
    def set_show_labels(self, show):
        """Set whether to show node labels."""
        self.show_labels = show
        self._update_scene()
    
    def set_show_ip_addresses(self, show):
        """Set whether to show IP addresses."""
        self.show_ip_addresses = show
        self._update_scene()
    
    def set_show_vendors(self, show):
        """Set whether to show vendor information."""
        self.show_vendors = show
        self._update_scene()
    
    def set_highlight_gateway(self, highlight):
        """Set whether to highlight the gateway node."""
        self.highlight_gateway = highlight
        self._update_scene()
    
    def set_highlight_threats(self, highlight):
        """Set whether to highlight threat nodes."""
        self.highlight_threats = highlight
        self._update_scene()
    
    def set_node_radius(self, radius):
        """Set the radius of nodes."""
        self.node_radius = radius
        self.gateway_radius = radius * 1.33
        self._update_scene()
    
    def set_edge_length(self, length):
        """Set the preferred edge length."""
        self.edge_length = length
    
    def set_repulsion_force(self, force):
        """Set the repulsion force between nodes."""
        self.repulsion_force = force
    
    def set_attraction_force(self, force):
        """Set the attraction force between connected nodes."""
        self.attraction_force = force / 1000.0 