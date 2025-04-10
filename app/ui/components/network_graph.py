from typing import Dict, List, Optional, Any, Tuple
from PyQt5.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel,
                           QPushButton, QComboBox, QFrame, QMenu)
from PyQt5.QtCore import Qt, pyqtSignal, QPoint, QRect, QSize
from PyQt5.QtGui import (QPainter, QPen, QBrush, QColor, QFont,
                        QPainterPath, QLinearGradient)
from app.utils.performance_monitor import measure_performance
import math

class NetworkNode:
    """Represents a node in the network graph"""
    def __init__(self, id: str, ip: str, mac: str, status: str = 'normal'):
        self.id = id
        self.ip = ip
        self.mac = mac
        self.status = status
        self.position = QPoint(0, 0)
        self.radius = 30
        self.connections = []
        
    def add_connection(self, node: 'NetworkNode', traffic: int = 0) -> None:
        """Add a connection to another node"""
        self.connections.append((node, traffic))
        
    def get_color(self) -> QColor:
        """Get color based on node status"""
        colors = {
            'normal': QColor('#4CAF50'),
            'attacker': QColor('#F44336'),
            'victim': QColor('#2196F3'),
            'suspicious': QColor('#FFC107')
        }
        return colors.get(self.status, QColor('#9E9E9E'))
        
    def get_tooltip(self) -> str:
        """Get tooltip text for the node"""
        return f"IP: {self.ip}\nMAC: {self.mac}\nStatus: {self.status}"

class NetworkEdge:
    """Represents a connection between nodes"""
    def __init__(self, source: NetworkNode, target: NetworkNode, traffic: int = 0):
        self.source = source
        self.target = target
        self.traffic = traffic
        
    def get_color(self) -> QColor:
        """Get color based on traffic level"""
        if self.traffic > 1000:
            return QColor('#F44336')
        elif self.traffic > 500:
            return QColor('#FF9800')
        elif self.traffic > 100:
            return QColor('#FFC107')
        else:
            return QColor('#4CAF50')
            
    def get_width(self) -> int:
        """Get line width based on traffic"""
        return min(5, max(1, self.traffic // 100))

class NetworkGraph(QWidget):
    """Network topology visualization component"""
    node_selected = pyqtSignal(NetworkNode)  # Emits when a node is selected
    
    def __init__(self, parent: Optional[QWidget] = None):
        super().__init__(parent)
        self.setMinimumSize(600, 400)
        self.nodes = {}
        self.edges = []
        self.selected_node = None
        self.dragging = False
        self.drag_start = QPoint()
        self.zoom = 1.0
        
        # Setup context menu
        self.setContextMenuPolicy(Qt.CustomContextMenu)
        self.customContextMenuRequested.connect(self.show_context_menu)
        
    @measure_performance('add_node')
    def add_node(self, node: NetworkNode) -> None:
        """Add a node to the graph"""
        self.nodes[node.id] = node
        self.update()
        
    @measure_performance('add_edge')
    def add_edge(self, edge: NetworkEdge) -> None:
        """Add an edge to the graph"""
        self.edges.append(edge)
        self.update()
        
    def highlight_attack_path(self, path: List[NetworkNode]) -> None:
        """Highlight a path of nodes involved in an attack"""
        for node in path:
            node.status = 'attacker' if node == path[0] else 'victim'
        self.update()
        
    def paintEvent(self, event) -> None:
        """Custom paint event for drawing the graph"""
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        
        # Apply zoom
        painter.scale(self.zoom, self.zoom)
        
        # Draw edges
        for edge in self.edges:
            self._draw_edge(painter, edge)
            
        # Draw nodes
        for node in self.nodes.values():
            self._draw_node(painter, node)
            
    def _draw_node(self, painter: QPainter, node: NetworkNode) -> None:
        """Draw a network node"""
        # Draw node circle
        color = node.get_color()
        painter.setPen(QPen(Qt.black, 2))
        painter.setBrush(QBrush(color))
        painter.drawEllipse(node.position, node.radius, node.radius)
        
        # Draw node label
        painter.setPen(Qt.black)
        font = QFont()
        font.setPointSize(8)
        painter.setFont(font)
        painter.drawText(
            QRect(node.position.x() - node.radius,
                  node.position.y() - node.radius,
                  node.radius * 2, node.radius * 2),
            Qt.AlignCenter,
            node.ip.split('.')[-1]  # Show last octet of IP
        )
        
        # Highlight selected node
        if node == self.selected_node:
            painter.setPen(QPen(Qt.blue, 3, Qt.DashLine))
            painter.setBrush(Qt.NoBrush)
            painter.drawEllipse(node.position, node.radius + 5, node.radius + 5)
            
    def _draw_edge(self, painter: QPainter, edge: NetworkEdge) -> None:
        """Draw a network edge"""
        # Calculate control points for curved line
        start = edge.source.position
        end = edge.target.position
        mid = (start + end) / 2
        control = QPoint(mid.x(), mid.y() - 50)
        
        # Create path for curved line
        path = QPainterPath()
        path.moveTo(start)
        path.quadTo(control, end)
        
        # Draw edge line
        color = edge.get_color()
        width = edge.get_width()
        painter.setPen(QPen(color, width))
        painter.drawPath(path)
        
        # Draw traffic label
        if edge.traffic > 0:
            painter.setPen(Qt.black)
            font = QFont()
            font.setPointSize(7)
            painter.setFont(font)
            painter.drawText(
                control,
                Qt.AlignCenter,
                f"{edge.traffic} pps"
            )
            
    def mousePressEvent(self, event) -> None:
        """Handle mouse press events"""
        pos = event.pos() / self.zoom
        
        # Check if a node was clicked
        for node in self.nodes.values():
            if (pos - node.position).manhattanLength() < node.radius:
                self.selected_node = node
                self.node_selected.emit(node)
                self.dragging = True
                self.drag_start = pos
                self.update()
                return
                
        self.selected_node = None
        self.update()
        
    def mouseMoveEvent(self, event) -> None:
        """Handle mouse move events"""
        if self.dragging and self.selected_node:
            pos = event.pos() / self.zoom
            delta = pos - self.drag_start
            self.selected_node.position += delta
            self.drag_start = pos
            self.update()
            
    def mouseReleaseEvent(self, event) -> None:
        """Handle mouse release events"""
        self.dragging = False
        
    def wheelEvent(self, event) -> None:
        """Handle mouse wheel events for zooming"""
        delta = event.angleDelta().y()
        if delta > 0:
            self.zoom *= 1.1
        else:
            self.zoom /= 1.1
        self.update()
        
    def show_context_menu(self, pos: QPoint) -> None:
        """Show context menu for node actions"""
        if not self.selected_node:
            return
            
        menu = QMenu(self)
        menu.addAction("View Details")
        menu.addAction("Block Traffic")
        menu.addAction("Add to Watchlist")
        menu.addAction("Export Data")
        menu.exec_(self.mapToGlobal(pos))
        
    def auto_layout(self) -> None:
        """Automatically layout nodes in a circular pattern"""
        center = QPoint(self.width() / 2 / self.zoom, self.height() / 2 / self.zoom)
        radius = min(self.width(), self.height()) / 3 / self.zoom
        angle_step = 360 / len(self.nodes)
        
        for i, node in enumerate(self.nodes.values()):
            angle = i * angle_step
            x = center.x() + radius * math.cos(math.radians(angle))
            y = center.y() + radius * math.sin(math.radians(angle))
            node.position = QPoint(x, y)
            
        self.update() 