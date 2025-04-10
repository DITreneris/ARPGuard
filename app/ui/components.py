from typing import Optional, List, Dict, Any, Callable
from PyQt5.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel, 
                            QPushButton, QTableWidget, QTableWidgetItem, 
                            QProgressBar, QComboBox, QLineEdit)
from PyQt5.QtCore import Qt, QTimer, pyqtSignal
from PyQt5.QtGui import QColor, QPalette
from app.ui.lazy_loader import LazyLoader
from app.utils.performance_monitor import measure_performance

class OptimizedTable(QTableWidget):
    """Optimized table widget with lazy loading and performance monitoring"""
    def __init__(self, parent: Optional[QWidget] = None):
        super().__init__(parent)
        self.setAlternatingRowColors(True)
        self.setSelectionBehavior(QTableWidget.SelectRows)
        self.setSelectionMode(QTableWidget.SingleSelection)
        self.verticalHeader().setVisible(False)
        self.horizontalHeader().setStretchLastSection(True)
        self.setSortingEnabled(True)
        
        # Performance optimization
        self._visible_rows = 0
        self._total_rows = 0
        self._data_cache = {}
        self._sort_column = 0
        self._sort_order = Qt.AscendingOrder
        
    @measure_performance('table_update')
    def update_data(self, data: List[Dict[str, Any]], columns: List[str]):
        """Update table data with performance optimization"""
        self.clear()
        self.setColumnCount(len(columns))
        self.setHorizontalHeaderLabels(columns)
        
        self._total_rows = len(data)
        self._data_cache = {i: row for i, row in enumerate(data)}
        
        # Only load visible rows initially
        self._visible_rows = min(50, self._total_rows)
        self.setRowCount(self._visible_rows)
        
        for row in range(self._visible_rows):
            self._update_row(row)
            
    def _update_row(self, row: int):
        """Update a single row with cached data"""
        if row >= self._total_rows:
            return
            
        data = self._data_cache[row]
        for col, value in enumerate(data.values()):
            item = QTableWidgetItem(str(value))
            item.setFlags(item.flags() & ~Qt.ItemIsEditable)
            self.setItem(row, col, item)
            
    def scrollContentsBy(self, dx: int, dy: int):
        """Override scroll to implement lazy loading"""
        super().scrollContentsBy(dx, dy)
        self._load_visible_rows()
        
    def _load_visible_rows(self):
        """Load rows that are currently visible"""
        visible_range = range(self.rowAt(0), self.rowAt(self.viewport().height()))
        for row in visible_range:
            if row < self._total_rows and row not in self._data_cache:
                self._update_row(row)

class StatusIndicator(QWidget):
    """Optimized status indicator with color coding and animations"""
    status_changed = pyqtSignal(str)
    
    def __init__(self, parent: Optional[QWidget] = None):
        super().__init__(parent)
        self.layout = QHBoxLayout(self)
        self.indicator = QLabel()
        self.status_label = QLabel()
        
        self.layout.addWidget(self.indicator)
        self.layout.addWidget(self.status_label)
        self.setLayout(self.layout)
        
        self._status_colors = {
            'ok': QColor('#4CAF50'),
            'warning': QColor('#FFC107'),
            'error': QColor('#F44336'),
            'info': QColor('#2196F3')
        }
        
    def set_status(self, status: str, message: str):
        """Set status with color coding"""
        self.status_label.setText(message)
        color = self._status_colors.get(status.lower(), QColor('#9E9E9E'))
        
        # Create a colored circle indicator
        self.indicator.setStyleSheet(f"""
            QLabel {{
                background-color: {color.name()};
                border-radius: 8px;
                min-width: 16px;
                min-height: 16px;
                max-width: 16px;
                max-height: 16px;
            }}
        """)
        
        self.status_changed.emit(status)

class OptimizedComboBox(QComboBox):
    """Optimized combo box with search and lazy loading"""
    def __init__(self, parent: Optional[QWidget] = None):
        super().__init__(parent)
        self.setEditable(True)
        self.lineEdit().setPlaceholderText("Search...")
        
        # Performance optimization
        self._items = []
        self._filter_timer = QTimer()
        self._filter_timer.setSingleShot(True)
        self._filter_timer.timeout.connect(self._apply_filter)
        
        self.lineEdit().textChanged.connect(self._on_text_changed)
        
    def add_items(self, items: List[str]):
        """Add items with lazy loading"""
        self._items = items
        self._load_visible_items()
        
    def _on_text_changed(self, text: str):
        """Handle text changes with debouncing"""
        self._filter_timer.start(300)  # 300ms debounce
        
    def _apply_filter(self):
        """Apply filter to items"""
        filter_text = self.lineEdit().text().lower()
        filtered_items = [item for item in self._items 
                         if filter_text in item.lower()]
        
        self.clear()
        self.addItems(filtered_items[:100])  # Limit visible items
        
    def _load_visible_items(self):
        """Load visible items with pagination"""
        self.clear()
        self.addItems(self._items[:100])

class ProgressIndicator(QWidget):
    """Optimized progress indicator with smooth animations"""
    def __init__(self, parent: Optional[QWidget] = None):
        super().__init__(parent)
        self.layout = QVBoxLayout(self)
        
        self.progress_bar = QProgressBar()
        self.progress_bar.setTextVisible(False)
        self.progress_bar.setMinimum(0)
        self.progress_bar.setMaximum(100)
        
        self.status_label = QLabel()
        self.status_label.setAlignment(Qt.AlignCenter)
        
        self.layout.addWidget(self.progress_bar)
        self.layout.addWidget(self.status_label)
        
        # Animation timer
        self._animation_timer = QTimer()
        self._animation_timer.timeout.connect(self._update_animation)
        self._current_value = 0
        self._target_value = 0
        
    def set_progress(self, value: int, message: str = ""):
        """Set progress with smooth animation"""
        self._target_value = max(0, min(100, value))
        self.status_label.setText(message)
        
        if not self._animation_timer.isActive():
            self._animation_timer.start(16)  # ~60 FPS
            
    def _update_animation(self):
        """Update progress animation"""
        if abs(self._current_value - self._target_value) < 1:
            self._current_value = self._target_value
            self._animation_timer.stop()
        else:
            self._current_value += (self._target_value - self._current_value) * 0.1
            
        self.progress_bar.setValue(int(self._current_value))

class OptimizedButton(QPushButton):
    """Optimized button with loading state and animations"""
    def __init__(self, text: str, parent: Optional[QWidget] = None):
        super().__init__(text, parent)
        self._original_text = text
        self._loading = False
        
        # Style
        self.setCursor(Qt.PointingHandCursor)
        self.setStyleSheet("""
            QPushButton {
                padding: 8px 16px;
                border-radius: 4px;
                background-color: #2196F3;
                color: white;
            }
            QPushButton:hover {
                background-color: #1976D2;
            }
            QPushButton:pressed {
                background-color: #0D47A1;
            }
            QPushButton:disabled {
                background-color: #BDBDBD;
            }
        """)
        
    def set_loading(self, loading: bool):
        """Set loading state with animation"""
        self._loading = loading
        self.setEnabled(not loading)
        
        if loading:
            self.setText("Loading...")
            # Add loading animation here
        else:
            self.setText(self._original_text) 