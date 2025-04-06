"""
Simple PyQt5 test script to diagnose loading issues.
"""
import sys
print(f"Python version: {sys.version}")
print(f"Python path: {sys.executable}")

try:
    import PyQt5
    print(f"PyQt5 path: {PyQt5.__file__}")
    print("PyQt5 imported successfully")
except ImportError as e:
    print(f"Error importing PyQt5: {e}")
    
try:
    from PyQt5 import QtCore
    print(f"PyQt5.QtCore version: {QtCore.PYQT_VERSION_STR}")
    print(f"Qt version: {QtCore.QT_VERSION_STR}")
    print("PyQt5.QtCore imported successfully")
except ImportError as e:
    print(f"Error importing PyQt5.QtCore: {e}")
    
try:
    from PyQt5.QtWidgets import QApplication, QLabel
    print("PyQt5.QtWidgets imported successfully")
except ImportError as e:
    print(f"Error importing PyQt5.QtWidgets: {e}")

if __name__ == "__main__":
    try:
        app = QApplication(sys.argv)
        print("QApplication created successfully")
        
        label = QLabel("Hello, PyQt5!")
        print("QLabel created successfully")
        
        label.show()
        print("Label shown successfully")
        
        print("Test completed. Press Ctrl+C to exit.")
        sys.exit(app.exec_())
    except Exception as e:
        print(f"Error running PyQt5 test: {e}") 