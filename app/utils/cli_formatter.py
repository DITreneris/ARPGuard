"""
CLI Formatter Utilities

This module provides formatting utilities for the CLI output, including
colored text, progress indicators, and other visual enhancements.
"""

import os
import sys
import time
import platform
from typing import Dict, Any, List, Optional, Union

# ANSI color codes
class Colors:
    RESET = "\033[0m"
    BLACK = "\033[30m"
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    MAGENTA = "\033[35m"
    CYAN = "\033[36m"
    WHITE = "\033[37m"
    BOLD = "\033[1m"
    UNDERLINE = "\033[4m"
    BRIGHT_RED = "\033[91m"
    BRIGHT_GREEN = "\033[92m"
    BRIGHT_YELLOW = "\033[93m"
    BRIGHT_BLUE = "\033[94m"
    BRIGHT_MAGENTA = "\033[95m"
    BRIGHT_CYAN = "\033[96m"
    BRIGHT_WHITE = "\033[97m"
    BG_RED = "\033[41m"
    BG_GREEN = "\033[42m"
    BG_YELLOW = "\033[43m"
    BG_BLUE = "\033[44m"
    BG_MAGENTA = "\033[45m"
    BG_CYAN = "\033[46m"
    BG_WHITE = "\033[47m"

class CLIFormatter:
    """Utility class for formatting CLI output."""
    
    def __init__(self, use_color: bool = True):
        """Initialize the formatter.
        
        Args:
            use_color: Whether to use color in output. Default is True.
        """
        self.use_color = use_color
        
        # Disable colors on unsupported terminals or Windows without ANSI support
        if platform.system() == "Windows" and not self._has_ansi_support():
            self.use_color = False
    
    def _has_ansi_support(self) -> bool:
        """Check if the terminal supports ANSI color codes.
        
        Returns:
            bool: True if ANSI is supported, False otherwise.
        """
        return os.environ.get('TERM') is not None or 'WT_SESSION' in os.environ
    
    def colorize(self, text: str, color: str, bold: bool = False) -> str:
        """Apply color to text.
        
        Args:
            text: The text to colorize
            color: The color to apply (use Colors constants)
            bold: Whether to make the text bold
            
        Returns:
            str: Colorized text
        """
        if not self.use_color:
            return text
            
        bold_prefix = Colors.BOLD if bold else ""
        return f"{bold_prefix}{color}{text}{Colors.RESET}"
    
    def success(self, message: str) -> str:
        """Format a success message.
        
        Args:
            message: The message to format
            
        Returns:
            str: Formatted message
        """
        prefix = self.colorize("[SUCCESS]", Colors.GREEN, True)
        return f"{prefix} {message}"
    
    def error(self, message: str) -> str:
        """Format an error message.
        
        Args:
            message: The message to format
            
        Returns:
            str: Formatted message
        """
        prefix = self.colorize("[ERROR]", Colors.RED, True)
        return f"{prefix} {message}"
    
    def warning(self, message: str) -> str:
        """Format a warning message.
        
        Args:
            message: The message to format
            
        Returns:
            str: Formatted message
        """
        prefix = self.colorize("[WARNING]", Colors.YELLOW, True)
        return f"{prefix} {message}"
    
    def info(self, message: str) -> str:
        """Format an info message.
        
        Args:
            message: The message to format
            
        Returns:
            str: Formatted message
        """
        prefix = self.colorize("[INFO]", Colors.BLUE, True)
        return f"{prefix} {message}"
    
    def header(self, title: str, width: int = 80) -> str:
        """Create a formatted header.
        
        Args:
            title: The header title
            width: The width of the header
            
        Returns:
            str: Formatted header
        """
        if not self.use_color:
            line = "=" * width
            return f"\n{line}\n{title.center(width)}\n{line}\n"
            
        line = self.colorize("=" * width, Colors.CYAN)
        title_formatted = self.colorize(title.center(width), Colors.CYAN, True)
        return f"\n{line}\n{title_formatted}\n{line}\n"
    
    def format_table(self, headers: List[str], rows: List[List[str]], 
                     colors: Optional[List[str]] = None) -> str:
        """Format data as a table.
        
        Args:
            headers: List of column headers
            rows: List of rows, each row is a list of column values
            colors: Optional list of colors to apply to each column
            
        Returns:
            str: Formatted table
        """
        if not rows:
            return "No data to display"
            
        # Calculate column widths based on content
        col_widths = [len(h) for h in headers]
        for row in rows:
            for i, col in enumerate(row):
                if i < len(col_widths):
                    col_widths[i] = max(col_widths[i], len(str(col)))
        
        # Format the headers
        header_fmt = ""
        separator = ""
        for i, header in enumerate(headers):
            width = col_widths[i]
            if self.use_color:
                header_fmt += self.colorize(f"{header:<{width}}", Colors.BRIGHT_WHITE, True)
            else:
                header_fmt += f"{header:<{width}}"
                
            separator += "-" * width
            
            # Add spacing between columns
            if i < len(headers) - 1:
                header_fmt += " | "
                separator += "-+-"
                
        result = f"{header_fmt}\n{separator}\n"
        
        # Format the rows
        for row in rows:
            row_fmt = ""
            for i, col in enumerate(row):
                if i < len(col_widths):
                    width = col_widths[i]
                    text = f"{col:<{width}}"
                    
                    # Apply color if specified
                    if self.use_color and colors and i < len(colors):
                        text = self.colorize(text, colors[i])
                        
                    row_fmt += text
                    
                    # Add spacing between columns
                    if i < len(row) - 1:
                        row_fmt += " | "
            
            result += f"{row_fmt}\n"
            
        return result
    
    def format_alert(self, alert: Dict[str, Any]) -> str:
        """Format an alert message.
        
        Args:
            alert: Alert dictionary with severity, type, and details
            
        Returns:
            str: Formatted alert message
        """
        severity = alert.get('severity', 'medium').upper()
        alert_type = alert.get('type', 'unknown')
        details = alert.get('details', '')
        
        if not self.use_color:
            return f"[{severity}] {alert_type}: {details}"
            
        # Color based on severity
        if severity == 'HIGH':
            severity_colored = self.colorize(f"[{severity}]", Colors.BRIGHT_RED, True)
        elif severity == 'MEDIUM':
            severity_colored = self.colorize(f"[{severity}]", Colors.BRIGHT_YELLOW, True)
        else:
            severity_colored = self.colorize(f"[{severity}]", Colors.BRIGHT_GREEN)
            
        # Format the alert type
        alert_type_colored = self.colorize(alert_type, Colors.BRIGHT_WHITE, True)
        
        return f"{severity_colored} {alert_type_colored}: {details}"
    
    def progress_bar(self, current: int, total: int, bar_length: int = 40, 
                     prefix: str = "", suffix: str = "") -> str:
        """Create a text-based progress bar.
        
        Args:
            current: Current progress value
            total: Total progress value
            bar_length: Length of the progress bar
            prefix: Text to display before the progress bar
            suffix: Text to display after the progress bar
            
        Returns:
            str: Formatted progress bar
        """
        if total == 0:
            percent = 100
        else:
            percent = int(100 * (current / float(total)))
            
        filled_length = int(bar_length * current // total)
        bar = '█' * filled_length + '░' * (bar_length - filled_length)
        
        if not self.use_color:
            return f"\r{prefix} [{bar}] {percent}% {suffix}"
            
        # Color the progress bar based on progress
        if percent < 30:
            color = Colors.RED
        elif percent < 70:
            color = Colors.YELLOW
        else:
            color = Colors.GREEN
            
        colored_bar = self.colorize(bar, color)
        percent_str = self.colorize(f"{percent}%", Colors.BRIGHT_WHITE, True)
        
        return f"\r{prefix} [{colored_bar}] {percent_str} {suffix}"
    
    def spinner(self, message: str, frames: Optional[List[str]] = None) -> callable:
        """Create a spinner for long-running operations.
        
        Args:
            message: Message to display with the spinner
            frames: Optional list of spinner frames
            
        Returns:
            callable: Function to update spinner state
        """
        if frames is None:
            frames = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏']
            
        if not self.use_color:
            frames = ['-', '\\', '|', '/']
            
        spinner_idx = [0]
        start_time = [time.time()]
        
        def update(status: Optional[str] = None, force_stop: bool = False) -> None:
            """Update the spinner.
            
            Args:
                status: Optional status message to update
                force_stop: Whether to force stop the spinner
            """
            current_idx = spinner_idx[0]
            current_frame = frames[current_idx % len(frames)]
            
            # Calculate elapsed time
            elapsed = time.time() - start_time[0]
            elapsed_str = f"{elapsed:.1f}s"
            
            # Update status if provided, otherwise use the original message
            display_msg = status if status is not None else message
            
            if not self.use_color:
                sys.stdout.write(f"\r{current_frame} {display_msg} ({elapsed_str})")
            else:
                frame_colored = self.colorize(current_frame, Colors.BRIGHT_CYAN, True)
                elapsed_colored = self.colorize(f"({elapsed_str})", Colors.BRIGHT_BLACK)
                sys.stdout.write(f"\r{frame_colored} {display_msg} {elapsed_colored}")
                
            sys.stdout.flush()
            
            # Increment spinner state
            spinner_idx[0] += 1
            
            # If force_stop, add newline
            if force_stop:
                sys.stdout.write("\n")
                sys.stdout.flush()
            
        return update
    
    def wrap_text(self, text: str, width: int = 80) -> str:
        """Wrap text to specified width.
        
        Args:
            text: Text to wrap
            width: Maximum line width
            
        Returns:
            str: Wrapped text
        """
        words = text.split()
        lines = []
        current_line = []
        current_length = 0
        
        for word in words:
            # If adding this word exceeds the line width
            if current_length + len(word) + len(current_line) > width:
                # Add the current line to lines
                if current_line:
                    lines.append(' '.join(current_line))
                    current_line = []
                    current_length = 0
                
                # If the word itself is longer than width, need to split it
                if len(word) > width:
                    for i in range(0, len(word), width):
                        lines.append(word[i:i+width])
                else:
                    current_line.append(word)
                    current_length += len(word)
            else:
                current_line.append(word)
                current_length += len(word)
                
        # Add the last line
        if current_line:
            lines.append(' '.join(current_line))
            
        return '\n'.join(lines)
    
    def tree(self, data: Dict[str, Any], indent: int = 0) -> str:
        """Format data as a tree structure.
        
        Args:
            data: Dictionary to display as a tree
            indent: Current indentation level
            
        Returns:
            str: Formatted tree
        """
        result = []
        
        for key, value in data.items():
            indent_str = "  " * indent
            
            if isinstance(value, dict):
                if self.use_color:
                    result.append(f"{indent_str}{self.colorize('➤', Colors.CYAN)} {self.colorize(key, Colors.BRIGHT_WHITE, True)}")
                else:
                    result.append(f"{indent_str}+ {key}")
                    
                result.append(self.tree(value, indent + 1))
            else:
                if self.use_color:
                    result.append(f"{indent_str}{self.colorize('•', Colors.GREEN)} {key}: {self.colorize(str(value), Colors.BRIGHT_GREEN)}")
                else:
                    result.append(f"{indent_str}- {key}: {value}")
                    
        return "\n".join(result)
    
    def device_status(self, ip: str, mac: str, status: str, 
                      extra_info: Optional[str] = None) -> str:
        """Format device status information.
        
        Args:
            ip: IP address of the device
            mac: MAC address of the device
            status: Status string (online, offline, suspicious)
            extra_info: Additional information about the device
            
        Returns:
            str: Formatted device status
        """
        if not self.use_color:
            extra = f" ({extra_info})" if extra_info else ""
            return f"{ip} [{mac}] - {status}{extra}"
            
        # Format IP and MAC
        ip_colored = self.colorize(ip, Colors.BRIGHT_WHITE, True)
        mac_colored = self.colorize(mac, Colors.BRIGHT_BLACK)
        
        # Color status based on value
        if status.lower() == 'online':
            status_colored = self.colorize(status, Colors.GREEN, True)
        elif status.lower() == 'offline':
            status_colored = self.colorize(status, Colors.RED)
        elif status.lower() == 'suspicious':
            status_colored = self.colorize(status, Colors.BRIGHT_RED, True)
        else:
            status_colored = self.colorize(status, Colors.YELLOW)
            
        # Format extra info
        extra = f" ({self.colorize(extra_info, Colors.BRIGHT_BLUE)})" if extra_info else ""
            
        return f"{ip_colored} [{mac_colored}] - {status_colored}{extra}"
    
    def format_help(self, command: str, description: str, 
                   examples: List[Dict[str, str]]) -> str:
        """Format help text for a command.
        
        Args:
            command: Command name
            description: Command description
            examples: List of example dictionaries with 'cmd' and 'desc' keys
            
        Returns:
            str: Formatted help text
        """
        if not self.use_color:
            result = [f"Command: {command}", "-" * 50, "", description, "", "Examples:"]
            
            for example in examples:
                result.append(f"  {example['cmd']}")
                result.append(f"    {example['desc']}")
                result.append("")
                
            return "\n".join(result)
            
        # Format command name
        command_title = self.colorize(f"Command: {command}", Colors.BRIGHT_WHITE, True)
        
        # Format separator
        separator = self.colorize("-" * 50, Colors.BRIGHT_BLACK)
        
        # Format description
        desc_wrapped = self.wrap_text(description)
        
        # Format examples
        examples_header = self.colorize("Examples:", Colors.BRIGHT_WHITE, True)
        examples_text = []
        
        for example in examples:
            cmd = self.colorize(f"  {example['cmd']}", Colors.BRIGHT_GREEN)
            desc = f"    {example['desc']}"
            examples_text.extend([cmd, desc, ""])
            
        return "\n".join([command_title, separator, "", desc_wrapped, "", 
                          examples_header, "", *examples_text])

# Create a default formatter
formatter = CLIFormatter() 