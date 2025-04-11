import pytest
from unittest.mock import Mock, patch
from app.components.cli import ARPGuardCLI

@pytest.fixture
def cli():
    return ARPGuardCLI()

def test_cli_initialization(cli):
    """Test CLI initialization."""
    assert cli.version == "1.0.0"
    assert cli.parser is not None
    assert cli.subparsers is not None
    assert hasattr(cli, 'device_discovery')
    assert hasattr(cli, 'arp_cache_monitor')
    assert hasattr(cli, 'packet_capture')
    assert hasattr(cli, 'config_manager')

def test_help_command(cli):
    """Test help command execution."""
    with patch('builtins.print') as mock_print:
        args = cli.parser.parse_args(['help'])
        result = cli._handle_help(args)
        assert mock_print.called
        assert result is None

def test_scan_command_basic(cli):
    """Test basic scan command execution."""
    with patch('app.components.device_discovery.DeviceDiscovery.discover') as mock_discover:
        mock_discover.return_value = [
            {'ip': '192.168.1.1', 'mac': '00:11:22:33:44:55', 'hostname': 'device1'},
            {'ip': '192.168.1.2', 'mac': '00:11:22:33:44:66', 'hostname': 'device2'}
        ]
        
        args = cli.parser.parse_args(['scan', '--subnet', '192.168.1.0/24'])
        result = cli._handle_scan(args)
        
        assert result == 0
        mock_discover.assert_called_once()

def test_monitor_command_basic(cli):
    """Test basic monitor command execution."""
    with patch('app.components.arp_cache_monitor.ARPCacheMonitor.start_monitoring') as mock_monitor:
        args = cli.parser.parse_args(['monitor', '--interface', 'eth0'])
        result = cli._handle_monitor(args)
        
        assert result == 0
        mock_monitor.assert_called_once()

def test_analyze_command_file(cli):
    """Test analyze command with file input."""
    with patch('app.components.packet_capture.PacketCapture.analyze_pcap') as mock_analyze:
        mock_analyze.return_value = {
            'packet_count': 100,
            'duration_seconds': 10,
            'protocols': {'TCP': 60, 'UDP': 40}
        }
        
        args = cli.parser.parse_args(['analyze', '--file', 'test.pcap'])
        result = cli._handle_analyze(args)
        
        assert result == 0
        mock_analyze.assert_called_once()

def test_config_get_command(cli):
    """Test config get command."""
    with patch('app.utils.config.ConfigManager.get') as mock_get:
        mock_get.return_value = {'key': 'value'}
        
        args = cli.parser.parse_args(['config', 'get', 'section', 'key'])
        cli._handle_config(args)
        
        mock_get.assert_called_once_with('section', 'key')

def test_config_set_command(cli):
    """Test config set command."""
    with patch('app.utils.config.ConfigManager.set') as mock_set:
        mock_set.return_value = True
        
        args = cli.parser.parse_args(['config', 'set', 'section', 'key', 'value'])
        cli._handle_config(args)
        
        mock_set.assert_called_once_with('section', 'key', 'value')

def test_invalid_command(cli):
    """Test handling of invalid command."""
    with pytest.raises(SystemExit):
        cli.parser.parse_args(['invalid_command'])

def test_keyboard_interrupt_handling(cli):
    """Test handling of keyboard interrupt."""
    with patch('app.components.device_discovery.DeviceDiscovery.discover') as mock_discover:
        mock_discover.side_effect = KeyboardInterrupt()
        
        result = cli.run(['scan', '--subnet', '192.168.1.0/24'])
        assert result == 130  # Standard exit code for SIGINT 