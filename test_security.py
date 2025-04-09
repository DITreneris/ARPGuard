import pytest
import json
import os
import tempfile
import subprocess
import base64
import hashlib
from pathlib import Path
from scapy.all import *
from arpguard.core import PacketCaptureEngine, AnalysisEngine
from arpguard.config import ConfigManager
from arpguard.storage import StorageManager
from arpguard.security import CredentialManager

class TestSecurity:
    @pytest.fixture
    def setup_environment(self):
        """Setup test environment with necessary components"""
        config = ConfigManager()
        pce = PacketCaptureEngine(config)
        ae = AnalysisEngine(config)
        sm = StorageManager(config)
        cm = CredentialManager(config)
        return config, pce, ae, sm, cm
    
    def test_config_input_validation(self, setup_environment):
        """Test S-001: Input validation for configuration"""
        config, _, _, _, _ = setup_environment
        
        # Test case 1: Invalid interface name
        with pytest.raises(ValueError, match="Invalid interface name"):
            config.set_interface("invalid_interface_!@#$%")
            
        # Test case 2: Invalid monitoring mode
        with pytest.raises(ValueError, match="Invalid monitoring mode"):
            config.set_monitoring_mode("super_aggressive_mode")
            
        # Test case 3: Invalid logging level
        with pytest.raises(ValueError, match="Invalid logging level"):
            config.set_logging_level("EXTREME_DETAIL")
            
        # Test case 4: Invalid network range
        with pytest.raises(ValueError, match="Invalid network range"):
            config.set_network_range("999.999.999.0/24")
            
        # Test case 5: SQL injection in log file path
        with pytest.raises(ValueError, match="Invalid log file path"):
            config.set_log_file("../logs/log.txt; DROP TABLE users;")
            
        # Test case 6: Deeply nested JSON configuration (potential DoS)
        deep_nesting = {}
        current = deep_nesting
        for i in range(100):  # Create a deeply nested structure
            current["nested"] = {}
            current = current["nested"]
            
        with tempfile.NamedTemporaryFile(mode='w+', suffix='.json', delete=False) as temp:
            json.dump(deep_nesting, temp)
            temp_path = temp.name
            
        with pytest.raises(ValueError, match="Configuration too complex"):
            config.load_from_file(temp_path)
            
        # Clean up
        os.unlink(temp_path)
        
        # Test case 7: Overly large configuration file (potential DoS)
        with tempfile.NamedTemporaryFile(mode='w+', suffix='.json', delete=False) as temp:
            # Create a 10MB configuration file
            large_data = {"data": "X" * 10_000_000}
            json.dump(large_data, temp)
            temp_path = temp.name
            
        with pytest.raises(ValueError, match="Configuration file too large"):
            config.load_from_file(temp_path)
            
        # Clean up
        os.unlink(temp_path)
        
        # Test valid configuration
        valid_config = {
            "interface": "eth0",
            "monitoring_mode": "passive",
            "logging_level": "INFO",
            "network_range": "192.168.1.0/24",
            "log_file": "arpguard.log"
        }
        
        with tempfile.NamedTemporaryFile(mode='w+', suffix='.json', delete=False) as temp:
            json.dump(valid_config, temp)
            temp_path = temp.name
            
        # This should not raise an exception
        config.load_from_file(temp_path)
        
        # Clean up
        os.unlink(temp_path)
        
        # Verify configuration was loaded correctly
        assert config.get_interface() == "eth0"
        assert config.get_monitoring_mode() == "passive"
        assert config.get_logging_level() == "INFO"
        assert config.get_network_range() == "192.168.1.0/24"
        assert config.get_log_file() == "arpguard.log"
        
    def test_packet_injection_protection(self, setup_environment):
        """Test S-002: Protection against packet injection"""
        _, pce, ae, _, _ = setup_environment
        
        # Test case 1: Malformed packet with invalid ethernet header
        malformed_packet = b'\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xdd'  # Truncated
        
        # Should handle this gracefully without crashing
        try:
            pce.process_raw_packet(malformed_packet)
        except Exception as e:
            pytest.fail(f"Processing malformed packet raised exception: {e}")
            
        # Test case 2: ARP packet with invalid ARP header
        invalid_arp = Ether(dst="ff:ff:ff:ff:ff:ff", src="00:11:22:33:44:55")/b'\x00\x01\x08\x00\x06'  # Truncated ARP
        
        # Should handle this gracefully without crashing
        try:
            result = ae.analyze_packet(invalid_arp)
            assert result.is_valid == False
        except Exception as e:
            pytest.fail(f"Processing invalid ARP packet raised exception: {e}")
            
        # Test case 3: Memory exhaustion attack (very large packet)
        large_packet = Ether()/IP()/TCP()/Raw(b"A" * 9000)  # Jumbo frame size data
        
        # Should handle this gracefully without excessive memory usage
        before_mem = Process().memory_info().rss
        try:
            pce.process_packet(large_packet)
        except Exception as e:
            pytest.fail(f"Processing large packet raised exception: {e}")
            
        after_mem = Process().memory_info().rss
        memory_increase = (after_mem - before_mem) / 1024 / 1024  # MB
        
        # Ensure memory increase is reasonable (less than 1MB for a single packet)
        assert memory_increase < 1.0, f"Memory increase too large: {memory_increase} MB"
        
        # Test case 4: Crafted ARP packet with inconsistent information
        # IP says 192.168.1.1 but ARP says 192.168.1.2
        inconsistent_packet = Ether(dst="ff:ff:ff:ff:ff:ff", src="00:11:22:33:44:55")/\
                              ARP(hwsrc="00:11:22:33:44:55", psrc="192.168.1.2")/\
                              IP(src="192.168.1.1")
        
        # Should detect this inconsistency
        result = ae.analyze_packet(inconsistent_packet)
        assert result.is_spoofing == True, "Failed to detect inconsistent packet information"
        
        # Test case 5: Crafted ARP reply storm (potential DoS)
        packets = []
        for i in range(1000):
            # Generate many different ARP replies
            packets.append(
                Ether(dst="ff:ff:ff:ff:ff:ff", src=f"00:11:22:33:44:{i%255:02x}")/
                ARP(op=2, hwsrc=f"00:11:22:33:44:{i%255:02x}", 
                    psrc=f"192.168.1.{i%254+1}", 
                    hwdst="00:aa:bb:cc:dd:ee", 
                    pdst="192.168.1.100")
            )
        
        # Process all packets (should handle this without crashing or excessive resource use)
        start_time = time.time()
        for packet in packets:
            pce.process_packet(packet)
            ae.analyze_packet(packet)
            
        end_time = time.time()
        duration = end_time - start_time
        
        # Should process at a reasonable rate (at least 10,000 packets/sec)
        rate = len(packets) / duration
        assert rate > 10000, f"Processing rate too slow under DoS condition: {rate:.2f} packets/sec"
        
    def test_secure_credential_storage(self, setup_environment):
        """Test S-003: Secure storage of credentials"""
        config, _, _, _, cm = setup_environment
        
        # Test case 1: Credential encryption
        test_creds = {
            "api_key": "secret_api_key_12345",
            "username": "admin_user",
            "password": "super_secure_password"
        }
        
        # Store credentials
        cm.store_credentials(test_creds)
        
        # Check that the storage file exists
        creds_file = Path(config.get_credentials_path())
        assert creds_file.exists(), "Credentials file not created"
        
        # File should be read-only for the current user
        assert oct(creds_file.stat().st_mode)[-3:] in ('400', '600'), "Credential file has wrong permissions"
        
        # Read the raw file contents
        with open(creds_file, 'r') as f:
            stored_data = f.read()
            
        # Raw storage should not contain the actual credentials
        assert "secret_api_key_12345" not in stored_data, "API key stored in plaintext"
        assert "super_secure_password" not in stored_data, "Password stored in plaintext"
        
        # Should be able to retrieve and decrypt credentials
        retrieved_creds = cm.get_credentials()
        assert retrieved_creds["api_key"] == "secret_api_key_12345", "API key not correctly retrieved"
        assert retrieved_creds["password"] == "super_secure_password", "Password not correctly retrieved"
        
        # Test case 2: Protection against tampering
        # Tamper with the credential file
        with open(creds_file, 'r+') as f:
            data = json.load(f)
            # Modify the encrypted data slightly
            if 'encrypted_data' in data:
                modified_data = list(base64.b64decode(data['encrypted_data']))
                modified_data[10] = (modified_data[10] + 1) % 256  # Change one byte
                data['encrypted_data'] = base64.b64encode(bytes(modified_data)).decode('utf-8')
                f.seek(0)
                json.dump(data, f)
                f.truncate()
        
        # Attempt to read tampered credentials should raise an exception
        with pytest.raises(ValueError, match="Credential integrity check failed"):
            cm.get_credentials()
        
        # Test case 3: Attempt to use a weak password for the credential manager
        with pytest.raises(ValueError, match="Password too weak"):
            cm.change_master_password("password123")
            
        # Strong password should be accepted
        cm.change_master_password("C0mpl3x!P@ssw0rd#2023")
        
        # Test case 4: Credential storage at rest uses strong encryption
        # Create a new credential manager with known key for testing
        test_key = hashlib.sha256(b"test_encryption_key").digest()
        test_cm = CredentialManager(config, override_key=test_key)
        
        # Store test credentials
        test_creds = {"api_key": "test_storage_key"}
        test_cm.store_credentials(test_creds)
        
        # Read the raw storage
        with open(config.get_credentials_path(), 'r') as f:
            stored_data = json.load(f)
        
        # Should use strong encryption (AES-GCM)
        assert "algorithm" in stored_data
        assert stored_data["algorithm"] == "AES-GCM", "Not using AES-GCM encryption"
        
        # Should include a random salt
        assert "salt" in stored_data
        salt = base64.b64decode(stored_data["salt"])
        assert len(salt) >= 16, "Salt too small"
        
        # Should have a random initialization vector
        assert "iv" in stored_data
        iv = base64.b64decode(stored_data["iv"])
        assert len(iv) >= 12, "IV too small"

if __name__ == "__main__":
    from psutil import Process  # Import here to avoid issues in test cases
    pytest.main([__file__, "-v"]) 