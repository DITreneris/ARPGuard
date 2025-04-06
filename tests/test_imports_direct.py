import sys
import os

# Add the app directory to the Python path
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'app'))

def test_imports():
    """Test imports and print results"""
    results = []
    
    # Core imports
    try:
        import components
        results.append(("Core components module", True))
    except ImportError as e:
        results.append(("Core components module", False, str(e)))
    
    # Component modules
    components_to_test = [
        "main_window",
        "network_scanner",
        "threat_detector",
        "arp_spoofer",
        "packet_view",
        "packet_analyzer",
        "session_history"
    ]
    
    for component in components_to_test:
        try:
            module = __import__(f"components.{component}", fromlist=[component])
            results.append((f"components.{component}", True))
        except ImportError as e:
            results.append((f"components.{component}", False, str(e)))
    
    # Utility modules
    utils_to_test = [
        "config",
        "database",
        "logger",
        "mac_vendor"
    ]
    
    for util in utils_to_test:
        try:
            module = __import__(f"utils.{util}", fromlist=[util])
            results.append((f"utils.{util}", True))
        except ImportError as e:
            results.append((f"utils.{util}", False, str(e)))
    
    # Print results
    print("\n=== Import Test Results ===")
    success_count = 0
    total_count = len(results)
    
    for result in results:
        if result[1]:
            print(f"✅ {result[0]}: OK")
            success_count += 1
        else:
            print(f"❌ {result[0]}: Failed - {result[2]}")
    
    print(f"\nSummary: {success_count}/{total_count} imports successful ({success_count / total_count * 100:.1f}%)")

if __name__ == "__main__":
    test_imports() 