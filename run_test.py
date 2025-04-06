import sys
import pytest
import os

def main():
    """Run the tests programmatically."""
    print("Starting tests...")
    
    # Define the test file path
    test_file = "tests/test_simple.py"
    
    # Check if the file exists
    if not os.path.exists(test_file):
        print(f"Test file not found: {test_file}")
        return 1
    
    print(f"Running tests in {test_file}")
    
    # Run pytest programmatically
    # Disable pytest-qt plugin with -p no:qt
    args = ["-v", "-p", "no:qt", test_file]
    result = pytest.main(args)
    
    # Print the result
    print(f"Test result: {result}")
    return result

if __name__ == "__main__":
    sys.exit(main()) 