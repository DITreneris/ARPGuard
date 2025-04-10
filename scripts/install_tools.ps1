# Install Wireshark
Write-Host "Installing Wireshark..."
winget install WiresharkFoundation.Wireshark

# Install iPerf3
Write-Host "Installing iPerf3..."
winget install iPerf3

# Install Python packages
Write-Host "Installing Python packages..."
python -m pip install -r requirements.txt

Write-Host "Installation complete. Please restart your terminal for changes to take effect." 