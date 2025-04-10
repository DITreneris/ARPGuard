# Gateway Configuration Guide

This guide explains how to configure gateway detection in ARP Guard for optimal protection against ARP spoofing attacks.

## Why Gateway Configuration Matters

Your network gateway (router) is a primary target for ARP spoofing attacks. Correctly configuring your gateway information allows ARP Guard to:

- Detect unauthorized changes to gateway MAC addresses
- Prioritize traffic involving gateway devices
- Alert you to potential "man-in-the-middle" attacks
- Prevent loss of internet connectivity due to ARP spoofing

## Automatic Gateway Detection

By default, ARP Guard automatically detects your network gateway. This works in most standard network configurations.

1. Open ARP Guard and go to the **Dashboard**
2. Under **Network Status**, verify that a gateway was detected:
   - Gateway IP should show your router's IP (typically 192.168.1.1 or similar)
   - Gateway MAC should show your router's MAC address

![Gateway Detection](../images/gateway_detection.png)

## Manual Gateway Configuration

In some cases, you may need to manually configure your gateway information:

1. Go to **Settings → Network → Gateway Configuration**
2. Turn off "Auto-detect gateway"
3. Enter your gateway information:
   - **Gateway IP**: Your router's IP address
   - **Gateway MAC**: Your router's MAC address
4. Click **Save Changes**

![Manual Gateway Configuration](../images/manual_gateway_config.png)

## How to Find Your Gateway Information

### Windows

1. Open Command Prompt (cmd)
2. Type `ipconfig` and press Enter
3. Look for "Default Gateway" - this is your gateway IP
4. Type `arp -a` and press Enter
5. Find the entry matching your gateway IP to get the MAC address

### macOS

1. Open Terminal
2. Type `netstat -nr | grep default` and press Enter
3. The first column shows your gateway IP
4. Type `arp -a` and press Enter
5. Find the entry matching your gateway IP to get the MAC address

### Linux

1. Open Terminal
2. Type `ip route | grep default` and press Enter
3. Look for "default via X.X.X.X" - X.X.X.X is your gateway IP
4. Type `arp -n` and press Enter
5. Find the entry matching your gateway IP to get the MAC address

## Multiple Gateway Configuration

ARP Guard supports networks with multiple gateways. To configure multiple gateways:

1. Go to **Settings → Network → Gateway Configuration**
2. Click **Add Gateway**
3. Enter the additional gateway information
4. Click **Save Changes**

## Configuration for VPN Users

If you use a VPN, follow these additional steps:

1. Go to **Settings → Network → Advanced**
2. Enable "Monitor VPN interfaces"
3. Add your VPN gateway information in the Gateway Configuration section
4. Enable "Dynamic gateway tracking" for better handling of VPN connections

## Verifying Your Configuration

To verify your gateway configuration is working correctly:

1. Go to **Tools → Network Scan**
2. Click **Scan Now**
3. When the scan completes, verify your gateway appears with a shield icon 🛡️
4. Click on the gateway device and select **Verify Gateway**

ARP Guard will confirm if it can correctly identify and monitor your gateway.

## Troubleshooting

### Gateway Not Detected

If ARP Guard fails to detect your gateway automatically:

1. **Check network connection**: Ensure you're connected to the network
2. **Check router/gateway**: Ensure your router is powered on and functioning
3. **Try network scan**: Run a network scan to detect all devices
4. **Configure manually**: Use the manual configuration steps above

### Gateway Changes Frequently

If you notice your gateway MAC address changes frequently:

1. **Check for multiple access points**: Some mesh networks use multiple devices
2. **Check for DHCP issues**: Your DHCP server might be assigning different gateways
3. **Consider ISP equipment**: Some ISPs update equipment MAC addresses periodically
4. **Configure trusted MAC range**: Add multiple trusted MAC addresses in settings

### False Alerts About Gateway

If you receive false alerts about gateway spoofing:

1. **Check for network changes**: Recent router replacement or firmware updates
2. **Update gateway information**: Reconfigure with current information
3. **Adjust sensitivity**: Go to **Settings → Detection → Sensitivity** and lower it
4. **Add to trusted devices**: Add the flagged MAC to your trusted devices list

### "Unknown Gateway" Warning

If you see an "Unknown Gateway" warning:

1. **Network configuration issue**: Your network might have multiple default routes
2. **Update gateway information**: Configure with current gateway details
3. **Check for VPN**: Disable VPN temporarily to test with your regular network
4. **Contact support**: If the issue persists, please contact our support team

## Configuration File Reference

Advanced users can directly edit the gateway configuration file:

**Location**: `<installation_directory>/data/gateway_info.json`

**Format**:
```json
{
  "ip": "192.168.1.1",
  "mac": "aa:bb:cc:dd:ee:ff",
  "last_seen": 1634567890.123,
  "verified": true
}
```

**Multiple Gateways Format**:
```json
{
  "ip": ["192.168.1.1", "10.0.0.1"],
  "mac": ["aa:bb:cc:dd:ee:ff", "11:22:33:44:55:66"],
  "last_seen": 1634567890.123,
  "verified": true
}
```

**Warning**: Editing this file manually may cause issues if the format is incorrect. Always back up the file before making changes.

## Flowchart: Gateway Configuration Decision

```
┌─────────────────┐
│ Start           │
└────────┬────────┘
         ▼
┌─────────────────┐     ┌─────────────────┐
│ Is this a       │ Yes │ Use automatic   │
│ standard home   ├────►│ detection       │
│ network?        │     └────────┬────────┘
└────────┬────────┘              │
         │ No                    │
         ▼                       │
┌─────────────────┐              │
│ Do you have     │ Yes          │
│ multiple        ├────┐         │
│ gateways?       │    │         │
└────────┬────────┘    │         │
         │ No          │         │
         ▼             ▼         ▼
┌─────────────────┐  ┌─────────────────┐
│ Using VPN or    │  │ Configure each  │
│ custom network  │  │ gateway manually │
│ configuration?  │  └────────┬────────┘
└────────┬────────┘           │
         │ Yes                │
         ▼                    │
┌─────────────────┐           │
│ Configure       │           │
│ manually with   │           │
│ advanced options│           │
└────────┬────────┘           │
         │                    │
         ▼                    ▼
┌─────────────────┐  ┌─────────────────┐
│ Test with       │  │ Verify with     │
│ network scan    │◄─┤ network scan    │
└────────┬────────┘  └─────────────────┘
         │
         ▼
┌─────────────────┐
│ Done            │
└─────────────────┘
```

## Performance Considerations

The gateway detection module has minimal performance impact, but for best results:

- **Standard networks**: Use automatic detection
- **Resource-constrained devices**: Use Lite Mode in settings
- **Complex networks**: Configure gateways manually for better accuracy

## Support

If you need additional help with gateway configuration:

- Visit our [online knowledge base](https://arpguard.example.com/support)
- Email our support team at support@arpguard.example.com
- Check our community forums for user-contributed tips

---

**Next steps:** After configuring your gateway, we recommend setting up [Alert Notifications](./alerts.md) to be notified of potential attacks. 