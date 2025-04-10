# Historical Data Analysis

This document describes the historical data analysis features of the ARPGuard application.

## Overview

ARPGuard's historical data analysis provides powerful tools for examining network security metrics over time. This feature allows administrators to:

- View historical trends of key performance metrics
- Analyze security incidents and attack patterns
- Correlate events across different time periods
- Export historical data for external analysis
- Generate comprehensive reports

## Supported Metrics

The following metrics are available for historical analysis:

| Metric | Description | Unit |
|--------|-------------|------|
| `packets_processed` | Total network packets processed | packets per second |
| `attacks_detected` | Security incidents identified | count |
| `network_throughput` | Network traffic volume | KB/s |
| `cpu_usage` | System CPU utilization | percentage |
| `memory_usage` | System memory utilization | percentage |
| `response_time` | System response time | milliseconds |

## API Endpoints

### Historical Data Retrieval

```http
GET /api/v1/monitor/historical
Authorization: Bearer <token>
```

Required query parameters:
- `metric`: Metric to analyze (one of the supported metrics listed above)
- `start_date`: Start date in ISO format (YYYY-MM-DDTHH:MM:SS)
- `end_date`: End date in ISO format (YYYY-MM-DDTHH:MM:SS)

Optional query parameters:
- `interval`: Interval for data points (1h, 6h, 1d), default: 1h

Example request:
```http
GET /api/v1/monitor/historical?metric=packets_processed&start_date=2024-04-01T00:00:00&end_date=2024-04-02T00:00:00&interval=1h
Authorization: Bearer <token>
```

Response:
```json
{
  "metric": "packets_processed",
  "start_date": "2024-04-01T00:00:00",
  "end_date": "2024-04-02T00:00:00",
  "interval": "1h",
  "data_points": [
    {
      "timestamp": "2024-04-01T00:00:00",
      "value": 1500
    },
    {
      "timestamp": "2024-04-01T01:00:00",
      "value": 1550
    },
    {
      "timestamp": "2024-04-01T02:00:00",
      "value": 1450
    },
    ...
  ]
}
```

## Data Retention Policies

By default, ARPGuard's historical data is retained according to the following policies:

| Resolution | Retention Period |
|------------|------------------|
| 1 minute   | 24 hours         |
| 1 hour     | 30 days          |
| 1 day      | 1 year           |

The data is automatically aggregated to save storage space while maintaining analytical value. For example, after 24 hours, the per-minute data is aggregated to hourly data.

## Data Visualization

The historical data API is designed to feed directly into visualization tools. The ARPGuard UI provides built-in visualization capabilities, but the data can also be exported for use with external tools like:

- Grafana
- Kibana
- Microsoft Power BI
- Tableau

## Usage Examples

### Python Client Example

```python
import requests
import json
from datetime import datetime, timedelta
import matplotlib.pyplot as plt

class ARPGuardHistoricalClient:
    def __init__(self, base_url, token):
        self.base_url = base_url
        self.headers = {
            "Authorization": f"Bearer {token}"
        }
        
    def get_historical_data(self, metric, start_date, end_date, interval="1h"):
        """Get historical data for a specific metric"""
        params = {
            "metric": metric,
            "start_date": start_date.isoformat() if isinstance(start_date, datetime) else start_date,
            "end_date": end_date.isoformat() if isinstance(end_date, datetime) else end_date,
            "interval": interval
        }
        
        response = requests.get(
            f"{self.base_url}/api/v1/monitor/historical",
            headers=self.headers,
            params=params
        )
        response.raise_for_status()
        return response.json()
        
    def plot_data(self, data):
        """Plot historical data using matplotlib"""
        timestamps = [point["timestamp"] for point in data["data_points"]]
        values = [point["value"] for point in data["data_points"]]
        
        plt.figure(figsize=(12, 6))
        plt.plot(timestamps, values)
        plt.title(f"{data['metric']} ({data['interval']} intervals)")
        plt.xlabel("Time")
        plt.ylabel(data["metric"])
        plt.xticks(rotation=45)
        plt.tight_layout()
        plt.grid(True)
        return plt
```

### Usage Example

```python
# Initialize client
client = ARPGuardHistoricalClient("http://localhost:8000", "your_token_here")

# Get historical data for attacks detected in the last 24 hours
end_date = datetime.now()
start_date = end_date - timedelta(days=1)

data = client.get_historical_data(
    metric="attacks_detected",
    start_date=start_date,
    end_date=end_date,
    interval="1h"
)

# Plot the data
plot = client.plot_data(data)
plot.savefig("attacks_last_24h.png")
print(f"Plot saved to attacks_last_24h.png")

# Get CPU usage for the last week with daily intervals
start_date = end_date - timedelta(days=7)
data = client.get_historical_data(
    metric="cpu_usage",
    start_date=start_date,
    end_date=end_date,
    interval="1d"
)

# Print statistics
values = [point["value"] for point in data["data_points"]]
print(f"Average CPU usage: {sum(values) / len(values):.2f}%")
print(f"Maximum CPU usage: {max(values):.2f}%")
print(f"Minimum CPU usage: {min(values):.2f}%")
```

## Analysis Techniques

### Trend Analysis

Trend analysis involves examining metrics over time to identify patterns and predict future behavior. For example:

1. **Linear Trends**: Steady increases or decreases in a metric over time
2. **Cyclic Patterns**: Recurring patterns that may indicate scheduled activities
3. **Anomalies**: Sudden spikes or drops that may indicate security incidents

### Correlating Multiple Metrics

Correlation analysis can reveal relationships between different metrics. For example:

1. **Attack Correlation**: Relationship between `attacks_detected` and `network_throughput`
2. **Performance Impact**: Correlation between `attacks_detected` and `cpu_usage`
3. **System Health**: Relationship between `response_time` and `memory_usage`

### Anomaly Detection

Historical data can be used to establish baselines and detect anomalies. Methods include:

1. **Statistical Methods**: Using standard deviations from the mean
2. **Machine Learning**: Using algorithms to learn normal patterns
3. **Rule-Based Systems**: Using predetermined thresholds

## Best Practices

1. **Data Collection**:
   - Collect data at appropriate intervals based on your needs
   - Ensure consistent collection across all metrics
   - Validate data quality regularly

2. **Data Analysis**:
   - Start with broad time ranges and narrow down as needed
   - Compare similar time periods (e.g., week to week)
   - Look for correlations between related metrics

3. **Reporting**:
   - Generate regular reports for key stakeholders
   - Include context with technical data
   - Focus on actionable insights

4. **Storage Management**:
   - Implement appropriate data retention policies
   - Archive historical data as needed
   - Balance storage needs with analytical value

## Integration with Other Systems

Historical data can be integrated with other systems for comprehensive security monitoring:

1. **SIEM Systems**: Export data to security information and event management systems
2. **Compliance Reporting**: Use historical data for compliance audits
3. **Executive Dashboards**: Provide high-level metrics for management review

## Troubleshooting

### Common Issues

1. **Missing Data Points**
   - Check data collection service uptime
   - Verify that no gaps exist in the collection schedule
   - Ensure proper error handling during collection

2. **Incorrect Values**
   - Validate sensor calibration
   - Check for overflow or rollover issues
   - Verify proper unit conversion

3. **Performance Issues**
   - Use appropriate interval for the time range
   - Limit queries to necessary metrics
   - Consider using data aggregation for long time periods 