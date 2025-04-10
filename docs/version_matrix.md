# ARP Guard API - Version Compatibility Matrix

This document provides information about the compatibility between different versions of the ARP Guard API and client libraries.

## API Versions

| API Version | Release Date | Status | Support End Date |
|-------------|--------------|--------|------------------|
| 1.0.0       | 2023-06-01   | Stable | 2024-12-31       |
| 0.9.0       | 2023-01-15   | Legacy | 2023-12-31       |
| 0.8.0       | 2022-09-01   | Deprecated | 2023-09-30   |

## Client Libraries

### Python Client

| Client Version | API Compatibility | Python Version | Dependencies |
|----------------|-------------------|----------------|--------------|
| 0.1.0          | 1.0.0             | >=3.7          | requests>=2.25.0, urllib3>=1.26.0 |

### TypeScript/JavaScript Client

| Client Version | API Compatibility | Node.js Version | Dependencies |
|----------------|-------------------|-----------------|--------------|
| 0.1.0          | 1.0.0             | >=16.0.0        | axios^1.6.0  |

### PHP Client

| Client Version | API Compatibility | PHP Version | Dependencies |
|----------------|-------------------|-------------|--------------|
| 0.1.0          | 1.0.0             | >=7.4       | guzzlehttp/guzzle^7.0 |

## Feature Support Matrix

This matrix shows the features supported by each client library version.

| Feature               | Python 0.1.0 | TypeScript 0.1.0 | PHP 0.1.0 |
|-----------------------|--------------|------------------|-----------|
| Authentication        | ✓            | ✓                | ✓         |
| Device Management     | ✓            | ✓                | ✓         |
| Alert Management      | ✓            | ✓                | ✓         |
| Network Management    | ✓            | ✓                | ✓         |
| Statistics            | ✓            | ✓                | ✓         |
| Rate Limit Handling   | ✓            | ✓                | ✓         |
| Automatic Retries     | ✓            | ✓                | ✓         |

## Rate Limiting Implementation

All client libraries implement token-based rate limiting with the following features:

1. **Rate Limit Headers**: All API responses include the following headers:
   - `X-RateLimit-Limit`: The maximum number of requests allowed
   - `X-RateLimit-Remaining`: The number of requests remaining in the current time window
   - `X-RateLimit-Reset`: Unix timestamp when the rate limit resets
   - `X-RateLimit-Type`: Type of rate limit applied (IP, user, token, endpoint)

2. **Automatic Handling**: All clients support automatic handling of rate limits by:
   - Extracting rate limit information from response headers
   - Waiting and retrying when a rate limit is exceeded
   - Respecting the `Retry-After` header

3. **Manual Control**: All clients allow disabling automatic rate limit handling

4. **Rate Limit Information**: All clients provide methods to access current rate limit information

## Upgrade Notes

### Upgrading from API 0.9.0 to 1.0.0

When upgrading from API version 0.9.0 to 1.0.0, note the following changes:

1. Authentication now requires both API key and API secret
2. Rate limiting has been implemented more strictly
3. Endpoint paths have changed from `/api/v0.9/...` to `/api/v1/...`
4. Response formats have been standardized

### Future Plans

The following features are planned for upcoming releases:

1. WebSocket support for real-time alerts
2. Batch operations for device management
3. Enhanced security features
4. Support for additional programming languages 