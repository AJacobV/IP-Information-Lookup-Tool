Overview
This command-line tool retrieves public IP information for the running host or for a user-specified IP address, normalizing results across multiple providers and failing over automatically if one provider is unavailable. It also checks and reports whether a user-supplied IP is private, loopback, or otherwise reserved using Python’s built-in ipaddress library before attempting any external lookup. Optional IPv6 discovery is performed via SeeIP’s IPv6-capable endpoint to display a public IPv6 address when available

Features
- Self-lookup mode that returns geolocation and network data for the caller using public IP APIs that support both IPv4 and IPv6.
- Target lookup mode that fetches details for a specific IPv4 or IPv6 address, normalizing key fields such as IP, version, ASN, organization/ISP, city, region, and country code.
- Reserved/private detection using Python’s ipaddress to block lookups for private, loopback, and other reserved ranges with clear messages.
- Failover across multiple providers to improve reliability when an upstream endpoint is slow or unavailable.
- Optional IPv6 display using SeeIP’s JSON IP endpoint for networks with IPv6 connectivity.

Requirements
- Python 3 and the requests HTTP library are required to perform API calls and parse responses.
- Install requests via pip if not already present, for example using python -m pip install requests.
