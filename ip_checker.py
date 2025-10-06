#!/usr/bin/env python3

"""
IP Addressing Information Prototype (with User Menu, Lookup, and Reserved IP Check)
Team members: 
Jason Wendell Agilada - Team Leader
Angelo Jacob Valeros - Developer
Julian Alfonso Cabansag - Developer
Vince Tyrone Vermudo - Quality Assurance
Created Date: 2025-10-04

Description:
This application allows a user to either retrieve their own public IP
addressing information or look up details for a specific IP address.
It now intelligently detects and handles reserved/private IP addresses.
It uses a list of public REST APIs with a failover mechanism.
"""

import requests
 # Used to send HTTP requests to online IP info services
import ipaddress
 # Used to check and handle IP address formats (IPv4/IPv6)
import sys
 # Used for system exit and command-line operations

API_PROVIDERS = [
 # List of online services to get IP information
    {
        'name': 'ipapi.co',
        'url': 'https://ipapi.co/json/',
        'lookup_url': 'https://ipapi.co/{ip}/json/'
    },
    {
        'name': 'ipinfo.io',
        'url': 'https://ipinfo.io/json',
        'lookup_url': 'https://ipinfo.io/{ip}/json'
    },
    {
        'name': 'freegeoip.app',
        'url': 'https://freegeoip.app/json/',
        'lookup_url': 'https://freegeoip.app/json/{ip}'
    }
]

IPV6_INFO_URL = "https://v6.seeip.org/jsonip"
 # URL to get your public IPv6 address

# Function to convert different API responses into the same format
def normalize_data(data, provider_name):
    """Translates JSON data from different APIs into a standard format."""
    normalized = {}
    if provider_name == 'ipapi.co':
        normalized['ip'] = data.get('ip', 'N/A')
        normalized['version'] = data.get('version', 'N/A')
        normalized['isp'] = data.get('org', 'N/A')
        normalized['asn'] = data.get('asn', 'N/A')
        normalized['city'] = data.get('city', 'N/A')
        normalized['region'] = data.get('region', 'N/A')
        normalized['country_code'] = data.get('country_code', 'N/A')
    elif provider_name == 'ipinfo.io':
        normalized['ip'] = data.get('ip', 'N/A')
        normalized['version'] = 'IPv4' if '.' in data.get('ip', '') else 'IPv6'
        org_data = data.get('org', '')
        normalized['asn'] = org_data.split(' ')[0] if ' ' in org_data else 'N/A'
        normalized['isp'] = ' '.join(org_data.split(' ')[1:]) if ' ' in org_data else org_data
        normalized['city'] = data.get('city', 'N/A')
        normalized['region'] = data.get('region', 'N/A')
        normalized['country_code'] = data.get('country', 'N/A')
    elif provider_name == 'freegeoip.app':
        normalized['ip'] = data.get('ip', 'N/A')
        normalized['version'] = 'IPv4' if '.' in data.get('ip', '') else 'IPv6'
        normalized['isp'] = data.get('isp', 'N/A')
        normalized['asn'] = 'N/A'
        normalized['city'] = data.get('city', 'N/A')
        normalized['region'] = data.get('region_name', 'N/A')
        normalized['country_code'] = data.get('country_code', 'N/A')
    return normalized

# Function to check if a string is a valid IP address
def is_valid_ip(ip_string):
    """Checks if the provided string is a valid IPv4 or IPv6 address."""
    try:
        ipaddress.ip_address(ip_string)
        return True
    except ValueError:
        return False

# Function to get IP information from online services
def get_public_ip_info(target_ip=None):
    """Fetches IP info, either for the user or a specified target IP."""
    for provider in API_PROVIDERS:
        if target_ip:
            url = provider['lookup_url'].format(ip=target_ip)
            print(f"--> Looking up {target_ip} using {provider['name']}...")
        else:
            url = provider['url']
            print(f"--> Attempting to fetch data from {provider['name']}...")
        
        try:
            response = requests.get(url, timeout=5)
            response.raise_for_status()
            raw_data = response.json()
            print(f"--> Success from {provider['name']}!")
            return normalize_data(raw_data, provider['name'])
        except requests.exceptions.RequestException as e:
            print(f"--> Failed to connect to {provider['name']}. Details: {e}")
            continue
    
    print("Error: All API providers failed.")
    return None

# Function to get your public IPv6 address
def get_public_ipv6():
    """Fetches the user's public IPv6 address."""
    print("--> Checking for public IPv6 address...")
    try:
        response = requests.get(IPV6_INFO_URL, timeout=3)
        response.raise_for_status()
        return response.json().get("ip")
    except requests.exceptions.RequestException:
        return "Not available on this network"

# Function to display IP information in a nice format
def display_info(ip_data, ipv6_address=None):
    """Formats and displays the collected IP information."""
    title = "Public IP Address Information"
    if ipv6_address is None:
        title = f"Information for IP: {ip_data.get('ip', '')}"
    
    print(f"\n--- {title} ---")
    
    main_ip = ip_data.get('ip', 'N/A')
    ip_version = ip_data.get('version', 'IP').upper()
    isp = ip_data.get('isp', 'N/A')
    asn = ip_data.get('asn', 'N/A')
    city = ip_data.get('city', 'N/A')
    region = ip_data.get('region', 'N/A')
    country_code = ip_data.get('country_code', 'N/A')
    location = f"{city}, {region}, {country_code}"
    
    print(f"{f'{ip_version} Address:':<25} {main_ip}")
    
    if ipv6_address:
        print(f"{'Public IPv6 Address:':<25} {ipv6_address}")
        
    print("-" * 45)
    print(f"{'ISP Provider:':<25} {isp}")
    print(f"{'ASN:':<25} {asn}")
    print(f"{'Geolocation:':<25} {location}")
    print("-----------------------------------------------\n")

# Main program that shows menu and handles user choices
def main():
    """Main function with menu and reserved IP address handling."""
    
    print("========================================")
    print("     IP Information Lookup Tool")
    print("========================================")
    print("Please select an option:")
    print("  1. Get my own computer's IP information")
    print("  2. Look up a specific IP address")
    print("========================================")
    
    choice = input("Enter your choice (1 or 2): ")
    
    ip_details = None
    
    if choice == '1':
        ip_details = get_public_ip_info()
        if ip_details:
            ipv6 = get_public_ipv6()
            display_info(ip_details, ipv6)
            
    elif choice == '2':
        ip_to_lookup = input("Enter the IP address to look up: ")
        if is_valid_ip(ip_to_lookup):
            # --- NEW: Check if the IP is private/reserved before calling the API ---
            ip_obj = ipaddress.ip_address(ip_to_lookup)
            if not ip_obj.is_global:
                print("\n--- IP Address Status ---")
                print(f"The IP address '{ip_to_lookup}' is a reserved address.")
                # Provide more specific information if possible
                if ip_obj.is_private:
                    print("Status: This IP is in a private network range (e.g., a home or corporate LAN).")
                elif ip_obj.is_loopback:
                    print("Status: This is a loopback address (refers to the local machine).")
                elif ip_obj.is_reserved:
                    print("Status: This IP is reserved for a special use-case by the IETF.")
                print("It cannot be looked up for public geolocation information.\n")
                sys.exit(0)
            
            
            # If the code reaches here, the IP is valid and public
            ip_details = get_public_ip_info(target_ip=ip_to_lookup)
            if ip_details:
                display_info(ip_details, None)
        else:
            print("\nError: Invalid IP address format. Please enter a valid IPv4 or IPv6 address.")
            sys.exit(1)
            
    else:
        print("\nError: Invalid choice. Please run the script again and enter 1 or 2.")
        sys.exit(1)

    if not ip_details:
        print("\nApplication failed to retrieve IP details. Exiting.")

if __name__ == "__main__":
    main()