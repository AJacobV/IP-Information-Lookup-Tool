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
import tkinter as tk
 # Used to create the graphical user interface
from tkinter import messagebox, scrolledtext
 # Used for popup messages and scrollable text area

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
    
    main_ip = ip_data.get('ip', 'N/A')
    ip_version = ip_data.get('version', 'IP').upper()
    isp = ip_data.get('isp', 'N/A')
    asn = ip_data.get('asn', 'N/A')
    city = ip_data.get('city', 'N/A')
    region = ip_data.get('region', 'N/A')
    country_code = ip_data.get('country_code', 'N/A')
    location = f"{city}, {region}, {country_code}"
    
    # Format the information as a string to return
    info_text = f"\n--- {title} ---\n"
    info_text += f"{f'{ip_version} Address:':<25} {main_ip}\n"
    
    if ipv6_address:
        info_text += f"{'Public IPv6 Address:':<25} {ipv6_address}\n"
        
    info_text += "-" * 45 + "\n"
    info_text += f"{'ISP Provider:':<25} {isp}\n"
    info_text += f"{'ASN:':<25} {asn}\n"
    info_text += f"{'Geolocation:':<25} {location}\n"
    info_text += "-----------------------------------------------\n"
    
    return info_text

# GUI Class to create the main window
class IPCheckerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("IP Information Lookup Tool")
        self.root.geometry("600x500")
        self.root.configure(bg='#f0f0f0')
        
        # Main title
        title = tk.Label(root, text="IP Information Lookup Tool", 
                        font=('Arial', 16, 'bold'), bg='#f0f0f0')
        title.pack(pady=10)
        
        # Button frame
        button_frame = tk.Frame(root, bg='#f0f0f0')
        button_frame.pack(pady=10)
        
        # Get my IP button
        self.my_ip_btn = tk.Button(button_frame, text="Get My IP Information", 
                                  command=self.get_my_ip, font=('Arial', 12),
                                  bg='#4CAF50', fg='white', padx=20, pady=10)
        self.my_ip_btn.pack(pady=5)
        
        # IP lookup frame
        lookup_frame = tk.Frame(root, bg='#f0f0f0')
        lookup_frame.pack(pady=10)
        
        # IP input label and entry
        ip_label = tk.Label(lookup_frame, text="Enter IP Address to lookup:", 
                           font=('Arial', 12), bg='#f0f0f0')
        ip_label.pack()
        
        self.ip_entry = tk.Entry(lookup_frame, font=('Arial', 12), width=20)
        self.ip_entry.pack(pady=5)
        
        # Lookup IP button
        self.lookup_btn = tk.Button(lookup_frame, text="Look Up IP", 
                                   command=self.lookup_ip, font=('Arial', 12),
                                   bg='#2196F3', fg='white', padx=20, pady=10)
        self.lookup_btn.pack(pady=5)
        
        # Results text area with scrollbar
        self.result_text = scrolledtext.ScrolledText(root, width=70, height=20, 
                                                    font=('Courier', 10))
        self.result_text.pack(pady=20, padx=20, fill=tk.BOTH, expand=True)
        
        # Status label
        self.status_label = tk.Label(root, text="Ready", 
                                    font=('Arial', 10), bg='#f0f0f0')
        self.status_label.pack(pady=5)
    
    def update_status(self, message):
        """Update the status label"""
        self.status_label.config(text=message)
        self.root.update()
    
    def get_my_ip(self):
        """Get current computer's IP information"""
        self.result_text.delete(1.0, tk.END)
        self.update_status("Getting your IP information...")
        
        try:
            ip_details = get_public_ip_info()
            if ip_details:
                ipv6 = get_public_ipv6()
                info_text = display_info(ip_details, ipv6)
                self.result_text.insert(tk.END, info_text)
                self.update_status("Successfully retrieved your IP information")
            else:
                self.result_text.insert(tk.END, "Failed to retrieve IP information. Please check your internet connection.")
                self.update_status("Failed to get IP information")
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred: {str(e)}")
            self.update_status("Error occurred")
    
    def lookup_ip(self):
        """Look up specific IP address"""
        ip_to_lookup = self.ip_entry.get().strip()
        
        if not ip_to_lookup:
            messagebox.showwarning("Input Required", "Please enter an IP address to lookup.")
            return
        
        self.result_text.delete(1.0, tk.END)
        self.update_status(f"Looking up {ip_to_lookup}...")
        
        try:
            if is_valid_ip(ip_to_lookup):
                # Check if the IP is private/reserved
                ip_obj = ipaddress.ip_address(ip_to_lookup)
                if not ip_obj.is_global:
                    status_text = f"\n--- IP Address Status ---\n"
                    status_text += f"The IP address '{ip_to_lookup}' is a reserved address.\n"
                    
                    if ip_obj.is_private:
                        status_text += "Status: This IP is in a private network range (e.g., a home or corporate LAN).\n"
                    elif ip_obj.is_loopback:
                        status_text += "Status: This is a loopback address (refers to the local machine).\n"
                    elif ip_obj.is_reserved:
                        status_text += "Status: This IP is reserved for a special use-case by the IETF.\n"
                    
                    status_text += "It cannot be looked up for public geolocation information.\n"
                    self.result_text.insert(tk.END, status_text)
                    self.update_status("IP is reserved/private")
                    return
                
                # If the code reaches here, the IP is valid and public
                ip_details = get_public_ip_info(target_ip=ip_to_lookup)
                if ip_details:
                    info_text = display_info(ip_details, None)
                    self.result_text.insert(tk.END, info_text)
                    self.update_status("Successfully looked up IP information")
                else:
                    self.result_text.insert(tk.END, "Failed to retrieve IP information. Please try again.")
                    self.update_status("Failed to lookup IP")
            else:
                messagebox.showerror("Invalid IP", "Invalid IP address format. Please enter a valid IPv4 or IPv6 address.")
                self.update_status("Invalid IP address")
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred: {str(e)}")
            self.update_status("Error occurred")

# Main program that creates and runs the GUI
def main():
    """Main function that starts the GUI application"""
    root = tk.Tk()
    app = IPCheckerGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()