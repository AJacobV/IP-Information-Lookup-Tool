#!/usr/bin/env python3

"""
IP Addressing Information Tool with GUI
Team members: 
Jason Wendell Agilada - Team Leader
Angelo Jacob Valeros - Developer
Julian Alfonso Cabansag - Developer
Vince Tyrone Vermudo - Quality Assurance
Created Date: 2025-10-04

Description:
This application allows a user to either retrieve their own public IP
addressing information or look up details for a specific IP address.
It now includes a modern graphical user interface.
"""

import requests
import ipaddress
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import threading

API_PROVIDERS = [
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


def is_valid_ip(ip_string):
    """Checks if the provided string is a valid IPv4 or IPv6 address."""
    try:
        ipaddress.ip_address(ip_string)
        return True
    except ValueError:
        return False


def get_public_ip_info(target_ip=None):
    """Fetches IP info, either for the user or a specified target IP."""
    for provider in API_PROVIDERS:
        if target_ip:
            url = provider['lookup_url'].format(ip=target_ip)
        else:
            url = provider['url']
        
        try:
            response = requests.get(url, timeout=5)
            response.raise_for_status()
            raw_data = response.json()
            return normalize_data(raw_data, provider['name'])
        except requests.exceptions.RequestException:
            continue
    
    return None


def get_public_ipv6():
    """Fetches the user's public IPv6 address."""
    try:
        response = requests.get(IPV6_INFO_URL, timeout=3)
        response.raise_for_status()
        return response.json().get("ip")
    except requests.exceptions.RequestException:
        return "Not available"


class IPLookupGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("IP Information Lookup Tool")
        self.root.geometry("650x550")
        
        # Set minimum window size
        self.root.minsize(500, 400)
        
        # Enable resizing
        self.root.resizable(True, True)
        
        # Set color scheme
        self.bg_color = "#2b2b2b"
        self.fg_color = "#ffffff"
        self.button_color = "#4CAF50"
        
        self.root.configure(bg=self.bg_color)
        
        # Configure grid weights for responsiveness
        self.root.grid_rowconfigure(0, weight=0)  # Title
        self.root.grid_rowconfigure(1, weight=0)  # Input
        self.root.grid_rowconfigure(2, weight=0)  # Buttons
        self.root.grid_rowconfigure(3, weight=1)  # Results (expandable)
        self.root.grid_rowconfigure(4, weight=0)  # Status bar
        self.root.grid_columnconfigure(0, weight=1)
        
        self.create_widgets()
    
    def create_widgets(self):
        # Title Frame
        title_frame = tk.Frame(self.root, bg=self.bg_color)
        title_frame.grid(row=0, column=0, pady=20, padx=20, sticky="ew")
        
        title_label = tk.Label(
            title_frame,
            text="IP Information Lookup Tool",
            font=("Arial", 18, "bold"),
            bg=self.bg_color,
            fg=self.fg_color
        )
        title_label.pack()
        
        subtitle_label = tk.Label(
            title_frame,
            text="Team: Agilada, Valeros, Cabansag, Vermudo",
            font=("Arial", 9),
            bg=self.bg_color,
            fg="#888888"
        )
        subtitle_label.pack()
        
        # Input Frame
        input_frame = tk.Frame(self.root, bg=self.bg_color)
        input_frame.grid(row=1, column=0, pady=10, padx=20, sticky="ew")
        input_frame.grid_columnconfigure(0, weight=1)
        
        tk.Label(
            input_frame,
            text="Enter IP Address (leave empty for your IP):",
            bg=self.bg_color,
            fg=self.fg_color,
            font=("Arial", 10)
        ).grid(row=0, column=0, sticky="w", pady=(0, 5))
        
        self.ip_entry = tk.Entry(
            input_frame,
            font=("Arial", 12)
        )
        self.ip_entry.grid(row=1, column=0, sticky="ew")
        
        # Buttons Frame
        button_frame = tk.Frame(self.root, bg=self.bg_color)
        button_frame.grid(row=2, column=0, pady=10, sticky="ew")
        
        # Center the buttons
        button_frame.grid_columnconfigure(0, weight=1)
        button_frame.grid_columnconfigure(1, weight=0)
        button_frame.grid_columnconfigure(2, weight=0)
        button_frame.grid_columnconfigure(3, weight=1)
        
        self.lookup_btn = tk.Button(
            button_frame,
            text="Lookup IP Info",
            command=self.lookup_ip,
            bg=self.button_color,
            fg="white",
            font=("Arial", 11, "bold"),
            width=15,
            cursor="hand2",
            relief="raised",
            bd=3
        )
        self.lookup_btn.grid(row=0, column=1, padx=5)
        
        self.clear_btn = tk.Button(
            button_frame,
            text="Clear Results",
            command=self.clear_results,
            bg="#f44336",
            fg="white",
            font=("Arial", 11, "bold"),
            width=15,
            cursor="hand2",
            relief="raised",
            bd=3
        )
        self.clear_btn.grid(row=0, column=2, padx=5)
        
        # Results Frame
        results_frame = tk.Frame(self.root, bg=self.bg_color)
        results_frame.grid(row=3, column=0, pady=10, padx=20, sticky="nsew")
        results_frame.grid_rowconfigure(1, weight=1)
        results_frame.grid_columnconfigure(0, weight=1)
        
        tk.Label(
            results_frame,
            text="Results:",
            bg=self.bg_color,
            fg=self.fg_color,
            font=("Arial", 11, "bold")
        ).grid(row=0, column=0, sticky="w", pady=(0, 5))
        
        # Create a frame for the text widget and scrollbar
        text_container = tk.Frame(results_frame, bg=self.bg_color)
        text_container.grid(row=1, column=0, sticky="nsew")
        text_container.grid_rowconfigure(0, weight=1)
        text_container.grid_columnconfigure(0, weight=1)
        
        self.results_text = tk.Text(
            text_container,
            font=("Courier New", 10),
            bg="#1e1e1e",
            fg="#00ff00",
            wrap=tk.WORD,
            relief="sunken",
            bd=2
        )
        self.results_text.grid(row=0, column=0, sticky="nsew")
        
        # Add scrollbar
        scrollbar = tk.Scrollbar(text_container, command=self.results_text.yview)
        scrollbar.grid(row=0, column=1, sticky="ns")
        self.results_text.config(yscrollcommand=scrollbar.set)
        
        # Status bar
        self.status_label = tk.Label(
            self.root,
            text="Ready",
            bg="#1e1e1e",
            fg="#00ff00",
            font=("Arial", 9),
            anchor="w",
            padx=10,
            relief="sunken"
        )
        self.status_label.grid(row=4, column=0, sticky="ew")
    
    def update_status(self, message):
        """Update the status bar message."""
        self.status_label.config(text=message)
    
    def clear_results(self):
        """Clear the results text box."""
        self.results_text.delete(1.0, tk.END)
        self.update_status("Results cleared")
    
    def lookup_ip(self):
        """Handle IP lookup in a separate thread to avoid freezing UI."""
        ip_address = self.ip_entry.get().strip()
        
        # Validate IP if provided
        if ip_address and not is_valid_ip(ip_address):
            messagebox.showerror("Invalid IP", "Please enter a valid IPv4 or IPv6 address.")
            return
        
        # Check if it's a private/reserved IP
        if ip_address:
            try:
                ip_obj = ipaddress.ip_address(ip_address)
                if not ip_obj.is_global:
                    error_msg = f"The IP address '{ip_address}' is a reserved address.\n\n"
                    if ip_obj.is_private:
                        error_msg += "This IP is in a private network range."
                    elif ip_obj.is_loopback:
                        error_msg += "This is a loopback address (local machine)."
                    elif ip_obj.is_reserved:
                        error_msg += "This IP is reserved for special use."
                    messagebox.showwarning("Reserved IP", error_msg)
                    return
            except ValueError:
                pass
        
        # Disable button during lookup
        self.lookup_btn.config(state="disabled")
        self.update_status("Fetching IP information...")
        
        # Run lookup in separate thread
        thread = threading.Thread(target=self._perform_lookup, args=(ip_address,))
        thread.daemon = True
        thread.start()
    
    def _perform_lookup(self, ip_address):
        """Perform the actual IP lookup."""
        try:
            target_ip = ip_address if ip_address else None
            ip_data = get_public_ip_info(target_ip)
            
            if not ip_data:
                self.root.after(0, lambda: messagebox.showerror(
                    "Error", "Failed to retrieve IP information from all providers."
                ))
                self.root.after(0, lambda: self.lookup_btn.config(state="normal"))
                self.root.after(0, lambda: self.update_status("Lookup failed"))
                return
            
            # Get IPv6 if looking up own IP
            ipv6 = None
            if not target_ip:
                ipv6 = get_public_ipv6()
            
            # Format results
            result_text = self._format_results(ip_data, ipv6)
            
            # Update UI in main thread
            self.root.after(0, lambda: self.display_results(result_text))
            self.root.after(0, lambda: self.lookup_btn.config(state="normal"))
            self.root.after(0, lambda: self.update_status("Lookup completed successfully"))
            
        except Exception as e:
            self.root.after(0, lambda: messagebox.showerror(
                "Error", f"An error occurred: {str(e)}"
            ))
            self.root.after(0, lambda: self.lookup_btn.config(state="normal"))
            self.root.after(0, lambda: self.update_status("Error occurred"))
    
    def _format_results(self, ip_data, ipv6=None):
        """Format IP data for display."""
        title = "Your Public IP Information" if ipv6 else f"IP Information for {ip_data.get('ip', '')}"
        
        result = f"{'=' * 50}\n"
        result += f"{title:^50}\n"
        result += f"{'=' * 50}\n\n"
        
        ip_version = ip_data.get('version', 'IP').upper()
        result += f"{ip_version} Address:        {ip_data.get('ip', 'N/A')}\n"
        
        if ipv6:
            result += f"IPv6 Address:        {ipv6}\n"
        
        result += f"\n{'-' * 50}\n"
        result += f"ISP Provider:        {ip_data.get('isp', 'N/A')}\n"
        result += f"ASN:                 {ip_data.get('asn', 'N/A')}\n"
        result += f"City:                {ip_data.get('city', 'N/A')}\n"
        result += f"Region:              {ip_data.get('region', 'N/A')}\n"
        result += f"Country Code:        {ip_data.get('country_code', 'N/A')}\n"
        result += f"{'-' * 50}\n"
        
        return result
    
    def display_results(self, text):
        """Display results in the text box."""
        self.results_text.delete(1.0, tk.END)
        self.results_text.insert(1.0, text)


def main():
    root = tk.Tk()
    app = IPLookupGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
