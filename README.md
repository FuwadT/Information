# Information
Information Gathering Script

This is a basic Python Script that can be used to gather information. 

Features
Device Information:

Retrieves the hostname, operating system, and local IP address of the device.
Public IP and Geolocation:

Fetches the public IP address of the device.
Uses the IP to gather geographical location data (country, region, city, latitude, longitude) using a geolocation API.
Port Scanning:

Scans the device for open ports using the nmap library (ports 1-1024).
Exploitation Identification:

Identifies potential security vulnerabilities based on open ports. This is a basic check against a predefined list of common exploits.
Requirements
Before running the script, make sure you have the following installed:

Python 3.x
Required libraries:
requests - For making HTTP requests to get public IP and location information.
nmap - For scanning open ports.
