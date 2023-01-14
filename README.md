# Netscan

A Network port scanner for linux that can scan for accessible devices and tries to find network device information with CDP/LLDP.

## Usage

Execute the script with:

Usage: ./netscan.sh [options] -i [interface]

Options:

-c Cleanup after scan

-i Interface to scan

-t Timeout for tcpdump

-h Show this help

## Requirements

This script requires root access and is tested on debian.
Required packages are:

- tcpdump
- dhclient
- lldpd
- nmap

## Credits:

- Tom Goedemé
- Jasper van Meel (regex)
