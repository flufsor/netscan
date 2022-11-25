# Netscan

A Network port scanner for linux that can scan for accessible devices and tries to find network device information with CDP/LLDP/SNMP.

## Usage

Execute the script with:

    ./netscan.sh $interface

- $Interface is the network interface to scan (eg: eth0, ens18)

## Requirements

This script requires root access and is tested on debian.
Required packages are:

- tcpdump
- dhclient

## Credits:

-Tom Goedemé
-Jasper van Meel (AWK Hero)
