#!/usr/bin/env bash
# title         : netscan.sh
# description   : A Network port scanner for linux.
# author        : Tom Goedemé https://github.com/flufsor
# usage         : ./netscan.sh [interface]
# ======================================================================================================================

TCPDUMP_TIMEOUT=60

function test_connection()
{
  # Ping test gateway
  if ping -q -c 1 -W 1 "$1" >/dev/null; then
    echo "IPv4 is up"
  else
    echo "IPv4 is down"
  fi
}

# Check if the user is root
if [ $(id -u) -ne 0 ]; then
  echo "Please run as root"
  exit 1
fi

# Check if the user has provided a valid interface
if [ -z "$1" ]; then
  echo "Please provide an interface"
  exit 1
else
  if [ $(ip addr | grep -c $1) -eq 0 ]; then
    echo "Please provide a valid interface"
    exit 1
  fi
  interface=$1
  interfaceShort=$(echo $interface | cut -c -6) # Some interfaces are too long
fi

echo "Starting Netscan on $interface"

# Set interface up
if [ $(cat /sys/class/net/$interface/operstate) = "down" ]; then
  echo "Setting $interface up"
  ip link set $interface up
else 
  echo "Interface $interface is already up"
fi

# Scan for VLANs
echo "Starting VLAN scan for $TCPDUMP_TIMEOUT seconds"
timeout $TCPDUMP_TIMEOUT tcpdump -nn -e vlan -i $interface > scans/tcpdump-$interface.log 2>/dev/null
mapfile -t vlans < <(cat scans/tcpdump-$interface.log  | grep -oP '(?:vlan )([0-9])+' | awk '{print $2}' | sort -nu)

if [ ${#vlans[@]} -ne 0 ]; then
  echo "VLANs found:"

  for vlan in "${vlans[@]}"; do
    echo -e "\t-VLAN: $vlan"
  done

  for vlan in "${vlans[@]}"; do
    echo -e "Scanning Vlan: $vlan"

    # Set interface up
    ip link add link $interface name $interfaceShort.$vlan type vlan id $vlan >/dev/null 2>&1
    # Requst DHCP address
    timeout 2 dhclient -cf ./dhclient.conf -d -1 $interfaceShort.$vlan &>/dev/null
    # Check for successful DHCP request
    ip=$(ip addr show $interfaceShort.$vlan | grep "inet " | awk '{print $2}')

    if [ -z "$ip" ]; then
      echo -e "\tCould not get ip address from DHCP server"
      echo -e "\tRunning manual IP scan"
    else
      echo -e "\tGot DHCP ip: $ip"
    fi
  done
else
  echo "No VLANs found, trying native vlan"
  request_dhcp_address $interface
fi
