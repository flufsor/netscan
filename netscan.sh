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

while getopts ':i:t:h' opt; do
  case "$opt" in
    i)
      if [[ ! -d /sys/class/net/${OPTARG} ]]; then
        echo "Please provide a valid interface"
        exit 1
      fi
      INTERFACE=$OPTARG
      INTERFACESHORT=$(echo $INTERFACE | cut -c -6) # Some interfaces are too long
      ;;

    t)
      TCPDUMP_TIMEOUT=$OPTARG
      ;;

    h)
      Usage: $(basename $0) -t <interface> [-i <vlan scan time>]
      exit 0
      ;;

    *)
      echo -e "Invalid command option.\nUsage: $(basename $0) -i <interface> [-t <vlan scan time>]"
      exit 1
      ;;
  esac
done
shift "$(($OPTIND -1))"

if [ -z "$INTERFACE" ]; then
  echo -e "Invalid command option.\nUsage: $(basename $0) -i <interface>"
  exit 1
fi

echo "Starting Netscan on $INTERFACE"

# Set interface up
if [ $(cat /sys/class/net/$INTERFACE/operstate) = "down" ]; then
  echo "Setting $INTERFACE up"
  ip link set $INTERFACE up
else 
  echo "Interface $INTERFACE is already up"
fi

# Scan for VLANs
echo "Starting VLAN scan for $TCPDUMP_TIMEOUT seconds"
timeout $TCPDUMP_TIMEOUT tcpdump -nnt -e vlan -i $INTERFACE > scans/tcpdump-$INTERFACE.log 2>/dev/null
mapfile -t vlans < <(cat scans/tcpdump-$INTERFACE.log  | grep -oP '(?:vlan )([0-9])+' | awk '{print $2}' | sort -nu)

if [ ${#vlans[@]} -ne 0 ]; then
  echo "VLANs found:"

  for vlan in "${vlans[@]}"; do
    echo -e "\t-VLAN: $vlan"
  done

  for vlan in "${vlans[@]}"; do
    echo -e "Scanning Vlan: $vlan"

    # Set interface up
    ip link add link $INTERFACE name $INTERFACESHORT.$vlan type vlan id $vlan >/dev/null 2>&1
    # Requst DHCP address
    timeout 2 dhclient -cf ./dhclient.conf -d -1 $INTERFACESHORT.$vlan &>/dev/null
    # Check for successful DHCP request
    ip=$(ip addr show $INTERFACESHORT.$vlan | grep "inet " | awk '{print $2}')

    if [ -z "$ip" ]; then
      echo -e "\tCould not get ip address from DHCP server"
      echo -e "\tRunning manual IP scan"
    else
      echo -e "\tGot DHCP ip: $ip"
    fi
  done
else
  echo "No VLANs found, trying native VLAN"
    timeout 2 dhclient -cf ./dhclient.conf -d -1 $INTERFACE &>/dev/null
fi

# Cleaning up vlan interfaces
echo "Cleaning Up"

for vlan in "${vlans[@]}"; do
  ip link del link dev $INTERFACESHORT.$vlan
done