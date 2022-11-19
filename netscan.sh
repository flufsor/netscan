#! /bin/sh

VLAN_MIN=1
VLAN_MAX=4094

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
  if [ $(ip addr | grep -w $1 | wc -l) -eq 0 ]; then
    echo "Please provide a valid interface"
    exit 1
  fi
  interface=$1
fi

echo "Starting Netscan on $interface"


# Set interface up
if [ $(cat /sys/class/net/$interface/operstate) = "down" ]; then
  echo "Setting $interface up"
  ip link set $interface up
  echo boo
fi

# Remove old DHCP lease
echo "Removing old DHCP lease"
dhclient -r $interface

# Request ip address from DHCP server
echo "Requesting ip address from DHCP server"
dhclient $interface -v

# TODO: Check if DHCP Succeeded
# Get ip address from ip command
if [ $? -ne 0 ]; then
  echo "Could not get ip address from DHCP server"
  exit 1
else
  ip=$(ip addr show $interface | grep "inet " | awk '{print $2}' | cut -d/ -f1)
  echo "Got ip address $ip"
  echo "Routes: " $(ip route show dev $interface)
fi

# TODO: Ping test gateway
# TODO: Ping test internet
